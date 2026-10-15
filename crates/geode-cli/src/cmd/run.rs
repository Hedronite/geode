//! `geode run` (SPEC-v034 G6; harmonized spec §3). Picks a transport and
//! hands the request to the one pipeline: `geode_grotto::inject::plan`
//! authorizes and decrypts, `geode_os::spawn` starts the child,
//! `inject::Collector` redacts and caps its output. This module does not
//! authorize, match `allow_cmds`, or redact on its own.
//!
//! Local mode only in this build: `human:local`, key in hand, no token.
//! `--socket` waits for the custody daemon. `--file` waits for the
//! memfd / tmpfs binding.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt as _;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use geode_grotto::audit::{self, ArgvCommit, AuditInput, Chain};
use geode_grotto::inject::{
    self, BindingSpec, Caller, Channel, Collector, PlanError, PlanRequest, VaultView,
};
use geode_grotto::policy::PrincipalId;
use geode_grotto::token::{CmdRule, RedactLevel};
use geode_grotto::Error;
use secrecy::ExposeSecret as _;

use crate::output::exit;
use crate::{cmd, GlobalArgs, OutMode};

const LOCAL_PRINCIPAL: &str = "human:local";
const DEFAULT_TIMEOUT_SECS: u64 = 120;

/// `geode run` — run a command with vault secrets injected into its env.
/// Values never reach Geode's output; the child's output is redacted.
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Vault directory the bindings come from.
    #[arg(long, value_name = "DIR")]
    pub vault: PathBuf,
    /// Custody daemon socket. Not available in this build.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Bind the vault object at PATH to env NAME (repeatable). NAME matches
    /// `[A-Z_][A-Z0-9_]{0,63}`; `PATH`, `HOME`, `LANG`, `TERM`, `GEODE_*`,
    /// `LD_*`, and `DYLD_*` are reserved.
    #[arg(long = "secret", value_name = "NAME=PATH")]
    pub secret: Vec<String>,
    /// File binding. Not available in local mode in this build.
    #[arg(long = "file", value_name = "NAME=PATH")]
    pub file: Vec<String>,
    /// Absolute canonical executable this local run may start (repeatable).
    /// With none, nothing runs.
    #[arg(long = "allow-cmd", value_name = "PATH")]
    pub allow_cmd: Vec<PathBuf>,
    /// Seconds before SIGTERM; SIGKILL follows 2 seconds later.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Forward stdin to the child (default: /dev/null).
    #[arg(long)]
    pub stdin: bool,
    /// Working directory for the child.
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<PathBuf>,
    /// Do not redact child output. Only a `human:*` principal with `admin`.
    #[arg(long)]
    pub no_redact: bool,
    /// Refused on `geode run` (argv is visible in ps/history).
    #[arg(long, value_name = "TOKEN", hide = true)]
    pub token: Option<String>,
    /// Token file. Socket mode only; local mode refuses any token.
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Token fd. Socket mode only; local mode refuses any token.
    #[arg(long, value_name = "N")]
    pub token_fd: Option<u32>,
    /// The command and its arguments, after `--`.
    #[arg(last = true, value_name = "CMD")]
    pub command: Vec<String>,
}

/// A refusal before spawn: the shipped exit code and one `geode:` line.
struct Refusal {
    code: i32,
    kind: &'static str,
    msg: String,
}

fn refuse(code: i32, kind: &'static str, msg: impl Into<String>) -> Refusal {
    Refusal {
        code,
        kind,
        msg: msg.into(),
    }
}

/// Entry point. Exits the process itself: after spawn the exit is the
/// child's.
pub fn run(args: &RunArgs, global: &GlobalArgs, out: OutMode) -> ! {
    let code = match local(args, global, out) {
        Ok(code) => code,
        Err(r) => {
            report_refusal(&r, out);
            r.code
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

fn report_refusal(r: &Refusal, out: OutMode) {
    match out {
        OutMode::Json => println!(
            "{}",
            serde_json::json!({
                "spawned": false,
                "error": {"code": r.kind, "message": r.msg},
            })
        ),
        OutMode::Text => eprintln!("geode: error: {}", r.msg),
    }
}

fn parse_bindings(raw: &[String]) -> Result<Vec<BindingSpec>, Refusal> {
    raw.iter()
        .map(|b| {
            let (name, path) = b
                .split_once('=')
                .ok_or_else(|| refuse(exit::USAGE, "usage", "--secret wants NAME=PATH"))?;
            Ok(BindingSpec {
                name: name.to_owned(),
                path: path.to_owned(),
            })
        })
        .collect()
}

fn token_present(args: &RunArgs) -> bool {
    args.token_file.is_some()
        || args.token_fd.is_some()
        || std::env::var_os("GEODE_TOKEN").is_some_and(|t| !t.is_empty())
}

/// Validate the parse-level rules before any key is touched.
fn preflight(args: &RunArgs) -> Result<(Vec<BindingSpec>, Vec<CmdRule>), Refusal> {
    if args.token.is_some() {
        return Err(refuse(
            exit::USAGE,
            "usage",
            "--token on argv is refused for geode run; use --token-file with --socket",
        ));
    }
    if args.socket.is_some() {
        return Err(refuse(
            exit::USAGE,
            "usage",
            "--socket needs the custody daemon, which this build does not have",
        ));
    }
    if token_present(args) {
        return Err(refuse(
            exit::TOKEN,
            "token_refused",
            "local geode run is human:local and refuses a token (GEODE_TOKEN, --token-file, --token-fd)",
        ));
    }
    if args.command.is_empty() {
        return Err(refuse(exit::USAGE, "usage", "no command after --"));
    }
    if !args.file.is_empty() {
        return Err(refuse(
            exit::USAGE,
            "usage",
            "--file is not available in local mode in this build; use --secret",
        ));
    }
    if args.timeout == 0 {
        return Err(refuse(
            exit::USAGE,
            "usage",
            "--timeout must be at least 1 second",
        ));
    }
    let bindings = parse_bindings(&args.secret)?;
    let mut cmds: Vec<CmdRule> = Vec::new();
    for p in &args.allow_cmd {
        let path = p
            .to_str()
            .ok_or_else(|| refuse(exit::USAGE, "usage", "--allow-cmd path is not UTF-8"))?;
        let path = cmd::agent::canonical_cmd(path)
            .map_err(|e| refuse(exit::USAGE, "usage", error_text(&e)))?;
        let rule = CmdRule {
            path,
            sha256: None,
            args_prefix: Vec::new(),
        };
        if !cmds.contains(&rule) {
            cmds.push(rule);
        }
    }
    Ok((bindings, cmds))
}

fn error_text(e: &Error) -> String {
    match e {
        Error::Format(m) => m.clone(),
        other => other.to_string(),
    }
}

/// Map a core error from key or vault load to the shipped codes.
fn load_refusal(e: &Error) -> Refusal {
    match e {
        Error::AuthFail => refuse(
            exit::AUTH,
            "auth_fail",
            "authentication / integrity failure",
        ),
        Error::Locked => refuse(exit::LOCKED, "locked", "vault is locked"),
        Error::PolicyDeny => refuse(exit::POLICY, "policy_deny", "policy deny"),
        Error::TokenInvalid => refuse(exit::TOKEN, "token_invalid", "token invalid"),
        other => refuse(exit::USAGE, "usage", error_text(other)),
    }
}

fn local(args: &RunArgs, global: &GlobalArgs, out: OutMode) -> Result<i32, Refusal> {
    let (bindings, cmds) = preflight(args)?;
    if geode_os::deny_core_dumps().is_err() {
        eprintln!("geode: warning: could not refuse core dumps for this process");
    }
    let key_path = cmd::require_key(global).map_err(|e| load_refusal(&e))?;
    let isk = cmd::load_isk(&key_path).map_err(|e| load_refusal(&e))?;
    let ctx = cmd::load_vault(&args.vault, &isk).map_err(|e| load_refusal(&e))?;
    drop(isk);
    let mk = geode_grotto::kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
    let policy = geode_grotto::policy::load_policy(&args.vault, &mk, ctx.vault_id, ctx.epoch)
        .map_err(|e| load_refusal(&e))?;
    // The audit chain must be writable before anything can spawn.
    let db = crate::cmd::audit::local_db_path().ok_or_else(|| {
        refuse(
            exit::USAGE,
            "usage",
            "no local audit path: set HOME or XDG_STATE_HOME",
        )
    })?;
    let mut chain = audit::open(&db).map_err(|e| {
        refuse(
            exit::USAGE,
            "usage",
            format!("audit db {}: {e}", db.display()),
        )
    })?;

    let principal = PrincipalId(LOCAL_PRINCIPAL.into());
    let caller = Caller {
        principal: &principal,
        policy: &policy,
        token: None,
        allow_cmds: &cmds,
        allow_hosts: &[],
        redact: RedactLevel::Strict,
    };
    let view = VaultView {
        root: &args.vault,
        ek: &ctx.ek,
        epoch: ctx.epoch,
        manifest: &ctx.manifest,
    };
    let base_path = std::env::var_os("PATH");
    let row = RowBase {
        vault_id: cmd::hex(&ctx.vault_id.0),
        paths: bindings.iter().map(|b| b.path.clone()).collect(),
    };
    let plan = match inject::plan(
        &caller,
        &view,
        &PlanRequest {
            bindings: &bindings,
            argv: &args.command,
            base_path: base_path.as_deref(),
            no_redact: args.no_redact,
        },
    ) {
        Ok(p) => p,
        Err(e) => return Err(plan_refusal(&mut chain, &row, e)),
    };
    execute(args, out, &plan, &mut chain, &row)
}

/// Fields every row of this run shares.
struct RowBase {
    vault_id: String,
    paths: Vec<String>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

fn append(
    chain: &mut Chain,
    row: &RowBase,
    outcome: &str,
    argv: ArgvCommit,
    exit_code: Option<i32>,
    hits: BTreeMap<String, u64>,
) {
    let input = AuditInput {
        ts: now(),
        token_id: String::new(),
        principal: LOCAL_PRINCIPAL.into(),
        peer_uid: None,
        peer_pid: None,
        vault_id: row.vault_id.clone(),
        op: "run".into(),
        paths: row.paths.clone(),
        exit_code,
        redaction_hits: hits,
        outcome: outcome.into(),
        custody: false,
        hosts: "unrestricted".into(),
        argv,
    };
    if let Err(e) = chain.append(input, crate::cmd::audit::mirror) {
        eprintln!("geode: warning: audit append failed: {e}");
    }
}

/// The argv commit for a run that did not spawn: empty argv0, no args.
fn not_spawned() -> ArgvCommit {
    ArgvCommit::Clean {
        argv0: String::new(),
        args: Vec::new(),
    }
}

/// Deny and argv-rejected plans get a row; usage and auth failures do not.
fn plan_refusal(chain: &mut Chain, row: &RowBase, e: PlanError) -> Refusal {
    match e {
        PlanError::Usage(m) => refuse(exit::USAGE, "usage", m),
        PlanError::Auth => refuse(
            exit::AUTH,
            "auth_fail",
            "authentication / integrity failure",
        ),
        PlanError::Deny { reason, .. } => {
            // Nothing spawned: argv0 is empty and no argument is hashed.
            append(
                chain,
                row,
                "policy_deny",
                not_spawned(),
                None,
                BTreeMap::new(),
            );
            refuse(exit::POLICY, "policy_deny", reason)
        }
        PlanError::ArgvRejected { exe } => {
            let msg = PlanError::ArgvRejected { exe: exe.clone() }.to_string();
            append(
                chain,
                row,
                "argv_rejected",
                ArgvCommit::Rejected { exe },
                None,
                BTreeMap::new(),
            );
            refuse(exit::POLICY, "argv_rejected", msg)
        }
    }
}

/// Child env from scratch: `PATH`, `HOME`, `LANG`, `TERM` from the caller
/// when set, then the bindings. Nothing else, so no `GEODE_TOKEN`.
fn child_env(plan: &inject::Plan) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = inject::BASE_ENV
        .iter()
        .filter_map(|k| std::env::var_os(k).map(|v| (OsString::from(k), v)))
        .collect();
    for (name, value) in &plan.env {
        env.push((
            OsString::from(name),
            OsStr::from_bytes(value.expose_secret()).to_os_string(),
        ));
    }
    env
}

fn execute(
    args: &RunArgs,
    out: OutMode,
    plan: &inject::Plan,
    chain: &mut Chain,
    row: &RowBase,
) -> Result<i32, Refusal> {
    // After authorization, before spawn (harmonized spec §3 Output).
    eprintln!(
        "geode: injected: {} (values withheld)",
        plan.names().join(", ")
    );
    let spec = geode_os::SpawnSpec {
        program: PathBuf::from(&plan.exe),
        args: plan.args.iter().map(OsString::from).collect(),
        env: child_env(plan),
        cwd: args.cwd.clone(),
        inherit_stdin: args.stdin,
        timeout: Duration::from_secs(args.timeout),
    };
    let mut collector = Collector::new(plan);
    let (mut buf_out, mut buf_err) = (Vec::new(), Vec::new());
    let mut emit = |ch: Channel, bytes: Vec<u8>| match (out, ch) {
        (OutMode::Json, Channel::Stdout) => buf_out.extend_from_slice(&bytes),
        (OutMode::Json, Channel::Stderr) => buf_err.extend_from_slice(&bytes),
        (OutMode::Text, Channel::Stdout) => {
            let mut o = std::io::stdout().lock();
            let _ = o.write_all(&bytes);
            let _ = o.flush();
        }
        (OutMode::Text, Channel::Stderr) => {
            let _ = std::io::stderr().lock().write_all(&bytes);
        }
    };
    let spawned = geode_os::spawn(spec, |s, chunk| {
        let ch = match s {
            geode_os::Stream::Stdout => Channel::Stdout,
            geode_os::Stream::Stderr => Channel::Stderr,
        };
        let bytes = collector.push(ch, chunk);
        emit(ch, bytes);
    });
    let outcome = match spawned {
        Ok(o) => o,
        Err(e) => {
            append(
                chain,
                row,
                "spawn_failed",
                not_spawned(),
                None,
                BTreeMap::new(),
            );
            return Err(refuse(
                exit::USAGE,
                "spawn_failed",
                format!("{}: cannot start: {e}", plan.exe),
            ));
        }
    };
    for ch in [Channel::Stdout, Channel::Stderr] {
        let tail = collector.finish(ch);
        emit(ch, tail);
    }
    let hits = collector.hits();
    let code = outcome.process_exit();
    let argv = ArgvCommit::Clean {
        argv0: plan.exe.clone(),
        args: plan.args.clone(),
    };
    let label = if outcome.timed_out {
        "timed_out"
    } else {
        "spawned"
    };
    append(chain, row, label, argv, Some(code), hits.clone());
    match out {
        OutMode::Json => println!(
            "{}",
            serde_json::json!({
                "spawned": true,
                "exit_code": outcome.exit_code,
                "signal": outcome.signal,
                "timed_out": outcome.timed_out,
                "stdout_redacted": String::from_utf8_lossy(&buf_out),
                "stderr_redacted": String::from_utf8_lossy(&buf_err),
                "truncated": collector.truncated(),
                "redaction_hits": hits,
            })
        ),
        OutMode::Text => {
            if outcome.timed_out {
                eprintln!("geode: warning: timed out after {}s", args.timeout);
            }
            if !hits.is_empty() {
                let list: Vec<String> = hits.iter().map(|(k, v)| format!("{k}\u{d7}{v}")).collect();
                eprintln!("geode: warning: redacted output: {}", list.join(", "));
            }
        }
    }
    Ok(code)
}
