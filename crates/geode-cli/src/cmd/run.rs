//! `geode run` (SPEC-v034 G6; harmonized spec §3). Picks a transport and
//! hands the request to the one pipeline: `geode_grotto::inject::plan`
//! authorizes and decrypts, `geode_os::spawn` starts the child,
//! `inject::Collector` redacts and caps its output. This module does not
//! authorize, match `allow_cmds`, or redact on its own.
//!
//! Local mode only in this build: `human:local`, key in hand, no token.
//! `--socket` is refused (exit 1); an agent reaches the custody daemon
//! through MCP `geode_run` instead. `--file` waits for the memfd / tmpfs
//! binding.
//!
//! Redaction catches the v1 encodings only (raw, base64, hex, one
//! percent-encoding, canonical JSON string) plus the known token
//! prefixes. It does not catch shell quoting or any other transform, and
//! it does not stop a hostile command.

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
///
/// Local use needs a key. A token is refused (exit 4). `--` is required
/// before the command. `argv[0]` is resolved
/// against `PATH`, canonicalized, and must match an `--allow-cmd`.
/// A bare path does not pin. A JSON object, or a rule in `--allow-cmds-file`,
/// pins `{path, sha256, args_prefix}` and is checked against the fd that
/// exec runs. `--require-pin`, or `"require_pin": true` in that file,
/// rejects a rule with no sha256. A pin is refused unless the binary and
/// every ancestor up to `/` is owned by root, not group- or other-writable,
/// and not a symlink. Every binding must pass policy, or nothing runs. The child
/// gets a fresh env: `PATH`, `HOME`, `LANG`, `TERM`, then the bindings. It
/// never gets `GEODE_TOKEN`.
///
/// Stdout carries only the child's redacted stdout. Stderr carries
/// `geode:` lines (warnings, `injected: NAMES (values withheld)`) and the
/// child's redacted stderr. Each stream is capped at 1 MiB, then
/// `[TRUNCATED]`. A bound value is replaced with `[REDACTED:NAME]`, or
/// `[REDACTED]` for a token-prefix match.
///
/// Redaction catches the v1 encodings only: raw, base64 (standard and
/// URL-safe), hex, one percent-encoding, and a canonical JSON string.
/// It does not catch shell quoting or any other transform. Redaction stops
/// accidents; it does not stop a hostile command.
///
/// Exit: before spawn, 1 usage, 2 auth, 3 policy deny or `argv[0]` not
/// allowed (including a pin miss), 4 token, 5 locked. After spawn, the
/// child's code, or 128+N for signal N.
#[derive(Args, Debug)]
pub struct RunArgs {
    /// Vault directory the bindings come from.
    #[arg(long, value_name = "DIR")]
    pub vault: PathBuf,
    /// Custody daemon socket. Refused in this build (exit 1); agents use
    /// MCP `geode_run` on the custody daemon.
    #[arg(long, value_name = "PATH")]
    pub socket: Option<PathBuf>,
    /// Bind the vault object at PATH to env NAME (repeatable). NAME matches
    /// `[A-Z_][A-Z0-9_]{0,63}`; `PATH`, `HOME`, `LANG`, `TERM`, `GEODE_*`,
    /// `LD_*`, and `DYLD_*` are reserved. The value goes only into the
    /// child's env and is never printed. A value under 8 bytes is refused.
    /// Child output is redacted for the v1 encodings only (raw, base64,
    /// hex, one percent-encoding, canonical JSON string). Shell quoting and
    /// other transforms are not caught. Redaction does not stop a hostile
    /// command.
    #[arg(long = "secret", value_name = "NAME=PATH")]
    pub secret: Vec<String>,
    /// File binding. Not available in local mode in this build.
    #[arg(long = "file", value_name = "NAME=PATH")]
    pub file: Vec<String>,
    /// Absolute canonical executable this local run may start (repeatable).
    /// With none, nothing runs.
    ///
    /// A path allows that program with no digest check. A JSON object pins
    /// it: `{"path":"/abs/exe","sha256":"<64 hex>","args_prefix":["…"]}`.
    /// `sha256` is required in the object (lowercase hex of the binary;
    /// uppercase is accepted and stored lowercase). `args_prefix` is the
    /// required leading arguments after the program and may be omitted or
    /// empty. A relative path, or a path that is not canonical, is refused.
    /// The digest is read from the fd that exec runs. A pin is refused
    /// unless that file and every ancestor up to `/` is owned by root, not
    /// group- or other-writable, and not a symlink. The error names the
    /// component that failed.
    #[arg(long = "allow-cmd", value_name = "PATH|JSON")]
    pub allow_cmd: Vec<String>,
    /// JSON list of pinned commands. Each object is
    /// `{"path":"/abs/exe","sha256":"<64 hex>","args_prefix":["…"]}`.
    /// `path` must be absolute and canonical. `sha256` is required.
    /// `args_prefix` may be omitted. Combined with `--allow-cmd`.
    /// An object `{"require_pin":true,"cmds":[…]}` is that list plus the
    /// require-pin setting (`require_pin` defaults to false). A list leaves
    /// require-pin off. On macOS the hashed fd cannot be exec'd; the child
    /// re-checks the path against that fd immediately before exec.
    #[arg(long, value_name = "FILE")]
    pub allow_cmds_file: Option<PathBuf>,
    /// Refuse an allow rule that has no sha256 pin, including a bare
    /// `--allow-cmd PATH`. `"require_pin": true` in `--allow-cmds-file`
    /// does the same. Off by default, so a bare path still runs.
    #[arg(long)]
    pub require_pin: bool,
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
    /// Token file. Socket mode only; local mode refuses any token (exit 4).
    #[arg(long, value_name = "PATH")]
    pub token_file: Option<PathBuf>,
    /// Token fd. Socket mode only; local mode refuses any token (exit 4).
    #[arg(long, value_name = "N")]
    pub token_fd: Option<u32>,
    /// The command and its arguments, after `--`. An argument that
    /// contains a bound value, in any v1 encoding, is refused
    /// (`argv_rejected`, exit 3).
    #[arg(last = true, value_name = "CMD")]
    pub command: Vec<String>,
}

/// A refusal before spawn: the shipped exit code and one `geode:` line.
/// Custody `geode_run` reports `kind` as the `isError` code.
pub(crate) struct Refusal {
    pub(crate) code: i32,
    pub(crate) kind: &'static str,
    pub(crate) msg: String,
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
            "local geode run refuses a token (GEODE_TOKEN, --token-file, --token-fd)",
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
    let cmds = load_run_cmds(args)?;
    Ok((bindings, cmds))
}

/// Allow rules from `--allow-cmd` and `--allow-cmds-file`. When require-pin
/// is on (flag or file), a rule with no sha256 is a usage error here, before
/// any key is read and before a child can start.
fn load_run_cmds(args: &RunArgs) -> Result<Vec<CmdRule>, Refusal> {
    let mut cmds: Vec<CmdRule> = Vec::new();
    for raw in &args.allow_cmd {
        let rule = cmd::agent::parse_allow_cmd_arg(raw)
            .map_err(|e| refuse(exit::USAGE, "usage", error_text(&e)))?;
        if !cmds.contains(&rule) {
            cmds.push(rule);
        }
    }
    let mut require_pin = args.require_pin;
    if let Some(file) = &args.allow_cmds_file {
        let parsed = cmd::agent::read_pinned_cmds_file(file)
            .map_err(|e| refuse(exit::USAGE, "usage", error_text(&e)))?;
        require_pin |= parsed.require_pin;
        for rule in parsed.rules {
            if !cmds.contains(&rule) {
                cmds.push(rule);
            }
        }
    }
    if require_pin {
        if let Some(rule) = cmds.iter().find(|r| r.sha256.is_none()) {
            return Err(refuse(
                exit::USAGE,
                "usage",
                format!("require-pin: allow-cmd '{}' has no sha256 pin", rule.path),
            ));
        }
    }
    Ok(cmds)
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
        enforce_hosts: false,
    };
    let view = VaultView {
        root: &args.vault,
        ek: &ctx.ek,
        epoch: ctx.epoch,
        manifest: &ctx.manifest,
    };
    let base_path = std::env::var_os("PATH");
    let row = RowBase {
        principal: LOCAL_PRINCIPAL.into(),
        token_id: String::new(),
        peer_uid: None,
        peer_pid: None,
        vault_id: cmd::hex(&ctx.vault_id.0),
        paths: bindings.iter().map(|b| b.path.clone()).collect(),
        custody: false,
        hosts: inject::hosts_label(&[]),
    };
    let mut plan = match inject::plan(
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
    execute(args, out, &mut plan, &mut chain, &row)
}

/// Fields every audit row of one run shares. Local runs are
/// `human:local`, no token, `custody: false`; custody runs carry the token
/// id, the kernel peer, and `custody: true`.
pub(crate) struct RowBase {
    pub(crate) principal: String,
    pub(crate) token_id: String,
    pub(crate) peer_uid: Option<u32>,
    pub(crate) peer_pid: Option<u32>,
    pub(crate) vault_id: String,
    pub(crate) paths: Vec<String>,
    pub(crate) custody: bool,
    pub(crate) hosts: String,
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
) -> Result<(), Refusal> {
    let input = AuditInput {
        ts: now(),
        token_id: row.token_id.clone(),
        principal: row.principal.clone(),
        peer_uid: row.peer_uid,
        peer_pid: row.peer_pid,
        vault_id: row.vault_id.clone(),
        op: "run".into(),
        paths: row.paths.clone(),
        exit_code,
        redaction_hits: hits,
        outcome: outcome.into(),
        custody: row.custody,
        hosts: row.hosts.clone(),
        argv,
    };
    // Fail closed (Fix 3): the SQLite chain is the source of truth, so a
    // row that cannot be written stops the run. A Facet mirror error is
    // not fatal; `Chain::append` already keeps the row in that case.
    chain
        .append(input, crate::cmd::audit::mirror)
        .map(|_| ())
        .map_err(|e| audit_failed(&e))
}

/// The refusal for a failed audit append. Exit 1, inside the frozen 0-5
/// set, as for an audit db that cannot be opened. The message names the
/// error only; no row field and no value is echoed.
fn audit_failed(e: &dyn std::fmt::Display) -> Refusal {
    refuse(
        exit::USAGE,
        "audit_failed",
        format!("audit append failed: {e}; refusing to run"),
    )
}

/// The argv commit for a run that did not spawn: empty argv0, no args.
fn not_spawned() -> ArgvCommit {
    ArgvCommit::Clean {
        argv0: String::new(),
        args: Vec::new(),
    }
}

/// Deny and argv-rejected plans get a row; usage and auth failures do not.
pub(crate) fn plan_refusal(chain: &mut Chain, row: &RowBase, e: PlanError) -> Refusal {
    match e {
        PlanError::Usage(m) => refuse(exit::USAGE, "usage", m),
        PlanError::Auth => refuse(
            exit::AUTH,
            "auth_fail",
            "authentication / integrity failure",
        ),
        PlanError::Deny { reason, .. } => {
            // Nothing spawned: argv0 is empty and no argument is hashed.
            if let Err(r) = append(
                chain,
                row,
                "policy_deny",
                not_spawned(),
                None,
                BTreeMap::new(),
            ) {
                return r;
            }
            refuse(exit::POLICY, "policy_deny", reason)
        }
        PlanError::ArgvRejected { exe } => {
            let msg = PlanError::ArgvRejected { exe: exe.clone() }.to_string();
            if let Err(r) = append(
                chain,
                row,
                "argv_rejected",
                ArgvCommit::Rejected { exe },
                None,
                BTreeMap::new(),
            ) {
                return r;
            }
            refuse(exit::POLICY, "argv_rejected", msg)
        }
    }
}

/// Child env from scratch: `PATH`, `HOME`, `LANG`, `TERM` from the caller
/// when set (`HOME` replaced by `home` when given), then the bindings.
/// Nothing else, so no `GEODE_TOKEN`.
fn child_env(plan: &inject::Plan, home: Option<&OsStr>) -> Vec<(OsString, OsString)> {
    let mut env: Vec<(OsString, OsString)> = inject::BASE_ENV
        .iter()
        .filter_map(|k| {
            let v = match (*k, home) {
                ("HOME", Some(h)) => Some(h.to_os_string()),
                _ => std::env::var_os(k),
            };
            v.map(|v| (OsString::from(k), v))
        })
        .collect();
    for (name, value) in &plan.env {
        env.push((
            OsString::from(name),
            OsStr::from_bytes(value.expose_secret()).to_os_string(),
        ));
    }
    env
}

/// How one planned run is started. Built by the transport.
pub(crate) struct ExecOpts {
    pub(crate) cwd: Option<PathBuf>,
    pub(crate) inherit_stdin: bool,
    pub(crate) timeout: Duration,
    pub(crate) identity: geode_os::ChildIdentity,
    pub(crate) allow_hosts: Vec<String>,
    /// `HOME` for the child; `None` keeps the caller's.
    pub(crate) home: Option<OsString>,
}

/// A finished run: how the child ended, hits, and whether output was cut.
pub(crate) struct Executed {
    pub(crate) outcome: geode_os::ChildOutcome,
    pub(crate) hits: BTreeMap<String, u64>,
    pub(crate) truncated: bool,
}

/// The one executor for both transports: spawn through `geode_os`, redact
/// and cap through `inject::Collector`, hand each safe chunk to `emit`,
/// and write the audit row. Local `geode run` streams; custody buffers.
/// A pinned exe's fd moves out of `plan` into the spawn.
pub(crate) fn execute_plan(
    plan: &mut inject::Plan,
    opts: ExecOpts,
    chain: &mut Chain,
    row: &RowBase,
    mut emit: impl FnMut(Channel, Vec<u8>),
) -> Result<Executed, Refusal> {
    let pin = plan
        .take_pin()
        .map(|(fd, meta)| geode_os::PinnedExe { fd, meta });
    let plan = &*plan;
    let argv = || ArgvCommit::Clean {
        argv0: plan.exe.clone(),
        args: plan.args.clone(),
    };
    // Intent row before any value leaves the plan (Fix 3). If it cannot be
    // written, no child env is built and nothing spawns.
    append(chain, row, "started", argv(), None, BTreeMap::new())?;
    let spec = geode_os::SpawnSpec {
        program: PathBuf::from(&plan.exe),
        args: plan.args.iter().map(OsString::from).collect(),
        env: child_env(plan, opts.home.as_deref()),
        cwd: opts.cwd,
        inherit_stdin: opts.inherit_stdin,
        timeout: opts.timeout,
    };
    let mut collector = Collector::new(plan);
    let spawned =
        geode_os::spawn_with_pin(spec, pin, &opts.identity, &opts.allow_hosts, |s, chunk| {
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
            )?;
            // A list that cannot be enforced is a refusal, never an
            // unconfined run.
            return Err(if opts.allow_hosts.is_empty() {
                refuse(
                    exit::USAGE,
                    "spawn_failed",
                    format!("{}: cannot start: {e}", plan.exe),
                )
            } else {
                refuse(
                    exit::POLICY,
                    "policy_deny",
                    format!("allow_hosts: cannot isolate the child network: {e}"),
                )
            });
        }
    };
    for ch in [Channel::Stdout, Channel::Stderr] {
        let tail = collector.finish(ch);
        emit(ch, tail);
    }
    let hits = collector.hits();
    let label = if outcome.timed_out {
        "timed_out"
    } else {
        "spawned"
    };
    append(
        chain,
        row,
        label,
        argv(),
        Some(outcome.process_exit()),
        hits.clone(),
    )?;
    Ok(Executed {
        outcome,
        hits,
        truncated: collector.truncated(),
    })
}

fn execute(
    args: &RunArgs,
    out: OutMode,
    plan: &mut inject::Plan,
    chain: &mut Chain,
    row: &RowBase,
) -> Result<i32, Refusal> {
    // After authorization, before spawn (harmonized spec §3 Output).
    eprintln!(
        "geode: injected: {} (values withheld)",
        plan.names().join(", ")
    );
    let opts = ExecOpts {
        cwd: args.cwd.clone(),
        inherit_stdin: args.stdin,
        timeout: Duration::from_secs(args.timeout),
        identity: geode_os::ChildIdentity::Inherit,
        allow_hosts: Vec::new(),
        home: None,
    };
    let (mut buf_out, mut buf_err) = (Vec::new(), Vec::new());
    let emit = |ch: Channel, bytes: Vec<u8>| match (out, ch) {
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
    let done = execute_plan(plan, opts, chain, row, emit)?;
    let Executed {
        outcome,
        hits,
        truncated,
    } = done;
    let code = outcome.process_exit();
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
                "truncated": truncated,
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
