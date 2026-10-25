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
use std::path::{Component, Path, PathBuf};
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

// The compile refusal is `not(debug_assertions)` only (`cargo build --release`,
// `cargo install`). A dev or test build can still enable `test-trusted-root`;
// the integration tests do. That is not a release guarantee.
// `--test-unconfined-hosts` is behind the same feature.
#[cfg(all(feature = "test-trusted-root", not(debug_assertions)))]
compile_error!(
    "feature `test-trusted-root` is test-only and insecure (it moves the pin trust root); \
     release builds, including `cargo install`, cannot enable it"
);

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
/// gets a fresh env: `PATH`, `HOME` (or `--home`), `LANG`, `TERM`, then the
/// bindings. It never gets `GEODE_TOKEN`. A run with `--secret` and no
/// `--allow-host` is refused before spawn on every OS.
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
    /// Host this run may contact with a bound secret (repeatable). Required
    /// when `--secret` is set. `host` or `host:port`. No scheme, path, or
    /// userinfo. An empty list is refused before spawn. The check is the
    /// custody allowlist. There is no switch that turns it off.
    #[arg(long = "allow-host", value_name = "HOST")]
    pub allow_host: Vec<String>,
    /// Test-only and insecure. Compiled out of release builds. Both this and
    /// `test_trusted_uid` are required together; production runs pass neither.
    #[cfg(feature = "test-trusted-root")]
    #[arg(long, hide = true, value_name = "DIR")]
    pub test_trusted_root: Option<PathBuf>,
    /// Uid that must own `test_trusted_root` and every component under it.
    #[cfg(feature = "test-trusted-root")]
    #[arg(long, hide = true, value_name = "UID")]
    pub test_trusted_uid: Option<u32>,
    /// Test-only and insecure. Compiled out of release builds. Skips host
    /// confinement so existing spawn tests can run without a network
    /// namespace. A release `geode` does not accept this flag.
    #[cfg(feature = "test-trusted-root")]
    #[arg(long, hide = true)]
    pub test_unconfined_hosts: bool,
    /// Seconds before SIGTERM; SIGKILL follows 2 seconds later.
    #[arg(long, value_name = "SECS", default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Forward stdin to the child (default: /dev/null).
    #[arg(long)]
    pub stdin: bool,
    /// Working directory for the child.
    #[arg(long, value_name = "DIR")]
    pub cwd: Option<PathBuf>,
    /// `HOME` for the child in place of the caller's. Must be absolute,
    /// must not contain `..`, and must not be the caller's `HOME`. This is
    /// a usability guard, not a boundary: the child still runs as the
    /// caller. Custody homes should be pre-created, owned by root or the
    /// daemon, mode 0700, and not a symlink.
    #[arg(long, value_name = "DIR")]
    pub home: Option<PathBuf>,
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

/// Parse-level inputs, checked before any key is touched.
struct Prepared {
    bindings: Vec<BindingSpec>,
    cmds: Vec<CmdRule>,
    hosts: Vec<String>,
    home: Option<OsString>,
}

/// Validate the parse-level rules before any key is touched.
fn preflight(args: &RunArgs) -> Result<Prepared, Refusal> {
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
    let hosts = parse_allow_hosts(&args.allow_host)?;
    let home = args
        .home
        .as_deref()
        .map(|d| check_home(d, std::env::var_os("HOME").as_deref()))
        .transpose()?;
    Ok(Prepared {
        home,
        bindings,
        cmds,
        hosts,
    })
}

/// `--home`: absolute, no `..`, and not the caller's `HOME`, compared by
/// components and again canonically when both resolve.
fn check_home(dir: &Path, caller: Option<&OsStr>) -> Result<OsString, Refusal> {
    let bad = |why: &str| {
        refuse(
            exit::USAGE,
            "usage",
            format!("--home {}: {why}", dir.display()),
        )
    };
    if !dir.is_absolute() {
        return Err(bad("must be an absolute path"));
    }
    if dir.components().any(|c| c == Component::ParentDir) {
        return Err(bad("must not contain .."));
    }
    if let Some(caller) = caller.filter(|h| !h.is_empty()).map(Path::new) {
        let same = dir == caller
            || matches!(
                (dir.canonicalize(), caller.canonicalize()),
                (Ok(a), Ok(b)) if a == b
            );
        if same {
            return Err(bad("is the caller's HOME"));
        }
    }
    Ok(dir.as_os_str().to_os_string())
}

/// `--allow-host` entries, lowercased, in first-seen order.
fn parse_allow_hosts(raw: &[String]) -> Result<Vec<String>, Refusal> {
    let mut hosts = Vec::new();
    for host in raw {
        let host = cmd::agent::normalize_host(host)
            .map_err(|e| refuse(exit::USAGE, "usage", error_text(&e)))?;
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(hosts)
}

/// True only in a test build that asked to skip host confinement.
fn unconfined_run(args: &RunArgs) -> bool {
    #[cfg(feature = "test-trusted-root")]
    {
        args.test_unconfined_hosts
    }
    #[cfg(not(feature = "test-trusted-root"))]
    {
        let _ = args;
        false
    }
}

/// Usable `allow_hosts` for a secret binding, or the shared refusal.
/// Local `geode run` and custody both call this. Empty is not allow-all.
pub(crate) fn secret_hosts_or_refuse(hosts: &[String]) -> Result<Vec<String>, Refusal> {
    match geode_os::egress::require_secret_hosts(hosts) {
        Ok(()) => Ok(hosts.to_vec()),
        Err(err) => Err(refuse(exit::POLICY, err.code(), err.to_string())),
    }
}

/// Hosts passed to spawn. An empty secret list writes a deny row and
/// returns the refusal. The test seam skips the check and confines nothing.
fn resolve_spawn_hosts(
    chain: &mut Chain,
    row: &RowBase,
    bindings: &[BindingSpec],
    hosts: &[String],
    unconfined: bool,
) -> Result<Vec<String>, Refusal> {
    if unconfined || bindings.is_empty() {
        return Ok(Vec::new());
    }
    match secret_hosts_or_refuse(hosts) {
        Ok(list) => Ok(list),
        Err(err) => Err(plan_refusal(
            chain,
            row,
            PlanError::Deny {
                reason: err.msg,
                exe: None,
            },
        )),
    }
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
    let Prepared {
        bindings,
        cmds,
        hosts: hosts_in,
        home,
    } = preflight(args)?;
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

    let unconfined = unconfined_run(args);
    let mut row = RowBase {
        principal: LOCAL_PRINCIPAL.into(),
        token_id: String::new(),
        peer_uid: None,
        peer_pid: None,
        vault_id: cmd::hex(&ctx.vault_id.0),
        paths: bindings.iter().map(|b| b.path.clone()).collect(),
        custody: false,
        hosts: "refused".into(),
    };
    let spawn_hosts = resolve_spawn_hosts(&mut chain, &row, &bindings, &hosts_in, unconfined)?;
    row.hosts = if spawn_hosts.is_empty() {
        inject::hosts_label(&[])
    } else {
        inject::hosts_label(&spawn_hosts)
    };
    let principal = PrincipalId(LOCAL_PRINCIPAL.into());
    let caller = Caller {
        principal: &principal,
        policy: &policy,
        token: None,
        allow_cmds: &cmds,
        allow_hosts: &spawn_hosts,
        redact: RedactLevel::Strict,
        // A non-empty list is enforced on every platform, not only Linux.
        enforce_hosts: !spawn_hosts.is_empty(),
    };
    let view = VaultView {
        root: &args.vault,
        ek: &ctx.ek,
        epoch: ctx.epoch,
        manifest: &ctx.manifest,
    };
    let base_path = std::env::var_os("PATH");
    let request = PlanRequest {
        bindings: &bindings,
        argv: &args.command,
        base_path: base_path.as_deref(),
        no_redact: args.no_redact,
    };
    let mut plan = match plan_run(args, &caller, &view, &request) {
        Ok(p) => p,
        Err(e) => return Err(plan_refusal(&mut chain, &row, e)),
    };
    execute(args, out, &mut plan, &mut chain, &row, (spawn_hosts, home))
}

/// Production `plan`, or the test root when that feature is compiled in.
fn plan_run<'a>(
    args: &RunArgs,
    caller: &Caller<'a>,
    view: &VaultView<'a>,
    request: &PlanRequest<'a>,
) -> Result<inject::Plan, PlanError> {
    #[cfg(feature = "test-trusted-root")]
    {
        match (args.test_trusted_root.as_deref(), args.test_trusted_uid) {
            (None, None) => inject::plan(caller, view, request),
            (Some(root), Some(uid)) => {
                inject::plan_with_test_root(caller, view, request, root, uid)
            }
            _ => Err(PlanError::Usage(
                "test-trusted-root and test-trusted-uid must be set together".into(),
            )),
        }
    }
    #[cfg(not(feature = "test-trusted-root"))]
    {
        let _ = args;
        inject::plan(caller, view, request)
    }
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

#[allow(clippy::too_many_arguments)]
fn append(
    chain: &mut Chain,
    row: &RowBase,
    outcome: &str,
    argv: ArgvCommit,
    exit_code: Option<i32>,
    hits: BTreeMap<String, u64>,
    hosts: &str,
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
        hosts: hosts.into(),
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
                &row.hosts,
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
                &row.hosts,
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
    /// Test-only. When set, an empty host list does not refuse a secret
    /// binding and the child is not confined. Absent from release builds.
    #[cfg(any(test, feature = "test-trusted-root"))]
    pub(crate) test_unconfined_hosts: bool,
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
    // Host refusal is before the intent row and before the child env, so a
    // secret with no allowlist never leaves the plan.
    let hosts_for_child = match confined_hosts(plan, &opts) {
        Ok(hosts) => hosts,
        Err(err) => {
            return Err(plan_refusal(
                chain,
                row,
                PlanError::Deny {
                    reason: err.msg,
                    exe: None,
                },
            ));
        }
    };
    let isolate = !hosts_for_child.is_empty();
    // Intent row before any value leaves the plan (Fix 3). If it cannot be
    // written, no child env is built and nothing spawns.
    append(
        chain,
        row,
        "started",
        argv(),
        None,
        BTreeMap::new(),
        &row.hosts,
    )?;
    let denials = geode_os::HostDenials::default();
    let spec = geode_os::SpawnSpec {
        program: PathBuf::from(&plan.exe),
        args: plan.args.iter().map(OsString::from).collect(),
        env: child_env(plan, opts.home.as_deref()),
        cwd: opts.cwd,
        inherit_stdin: opts.inherit_stdin,
        timeout: opts.timeout,
        host_denials: denials.clone(),
    };
    let mut collector = Collector::new(plan);
    let spawned =
        geode_os::spawn_with_pin(spec, pin, &opts.identity, &hosts_for_child, |s, chunk| {
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
                &row.hosts,
            )?;
            // A list that cannot be enforced is a refusal, never an
            // unconfined run.
            return Err(if !isolate {
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
    record_host_denials(chain, row, &argv, &denials)?;
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
        &row.hosts,
    )?;
    Ok(Executed {
        outcome,
        hits,
        truncated: collector.truncated(),
    })
}

/// One `host_denied` audit row per proxy refusal, after the child and
/// before the close row. A failed append is `audit_failed`; the child has
/// already run. The token is not written.
fn record_host_denials(
    chain: &mut Chain,
    row: &RowBase,
    argv: &impl Fn() -> ArgvCommit,
    denials: &geode_os::HostDenials,
) -> Result<(), Refusal> {
    for host in denials.snapshot() {
        append(
            chain,
            row,
            "host_denied",
            argv(),
            None,
            BTreeMap::new(),
            &host,
        )?;
    }
    Ok(())
}

/// Hosts the child may dial. The test seam returns an empty list and does
/// not refuse. Otherwise a secret binding with an empty list is a refusal.
fn confined_hosts(plan: &inject::Plan, opts: &ExecOpts) -> Result<Vec<String>, Refusal> {
    if exec_unconfined(opts) {
        return Ok(Vec::new());
    }
    if plan.env.is_empty() {
        return Ok(opts.allow_hosts.clone());
    }
    secret_hosts_or_refuse(&opts.allow_hosts)
}

fn exec_unconfined(opts: &ExecOpts) -> bool {
    #[cfg(any(test, feature = "test-trusted-root"))]
    {
        opts.test_unconfined_hosts
    }
    #[cfg(not(any(test, feature = "test-trusted-root")))]
    {
        let _ = opts;
        false
    }
}

fn execute(
    args: &RunArgs,
    out: OutMode,
    plan: &mut inject::Plan,
    chain: &mut Chain,
    row: &RowBase,
    (hosts, home): (Vec<String>, Option<OsString>),
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
        allow_hosts: hosts,
        #[cfg(any(test, feature = "test-trusted-root"))]
        test_unconfined_hosts: unconfined_run(args),
        home,
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

#[cfg(test)]
mod host_policy_tests {
    use super::secret_hosts_or_refuse;
    use crate::output::exit;

    #[test]
    fn empty_secret_allow_hosts_is_policy_deny() {
        let err = secret_hosts_or_refuse(&[]).unwrap_err();
        assert_eq!(err.code, exit::POLICY);
        assert_eq!(err.kind, "policy_deny");
        assert!(err.msg.contains("allow_hosts"), "{}", err.msg);
        assert!(err.msg.contains("refusing"), "{}", err.msg);
        let unusable = secret_hosts_or_refuse(&[":not-a-port".into()]).unwrap_err();
        assert_eq!(unusable.kind, "policy_deny");
    }

    #[test]
    fn local_and_custody_host_gate_agree() {
        let hosts = vec!["API.example.com".into(), "db.example.com:5432".into()];
        assert!(secret_hosts_or_refuse(&hosts).is_ok());
        let cases = [
            ("api.example.com", 443u16, true),
            ("db.example.com", 5432, true),
            ("db.example.com", 5433, false),
            ("evil.example", 443, false),
        ];
        for (host, port, allowed) in cases {
            let decided = geode_os::egress::gate(&hosts, host, port);
            assert_eq!(decided.is_ok(), allowed, "{host}:{port}");
            if let Err(err) = decided {
                assert_eq!(err.code(), "host_denied");
            }
        }
    }

    #[test]
    fn proxy_denial_is_an_audit_row() {
        let dir = std::env::temp_dir().join(format!(
            "geode-deny-audit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("audit.db");
        let mut chain = geode_grotto::audit::open(&db).unwrap();
        let row = super::RowBase {
            principal: "human:local".into(),
            token_id: String::new(),
            peer_uid: None,
            peer_pid: None,
            vault_id: "00".into(),
            paths: vec!["cfg/note".into()],
            custody: false,
            hosts: "api.example.com".into(),
        };
        let denials = geode_os::HostDenials::default();
        denials.record("blocked.example", 443);
        let argv = || geode_grotto::audit::ArgvCommit::Clean {
            argv0: "/bin/sh".into(),
            args: Vec::new(),
        };
        super::record_host_denials(&mut chain, &row, &argv, &denials)
            .unwrap_or_else(|err| panic!("{}", err.msg));
        drop(chain);
        let conn = rusqlite::Connection::open(&db).unwrap();
        let (outcome, hosts): (String, String) = conn
            .query_row(
                "SELECT outcome, hosts FROM audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(outcome, "host_denied");
        assert_eq!(hosts, "blocked.example:443");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod home_tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        run: RunArgs,
    }

    fn parse(flags: &[&str]) -> Result<RunArgs, clap::Error> {
        let mut argv = vec!["geode", "--vault", "/v"];
        argv.extend_from_slice(flags);
        argv.extend(["--", "/bin/true"]);
        Cli::try_parse_from(argv).map(|c| c.run)
    }

    fn refused_ok<T>(r: Result<T, Refusal>) -> T {
        match r {
            Ok(v) => v,
            Err(e) => panic!("refused: {}", e.msg),
        }
    }

    fn refused<T>(r: Result<T, Refusal>) -> Refusal {
        match r {
            Ok(_) => panic!("accepted"),
            Err(e) => e,
        }
    }

    #[test]
    fn only_allow_host_is_accepted() {
        let a = parse(&["--allow-host", "api.example.com"]).unwrap();
        assert_eq!(a.allow_host, ["api.example.com"]);
        assert!(parse(&["--allow-hosts", "api.example.com"]).is_err());
    }

    #[test]
    fn secret_without_hosts_is_refused_with_home_on_every_os() {
        let a = parse(&["--home", "/srv/geode-home", "--secret", "K=cfg/k"]).unwrap();
        assert!(a.allow_host.is_empty());
        let err = refused(secret_hosts_or_refuse(&refused_ok(parse_allow_hosts(
            &a.allow_host,
        ))));
        assert_eq!((err.code, err.kind), (exit::POLICY, "policy_deny"));
    }

    #[test]
    fn home_flag_parses_to_the_dir() {
        let a = parse(&["--home", "/srv/geode-home"]).unwrap();
        assert_eq!(a.home.as_deref(), Some(Path::new("/srv/geode-home")));
        let got = check_home(a.home.as_deref().unwrap(), Some(OsStr::new("/Users/me")));
        assert_eq!(got.ok().unwrap(), OsString::from("/srv/geode-home"));
    }

    #[test]
    fn home_must_be_absolute_without_dotdot() {
        for d in ["rel/home", "./home", "/srv/../Users/me"] {
            let r = refused(check_home(Path::new(d), Some(OsStr::new("/Users/me"))));
            assert_eq!(r.code, exit::USAGE, "{d}");
            assert!(r.msg.starts_with("--home "), "{}", r.msg);
        }
    }

    #[test]
    fn home_equal_to_caller_home_is_refused() {
        for d in ["/Users/me", "/Users/me/", "/Users//me", "/Users/./me"] {
            let r = refused(check_home(Path::new(d), Some(OsStr::new("/Users/me"))));
            assert!(r.msg.contains("caller's HOME"), "{d}: {}", r.msg);
        }
    }

    #[test]
    fn home_resolving_to_caller_home_is_refused() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        let link = base.path().join("link");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let r = refused(check_home(&link, Some(real.as_os_str())));
        assert!(r.msg.contains("caller's HOME"), "{}", r.msg);
        assert!(check_home(base.path(), Some(real.as_os_str())).is_ok());
    }

    #[test]
    fn home_with_no_caller_home_is_accepted() {
        assert!(check_home(Path::new("/srv/geode-home"), None).is_ok());
        assert!(check_home(Path::new("/srv/geode-home"), Some(OsStr::new(""))).is_ok());
    }
}
