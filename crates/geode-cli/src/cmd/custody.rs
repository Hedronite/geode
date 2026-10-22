//! Custody daemon and its control verbs (SPEC-v034 G7; design §1, §5).
//!
//! `geode agent serve --custody --vault DIR` runs as `geode` / `_geode`,
//! never euid 0 and never the console user. It owns the `.gkey`, the
//! unlocked session, and the vault binding. It listens on the fixed custody
//! socket (mode 0660, group `geode-agents`) and never creates its parent.
//! It never mounts.
//!
//! Per connection: the peer's uid/gid/pid come from the kernel. A token
//! arrives once in `initialize` as `params._meta.geode_token`, must carry
//! `peer_uid`, and must match the peer. The agent tools are the frozen
//! three, plus `geode_run` only when the bound token holds `inject` (G8).
//! `geode_run` returns one buffered result; values never come back.
//! Redaction catches the v1 encodings only (raw, base64, hex, one
//! percent-encoding, canonical JSON string) and the known token prefixes.
//! It does not catch shell quoting or any other transform, and it does not
//! stop a hostile command; `allow_cmds` and `allow_hosts` narrow who can
//! try.
//!
//! `geode custody unlock|lock|status` are clients. They resolve no key.
//! `unlock` and `lock` are refused for a peer in `geode-agents`. `status`
//! prints no key bytes. Identity decisions live in `geode_os::ident`.

use std::io::{BufRead as _, BufReader, IsTerminal as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clap::{Args, Subcommand};
use geode_grotto::token::{self, Token};
use geode_grotto::{Error, Result};
use geode_os::ident::{self, PeerCred};

use crate::cmd::agent::{
    mcp_error_code, normalize_sealed, now_secs, rpc_error, rpc_line_too_large, rpc_ok,
    tool_descriptors_for, write_frame, AgentCall, StdioServer, MCP_PROTOCOL_VERSION,
};
use crate::cmd::run;
use crate::{cmd, GlobalArgs, OutMode, TokenSource};
use geode_grotto::inject;
use geode_grotto::policy::Op;

/// Idle lock for the custody session (core `session::DEFAULT_IDLE_LOCK`).
const IDLE_LOCK: Duration = geode_grotto::session::DEFAULT_IDLE_LOCK;
/// JSON-RPC error code for every custody refusal; `data.code` names it.
const CUSTODY_ERROR: i64 = -32000;
const RATE_MAX: u32 = 128;
const RATE_WINDOW: Duration = Duration::from_secs(10);
const AGENT_TOOLS: [&str; 3] = ["geode_list", "geode_read", "geode_write"];
const RUN_TOOL: &str = "geode_run";
/// `geode_run` default and ceiling, in seconds (design §3).
const RUN_TIMEOUT_DEFAULT: u64 = 120;
const RUN_TIMEOUT_MAX: u64 = 3600;

/// The `geode_run` descriptor (design §5). The token is never an argument.
fn run_descriptor() -> serde_json::Value {
    serde_json::json!({
        "name": RUN_TOOL,
        "description": "Run an allowlisted command with vault secrets injected into its env. Values never return: stdout and stderr come back redacted in one buffered result. A non-zero child exit is a normal result with exit_code; isError means Geode refused.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "vault": {"type": "string", "description": "The daemon's vault directory"},
                "argv": {"type": "array", "items": {"type": "string"}, "description": "Command and arguments; argv[0] must be in the token's allow_cmds"},
                "secrets": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Env NAME to vault path"},
                "files": {"type": "object", "additionalProperties": {"type": "string"}, "description": "File bindings (not available in this build)"},
                "cwd": {"type": "string", "description": "Working directory for the child"},
                "timeout_s": {"type": "integer", "description": "Seconds before SIGTERM (default 120)"},
            },
            "required": ["vault", "argv", "secrets"],
        },
    })
}

/// Parsed `geode_run` arguments.
struct RunRequest {
    argv: Vec<String>,
    bindings: Vec<inject::BindingSpec>,
    cwd: Option<PathBuf>,
    timeout: Duration,
}

impl RunRequest {
    fn parse(args: &serde_json::Value) -> std::result::Result<Self, Refusal> {
        let usage = |m: &str| refusal("usage", m.to_owned());
        let argv = args["argv"]
            .as_array()
            .ok_or_else(|| usage("argv must be an array of strings"))?
            .iter()
            .map(|a| a.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| usage("argv must be an array of strings"))?;
        let secrets = args["secrets"]
            .as_object()
            .ok_or_else(|| usage("secrets must be an object of NAME to vault path"))?;
        let bindings = secrets
            .iter()
            .map(|(name, path)| {
                path.as_str().map(|p| inject::BindingSpec {
                    name: name.clone(),
                    path: p.to_owned(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| usage("secrets values must be vault paths"))?;
        if args["files"].as_object().is_some_and(|f| !f.is_empty()) {
            return Err(usage(
                "files bindings are not available in this build; use secrets",
            ));
        }
        let timeout = match args.get("timeout_s") {
            None | Some(serde_json::Value::Null) => RUN_TIMEOUT_DEFAULT,
            Some(v) => v
                .as_u64()
                .filter(|t| (1..=RUN_TIMEOUT_MAX).contains(t))
                .ok_or_else(|| usage("timeout_s must be 1..3600"))?,
        };
        Ok(Self {
            argv,
            bindings,
            cwd: args["cwd"].as_str().map(PathBuf::from),
            timeout: Duration::from_secs(timeout),
        })
    }
}

/// The fixed custody socket. The parent comes from systemd
/// `RuntimeDirectory=` or the launchd plist; Geode does not create it.
#[must_use]
pub fn default_socket() -> PathBuf {
    if cfg!(target_os = "macos") {
        PathBuf::from("/var/run/geode/custody.sock")
    } else {
        PathBuf::from("/run/geode/custody.sock")
    }
}

// ---------------------------------------------------------------------
// Client verbs
// ---------------------------------------------------------------------

/// `geode custody` — control the custody daemon over its socket.
///
/// These verbs are clients. They resolve no key and send no token. The
/// daemon itself is `geode agent serve --custody --vault DIR`. `unlock`
/// and `lock` are refused for a peer in `geode-agents`. No verb prints key
/// bytes or the passphrase.
#[derive(Args, Debug)]
pub struct CustodyArgs {
    #[command(subcommand)]
    pub cmd: CustodyCmd,
}

#[derive(Subcommand, Debug)]
pub enum CustodyCmd {
    /// Unlock the daemon's key. Passphrase from `--passphrase-fd`, else a
    /// no-echo prompt on a TTY; with neither, exit 1. The passphrase goes
    /// to the daemon over the socket and is never printed. Refused for
    /// members of `geode-agents`.
    Unlock {
        /// Custody socket (default: the platform custody socket).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Read the passphrase from open file descriptor N (first line).
        #[arg(long, value_name = "N")]
        passphrase_fd: Option<u32>,
    },
    /// Lock the daemon's session. Refused for members of `geode-agents`.
    Lock {
        /// Custody socket (default: the platform custody socket).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
    /// Locked or unlocked, idle time left, socket, daemon uid, and key id.
    /// No key bytes.
    Status {
        /// Custody socket (default: the platform custody socket).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}

pub fn run(args: &CustodyArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (socket, method) = match &args.cmd {
        CustodyCmd::Unlock { socket, .. } => (socket, "geode/custody.unlock"),
        CustodyCmd::Lock { socket } => (socket, "geode/custody.lock"),
        CustodyCmd::Status { socket } => (socket, "geode/custody.status"),
    };
    let socket = socket.clone().unwrap_or_else(default_socket);
    socket_mode_key_rules(global)?;
    refuse_passphrase_env_in_agent_context(token_source_present(None))?;
    let mut params = serde_json::json!({});
    if let CustodyCmd::Unlock { passphrase_fd, .. } = &args.cmd {
        if passphrase_fd.is_none() && !std::io::stdin().is_terminal() {
            return Err(Error::Format(
                "custody unlock needs --passphrase-fd N or a TTY".into(),
            ));
        }
        if let Some(fd) = passphrase_fd {
            crate::output::load_passphrase_fd(*fd).map_err(Error::Io)?;
        }
    }
    let mut client = Client::connect(&socket)?;
    if let CustodyCmd::Unlock { .. } = &args.cmd {
        // Read the passphrase only after the peer passed the custody checks.
        let pass = match crate::output::fd_passphrase() {
            Some(p) => p,
            None => crate::output::prompt_passphrase("custody passphrase: ").map_err(Error::Io)?,
        };
        params["passphrase"] = serde_json::json!(pass.as_str());
    }
    let result = client.call(method, &params)?;
    let text = match method {
        "geode/custody.status" => status_text(&result),
        "geode/custody.unlock" => "custody unlocked".to_owned(),
        _ => "custody locked".to_owned(),
    };
    let verb = method.trim_start_matches("geode/").replace('.', "_");
    cmd::emit(out, &verb, result, &text);
    Ok(())
}

fn status_text(r: &serde_json::Value) -> String {
    let dash = |v: &serde_json::Value| {
        if v.is_null() {
            "-".to_owned()
        } else {
            v.to_string().trim_matches('"').to_owned()
        }
    };
    let state = if r["locked"].as_bool().unwrap_or(true) {
        "locked"
    } else {
        "unlocked"
    };
    format!(
        "custody {state}\n  idle-left {}\n  socket {}\n  daemon-uid {}\n  key-id {}",
        dash(&r["idle_left_secs"]),
        dash(&r["socket"]),
        dash(&r["daemon_uid"]),
        dash(&r["key_id"]),
    )
}

/// Socket mode resolves no key (design §1). `--key` is refused;
/// `GEODE_KEY_FILE` is ignored with one warning.
pub(crate) fn socket_mode_key_rules(global: &GlobalArgs) -> Result<()> {
    let Some(key) = &global.key else {
        return Ok(());
    };
    let from_env = std::env::var_os("GEODE_KEY_FILE").is_some_and(|v| Path::new(&v) == key);
    if from_env {
        eprintln!("geode: warning: GEODE_KEY_FILE ignored in socket mode");
        Ok(())
    } else {
        Err(Error::Format(
            "--key cannot be combined with --socket: socket mode resolves no key".into(),
        ))
    }
}

/// Any token source on the command line or in the environment.
fn token_source_present(src: Option<&TokenSource>) -> bool {
    src.is_some_and(|t| t.token.is_some() || t.token_file.is_some() || t.token_fd.is_some())
        || std::env::var_os("GEODE_TOKEN").is_some_and(|t| !t.is_empty())
}

/// Design §6: on `custody` and `agent serve --custody`, `GEODE_PASSPHRASE`
/// is refused when a token source is present and stdin or stdout is not a
/// TTY. Existing verbs are untouched.
pub(crate) fn refuse_passphrase_env_in_agent_context(token_present: bool) -> Result<()> {
    let set = std::env::var_os("GEODE_PASSPHRASE").is_some();
    let tty = std::io::stdin().is_terminal() && std::io::stdout().is_terminal();
    if set && token_present && !tty {
        return Err(Error::Format(
            "GEODE_PASSPHRASE refused in an agent context; use --passphrase-fd".into(),
        ));
    }
    Ok(())
}

/// A connected custody client.
struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: u64,
}

impl Client {
    /// Connect, `initialize` with no token, require a custody server, and
    /// refuse a custody peer that shares the caller's uid.
    fn connect(socket: &Path) -> Result<Self> {
        let stream = UnixStream::connect(socket).map_err(|e| {
            Error::Format(format!(
                "cannot connect to custody socket {}: {e}",
                socket.display()
            ))
        })?;
        let peer = ident::peer_cred(&stream).map_err(Error::Io)?;
        let mut c = Self {
            reader: BufReader::new(stream.try_clone().map_err(Error::Io)?),
            writer: stream,
            next_id: 1,
        };
        let init = c.call(
            "initialize",
            &serde_json::json!({"protocolVersion": MCP_PROTOCOL_VERSION, "capabilities": {}}),
        )?;
        if init["capabilities"]["experimental"]["geode"]["custody"] != true {
            return Err(Error::Format(format!(
                "{} is not a custody socket",
                socket.display()
            )));
        }
        ident::check_custody_peer(peer.uid, ident::euid()).map_err(Error::Format)?;
        Ok(c)
    }

    fn call(&mut self, method: &str, params: &serde_json::Value) -> Result<serde_json::Value> {
        let id = self.next_id;
        self.next_id += 1;
        let frame =
            serde_json::json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        write_frame(&mut self.writer, &frame)?;
        let mut line = String::new();
        if self.reader.read_line(&mut line).map_err(Error::Io)? == 0 {
            return Err(Error::Format("custody daemon closed the connection".into()));
        }
        let resp: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| Error::Format(format!("custody reply: {e}")))?;
        if let Some(err) = resp.get("error") {
            return Err(remote_error(err));
        }
        Ok(resp
            .get("result")
            .cloned()
            .unwrap_or(serde_json::Value::Null))
    }
}

/// Map a daemon refusal onto the shipped exit families.
fn remote_error(err: &serde_json::Value) -> Error {
    let msg = err["message"]
        .as_str()
        .unwrap_or("custody error")
        .to_owned();
    match err["data"]["code"].as_str().unwrap_or("") {
        "policy_deny" => {
            eprintln!("geode: error: {msg}");
            Error::PolicyDeny
        }
        "auth_fail" => Error::AuthFail,
        "locked" => Error::Locked,
        "token_invalid" | "unauthenticated" => {
            eprintln!("geode: error: {msg}");
            Error::TokenInvalid
        }
        _ => Error::Format(msg),
    }
}

// ---------------------------------------------------------------------
// Daemon
// ---------------------------------------------------------------------

/// `geode agent serve --custody --vault DIR` (design §1).
pub(crate) fn serve(
    stdio: bool,
    socket: Option<&Path>,
    vault: Option<&Path>,
    token_src: &TokenSource,
    global: &GlobalArgs,
) -> Result<()> {
    if stdio {
        return Err(Error::Format(
            "--custody cannot be combined with --stdio".into(),
        ));
    }
    if socket.is_some() {
        return Err(Error::Format(format!(
            "--custody listens on {}; --socket is the plain transport",
            default_socket().display()
        )));
    }
    if token_src.token.is_some() || token_src.token_file.is_some() || token_src.token_fd.is_some() {
        return Err(Error::Format(
            "--custody binds a token per connection; drop the serve-time token".into(),
        ));
    }
    let vault = vault.ok_or_else(|| Error::Format("--custody needs --vault DIR".into()))?;
    refuse_passphrase_env_in_agent_context(token_source_present(Some(token_src)))?;
    let me = ident::euid();
    let daemon_user = ident::lookup_user(ident::DAEMON_USER).map_err(Error::Io)?;
    ident::check_daemon_identity(me, ident::console_uid(), daemon_user.map(|u| u.uid))
        .map_err(Error::Format)?;
    let key = cmd::require_key(global)?;
    let agents_gid = ident::lookup_group(ident::AGENTS_GROUP)
        .map_err(Error::Io)?
        .ok_or_else(|| Error::Format(format!("group {} does not exist", ident::AGENTS_GROUP)))?;
    if geode_os::deny_core_dumps().is_err() {
        eprintln!("geode: warning: could not refuse core dumps for this process");
    }
    let audit_db = crate::cmd::audit::local_db_path()
        .ok_or_else(|| Error::Format("no audit path for the custody user: set HOME".into()))?;
    let socket = default_socket();
    let listener = bind_custody(&socket, Some(agents_gid))?;
    let paths = DaemonPaths {
        vault: vault.to_path_buf(),
        key,
        socket: socket.clone(),
        audit_db,
    };
    let daemon = Arc::new(Daemon::new(
        paths,
        me,
        Agents::Gid(agents_gid),
        ChildRule::Os,
    ));
    let result = daemon.listen(&listener);
    let _ = std::fs::remove_file(&socket);
    result
}

/// Bind the custody socket: the parent must exist (never created here), a
/// live socket at the path is refused, a stale one is replaced, then mode
/// 0660 and, when given, group `gid`. Any failure after bind unlinks it.
pub(crate) fn bind_custody(path: &Path, gid: Option<u32>) -> Result<UnixListener> {
    use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| Error::Format("custody socket path has no parent".into()))?;
    if !parent.is_dir() {
        return Err(Error::Format(format!(
            "custody socket parent does not exist: {} (Geode does not create it)",
            parent.display()
        )));
    }
    if let Ok(meta) = std::fs::symlink_metadata(path) {
        if !meta.file_type().is_socket() || UnixStream::connect(path).is_ok() {
            return Err(Error::Format(format!(
                "custody socket path is in use: {}",
                path.display()
            )));
        }
        std::fs::remove_file(path).map_err(Error::Io)?;
    }
    let listener = UnixListener::bind(path)
        .map_err(|e| Error::Format(format!("bind {}: {e}", path.display())))?;
    let finish = || -> std::io::Result<()> {
        if let Some(g) = gid {
            std::os::unix::fs::chown(path, None, Some(g))?;
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))
    };
    if let Err(e) = finish() {
        let _ = std::fs::remove_file(path);
        return Err(Error::Format(format!(
            "custody socket {}: {e}",
            path.display()
        )));
    }
    Ok(listener)
}

/// Who may not unlock or lock.
pub(crate) enum Agents {
    /// Production: members of this gid (primary or supplementary).
    Gid(u32),
    /// Tests: these peer uids count as agents.
    #[cfg_attr(not(test), allow(dead_code))]
    Uids(Vec<u32>),
}

struct Unlocked {
    ctx: cmd::VaultCtx,
    last_used: Instant,
}

pub(crate) struct Daemon {
    vault: PathBuf,
    key: PathBuf,
    socket: PathBuf,
    daemon_uid: u32,
    agents: Agents,
    idle: Duration,
    session: Mutex<Option<Unlocked>>,
    audit_db: PathBuf,
    child: ChildRule,
}

/// The files a daemon owns. The seatbelt denies `key`, `audit_db`, and
/// `socket` to a macOS child.
pub(crate) struct DaemonPaths {
    pub(crate) vault: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) socket: PathBuf,
    pub(crate) audit_db: PathBuf,
}

/// How a `geode_run` child identity is chosen.
pub(crate) enum ChildRule {
    /// Production: `geode-run` on Linux, the seatbelted daemon on macOS
    /// (`geode_os::ident::child_identity`). Never the agent uid.
    Os,
    /// Tests: a fixed identity, since the runner has no custody accounts.
    #[cfg_attr(not(test), allow(dead_code))]
    Fixed(geode_os::ChildIdentity),
}

/// One custody refusal, sent as a JSON-RPC error with `data.code`.
struct Refusal {
    code: &'static str,
    msg: String,
}

fn refusal(code: &'static str, msg: impl Into<String>) -> Refusal {
    Refusal {
        code,
        msg: msg.into(),
    }
}

impl From<Error> for Refusal {
    fn from(e: Error) -> Self {
        let msg = match &e {
            Error::Format(m) => m.clone(),
            other => other.to_string(),
        };
        refusal(mcp_error_code(&e), msg)
    }
}

/// Per-connection state: the kernel's peer and the bound token.
struct Conn {
    peer: PeerCred,
    sealed: Option<Vec<u8>>,
    calls: u32,
    window: Instant,
}

impl Daemon {
    pub(crate) fn new(
        paths: DaemonPaths,
        daemon_uid: u32,
        agents: Agents,
        child: ChildRule,
    ) -> Self {
        Self {
            vault: paths.vault,
            key: paths.key,
            socket: paths.socket,
            daemon_uid,
            agents,
            idle: IDLE_LOCK,
            session: Mutex::new(None),
            audit_db: paths.audit_db,
            child,
        }
    }

    /// Accept forever; one thread per connection.
    pub(crate) fn listen(self: &Arc<Self>, listener: &UnixListener) -> Result<()> {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let d = Arc::clone(self);
            std::thread::spawn(move || {
                let _ = d.handle(stream);
            });
        }
        Ok(())
    }

    fn handle(&self, stream: UnixStream) -> Result<()> {
        let peer = ident::peer_cred(&stream).map_err(Error::Io)?;
        let mut conn = Conn {
            peer,
            sealed: None,
            calls: 0,
            window: Instant::now(),
        };
        let reader = BufReader::new(stream.try_clone().map_err(Error::Io)?);
        let mut writer = stream;
        for line in reader.lines() {
            let line = line.map_err(Error::Io)?;
            if line.trim().is_empty() {
                continue;
            }
            if rpc_line_too_large(&line) {
                write_frame(
                    &mut writer,
                    &rpc_error(&serde_json::Value::Null, -32600, "frame exceeds 1 MiB cap"),
                )?;
                continue;
            }
            let Ok(req) = serde_json::from_str::<serde_json::Value>(&line) else {
                write_frame(
                    &mut writer,
                    &rpc_error(&serde_json::Value::Null, -32700, "parse error"),
                )?;
                continue;
            };
            let Some(id) = req.get("id").cloned() else {
                continue;
            };
            let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let params = req
                .get("params")
                .cloned()
                .unwrap_or(serde_json::Value::Null);
            let frame = match self.dispatch(&mut conn, method, &params) {
                Ok(Some(result)) => rpc_ok(&id, &result),
                Ok(None) => rpc_error(&id, -32601, &format!("unknown method '{method}'")),
                Err(r) => serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {"code": CUSTODY_ERROR, "message": r.msg, "data": {"code": r.code}},
                }),
            };
            write_frame(&mut writer, &frame)?;
        }
        Ok(())
    }

    /// `Ok(None)` is an unknown method. There is no mount method.
    fn dispatch(
        &self,
        conn: &mut Conn,
        method: &str,
        params: &serde_json::Value,
    ) -> std::result::Result<Option<serde_json::Value>, Refusal> {
        Ok(Some(match method {
            "initialize" => self.initialize(conn, params)?,
            "ping" => serde_json::json!({}),
            "tools/list" => serde_json::json!({"tools": self.tools(conn)}),
            "tools/call" => self.tool_call(conn, params),
            "geode/custody.unlock" => self.unlock(conn, params)?,
            "geode/custody.lock" => self.lock(conn)?,
            "geode/custody.status" => self.status(),
            _ => return Ok(None),
        }))
    }

    fn initialize(
        &self,
        conn: &mut Conn,
        params: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, Refusal> {
        if let Some(tok) = params["_meta"]["geode_token"].as_str() {
            let sealed = normalize_sealed(tok.as_bytes())?;
            self.verify_token(conn.peer, &sealed)?;
            conn.sealed = Some(sealed);
        }
        Ok(serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {
                "tools": {"listChanged": false},
                "experimental": {"geode": {"custody": true}},
            },
            "serverInfo": {"name": "geode", "version": env!("CARGO_PKG_VERSION")},
        }))
    }

    /// The token must open under the session EK, be in date, carry
    /// `peer_uid`, and match the kernel's peer uid.
    fn verify_token(&self, peer: PeerCred, sealed: &[u8]) -> std::result::Result<Token, Refusal> {
        let mut guard = self
            .session
            .lock()
            .map_err(|_| refusal("io", "session poisoned"))?;
        let s = self.live(&mut guard)?;
        let claims = token::inspect(sealed, &s.ctx.ek, now_secs())?;
        match claims.peer_uid {
            None => Err(refusal(
                "unauthenticated",
                "custody token needs a peer_uid claim",
            )),
            Some(u) if u != peer.uid => Err(refusal(
                "unauthenticated",
                "token peer_uid does not match the peer",
            )),
            Some(_) => Ok(claims),
        }
    }

    /// The unlocked session, idle-locking it first when it has expired.
    fn live<'a>(
        &self,
        guard: &'a mut Option<Unlocked>,
    ) -> std::result::Result<&'a mut Unlocked, Refusal> {
        if guard
            .as_ref()
            .is_some_and(|s| s.last_used.elapsed() >= self.idle)
        {
            *guard = None;
        }
        guard
            .as_mut()
            .ok_or_else(|| refusal("locked", "custody is locked"))
    }

    /// The frozen three, plus `geode_run` only when the bound token holds
    /// `Inject` (design §5).
    fn tools(&self, conn: &Conn) -> Vec<serde_json::Value> {
        let claims = conn.sealed.as_ref().and_then(|sealed| {
            let mut guard = self.session.lock().ok()?;
            let s = self.live(&mut guard).ok()?;
            token::inspect(sealed, &s.ctx.ek, now_secs()).ok()
        });
        let inject = claims
            .as_ref()
            .is_some_and(|c| c.allow_ops.contains(&Op::Inject));
        let mut tools = tool_descriptors_for(claims.map(|c| c.allow_prefix));
        if inject {
            tools.push(run_descriptor());
        }
        tools
    }

    fn tool_call(&self, conn: &mut Conn, params: &serde_json::Value) -> serde_json::Value {
        match self.tool_call_inner(conn, params) {
            Ok(doc) => serde_json::json!({"content": [{"type": "text", "text": doc.to_string()}]}),
            Err(r) => serde_json::json!({
                "content": [{"type": "text", "text": serde_json::json!({
                    "ok": false,
                    "error": {"code": r.code, "message": r.msg},
                }).to_string()}],
                "isError": true,
            }),
        }
    }

    fn tool_call_inner(
        &self,
        conn: &mut Conn,
        params: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, Refusal> {
        let name = params["name"].as_str().unwrap_or("");
        if !AGENT_TOOLS.contains(&name) && name != RUN_TOOL {
            // Unknown names are refused like an unadvertised tool, never as
            // a protocol error.
            return Err(refusal(
                "policy_deny",
                format!("tool '{name}' is not available"),
            ));
        }
        let sealed = conn
            .sealed
            .clone()
            .ok_or_else(|| refusal("unauthenticated", "no token bound to this connection"))?;
        if conn.window.elapsed() >= RATE_WINDOW {
            conn.window = Instant::now();
            conn.calls = 0;
        }
        conn.calls = conn.calls.saturating_add(1);
        if conn.calls > RATE_MAX {
            return Err(refusal("rate_limited", "128 tool calls / 10 s per token"));
        }
        let empty = serde_json::json!({});
        let args = params.get("arguments").unwrap_or(&empty);
        let claims = self.verify_token(conn.peer, &sealed)?;
        if name == RUN_TOOL && !claims.allow_ops.contains(&Op::Inject) {
            return Err(refusal("policy_deny", "token does not hold inject"));
        }
        let vault = args["vault"].as_str().unwrap_or("");
        if !same_dir(Path::new(vault), &self.vault) {
            return Err(refusal(
                "vault_mismatch",
                "vault is not this daemon's vault",
            ));
        }
        if name == RUN_TOOL {
            return self.run_tool(conn.peer, &claims, args);
        }
        let mut guard = self
            .session
            .lock()
            .map_err(|_| refusal("io", "session poisoned"))?;
        let s = self.live(&mut guard)?;
        s.last_used = Instant::now();
        let vault_str = self.vault.to_str().unwrap_or_default();
        let call = AgentCall {
            facet_events: false,
            ctx: &s.ctx,
            claims: &claims,
            sealed: &sealed,
            now: now_secs(),
            vault: vault_str,
            args,
        };
        Ok(match name {
            "geode_list" => StdioServer::list_tool(&call),
            "geode_read" => StdioServer::read_tool(&call),
            _ => StdioServer::write_tool(&call),
        }?)
    }

    /// `geode_run` (design §3, §5): the same `inject::plan` and executor as
    /// local `geode run`, with the token as the authority. One buffered
    /// result; `isError` only for a Geode-side refusal.
    fn run_tool(
        &self,
        peer: PeerCred,
        claims: &Token,
        args: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, Refusal> {
        if !claims.allow_ops.contains(&Op::Inject) {
            return Err(refusal("policy_deny", "token does not hold inject"));
        }
        let req = RunRequest::parse(args)?;
        let row_paths: Vec<String> = req.bindings.iter().map(|b| b.path.clone()).collect();
        let mut chain = geode_grotto::audit::open(&self.audit_db)
            .map_err(|e| refusal("io", format!("audit db: {e}")))?;
        // Plan under the session lock; the child runs after it is released.
        let (mut plan, row) = {
            let mut guard = self
                .session
                .lock()
                .map_err(|_| refusal("io", "session poisoned"))?;
            let s = self.live(&mut guard)?;
            s.last_used = Instant::now();
            let ctx = &s.ctx;
            let mk = geode_grotto::kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
            let policy =
                geode_grotto::policy::load_policy(&self.vault, &mk, ctx.vault_id, ctx.epoch)?;
            let row = run::RowBase {
                principal: claims.principal_id.0.clone(),
                token_id: cmd::hex(&claims.token_id.0),
                peer_uid: Some(peer.uid),
                peer_pid: peer.pid.and_then(|p| u32::try_from(p).ok()),
                vault_id: cmd::hex(&ctx.vault_id.0),
                paths: row_paths,
                custody: true,
                hosts: inject::hosts_label(&claims.allow_hosts),
            };
            let caller = inject::Caller {
                principal: &claims.principal_id,
                policy: &policy,
                token: Some(claims),
                allow_cmds: &claims.allow_cmds,
                allow_hosts: &claims.allow_hosts,
                redact: claims.redact,
                enforce_hosts: cfg!(target_os = "linux"),
            };
            let view = inject::VaultView {
                root: &self.vault,
                ek: &ctx.ek,
                epoch: ctx.epoch,
                manifest: &ctx.manifest,
            };
            let base_path = std::env::var_os("PATH");
            let planned = inject::plan(
                &caller,
                &view,
                &inject::PlanRequest {
                    bindings: &req.bindings,
                    argv: &req.argv,
                    base_path: base_path.as_deref(),
                    no_redact: false,
                },
            );
            match planned {
                Ok(p) => (p, row),
                Err(e) => {
                    let r = run::plan_refusal(&mut chain, &row, e);
                    return Err(refusal(r.kind, r.msg));
                }
            }
        };
        let identity = self.child_identity(peer)?;
        let opts = run::ExecOpts {
            cwd: req.cwd,
            inherit_stdin: false,
            timeout: req.timeout,
            identity,
            allow_hosts: claims.allow_hosts.clone(),
            home: Some(std::ffi::OsString::from("/")),
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let done = run::execute_plan(&mut plan, opts, &mut chain, &row, |ch, bytes| match ch {
            inject::Channel::Stdout => out.extend_from_slice(&bytes),
            inject::Channel::Stderr => err.extend_from_slice(&bytes),
        })
        .map_err(|r| refusal(r.kind, r.msg))?;
        Ok(serde_json::json!({
            "spawned": true,
            "exit_code": done.outcome.exit_code,
            "signal": done.outcome.signal,
            "timed_out": done.outcome.timed_out,
            "stdout_redacted": String::from_utf8_lossy(&out),
            "stderr_redacted": String::from_utf8_lossy(&err),
            "truncated": done.truncated,
            "redaction_hits": done.hits,
        }))
    }

    fn child_identity(
        &self,
        peer: PeerCred,
    ) -> std::result::Result<geode_os::ChildIdentity, Refusal> {
        match &self.child {
            ChildRule::Fixed(id) => Ok(id.clone()),
            ChildRule::Os => {
                let run_user = ident::lookup_user(ident::RUN_USER).ok().flatten();
                let deny = [
                    self.key.as_path(),
                    self.audit_db.as_path(),
                    self.socket.as_path(),
                ];
                ident::child_identity(
                    ident::Os::current(),
                    self.daemon_uid,
                    peer.uid,
                    run_user,
                    &deny,
                )
                .map_err(|e| refusal("policy_deny", e))
            }
        }
    }

    fn require_control(&self, peer: PeerCred) -> std::result::Result<(), Refusal> {
        let allowed = match &self.agents {
            // An unknown peer uid has no group list: treat it as an agent.
            Agents::Gid(g) => ident::user_gids(peer.uid).is_ok_and(|mut gids| {
                gids.push(peer.gid);
                ident::may_control(&gids, Some(*g))
            }),
            Agents::Uids(uids) => !uids.contains(&peer.uid),
        };
        if allowed {
            Ok(())
        } else {
            Err(refusal(
                "policy_deny",
                format!("{} may not unlock or lock custody", ident::AGENTS_GROUP),
            ))
        }
    }

    fn unlock(
        &self,
        conn: &Conn,
        params: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, Refusal> {
        self.require_control(conn.peer)?;
        let isk = cmd::load_isk_given(&self.key, params["passphrase"].as_str())?;
        let ctx = cmd::load_vault(&self.vault, &isk)?;
        drop(isk);
        let key_id = cmd::hex(&ctx.key_id.0);
        let mut guard = self
            .session
            .lock()
            .map_err(|_| refusal("io", "session poisoned"))?;
        *guard = Some(Unlocked {
            ctx,
            last_used: Instant::now(),
        });
        Ok(serde_json::json!({"locked": false, "key_id": key_id}))
    }

    fn lock(&self, conn: &Conn) -> std::result::Result<serde_json::Value, Refusal> {
        self.require_control(conn.peer)?;
        let mut guard = self
            .session
            .lock()
            .map_err(|_| refusal("io", "session poisoned"))?;
        *guard = None;
        Ok(serde_json::json!({"locked": true}))
    }

    /// Public facts only: no key bytes, no token, no binding value.
    fn status(&self) -> serde_json::Value {
        let mut guard = self.session.lock().ok();
        let live = guard.as_mut().and_then(|g| self.live(g).ok().map(|s| &*s));
        let (locked, idle_left, key_id) = match live {
            Some(s) => (
                false,
                Some(self.idle.saturating_sub(s.last_used.elapsed()).as_secs()),
                Some(cmd::hex(&s.ctx.key_id.0)),
            ),
            None => (true, None, None),
        };
        serde_json::json!({
            "locked": locked,
            "idle_left_secs": idle_left,
            "socket": self.socket.display().to_string(),
            "daemon_uid": self.daemon_uid,
            "key_id": key_id,
            "vault": self.vault.display().to_string(),
        })
    }
}

fn same_dir(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use geode_grotto::policy::{Op, PrincipalId};
    use geode_grotto::token::{RedactLevel, TokenId};
    use std::os::unix::fs::PermissionsExt as _;

    const DUMMY: &str = "sk-dummy-0000QA";

    fn geode(args: &[&str]) {
        let cli = crate::Cli::try_parse_from(std::iter::once("geode").chain(args.iter().copied()))
            .unwrap();
        let out = OutMode::Json;
        let r = match cli.command.as_ref().unwrap() {
            crate::Commands::Keygen(a) => cmd::key::run(a, out),
            crate::Commands::Vault(a) => cmd::vault::run(a, &cli.global, out),
            crate::Commands::Seal(a) => cmd::seal::run(a, &cli.global, out),
            _ => unreachable!(),
        };
        r.unwrap();
    }

    struct Fx {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        socket: PathBuf,
    }

    impl Fx {
        fn key(&self) -> PathBuf {
            self.dir.join("k.gkey")
        }
        fn vault(&self) -> PathBuf {
            self.dir.join("v.geode")
        }
    }

    /// Raw key, vault, one object, and a bound custody socket served by an
    /// in-process daemon whose `Agents` rule is `agents`.
    fn start(agents: Agents) -> Fx {
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let p = |s: &str| dir.join(s).to_str().unwrap().to_owned();
        geode(&["keygen", "--insecure-plaintext", &p("k.gkey")]);
        geode(&["--key", &p("k.gkey"), "vault", "init", &p("v.geode")]);
        std::fs::create_dir_all(dir.join("src/cfg")).unwrap();
        std::fs::write(dir.join("src/cfg/note"), DUMMY).unwrap();
        geode(&["--key", &p("k.gkey"), "seal", &p("src"), &p("v.geode")]);
        // The test makes the parent; the product never does.
        std::fs::create_dir(dir.join("run")).unwrap();
        let socket = dir.join("run/custody.sock");
        let listener = bind_custody(&socket, None).unwrap();
        let paths = DaemonPaths {
            vault: dir.join("v.geode"),
            key: dir.join("k.gkey"),
            socket: socket.clone(),
            audit_db: dir.join("state/audit.db"),
        };
        let d = Arc::new(Daemon::new(
            paths,
            4242,
            agents,
            ChildRule::Fixed(geode_os::ChildIdentity::Inherit),
        ));
        std::thread::spawn(move || d.listen(&listener));
        Fx {
            _tmp: tmp,
            dir,
            socket,
        }
    }

    struct Raw {
        r: BufReader<UnixStream>,
        w: UnixStream,
        id: u64,
    }

    fn raw(fx: &Fx) -> Raw {
        let s = UnixStream::connect(&fx.socket).unwrap();
        Raw {
            r: BufReader::new(s.try_clone().unwrap()),
            w: s,
            id: 0,
        }
    }

    impl Raw {
        fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
            self.id += 1;
            let f = serde_json::json!({"jsonrpc": "2.0", "id": self.id, "method": method, "params": params});
            write_frame(&mut self.w, &f).unwrap();
            let mut line = String::new();
            self.r.read_line(&mut line).unwrap();
            serde_json::from_str(&line).unwrap()
        }
    }

    fn err_code(resp: &serde_json::Value) -> String {
        resp["error"]["data"]["code"]
            .as_str()
            .unwrap_or("")
            .to_owned()
    }

    fn tool_err(resp: &serde_json::Value) -> String {
        assert_eq!(resp["result"]["isError"], true, "{resp}");
        let text: serde_json::Value =
            serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap();
        text["error"]["code"].as_str().unwrap().to_owned()
    }

    /// A token for `human:local` (the default policy grants it) with
    /// `peer_uid`, sealed under the vault's EK.
    fn token_hex(fx: &Fx, peer_uid: Option<u32>) -> String {
        token_with(
            fx,
            peer_uid,
            vec![Op::List, Op::Read],
            Vec::new(),
            Vec::new(),
        )
    }

    /// The first `name` on PATH, canonicalized, as the plan resolves it.
    fn canonical_on_path(name: &str) -> String {
        let path = std::env::var_os("PATH").unwrap();
        let found = std::env::split_paths(&path)
            .map(|d| d.join(name))
            .find(|p| p.is_file())
            .unwrap();
        std::fs::canonicalize(found)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    fn inject_token(fx: &Fx, hosts: Vec<String>) -> String {
        let sh = geode_grotto::token::CmdRule {
            path: canonical_on_path("sh"),
            sha256: None,
            args_prefix: Vec::new(),
        };
        token_with(
            fx,
            Some(ident::euid()),
            vec![Op::List, Op::Inject],
            vec![sh],
            hosts,
        )
    }

    fn token_with(
        fx: &Fx,
        peer_uid: Option<u32>,
        allow_ops: Vec<Op>,
        allow_cmds: Vec<geode_grotto::token::CmdRule>,
        allow_hosts: Vec<String>,
    ) -> String {
        let isk = cmd::load_isk_given(&fx.key(), None).unwrap();
        let ctx = cmd::load_vault(&fx.vault(), &isk).unwrap();
        let now = now_secs();
        let claims = Token {
            token_id: TokenId([7; 16]),
            vault_id: ctx.vault_id,
            epoch: ctx.epoch,
            principal_id: PrincipalId("human:local".into()),
            not_before: now,
            not_after: now + 600,
            allow_ops,
            allow_prefix: vec!["cfg/".into()],
            max_bytes: 1 << 20,
            allow_cmds,
            allow_hosts,
            peer_uid,
            redact: RedactLevel::Strict,
        };
        let mk = geode_grotto::kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
        let policy =
            geode_grotto::policy::load_policy(&fx.vault(), &mk, ctx.vault_id, ctx.epoch).unwrap();
        cmd::hex(&token::issue_narrow(&claims, &ctx.ek, &policy).unwrap())
    }

    fn isk_hex(fx: &Fx) -> String {
        let raw = std::fs::read(fx.key()).unwrap();
        cmd::hex(&raw[6..38])
    }

    /// Unlock `fx`, then open a connection bound to `tok`.
    fn bound(fx: &Fx, tok: &str) -> Raw {
        let mut c = raw(fx);
        c.call("geode/custody.unlock", serde_json::json!({}));
        let mut a = raw(fx);
        let r = a.call(
            "initialize",
            serde_json::json!({"_meta": {"geode_token": tok}}),
        );
        assert!(r.get("error").is_none(), "{r}");
        a
    }

    fn run_call(a: &mut Raw, fx: &Fx, argv: &[&str]) -> serde_json::Value {
        let vault = fx.vault().to_str().unwrap().to_owned();
        a.call(
            "tools/call",
            serde_json::json!({"name": "geode_run", "arguments": {
                "vault": vault, "argv": argv, "secrets": {"KEY": "cfg/note"},
            }}),
        )
    }

    fn tool_doc(resp: &serde_json::Value) -> serde_json::Value {
        assert!(
            resp["result"]["isError"].is_null(),
            "unexpected isError: {resp}"
        );
        serde_json::from_str(resp["result"]["content"][0]["text"].as_str().unwrap()).unwrap()
    }

    fn rows(fx: &Fx) -> Vec<(String, i64, String, Option<i64>)> {
        let conn = rusqlite::Connection::open(fx.dir.join("state/audit.db")).unwrap();
        let mut st = conn
            .prepare("SELECT outcome, custody, hosts, exit_code FROM audit ORDER BY seq")
            .unwrap();
        st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .map(std::result::Result::unwrap)
            .collect()
    }

    #[test]
    fn geode_run_is_advertised_only_with_inject() {
        let fx = start(Agents::Uids(Vec::new()));
        let names = |a: &mut Raw| -> Vec<String> {
            let r = a.call("tools/list", serde_json::json!({}));
            r["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_owned())
                .collect()
        };
        let mut reader = bound(&fx, &token_hex(&fx, Some(ident::euid())));
        assert_eq!(names(&mut reader), AGENT_TOOLS);
        let mut injector = bound(&fx, &inject_token(&fx, Vec::new()));
        let n = names(&mut injector);
        assert_eq!(n, ["geode_list", "geode_read", "geode_write", "geode_run"]);
        // Without Inject the call is policy_deny, never unknown-tool.
        let r = run_call(&mut reader, &fx, &["sh", "-c", "true"]);
        assert_eq!(tool_err(&r), "policy_deny");
    }

    #[test]
    fn geode_run_child_exit_1_is_one_buffered_result() {
        let fx = start(Agents::Uids(Vec::new()));
        let mut a = bound(&fx, &inject_token(&fx, Vec::new()));
        let r = run_call(
            &mut a,
            &fx,
            &["sh", "-c", "echo $KEY; echo $KEY >&2; exit 1"],
        );
        let doc = tool_doc(&r);
        assert_eq!(doc["spawned"], true);
        assert_eq!(doc["exit_code"], 1);
        assert_eq!(doc["timed_out"], false);
        assert_eq!(doc["stdout_redacted"], "[REDACTED:KEY]\n");
        assert_eq!(doc["stderr_redacted"], "[REDACTED:KEY]\n");
        assert_eq!(doc["redaction_hits"]["KEY"], 2);
        assert!(!r.to_string().contains(DUMMY), "dummy in the MCP result");
        let rows = rows(&fx);
        let (outcome, custody, hosts, exit) = rows.last().unwrap();
        assert_eq!(
            (outcome.as_str(), *custody, hosts.as_str(), *exit),
            ("spawned", 1, "unrestricted", Some(1))
        );
        let db = std::fs::read(fx.dir.join("state/audit.db")).unwrap();
        assert!(
            !String::from_utf8_lossy(&db).contains(DUMMY),
            "dummy in the audit db"
        );
    }

    #[test]
    fn geode_run_refusals_are_is_error() {
        let fx = start(Agents::Uids(Vec::new()));
        let mut a = bound(&fx, &inject_token(&fx, Vec::new()));
        let wrong = a.call(
            "tools/call",
            serde_json::json!({"name": "geode_run", "arguments": {
                "vault": fx.dir.to_str().unwrap(), "argv": ["sh"], "secrets": {"KEY": "cfg/note"},
            }}),
        );
        assert_eq!(tool_err(&wrong), "vault_mismatch");
        // argv[0] outside allow_cmds.
        let geode = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let r = run_call(&mut a, &fx, &[geode.to_str().unwrap()]);
        assert_eq!(tool_err(&r), "policy_deny");
        // A needle in argv.
        let r = run_call(&mut a, &fx, &["sh", "-c", &format!("echo {DUMMY}")]);
        assert_eq!(tool_err(&r), "argv_rejected");
        assert!(!r.to_string().contains(DUMMY));
        let outcomes: Vec<String> = rows(&fx).into_iter().map(|r| r.0).collect();
        assert_eq!(outcomes, ["policy_deny", "argv_rejected"]);
    }

    #[test]
    fn geode_run_allow_hosts_per_os() {
        let fx = start(Agents::Uids(Vec::new()));
        let mut a = bound(&fx, &inject_token(&fx, vec!["api.example.com".into()]));
        let marker = fx.dir.join("ran.marker");
        let script = format!("echo x > '{}'", marker.display());
        let r = run_call(&mut a, &fx, &["sh", "-c", &script]);
        if cfg!(target_os = "linux") {
            // Enforced in a netns, or refused when the host cannot make one.
            if r["result"]["isError"] == true {
                assert_eq!(tool_err(&r), "policy_deny");
                assert!(r.to_string().contains("allow_hosts"), "{r}");
                assert!(!marker.exists(), "ran without isolation");
            } else {
                assert_eq!(tool_doc(&r)["exit_code"], 0);
                assert_eq!(rows(&fx).last().unwrap().2, "api.example.com");
            }
        } else {
            assert_eq!(tool_err(&r), "policy_deny");
            assert!(
                r.to_string()
                    .contains("allow_hosts: unsupported on this host"),
                "{r}"
            );
            assert!(!marker.exists(), "macOS must refuse before spawn");
        }
    }

    #[test]
    fn custody_socket_is_0660_and_parent_is_never_created() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("custody.sock");
        let _l = bind_custody(&sock, None).unwrap();
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        // A live socket at the path is refused.
        assert!(bind_custody(&sock, None).is_err());

        let missing = tmp.path().join("nope/custody.sock");
        assert!(bind_custody(&missing, None).is_err());
        assert!(!tmp.path().join("nope").exists(), "parent was created");
        assert_eq!(default_socket().file_name().unwrap(), "custody.sock");
    }

    #[test]
    fn status_unlock_tools_lock_round_trip() {
        let fx = start(Agents::Uids(Vec::new()));
        let mut c = raw(&fx);
        let init = c.call("initialize", serde_json::json!({}));
        assert_eq!(
            init["result"]["capabilities"]["experimental"]["geode"]["custody"],
            true
        );
        assert_eq!(
            init["result"]["capabilities"]["tools"]["listChanged"],
            false
        );

        let st = c.call("geode/custody.status", serde_json::json!({}));
        assert_eq!(st["result"]["locked"], true);
        assert!(st["result"]["key_id"].is_null());

        // A token cannot bind while locked.
        let tok = token_hex(&fx, Some(ident::euid()));
        let mut early = raw(&fx);
        let r = early.call(
            "initialize",
            serde_json::json!({"_meta": {"geode_token": tok}}),
        );
        assert_eq!(err_code(&r), "locked", "{r}");

        let un = c.call("geode/custody.unlock", serde_json::json!({}));
        assert_eq!(un["result"]["locked"], false, "{un}");
        let st = c.call("geode/custody.status", serde_json::json!({}));
        let s = st.to_string();
        assert_eq!(st["result"]["locked"], false);
        assert_eq!(st["result"]["daemon_uid"], 4242);
        assert!(st["result"]["idle_left_secs"].as_u64().unwrap() > 0);
        assert_eq!(st["result"]["key_id"].as_str().unwrap().len(), 32);
        assert!(!s.contains(&isk_hex(&fx)), "status printed the ISK");
        assert!(!s.contains(DUMMY));

        let mut a = raw(&fx);
        let r = a.call(
            "initialize",
            serde_json::json!({"_meta": {"geode_token": tok}}),
        );
        assert!(r.get("error").is_none(), "{r}");
        let tools = a.call("tools/list", serde_json::json!({}));
        let names: Vec<&str> = tools["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, AGENT_TOOLS, "geode_run must not be advertised");
        let vault = fx.vault().to_str().unwrap().to_owned();
        let read = a.call(
            "tools/call",
            serde_json::json!({"name": "geode_read", "arguments": {"vault": vault, "path": "cfg/note"}}),
        );
        assert!(read["result"]["isError"].is_null(), "{read}");
        assert!(read.to_string().contains(DUMMY), "Read token reads text");

        let mism = a.call(
            "tools/call",
            serde_json::json!({"name": "geode_read", "arguments": {"vault": fx.dir.to_str().unwrap(), "path": "cfg/note"}}),
        );
        assert_eq!(tool_err(&mism), "vault_mismatch");
        let run = a.call(
            "tools/call",
            serde_json::json!({"name": "geode_run", "arguments": {}}),
        );
        assert_eq!(tool_err(&run), "policy_deny");
        let mount = a.call("geode/custody.mount", serde_json::json!({}));
        assert_eq!(mount["error"]["code"], -32601, "the daemon never mounts");

        let lk = c.call("geode/custody.lock", serde_json::json!({}));
        assert_eq!(lk["result"]["locked"], true);
        let after = a.call(
            "tools/call",
            serde_json::json!({"name": "geode_read", "arguments": {"vault": vault, "path": "cfg/note"}}),
        );
        assert_eq!(tool_err(&after), "locked");
    }

    #[test]
    fn token_needs_matching_peer_uid() {
        let fx = start(Agents::Uids(Vec::new()));
        let mut c = raw(&fx);
        c.call("geode/custody.unlock", serde_json::json!({}));
        let vault = fx.vault().to_str().unwrap().to_owned();
        for (peer_uid, why) in [
            (None, "missing"),
            (Some(ident::euid().wrapping_add(1)), "mismatched"),
        ] {
            let tok = token_hex(&fx, peer_uid);
            let mut a = raw(&fx);
            let r = a.call(
                "initialize",
                serde_json::json!({"_meta": {"geode_token": tok}}),
            );
            assert_eq!(err_code(&r), "unauthenticated", "{why}: {r}");
            let call = a.call(
                "tools/call",
                serde_json::json!({"name": "geode_read", "arguments": {"vault": vault, "path": "cfg/note"}}),
            );
            assert_eq!(tool_err(&call), "unauthenticated", "{why}");
            assert!(!call.to_string().contains(DUMMY));
        }
    }

    #[test]
    fn agents_cannot_unlock_or_lock_but_can_read_status() {
        let fx = start(Agents::Uids(vec![ident::euid()]));
        let mut c = raw(&fx);
        let un = c.call(
            "geode/custody.unlock",
            serde_json::json!({"passphrase": "guess"}),
        );
        assert_eq!(err_code(&un), "policy_deny", "{un}");
        let lk = c.call("geode/custody.lock", serde_json::json!({}));
        assert_eq!(err_code(&lk), "policy_deny");
        let st = c.call("geode/custody.status", serde_json::json!({}));
        assert_eq!(st["result"]["locked"], true);
    }

    #[test]
    fn identity_rules_are_the_os_crate_rules() {
        assert!(ident::check_daemon_identity(0, None, Some(0)).is_err());
        assert!(ident::check_custody_peer(9, 9).is_err());
    }
}
