//! `geode agent` — agent plane verbs (06-agent-plane). Thin adapter over
//! `geode_grotto::token` (G2b, v0.2.1) and `geode_grotto::agent_ops`
//! (G1, v0.2.2): the CLI authenticates the vault (`load_vault`), resolves
//! the caller's sealed token (`--token-file`/`--token-fd`/`--token` on
//! agent verbs only, else `GEODE_TOKEN`), and delegates every authorization decision to core.
//! The clap shape is frontend's chrome (`crate::AgentArgs`); this module
//! is the behavior.
//!
//! Secret discipline: the ISK is dropped right after vault authentication,
//! the EK never leaves this module, and neither is ever printed. Stdout of
//! `token issue` carries only the sealed token (`GTOK...`); `read` carries
//! only the plaintext body; metadata goes to stderr. `serve --stdio`
//! reserves stdout for MCP frames only (Facet event lines go to stderr).
//!
//! G1 (v0.2.2): `list`/`read`/`write` and `serve --stdio` (the MCP
//! `tools/list` and `tools/call` methods for `geode_list`, `geode_read`,
//! `geode_write`). The
//! default toolset has no `geode_keygen` / `geode_cat_key` / `geode_mount`
//! (06-agent-plane 3). The Unix-socket transport remains a later gate and
//! exits 1 (usage) by design.
//!
//! Soft Jev remainder (`agent scope` + MCP wrapper when
//! `GEODE_JEV_TRANSPORT` is set): Choice `{allow, deny, ask}` on the
//! non-prefix intent. Prefix / `../` / TTL / MAC stay in core. Jev never
//! sees a token and never decides seal/open/verify. Shadow: `auto_allow`
//! is always false.

use std::collections::HashMap;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use geode_grotto::agent_ops::{self, ReadBody, ReadMode};
use geode_grotto::kdf::EpochKey;
use geode_grotto::policy::{Op, PrincipalId};
use geode_grotto::token::{self, CmdRule, RedactLevel, Token, TokenId, TokenKind};
use geode_grotto::{Error, Result};

use crate::{
    cmd, AgentArgs, AgentCmd, GlobalArgs, OutMode, ReadModeArg, RedactArg, TokenCmd, TokenSource,
};

/// Default per-token byte cap when `--max-bytes` is omitted (06-agent-plane
/// 4 read discipline: agents are steered to hash large artifacts).
const DEFAULT_MAX_BYTES: u64 = 1_048_576;

/// MCP protocol version the stdio server speaks.
pub(crate) const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
const MAX_JSON_RPC_FRAME_BYTES: usize = 1 << 20;

#[cfg(unix)]
pub(crate) fn ensure_private_parent(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let Some(parent) = path.parent() else {
        return Err(Error::Format("socket path has no parent".into()));
    };
    let parent = if parent.as_os_str().is_empty() {
        std::path::Path::new(".")
    } else {
        parent
    };
    if !parent.is_dir() {
        return Err(Error::Format(format!(
            "socket parent directory does not exist: {}",
            parent.display()
        )));
    }
    let meta = std::fs::metadata(parent).map_err(Error::Io)?;
    if meta.permissions().mode() & 0o077 != 0 {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| Error::Format(format!("chmod {}: {e}", parent.display())))?;
    }
    Ok(())
}

pub(crate) fn rpc_line_too_large(line: &str) -> bool {
    line.len() > MAX_JSON_RPC_FRAME_BYTES
}

/// 06-agent-plane 6.5: 128 tool calls / 10 s per token. The ceiling is
/// env-overridable (`GEODE_AGENT_RATE_MAX`); the window is not.
const RATE_MAX: u32 = 128;
const RATE_WINDOW_SECS: u64 = 10;

pub fn run(args: &AgentArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        AgentCmd::Token { cmd: token_cmd } => match token_cmd {
            TokenCmd::Issue {
                vault,
                principal,
                ttl,
                ops,
                allow_prefix,
                max_bytes,
                allow_cmd,
                allow_cmds_file,
                allow_host,
                peer_uid,
                redact,
                run_only,
            } => issue(
                vault,
                principal,
                ttl,
                ops,
                allow_prefix,
                *max_bytes,
                &InjectClaimArgs {
                    allow_cmd,
                    allow_cmds_file: allow_cmds_file.as_deref(),
                    allow_host,
                    peer_uid: *peer_uid,
                    redact: *redact,
                },
                *run_only,
                global,
                out,
            ),
            TokenCmd::Inspect { token, vault } => inspect(token.as_deref(), vault, global, out),
        },
        AgentCmd::List {
            vault,
            prefix,
            token,
        } => list(vault, prefix.as_deref(), token, global, out),
        AgentCmd::Read {
            vault,
            path,
            mode,
            token,
        } => read(vault, path, *mode, token, global, out),
        AgentCmd::Write { vault, path, token } => write(vault, path, token, global, out),
        AgentCmd::Serve {
            stdio,
            socket,
            custody,
            vault,
            token,
        } => {
            if *custody {
                cmd::custody::serve(*stdio, socket.as_deref(), vault.as_deref(), token, global)
            } else if vault.is_some() {
                Err(Error::Format("--vault on serve needs --custody".into()))
            } else {
                serve(*stdio, socket.as_deref(), token, global)
            }
        }
        AgentCmd::Scope {
            path,
            op,
            allow_prefix,
            principal,
            intent,
            body_digest,
        } => scope(
            &ScopeRequest {
                path,
                op,
                allow_prefix,
                principal,
                intent: intent.as_deref(),
                body_digest: body_digest.as_deref(),
            },
            out,
        ),
    }
}

pub(crate) fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Parse a TTL: bare seconds or `Ns`/`Nm`/`Nh`. Range-checked against
/// `[1, MAX_TTL_SECS]` — a security parameter is never silently clamped.
fn parse_ttl(s: &str) -> Result<u64> {
    let (digits, mult) = match s.as_bytes().last() {
        Some(b's') => (&s[..s.len() - 1], 1_u64),
        Some(b'm') => (&s[..s.len() - 1], 60),
        Some(b'h') => (&s[..s.len() - 1], 3600),
        _ => (s, 1),
    };
    let n: u64 = digits
        .parse()
        .map_err(|_| Error::Format(format!("bad ttl '{s}' (use seconds, or Ns/Nm/Nh)")))?;
    let secs = n
        .checked_mul(mult)
        .ok_or_else(|| Error::Format("ttl overflow".into()))?;
    if secs == 0 || secs > token::MAX_TTL_SECS {
        return Err(Error::Format(format!(
            "ttl out of range: 1s..{}s (12h)",
            token::MAX_TTL_SECS
        )));
    }
    Ok(secs)
}

/// Parse the comma-separated op list. `mount`/`admin` are rejected: the
/// agent toolset has no mount and tokens only narrow policy (06-agent-plane
/// 3; 10-policy 2).
fn parse_ops(s: &str) -> Result<Vec<Op>> {
    let mut ops = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let op = match part {
            "list" => Op::List,
            "read" => Op::Read,
            "write" => Op::Write,
            "verify" => Op::Verify,
            "inject" => Op::Inject,
            "mount" | "admin" => {
                return Err(Error::Format(format!(
                    "op '{part}' is never granted to an agent token"
                )));
            }
            _ => return Err(Error::Format(format!("unknown op '{part}'"))),
        };
        if !ops.contains(&op) {
            ops.push(op);
        }
    }
    if ops.is_empty() {
        return Err(Error::Format("no ops granted".into()));
    }
    Ok(ops)
}

/// Validate allow-prefixes: non-empty, no `..` components (06-agent-plane
/// 6.2), normalized to a trailing `/`. At least one prefix is required — a
/// token with no prefix would not narrow anything (10-policy 2).
fn normalize_prefixes(prefixes: &[String]) -> Result<Vec<String>> {
    if prefixes.is_empty() {
        return Err(Error::Format(
            "missing --allow-prefix (a token must narrow to at least one prefix)".into(),
        ));
    }
    let mut out = Vec::with_capacity(prefixes.len());
    for p in prefixes {
        if p.is_empty() || p.split('/').any(|c| c == "..") {
            return Err(Error::Format(format!("bad allow-prefix '{p}'")));
        }
        let mut p = p.clone();
        if !p.ends_with('/') {
            p.push('/');
        }
        out.push(p);
    }
    Ok(out)
}

/// The SPEC-v034 G4 inject claim flags on `token issue`.
struct InjectClaimArgs<'a> {
    allow_cmd: &'a [PathBuf],
    allow_cmds_file: Option<&'a Path>,
    allow_host: &'a [String],
    peer_uid: Option<u32>,
    redact: RedactArg,
}

/// The parsed inject claims, validated before any vault I/O.
struct InjectClaims {
    allow_cmds: Vec<CmdRule>,
    allow_hosts: Vec<String>,
    peer_uid: Option<u32>,
    redact: RedactLevel,
}

/// Validate one command path: absolute, equal to its canonical form, and a
/// regular file with an execute bit. Usage error (exit 1) otherwise.
pub(crate) fn canonical_cmd(path: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(Error::Format(format!(
            "allow-cmd '{path}' is not an absolute path"
        )));
    }
    let canon =
        std::fs::canonicalize(p).map_err(|e| Error::Format(format!("allow-cmd '{path}': {e}")))?;
    if canon != p {
        return Err(Error::Format(format!(
            "allow-cmd '{path}' is not canonical (resolves to {})",
            canon.display()
        )));
    }
    let md = std::fs::metadata(&canon).map_err(Error::Io)?;
    if !md.is_file() || md.permissions().mode() & 0o111 == 0 {
        return Err(Error::Format(format!(
            "allow-cmd '{path}' is not an executable file"
        )));
    }
    Ok(path.to_owned())
}

/// Parse `--allow-cmds-file` for `token issue`. `sha256` may be omitted.
/// Unknown keys are refused so a typo cannot silently widen a rule.
fn read_cmds_file(file: &Path) -> Result<Vec<CmdRule>> {
    read_cmd_rules_file(file, false)
}

/// `--allow-cmds-file` for `geode run`, after it has been read.
pub(crate) struct PinnedCmdsFile {
    pub rules: Vec<CmdRule>,
    /// `true` when the file is an object with `"require_pin": true`.
    /// A JSON list leaves this off.
    pub require_pin: bool,
}

/// Parse `--allow-cmds-file` for `geode run`. Every rule must include `sha256`.
///
/// A JSON list is the existing file. An object
/// `{"require_pin": true, "cmds": [ … ]}` is the same list plus the
/// require-pin setting. Unknown keys are refused.
pub(crate) fn read_pinned_cmds_file(file: &Path) -> Result<PinnedCmdsFile> {
    let value = read_cmds_json(file)?;
    match &value {
        serde_json::Value::Array(list) => Ok(PinnedCmdsFile {
            rules: rules_from_list(list, true)?,
            require_pin: false,
        }),
        serde_json::Value::Object(obj) => parse_run_cmds_object(file, obj),
        _ => Err(Error::Format(format!(
            "allow-cmds-file {}: expected a JSON list of command rules, or an object with require_pin and cmds",
            file.display()
        ))),
    }
}

/// One `--allow-cmd` value on `geode run`.
///
/// A bare absolute path is the existing unpinned rule (`sha256` unset).
/// A JSON object is a pin and `sha256` is required:
/// `{"path":"/abs/exe","sha256":"<64 hex>","args_prefix":["…"]}`.
/// `args_prefix` is the required leading arguments after the program and may
/// be omitted. A JSON list belongs in `--allow-cmds-file`.
pub(crate) fn parse_allow_cmd_arg(raw: &str) -> Result<CmdRule> {
    let trimmed = raw.trim();
    if trimmed.starts_with('[') {
        return Err(Error::Format(
            "allow-cmd JSON must be one object; a list belongs in --allow-cmds-file".into(),
        ));
    }
    if trimmed.starts_with('{') {
        let value: serde_json::Value = serde_json::from_str(trimmed)
            .map_err(|e| Error::Format(format!("allow-cmd: bad JSON: {e}")))?;
        return parse_rule_object(&value, "allow-cmd", true);
    }
    Ok(CmdRule {
        path: canonical_cmd(raw)?,
        sha256: None,
        args_prefix: Vec::new(),
    })
}

fn read_cmds_json(file: &Path) -> Result<serde_json::Value> {
    let bytes = std::fs::read(file)
        .map_err(|e| Error::Format(format!("allow-cmds-file {}: {e}", file.display())))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| Error::Format(format!("allow-cmds-file {}: bad JSON: {e}", file.display())))
}

fn read_cmd_rules_file(file: &Path, require_sha256: bool) -> Result<Vec<CmdRule>> {
    let value = read_cmds_json(file)?;
    let list = value.as_array().ok_or_else(|| {
        Error::Format(format!(
            "allow-cmds-file {}: expected a JSON list of command rules",
            file.display()
        ))
    })?;
    rules_from_list(list, require_sha256)
}

fn rules_from_list(list: &[serde_json::Value], require_sha256: bool) -> Result<Vec<CmdRule>> {
    let mut rules = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        rules.push(parse_rule_object(
            item,
            &format!("allow-cmds-file rule {i}"),
            require_sha256,
        )?);
    }
    Ok(rules)
}

fn parse_run_cmds_object(
    file: &Path,
    obj: &serde_json::Map<String, serde_json::Value>,
) -> Result<PinnedCmdsFile> {
    const KEYS: [&str; 2] = ["require_pin", "cmds"];
    if let Some(k) = obj.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(Error::Format(format!(
            "allow-cmds-file {}: unknown key '{k}' (require_pin, cmds)",
            file.display()
        )));
    }
    let require_pin = match obj.get("require_pin") {
        None => false,
        Some(serde_json::Value::Bool(on)) => *on,
        Some(_) => {
            return Err(Error::Format(format!(
                "allow-cmds-file {}: require_pin must be true or false",
                file.display()
            )));
        }
    };
    let cmds = obj.get("cmds").ok_or_else(|| {
        Error::Format(format!(
            "allow-cmds-file {}: expected \"cmds\" array",
            file.display()
        ))
    })?;
    let list = cmds.as_array().ok_or_else(|| {
        Error::Format(format!(
            "allow-cmds-file {}: \"cmds\" must be a JSON list of command rules",
            file.display()
        ))
    })?;
    Ok(PinnedCmdsFile {
        rules: rules_from_list(list, true)?,
        require_pin,
    })
}

/// One `{path, sha256, args_prefix}` object. Unknown keys are refused.
fn parse_rule_object(
    item: &serde_json::Value,
    label: &str,
    require_sha256: bool,
) -> Result<CmdRule> {
    const KEYS: [&str; 3] = ["path", "sha256", "args_prefix"];
    let obj = item
        .as_object()
        .ok_or_else(|| Error::Format(format!("{label}: expected an object")))?;
    if let Some(k) = obj.keys().find(|k| !KEYS.contains(&k.as_str())) {
        return Err(Error::Format(format!(
            "{label}: unknown key '{k}' (path, sha256, args_prefix)"
        )));
    }
    let rule: CmdRule =
        serde_json::from_value(item.clone()).map_err(|e| Error::Format(format!("{label}: {e}")))?;
    finish_rule(rule, label, require_sha256)
}

fn finish_rule(mut rule: CmdRule, label: &str, require_sha256: bool) -> Result<CmdRule> {
    rule.path = canonical_cmd(&rule.path)?;
    match rule.sha256 {
        Some(sum) => {
            let ok = sum.len() == 64 && sum.bytes().all(|b| b.is_ascii_hexdigit());
            if !ok {
                return Err(Error::Format(format!(
                    "{label}: sha256 must be 64 hex characters"
                )));
            }
            rule.sha256 = Some(sum.to_ascii_lowercase());
        }
        None if require_sha256 => {
            return Err(Error::Format(format!(
                "{label}: sha256 is required (64 hex characters)"
            )));
        }
        None => {}
    }
    Ok(rule)
}

/// Validate a host: non-empty ASCII with no whitespace, scheme, path, or
/// userinfo. Lowercased.
pub(crate) fn normalize_host(host: &str) -> Result<String> {
    let bad = host.is_empty()
        || !host.is_ascii()
        || host.contains("://")
        || host
            .chars()
            .any(|c| c.is_ascii_whitespace() || c == '/' || c == '@');
    if bad {
        return Err(Error::Format(format!("bad allow-host '{host}'")));
    }
    Ok(host.to_ascii_lowercase())
}

fn parse_inject_claims(args: &InjectClaimArgs<'_>) -> Result<InjectClaims> {
    let mut allow_cmds: Vec<CmdRule> = Vec::new();
    for p in args.allow_cmd {
        let path = p
            .to_str()
            .ok_or_else(|| Error::Format("allow-cmd path is not UTF-8".into()))?;
        let rule = CmdRule {
            path: canonical_cmd(path)?,
            sha256: None,
            args_prefix: Vec::new(),
        };
        if !allow_cmds.contains(&rule) {
            allow_cmds.push(rule);
        }
    }
    if let Some(file) = args.allow_cmds_file {
        for rule in read_cmds_file(file)? {
            if !allow_cmds.contains(&rule) {
                allow_cmds.push(rule);
            }
        }
    }
    let mut allow_hosts: Vec<String> = Vec::new();
    for h in args.allow_host {
        let h = normalize_host(h)?;
        if !allow_hosts.contains(&h) {
            allow_hosts.push(h);
        }
    }
    Ok(InjectClaims {
        allow_cmds,
        allow_hosts,
        peer_uid: args.peer_uid,
        redact: match args.redact {
            RedactArg::Strict => RedactLevel::Strict,
            RedactArg::Hidden => RedactLevel::Hidden,
        },
    })
}

fn redact_str(level: RedactLevel) -> &'static str {
    match level {
        RedactLevel::Strict => "strict",
        RedactLevel::Hidden => "hidden",
    }
}

fn kind_str(kind: TokenKind) -> &'static str {
    match kind {
        TokenKind::Full => "full",
        TokenKind::Run => "run",
    }
}

/// One command rule as inspect text: the path, then any digest and
/// argument prefix.
fn cmd_rule_text(rule: &CmdRule) -> String {
    let mut s = rule.path.clone();
    if let Some(sum) = &rule.sha256 {
        s.push_str(" sha256=");
        s.push_str(sum);
    }
    if !rule.args_prefix.is_empty() {
        s.push_str(" args=");
        s.push_str(&rule.args_prefix.join(" "));
    }
    s
}

#[allow(clippy::too_many_arguments)]
fn issue(
    vault: &std::path::Path,
    principal: &str,
    ttl: &str,
    ops: &str,
    allow_prefix: &[String],
    max_bytes: Option<u64>,
    inject: &InjectClaimArgs<'_>,
    run_only: bool,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    // All input validation is a usage error (exit 1) and happens before any
    // vault I/O; core re-validates token ⊆ policy before sealing.
    let principal = PrincipalId(principal.to_owned());
    principal.validate()?;
    let ops = parse_ops(ops)?;
    if run_only && ops.contains(&Op::Read) {
        return Err(Error::Format("run-only token cannot include read".into()));
    }
    let prefixes = normalize_prefixes(allow_prefix)?;
    let ttl = parse_ttl(ttl)?;
    let max_bytes = max_bytes.unwrap_or(DEFAULT_MAX_BYTES);
    let inject = parse_inject_claims(inject)?;

    // Authenticate the vault for vault_id + epoch. The ISK is dropped
    // immediately after; nothing secret is ever printed.
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(vault, &isk)?;
    drop(isk);

    let now = now_secs();
    let mut id = [0u8; 16];
    getrandom::fill(&mut id).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    let claims = Token {
        token_id: TokenId(id),
        vault_id: ctx.vault_id,
        epoch: ctx.epoch,
        principal_id: principal,
        not_before: now,
        not_after: now.saturating_add(i64::try_from(ttl).unwrap_or(i64::MAX)),
        allow_ops: ops,
        allow_prefix: prefixes,
        max_bytes,
        allow_cmds: inject.allow_cmds,
        allow_hosts: inject.allow_hosts,
        peer_uid: inject.peer_uid,
        redact: inject.redact,
        kind: if run_only {
            TokenKind::Run
        } else {
            TokenKind::Full
        },
    };
    // 10-policy 2.5: a token may only narrow policy, never widen — issue
    // refuses a grant policy would deny (`Error::PolicyDeny`, exit 3).
    // `load_policy` returns the default policy when no file is sealed
    // (`human:local` admin on `""`, everyone else deny), so an agent grant
    // on a policy-less vault fails closed.
    let mk = geode_grotto::kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
    let policy = geode_grotto::policy::load_policy(vault, &mk, ctx.vault_id, ctx.epoch)?;
    let sealed = token::issue_narrow(&claims, &ctx.ek, &policy)?;
    let id_hex = cmd::hex(&id);
    if claims.allow_ops.contains(&Op::Inject) && claims.allow_cmds.is_empty() {
        eprintln!("note: token {id_hex} has inject but no --allow-cmd; it cannot run anything");
    }

    match out {
        OutMode::Json => {
            cmd::emit(
                out,
                "agent_token_issue",
                serde_json::json!({
                    "vault": vault.display().to_string(),
                    "token_id": id_hex,
                    "principal": claims.principal_id.0,
                    "ttl_secs": ttl,
                    "token": cmd::hex(&sealed),
                }),
                "",
            );
        }
        OutMode::Text => {
            // Stdout carries ONLY the sealed token (pipe-clean,
            // 06-agent-plane 2: "Stdout is the sealed token"). The human
            // summary goes to stderr so `... > tok` is safe.
            let mut stdout = std::io::stdout().lock();
            stdout.write_all(&sealed).map_err(Error::Io)?;
            stdout.flush().map_err(Error::Io)?;
            eprintln!(
                "token {id_hex} issued for {} (ttl {}s)",
                claims.principal_id.0, ttl
            );
        }
    }
    Ok(())
}

/// Read the sealed token from PATH, else `$GEODE_TOKEN`, else stdin.
fn read_sealed_token(path: Option<&std::path::Path>) -> Result<Vec<u8>> {
    if let Some(p) = path {
        return std::fs::read(p).map_err(Error::Io);
    }
    if let Some(tok) = std::env::var_os("GEODE_TOKEN") {
        let tok = tok.to_string_lossy().trim().to_owned();
        if !tok.is_empty() {
            return Ok(tok.into_bytes());
        }
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    if buf.is_empty() {
        return Err(Error::Format(
            "no token: pass TOKEN path, set GEODE_TOKEN, or pipe stdin".into(),
        ));
    }
    Ok(buf)
}

/// Normalize an ingested token: trim trailing whitespace, and accept the
/// hex-armored form (the `--output json` `token` field) when the raw
/// `GTOK` magic is absent — env vars and editors cannot carry binary NULs.
pub(crate) fn normalize_sealed(raw: &[u8]) -> Result<Vec<u8>> {
    let trimmed: &[u8] = raw.trim_ascii_end();
    if trimmed.starts_with(geode_grotto::MAGIC_GTOK) {
        return Ok(trimmed.to_vec());
    }
    let text = std::str::from_utf8(trimmed)
        .map_err(|_| Error::Format("token is neither GTOK binary nor hex".into()))?;
    if text.len() % 2 != 0 || text.is_empty() {
        return Err(Error::Format("token hex has odd/empty length".into()));
    }
    let mut out = vec![0u8; text.len() / 2];
    cmd::unhex(text, &mut out)?;
    if !out.starts_with(geode_grotto::MAGIC_GTOK) {
        return Err(Error::Format("token hex does not decode to GTOK".into()));
    }
    Ok(out)
}

fn inspect(
    path: Option<&std::path::Path>,
    vault: &std::path::Path,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = normalize_sealed(&read_sealed_token(path)?)?;
    // Authenticate the vault for the EK (TokenKey derives from it). The
    // ISK is dropped immediately after; nothing secret is ever printed.
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(vault, &isk)?;
    drop(isk);
    // Core verifies MAC + expiry before any claim is shown; an expired
    // token is `Error::TokenInvalid` (exit 4), tamper/wrong-key is
    // `Error::AuthFail` (exit 2) — never a display of unverified claims.
    let claims = token::inspect(&sealed, &ctx.ek, now_secs())?;
    let ops: Vec<String> = claims
        .allow_ops
        .iter()
        .map(|op| format!("{op:?}").to_lowercase())
        .collect();
    cmd::emit(
        out,
        "agent_token_inspect",
        serde_json::json!({
            "token_id": cmd::hex(&claims.token_id.0),
            "kind": kind_str(claims.kind),
            "vault_id": cmd::hex(&claims.vault_id.0),
            "epoch": claims.epoch.0,
            "principal": claims.principal_id.0,
            "not_before": claims.not_before,
            "not_after": claims.not_after,
            "allow_ops": ops,
            "allow_prefix": claims.allow_prefix,
            "max_bytes": claims.max_bytes,
            "allow_cmds": claims.allow_cmds,
            "allow_hosts": claims.allow_hosts,
            "peer_uid": claims.peer_uid,
            "redact": redact_str(claims.redact),
        }),
        &format!(
            "token {}\n  kind {}\n  principal {}\n  vault {} epoch {}\n  valid {}..{}\n  ops {}\n  prefixes {}\n  max-bytes {}\n  allow-cmds {}\n  allow-hosts {}\n  peer-uid {}\n  redact {}",
            cmd::hex(&claims.token_id.0),
            kind_str(claims.kind),
            claims.principal_id.0,
            cmd::hex(&claims.vault_id.0),
            claims.epoch.0,
            claims.not_before,
            claims.not_after,
            ops.join(","),
            claims.allow_prefix.join(","),
            claims.max_bytes,
            if claims.allow_cmds.is_empty() {
                "-".to_owned()
            } else {
                claims
                    .allow_cmds
                    .iter()
                    .map(cmd_rule_text)
                    .collect::<Vec<_>>()
                    .join(", ")
            },
            if claims.allow_hosts.is_empty() {
                "-".to_owned()
            } else {
                claims.allow_hosts.join(",")
            },
            claims
                .peer_uid
                .map_or_else(|| "-".to_owned(), |u| u.to_string()),
            redact_str(claims.redact),
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// G1 (v0.2.2): token-gated list / read / write + stdio MCP server.
// ---------------------------------------------------------------------

/// Resolve the caller's sealed token for the agent verbs (SPEC-v034 G2):
/// `--token-file PATH` (0600, caller-owned), `--token-fd N`, raw `--token`
/// (warns once, still works), else `GEODE_TOKEN` (06-agent-plane 3). These
/// flags live on the agent verbs only — never global, so they cannot reach
/// `geode tui` (14-tui 1.4). Stdin is NOT a token source here: `write` owns
/// stdin for the body. The hex-armored form is accepted because env vars
/// cannot carry binary NULs. `--passphrase-fd` is loaded here too, before
/// any key unlock.
fn resolve_agent_token(src: &TokenSource) -> Result<Vec<u8>> {
    if let Some(fd) = src.passphrase_fd {
        crate::output::load_passphrase_fd(fd).map_err(Error::Io)?;
    }
    let raw: Vec<u8> = if let Some(path) = &src.token_file {
        read_token_file(path)?
    } else if let Some(fd) = src.token_fd {
        read_token_fd(fd)?
    } else if let Some(flag) = &src.token {
        crate::output::warn_token_argv();
        flag.as_bytes().to_vec()
    } else {
        std::env::var_os("GEODE_TOKEN")
            .map(|v| v.to_string_lossy().into_owned().into_bytes())
            .unwrap_or_default()
    };
    if raw.iter().all(u8::is_ascii_whitespace) {
        return Err(Error::Format(
            "missing token: pass --token-file, --token-fd, or set GEODE_TOKEN".into(),
        ));
    }
    normalize_sealed(&raw)
}

/// Upper bound on a token read from a file or fd. A sealed token is far
/// smaller; this only stops an accidental huge read.
const TOKEN_READ_CAP: u64 = 64 * 1024;

/// `--token-file PATH`: the file must be a regular file, mode exactly 0600,
/// and owned by the caller, or exit 1. Mode and owner come from the opened
/// handle, so a swap after the check cannot change what is read. The error
/// names the path, the mode, and the uids — never the token bytes.
fn read_token_file(path: &Path) -> Result<Vec<u8>> {
    use std::os::unix::fs::MetadataExt;
    let f = std::fs::File::open(path)
        .map_err(|e| Error::Format(format!("token file {}: cannot open: {e}", path.display())))?;
    let md = f.metadata().map_err(Error::Io)?;
    let mode = md.mode() & 0o7777;
    let me = caller_uid()?;
    if !md.is_file() || mode != 0o600 || md.uid() != me {
        return Err(Error::Format(format!(
            "token file {} must be a regular file with mode 0600 owned by uid {me} \
             (found mode 0o{mode:03o}, owner uid {})",
            path.display(),
            md.uid()
        )));
    }
    let mut buf = Vec::new();
    f.take(TOKEN_READ_CAP)
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    Ok(buf)
}

/// `--token-fd N`: read the token from an fd the caller opened, via
/// `/dev/fd/N` (no `unsafe`). The error names the fd, never the bytes.
fn read_token_fd(fd: u32) -> Result<Vec<u8>> {
    let f = std::fs::File::open(format!("/dev/fd/{fd}"))
        .map_err(|e| Error::Format(format!("--token-fd {fd}: cannot open: {e}")))?;
    let mut buf = Vec::new();
    f.take(TOKEN_READ_CAP)
        .read_to_end(&mut buf)
        .map_err(Error::Io)?;
    Ok(buf)
}

/// The caller's effective uid without `unsafe` (forbidden workspace-wide).
/// Linux reads the `Uid:` line of `/proc/self/status`, which stays readable
/// when the process is non-dumpable. Elsewhere, a fresh probe file in the
/// temp dir is created, its owner read, and the file removed.
fn caller_uid() -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").map_err(Error::Io)?;
        status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().nth(1))
            .and_then(|euid| euid.parse().ok())
            .ok_or_else(|| Error::Format("cannot read caller uid from /proc/self/status".into()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        use std::os::unix::fs::MetadataExt;
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let probe = std::env::temp_dir().join(format!(".geode-uid-{}-{nanos}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .map_err(Error::Io)?;
        let uid = f.metadata().map(|m| m.uid());
        drop(f);
        let _ = std::fs::remove_file(&probe);
        uid.map_err(Error::Io)
    }
}

/// Authenticate a vault for its EK. The ISK is dropped immediately after;
/// nothing secret is ever printed.
fn vault_ctx(vault: &Path, global: &GlobalArgs) -> Result<cmd::VaultCtx> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(vault, &isk)?;
    drop(isk);
    Ok(ctx)
}

/// Default list prefix: the token's first allow-prefix (the clap chrome
/// makes PREFIX optional; a token always narrows to at least one).
fn default_prefix(sealed: &[u8], ek: &EpochKey, now: i64) -> Result<String> {
    let claims = token::inspect(sealed, ek, now)?;
    claims
        .allow_prefix
        .first()
        .cloned()
        .ok_or_else(|| Error::Format("token grants no prefix to list".into()))
}

/// `geode agent list` (06-agent-plane 3 `geode_list`). Text mode is
/// pipe-clean: one vault-relative path per line on stdout.
fn list(
    vault: &Path,
    prefix: Option<&str>,
    token_src: &TokenSource,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_src)?;
    let ctx = vault_ctx(vault, global)?;
    let now = now_secs();
    let owned: String;
    let prefix = if let Some(p) = prefix {
        p
    } else {
        owned = default_prefix(&sealed, &ctx.ek, now)?;
        owned.as_str()
    };
    let entries = agent_ops::list(&ctx.ek, vault, &sealed, now, prefix, false)?;
    match out {
        OutMode::Json => {
            let files: Vec<serde_json::Value> = entries
                .iter()
                .map(|e| {
                    serde_json::json!({
                        "path": e.path,
                        "plain_len": e.plain_len,
                        "content_root": cmd::hex(&e.content_root),
                    })
                })
                .collect();
            cmd::emit(
                out,
                "agent_list",
                serde_json::json!({
                    "vault": vault.display().to_string(),
                    "prefix": prefix,
                    "files": files.len(),
                    "entries": files,
                }),
                "",
            );
        }
        OutMode::Text => {
            let mut stdout = std::io::stdout().lock();
            for e in &entries {
                stdout.write_all(e.path.as_bytes()).map_err(Error::Io)?;
                stdout.write_all(b"\n").map_err(Error::Io)?;
            }
            stdout.flush().map_err(Error::Io)?;
        }
    }
    Ok(())
}

/// Render a read outcome as the JSON doc shared by CLI `--output json` and
/// the MCP `geode_read` result (06-agent-plane 4: truncated reads carry
/// `truncated`/`plain_len`/`sha256`/`preview`).
fn read_doc(outcome: &agent_ops::ReadOutcome, mode: ReadMode) -> serde_json::Value {
    let mut doc = serde_json::json!({
        "path": outcome.path,
        "plain_len": outcome.plain_len,
        "truncated": outcome.truncated,
    });
    // Hash mode is the sealed content root only. No plaintext digest, no body.
    if mode == ReadMode::Hash {
        if let Some(root) = outcome.content_root {
            doc["content_root"] = serde_json::json!(cmd::hex(&root));
        }
        return doc;
    }
    if let Some(sha) = outcome.sha256 {
        doc["sha256"] = serde_json::json!(cmd::hex(&sha));
    }
    match &outcome.body {
        ReadBody::Full(bytes) => match std::str::from_utf8(bytes) {
            Ok(text) if mode == ReadMode::Text => {
                doc["text"] = serde_json::json!(text);
            }
            _ => {
                doc["hex"] = serde_json::json!(cmd::hex(bytes));
            }
        },
        ReadBody::Preview { bytes, text } => {
            if let Some(text) = text {
                doc["preview"] = serde_json::json!(text);
            } else {
                doc["preview_hex"] = serde_json::json!(cmd::hex(bytes));
            }
        }
        ReadBody::None => {}
    }
    doc
}

/// `geode agent read` (06-agent-plane 4 `geode_read`). Text mode writes the
/// plaintext body (or the truncated preview) to stdout, pipe-clean; the
/// sha256/truncation note goes to stderr.
fn read(
    vault: &Path,
    path: &str,
    mode: Option<ReadModeArg>,
    token_src: &TokenSource,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_src)?;
    let ctx = vault_ctx(vault, global)?;
    let now = now_secs();
    // SPEC-v034 G3/G4: the default follows the grant — `text` for a `Read`
    // token, `hash` for `Inject` without `Read`. Core decides the gate.
    let mode = match mode {
        Some(ReadModeArg::Text) => ReadMode::Text,
        Some(ReadModeArg::Hex) => ReadMode::Hex,
        Some(ReadModeArg::Hash) => ReadMode::Hash,
        None => agent_ops::default_read_mode(&token::inspect(&sealed, &ctx.ek, now)?.allow_ops),
    };
    let outcome = agent_ops::read(&ctx.ek, vault, &sealed, now, path, None, mode, false)?;
    match out {
        OutMode::Json => {
            cmd::emit(out, "agent_read", read_doc(&outcome, mode), "");
        }
        OutMode::Text => {
            let mut stdout = std::io::stdout().lock();
            match (&outcome.body, mode) {
                (ReadBody::Full(bytes) | ReadBody::Preview { bytes, .. }, ReadMode::Hex) => {
                    stdout
                        .write_all(cmd::hex(bytes).as_bytes())
                        .map_err(Error::Io)?;
                    stdout.write_all(b"\n").map_err(Error::Io)?;
                }
                (ReadBody::Full(bytes) | ReadBody::Preview { bytes, .. }, _) => {
                    stdout.write_all(bytes).map_err(Error::Io)?;
                }
                (ReadBody::None, _) => {
                    // Hash mode: the sealed content root, never a plaintext digest.
                    let root = outcome
                        .content_root
                        .ok_or_else(|| Error::Format("hash read missing content_root".into()))?;
                    writeln!(stdout, "{}", cmd::hex(&root)).map_err(Error::Io)?;
                }
            }
            stdout.flush().map_err(Error::Io)?;
            if let ReadBody::Preview { bytes, .. } = &outcome.body {
                let sha = outcome.sha256.map(|s| cmd::hex(&s)).unwrap_or_default();
                eprintln!(
                    "truncated: {} bytes shown of {} (sha256 {})",
                    bytes.len(),
                    outcome.plain_len,
                    sha,
                );
            }
        }
    }
    Ok(())
}

/// `geode agent write` (06-agent-plane 3, 4 `geode_write`): seal stdin at
/// PATH under an allow prefix. The stdin read is bounded by the token's
/// body cap + 1 so a runaway producer is denied before an unbounded
/// allocation; core re-enforces the same cap.
fn write(
    vault: &Path,
    path: &str,
    token_src: &TokenSource,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_src)?;
    let ctx = vault_ctx(vault, global)?;
    let now = now_secs();
    let claims = token::inspect(&sealed, &ctx.ek, now)?;
    let cap = claims.max_bytes;
    let mut body = Vec::new();
    std::io::stdin()
        .lock()
        .take(cap.saturating_add(1))
        .read_to_end(&mut body)
        .map_err(Error::Io)?;
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > cap {
        return Err(Error::PolicyDeny);
    }
    let outcome = agent_ops::write(&ctx.ek, vault, &sealed, now, path, &body, false)?;
    cmd::emit(
        out,
        "agent_write",
        serde_json::json!({
            "vault": vault.display().to_string(),
            "path": outcome.path,
            "plain_bytes": outcome.plain_len,
            "object_id": cmd::hex(&outcome.object_id.0),
            "content_root": cmd::hex(&outcome.content_root),
        }),
        &format!(
            "sealed {} ({} bytes, object {})",
            outcome.path,
            outcome.plain_len,
            cmd::hex(&outcome.object_id.0),
        ),
    );
    Ok(())
}

struct ScopeRequest<'a> {
    path: &'a str,
    op: &'a str,
    allow_prefix: &'a [String],
    principal: &'a str,
    intent: Option<&'a str>,
    body_digest: Option<&'a str>,
}

/// `geode agent scope` — named remainder ask. No vault, no token, no key.
/// Code owns prefix / `..`; Jev classifies the rest in shadow.
fn scope(req: &ScopeRequest<'_>, out: OutMode) -> Result<()> {
    let ask = geode_grotto::jev::RemainderAsk {
        verb: req.op.to_ascii_lowercase(),
        path: req.path.to_owned(),
        principal: req.principal.to_owned(),
        allow_prefix: req.allow_prefix.to_vec(),
        intent: req.intent.unwrap_or("").to_owned(),
        body_digest: req.body_digest.map(str::to_owned),
    };
    let decision = geode_grotto::jev::ask(&ask, &geode_grotto::jev::Transport::resolve_cli())?;
    let extra = serde_json::to_value(&decision)
        .map_err(|e| Error::Format(format!("jev decision json: {e}")))?;
    cmd::emit(
        out,
        "agent_scope",
        extra,
        &format!(
            "choice {} (status {}, auto_allow {}, transport {})",
            decision.choice.as_str(),
            decision.status,
            decision.auto_allow,
            decision.transport
        ),
    );
    Ok(())
}

/// Soft remainder annotation for MCP tools. Opt-in via `GEODE_JEV_TRANSPORT`.
/// Never blocks a code-allowed op; never runs when code already denied.
fn remainder_annotation(
    verb: &str,
    path: &str,
    claims: &Token,
    args: &serde_json::Value,
    body: Option<&[u8]>,
) -> Option<serde_json::Value> {
    if !geode_grotto::jev::Transport::is_configured() {
        return None;
    }
    let intent = args
        .get("intent")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    let ask = geode_grotto::jev::RemainderAsk {
        verb: verb.to_owned(),
        path: path.to_owned(),
        principal: claims.principal_id.0.clone(),
        allow_prefix: claims.allow_prefix.clone(),
        intent,
        body_digest: body.map(geode_grotto::jev::body_digest),
    };
    match geode_grotto::jev::ask(&ask, &geode_grotto::jev::Transport::resolve()) {
        Ok(d) => serde_json::to_value(d).ok(),
        Err(e) => Some(serde_json::json!({
            "shadow": true,
            "auto_allow": false,
            "choice": "ask",
            "status": "unavailable",
            "reason": e.to_string(),
        })),
    }
}

fn with_jev(mut doc: serde_json::Value, jev: Option<serde_json::Value>) -> serde_json::Value {
    if let Some(j) = jev {
        if let Some(o) = doc.as_object_mut() {
            o.insert("jev".into(), j);
        }
    }
    doc
}

// ---------------------------------------------------------------------
// `geode agent serve --stdio` — MCP over newline-delimited JSON-RPC.
// ---------------------------------------------------------------------

/// JSON-RPC result frame.
pub(crate) fn rpc_ok(id: &serde_json::Value, result: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// JSON-RPC error frame.
pub(crate) fn rpc_error(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

/// Error family names mirroring `cmd::fail` (05-cli 3) for MCP tool
/// errors — the process never exits mid-session on a tool failure.
pub(crate) fn mcp_error_code(err: &Error) -> &'static str {
    match err {
        Error::AuthFail => "auth_fail",
        Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => "not_found",
        Error::Io(_) => "io",
        Error::PolicyDeny => "policy_deny",
        Error::TokenInvalid => "token_invalid",
        Error::Locked => "locked",
        Error::Format(_) | Error::Crypto(_) | Error::NotImplemented => "usage",
    }
}

/// One authenticated agent-plane tool call (06-agent-plane 3/4).
pub(crate) struct AgentCall<'a> {
    pub(crate) facet_events: bool,
    pub(crate) ctx: &'a cmd::VaultCtx,
    pub(crate) claims: &'a Token,
    pub(crate) sealed: &'a [u8],
    pub(crate) now: i64,
    pub(crate) vault: &'a str,
    pub(crate) args: &'a serde_json::Value,
}

/// The stdio MCP server (06-agent-plane 3). One process, one token; EK is
/// unwrapped once per vault and cached — the ISK is dropped after each
/// unwrap and never held across requests.
pub(crate) struct StdioServer<'g> {
    global: &'g GlobalArgs,
    sealed: Vec<u8>,
    ctxs: HashMap<PathBuf, cmd::VaultCtx>,
    calls: u32,
    window_start: Instant,
    facet_events: bool,
}

impl<'g> StdioServer<'g> {
    fn new(global: &'g GlobalArgs, sealed: Vec<u8>) -> Self {
        Self {
            global,
            sealed,
            ctxs: HashMap::new(),
            calls: 0,
            window_start: Instant::now(),
            facet_events: std::env::var_os("GEODE_FACET_EVENTS")
                .is_some_and(|v| v.to_string_lossy() == "1"),
        }
    }

    /// Unwrap-once EK cache, keyed by vault path. ISK is loaded and dropped
    /// inside `vault_ctx` on a cache miss only.
    fn ctx_for<'a>(
        ctxs: &'a mut HashMap<PathBuf, cmd::VaultCtx>,
        global: &GlobalArgs,
        vault: &str,
    ) -> Result<&'a cmd::VaultCtx> {
        let path = PathBuf::from(vault);
        if !ctxs.contains_key(&path) {
            let ctx = vault_ctx(&path, global)?;
            ctxs.insert(path.clone(), ctx);
        }
        Ok(ctxs.get(&path).expect("inserted above"))
    }

    /// 06-agent-plane 6 item 5: 128 tool calls / 10 s per token, configurable
    /// (`GEODE_AGENT_RATE_MAX`). This is a **fixed** window that resets after
    /// `RATE_WINDOW_SECS`; a true sliding window is not implemented.
    /// Returns false when the caller is over the limit for the current window.
    fn rate_allow(&mut self) -> bool {
        let max = std::env::var("GEODE_AGENT_RATE_MAX")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(RATE_MAX);
        if self.window_start.elapsed() >= Duration::from_secs(RATE_WINDOW_SECS) {
            self.window_start = Instant::now();
            self.calls = 0;
        }
        self.calls = self.calls.saturating_add(1);
        self.calls <= max
    }

    /// 06-agent-plane 6.1: tool descriptions state the allow prefix. The
    /// token cannot be inspected before the first vault unwrap (`TokenKey`
    /// derives from the EK), so until then the description says the binary
    /// enforces the grant.
    fn tool_descriptors(&self) -> Vec<serde_json::Value> {
        let grants = self.ctxs.values().next().and_then(|ctx| {
            token::inspect(&self.sealed, &ctx.ek, now_secs())
                .ok()
                .map(|t| t.allow_prefix)
        });
        tool_descriptors_for(grants)
    }

    /// 06-agent-plane 5: when `GEODE_FACET_EVENTS=1`, append one JSON event
    /// per tool call. Stdout is the MCP frame channel, so events go to
    /// stderr. Payloads carry public ids only — never keys, never bodies.
    fn facet_event(
        enabled: bool,
        ctx: &cmd::VaultCtx,
        claims: &Token,
        op: &str,
        path: &str,
        content_root: Option<&[u8; 32]>,
    ) {
        if !enabled {
            return;
        }
        let doc = geode_grotto::event::build_facet_event(
            &cmd::hex(&ctx.vault_id.0),
            ctx.epoch.0,
            op,
            &claims.principal_id.0,
            path,
            content_root.map(|r| cmd::hex(r)).as_deref(),
            None,
        )
        .unwrap_or_else(|_| {
            serde_json::json!({
                "schema": "geode.event.v1",
                "verb": op,
                "ok": false,
                "error": {"code": "event_rejected", "message": "event payload rejected"},
            })
        });
        eprintln!("{doc}");
    }

    /// Execute one tool against a verified token. Tool failures are
    /// returned, never process-fatal.
    fn dispatch_tool(&mut self, name: &str, args: &serde_json::Value) -> Result<serde_json::Value> {
        let vault = args
            .get("vault")
            .and_then(|v| v.as_str())
            .ok_or_else(|| Error::Format("missing argument 'vault'".into()))?;
        let ctx = Self::ctx_for(&mut self.ctxs, self.global, vault)?;
        let now = now_secs();
        // Verify MAC + expiry once up front (core re-verifies inside each
        // op); the claims drive the default prefix and Facet events.
        let claims = token::inspect(&self.sealed, &ctx.ek, now)?;
        match name {
            "geode_list" => Self::list_tool(&AgentCall {
                facet_events: self.facet_events,
                ctx,
                claims: &claims,
                sealed: &self.sealed,
                now,
                vault,
                args,
            }),
            "geode_read" => Self::read_tool(&AgentCall {
                facet_events: self.facet_events,
                ctx,
                claims: &claims,
                sealed: &self.sealed,
                now,
                vault,
                args,
            }),
            "geode_write" => Self::write_tool(&AgentCall {
                facet_events: self.facet_events,
                ctx,
                claims: &claims,
                sealed: &self.sealed,
                now,
                vault,
                args,
            }),
            other => Err(Error::Format(format!("unknown tool '{other}'"))),
        }
    }

    /// `geode_list` (06-agent-plane 3): entries under a covered prefix.
    pub(crate) fn list_tool(call: &AgentCall<'_>) -> Result<serde_json::Value> {
        let prefix = match call.args.get("prefix").and_then(|p| p.as_str()) {
            Some(p) => p.to_owned(),
            None => call
                .claims
                .allow_prefix
                .first()
                .cloned()
                .ok_or_else(|| Error::Format("token grants no prefix to list".into()))?,
        };
        let entries = agent_ops::list(
            &call.ctx.ek,
            Path::new(call.vault),
            call.sealed,
            call.now,
            &prefix,
            false,
        )?;
        let files: Vec<serde_json::Value> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "path": e.path,
                    "plain_len": e.plain_len,
                    "content_root": cmd::hex(&e.content_root),
                })
            })
            .collect();
        Self::facet_event(
            call.facet_events,
            call.ctx,
            call.claims,
            "list",
            &prefix,
            None,
        );
        let jev = remainder_annotation("list", &prefix, call.claims, call.args, None);
        Ok(with_jev(
            serde_json::json!({
                "ok": true,
                "verb": "list",
                "path": prefix,
                "files": files.len(),
                "entries": files,
            }),
            jev,
        ))
    }

    /// `geode_read` (06-agent-plane 4): body, capped preview, or hash only.
    pub(crate) fn read_tool(call: &AgentCall<'_>) -> Result<serde_json::Value> {
        let path = call
            .args
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::Format("missing argument 'path'".into()))?;
        let max_bytes = call
            .args
            .get("max_bytes")
            .and_then(serde_json::Value::as_u64);
        // MCP default is hash for every token. Text and hex are explicit.
        // CLI `geode agent read` keeps `default_read_mode`.
        let mode = match call.args.get("mode").and_then(|m| m.as_str()) {
            None | Some("hash") => ReadMode::Hash,
            Some("text") => ReadMode::Text,
            Some("hex") => ReadMode::Hex,
            Some(other) => {
                return Err(Error::Format(format!("bad mode '{other}' (text|hex|hash)")));
            }
        };
        let outcome = match agent_ops::read(
            &call.ctx.ek,
            Path::new(call.vault),
            call.sealed,
            call.now,
            path,
            max_bytes,
            mode,
            false,
        ) {
            Ok(outcome) => outcome,
            Err(e) => {
                if matches!(&e, Error::Format(m) if m == "plaintext_denied") {
                    Self::facet_event(call.facet_events, call.ctx, call.claims, "read", path, None);
                }
                return Err(e);
            }
        };
        Self::facet_event(
            call.facet_events,
            call.ctx,
            call.claims,
            "read",
            &outcome.path,
            None,
        );
        let mut doc = read_doc(&outcome, mode);
        doc["ok"] = serde_json::json!(true);
        doc["verb"] = serde_json::json!("read");
        Ok(with_jev(
            doc,
            remainder_annotation("read", &outcome.path, call.claims, call.args, None),
        ))
    }

    /// `geode_write` (06-agent-plane 3, 4): seal `body`/`body_hex` at path.
    pub(crate) fn write_tool(call: &AgentCall<'_>) -> Result<serde_json::Value> {
        let path = call
            .args
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::Format("missing argument 'path'".into()))?;
        let body: Vec<u8> = match (call.args.get("body"), call.args.get("body_hex")) {
            (Some(b), None) => b
                .as_str()
                .ok_or_else(|| Error::Format("'body' must be a string".into()))?
                .as_bytes()
                .to_vec(),
            (None, Some(h)) => {
                let h = h
                    .as_str()
                    .ok_or_else(|| Error::Format("'body_hex' must be a string".into()))?;
                if h.len() % 2 != 0 || h.is_empty() {
                    return Err(Error::Format("body_hex has odd/empty length".into()));
                }
                let mut v = vec![0u8; h.len() / 2];
                cmd::unhex(h, &mut v)?;
                v
            }
            _ => {
                return Err(Error::Format(
                    "exactly one of 'body' or 'body_hex' is required".into(),
                ));
            }
        };
        let outcome = agent_ops::write(
            &call.ctx.ek,
            Path::new(call.vault),
            call.sealed,
            call.now,
            path,
            &body,
            false,
        )?;
        Self::facet_event(
            call.facet_events,
            call.ctx,
            call.claims,
            "write",
            &outcome.path,
            Some(&outcome.content_root),
        );
        Ok(with_jev(
            serde_json::json!({
                "ok": true,
                "verb": "write",
                "path": outcome.path,
                "plain_bytes": outcome.plain_len,
                "object_id": cmd::hex(&outcome.object_id.0),
                "content_root": cmd::hex(&outcome.content_root),
            }),
            remainder_annotation("write", &outcome.path, call.claims, call.args, Some(&body)),
        ))
    }

    /// Handle one `tools/call` request frame.
    fn tool_call(
        &mut self,
        id: &serde_json::Value,
        params: Option<&serde_json::Value>,
    ) -> serde_json::Value {
        let name = params
            .and_then(|p| p.get("name"))
            .and_then(|n| n.as_str())
            .unwrap_or("");
        if name == "geode_run" {
            // Design §5: a server that does not advertise `geode_run`
            // answers it with `policy_deny`, not an unknown-tool error.
            return rpc_ok(
                id,
                &serde_json::json!({
                    "content": [{"type": "text", "text": serde_json::json!({
                        "ok": false,
                        "error": {"code": "policy_deny", "message": "geode_run is served only by the custody daemon"},
                    }).to_string()}],
                    "isError": true,
                }),
            );
        }
        if !matches!(name, "geode_list" | "geode_read" | "geode_write") {
            return rpc_error(id, -32602, &format!("unknown tool '{name}'"));
        }
        if !self.rate_allow() {
            return rpc_error(id, -32000, "rate_limited: 128 tool calls / 10 s per token");
        }
        let empty = serde_json::json!({});
        let args = params.and_then(|p| p.get("arguments")).unwrap_or(&empty);
        match self.dispatch_tool(name, args) {
            Ok(doc) => rpc_ok(
                id,
                &serde_json::json!({"content": [{"type": "text", "text": doc.to_string()}]}),
            ),
            Err(e) => rpc_ok(
                id,
                &serde_json::json!({
                    "content": [{"type": "text", "text": serde_json::json!({
                        "ok": false,
                        "error": {"code": mcp_error_code(&e), "message": e.to_string()},
                    }).to_string()}],
                    "isError": true,
                }),
            ),
        }
    }

    /// Frame loop: newline-delimited JSON-RPC on stdin/stdout. Notifications
    /// (no `id`) are never answered. EOF is a clean exit 0.
    fn run_loop(&mut self) -> Result<()> {
        let stdin = std::io::stdin();
        let mut stdout = std::io::stdout().lock();
        for line in BufReader::new(stdin.lock()).lines() {
            let line = line.map_err(Error::Io)?;
            if line.trim().is_empty() {
                continue;
            }
            if rpc_line_too_large(&line) {
                let frame = rpc_error(&serde_json::Value::Null, -32600, "frame exceeds 1 MiB cap");
                write_frame(&mut stdout, &frame)?;
                continue;
            }
            let request: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let frame = rpc_error(
                        &serde_json::Value::Null,
                        -32700,
                        &format!("parse error: {e}"),
                    );
                    write_frame(&mut stdout, &frame)?;
                    continue;
                }
            };
            let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let Some(id) = request.get("id").cloned() else {
                continue; // notification (e.g. notifications/initialized)
            };
            let frame = match method {
                "initialize" => rpc_ok(
                    &id,
                    &serde_json::json!({
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "geode", "version": env!("CARGO_PKG_VERSION")},
                    }),
                ),
                "ping" => rpc_ok(&id, &serde_json::json!({})),
                "tools/list" => rpc_ok(&id, &serde_json::json!({"tools": self.tool_descriptors()})),
                "tools/call" => self.tool_call(&id, request.get("params")),
                _ => rpc_error(&id, -32601, &format!("unknown method '{method}'")),
            };
            write_frame(&mut stdout, &frame)?;
        }
        Ok(())
    }

    /// Unix-socket variant of the frame loop: the same newline-delimited
    /// JSON-RPC frames, one connection at a time, bytes to the socket only.
    fn run_loop_unix(&mut self, listener: &std::os::unix::net::UnixListener) -> Result<()> {
        let (stream, _addr) = listener.accept().map_err(Error::Io)?;
        let reader_stream = stream.try_clone().map_err(Error::Io)?;
        let reader = BufReader::new(reader_stream);
        let mut writer = std::io::BufWriter::new(stream);
        for line in reader.lines() {
            let line = line.map_err(Error::Io)?;
            if line.trim().is_empty() {
                continue;
            }
            if rpc_line_too_large(&line) {
                let frame = rpc_error(&serde_json::Value::Null, -32600, "frame exceeds 1 MiB cap");
                write_frame(&mut writer, &frame)?;
                writer.flush().map_err(Error::Io)?;
                continue;
            }
            let request: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    let frame = rpc_error(
                        &serde_json::Value::Null,
                        -32700,
                        &format!("parse error: {e}"),
                    );
                    write_frame(&mut writer, &frame)?;
                    writer.flush().map_err(Error::Io)?;
                    continue;
                }
            };
            let method = request.get("method").and_then(|m| m.as_str()).unwrap_or("");
            let Some(id) = request.get("id").cloned() else {
                continue;
            };
            let frame = match method {
                "initialize" => rpc_ok(
                    &id,
                    &serde_json::json!({
                        "protocolVersion": MCP_PROTOCOL_VERSION,
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": "geode", "version": env!("CARGO_PKG_VERSION")},
                    }),
                ),
                "ping" => rpc_ok(&id, &serde_json::json!({})),
                "tools/list" => rpc_ok(&id, &serde_json::json!({"tools": self.tool_descriptors()})),
                "tools/call" => self.tool_call(&id, request.get("params")),
                _ => rpc_error(&id, -32601, &format!("unknown method '{method}'")),
            };
            write_frame(&mut writer, &frame)?;
            writer.flush().map_err(Error::Io)?;
        }
        Ok(())
    }
}

/// The frozen `geode_list` / `geode_read` / `geode_write` descriptors
/// (06-agent-plane 3). `grants` is the token's allow prefixes when known.
/// Shared by stdio, plain `--socket`, and `--custody`.
pub(crate) fn tool_descriptors_for(grants: Option<Vec<String>>) -> Vec<serde_json::Value> {
    let note = match grants {
        Some(prefixes) => format!(" Your token allows: {}.", prefixes.join(", ")),
        None => " Your token's allow prefixes are enforced by the binary.".to_string(),
    };
    let vault_prop = serde_json::json!({"type": "string", "description": "Vault directory"});
    vec![
        serde_json::json!({
            "name": "geode_list",
            "description": format!("List sealed vault entries under a prefix. Policy-enforced; returns no file bodies.{note}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": vault_prop.clone(),
                    "prefix": {"type": "string", "description": "Prefix to list under (default: the token's first allow prefix)"},
                    "intent": {"type": "string", "description": "Optional note. Not a credential, and it does not change what the token allows."},
                },
                "required": ["vault"],
            },
        }),
        serde_json::json!({
            "name": "geode_read",
            "description": format!("Read one vault path. Honors the token max_bytes cap; use mode=hash for large files.{note}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": vault_prop.clone(),
                    "path": {"type": "string", "description": "Vault-relative object path"},
                    "max_bytes": {"type": "integer", "description": "Read cap (default 64 KiB; hard cap from the token)"},
                    "mode": {"type": "string", "enum": ["text", "hex", "hash"], "description": "Rendering mode. Omitted mode is hash for every token and returns content_root, with no body and no plaintext digest. text or hex require an explicit mode and the read op; without read, including a run-only token, they return plaintext_denied and no body."},
                    "intent": {"type": "string", "description": "Optional note. Not a credential, and it does not change what the token allows."},
                },
                "required": ["vault", "path"],
            },
        }),
        serde_json::json!({
            "name": "geode_write",
            "description": format!("Seal bytes at a vault path under an allow prefix. Creates a new object_id; body cap is the token max_bytes.{note}"),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "vault": vault_prop.clone(),
                    "path": {"type": "string", "description": "Vault-relative object path"},
                    "body": {"type": "string", "description": "UTF-8 body"},
                    "body_hex": {"type": "string", "description": "Hex-encoded raw bytes (exactly one of body/body_hex)"},
                    "intent": {"type": "string", "description": "Optional note. Not a credential, and it does not change what the token allows."},
                },
                "required": ["vault", "path"],
            },
        }),
    ]
}

/// Write one NDJSON frame to stdout (the only bytes serve puts there).
pub(crate) fn write_frame(
    stdout: &mut impl std::io::Write,
    frame: &serde_json::Value,
) -> Result<()> {
    let line =
        serde_json::to_string(frame).map_err(|e| Error::Format(format!("json encode: {e}")))?;
    stdout.write_all(line.as_bytes()).map_err(Error::Io)?;
    stdout.write_all(b"\n").map_err(Error::Io)?;
    stdout.flush().map_err(Error::Io)
}

/// `geode agent serve` (06-agent-plane 3). `--stdio` speaks MCP over
/// stdin/stdout; the Unix-socket transport is a later gate and exits 1
/// (usage) by design. No token, no server — fail closed (kill criterion).
fn serve(
    stdio: bool,
    socket: Option<&Path>,
    token_src: &TokenSource,
    global: &GlobalArgs,
) -> Result<()> {
    match (stdio, socket) {
        (false, None) | (true, Some(_)) => Err(Error::NotImplemented),
        (true, None) => {
            let sealed = resolve_agent_token(token_src)?;
            StdioServer::new(global, sealed).run_loop()
        }
        (false, Some(path)) => {
            let sealed = resolve_agent_token(token_src)?;
            serve_socket(global, sealed, path)
        }
    }
}

/// Unix-socket MCP server: the same newline-delimited JSON-RPC frames as
/// `--stdio`, over the socket. The parent directory must already exist;
/// the bind fails if the socket path exists; the file gets mode 0600 and
/// is unlinked on exit (this process unbinds its own socket).
fn serve_socket(global: &GlobalArgs, sealed: Vec<u8>, path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    if path.exists() {
        return Err(Error::Format(format!(
            "socket path already exists: {}",
            path.display()
        )));
    }
    ensure_private_parent(path)?;
    let listener = UnixListener::bind(path).map_err(|e| {
        let _ = std::fs::remove_file(path);
        Error::Format(format!("bind {}: {e}", path.display()))
    })?;
    // SPEC G0.4: after this process bound the socket, any error — including
    // a chmod failure — must unlink PATH before returning.
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        let _ = std::fs::remove_file(path);
        return Err(Error::Format(format!("chmod {}: {e}", path.display())));
    }
    let result = StdioServer::new(global, sealed).run_loop_unix(&listener);
    let _ = std::fs::remove_file(path);
    result
}

#[cfg(test)]
mod r_apply_tests {
    use super::*;
    #[test]
    fn rpc_frame_cap_is_exclusive_at_the_boundary() {
        assert!(!rpc_line_too_large(
            &"x".repeat(MAX_JSON_RPC_FRAME_BYTES - 1)
        ));
        assert!(!rpc_line_too_large(&"x".repeat(MAX_JSON_RPC_FRAME_BYTES)));
        assert!(rpc_line_too_large(
            &"x".repeat(MAX_JSON_RPC_FRAME_BYTES + 1)
        ));
    }
    #[cfg(unix)]
    #[test]
    fn parent_with_group_bits_is_tightened_to_0700() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("sockdir");
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_parent(&dir.join("agent.sock")).unwrap();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
}
