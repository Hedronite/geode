//! `geode agent` — agent plane verbs (06-agent-plane). Thin adapter over
//! `geode_grotto::token` (G2b, v0.2.1) and `geode_grotto::agent_ops`
//! (G1, v0.2.2): the CLI authenticates the vault (`load_vault`), resolves
//! the caller's sealed token (`--token` on agent verbs only, else
//! `GEODE_TOKEN`), and delegates every authorization decision to core.
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
use geode_grotto::token::{self, Token, TokenId};
use geode_grotto::{Error, Result};

use crate::{cmd, AgentArgs, AgentCmd, GlobalArgs, OutMode, TokenCmd};

/// Default per-token byte cap when `--max-bytes` is omitted (06-agent-plane
/// 4 read discipline: agents are steered to hash large artifacts).
const DEFAULT_MAX_BYTES: u64 = 1_048_576;

/// MCP protocol version the stdio server speaks.
const MCP_PROTOCOL_VERSION: &str = "2025-06-18";
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

fn rpc_line_too_large(line: &str) -> bool {
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
            } => issue(
                vault,
                principal,
                ttl,
                ops,
                allow_prefix,
                *max_bytes,
                global,
                out,
            ),
            TokenCmd::Inspect { token, vault } => inspect(token.as_deref(), vault, global, out),
        },
        AgentCmd::List {
            vault,
            prefix,
            token,
        } => list(vault, prefix.as_deref(), token.as_deref(), global, out),
        AgentCmd::Read { vault, path, token } => read(vault, path, token.as_deref(), global, out),
        AgentCmd::Write { vault, path, token } => write(vault, path, token.as_deref(), global, out),
        AgentCmd::Serve {
            stdio,
            socket,
            token,
        } => serve(*stdio, socket.as_deref(), token.as_deref(), global),
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

fn now_secs() -> i64 {
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
            "mount" | "admin" => {
                return Err(Error::Format(format!(
                    "op '{part}' is never granted to an agent token (06-agent-plane 3)"
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

#[allow(clippy::too_many_arguments)]
fn issue(
    vault: &std::path::Path,
    principal: &str,
    ttl: &str,
    ops: &str,
    allow_prefix: &[String],
    max_bytes: Option<u64>,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    // All input validation is a usage error (exit 1) and happens before any
    // vault I/O; core re-validates token ⊆ policy before sealing.
    let principal = PrincipalId(principal.to_owned());
    principal.validate()?;
    let ops = parse_ops(ops)?;
    let prefixes = normalize_prefixes(allow_prefix)?;
    let ttl = parse_ttl(ttl)?;
    let max_bytes = max_bytes.unwrap_or(DEFAULT_MAX_BYTES);

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
fn normalize_sealed(raw: &[u8]) -> Result<Vec<u8>> {
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
            "vault_id": cmd::hex(&claims.vault_id.0),
            "epoch": claims.epoch.0,
            "principal": claims.principal_id.0,
            "not_before": claims.not_before,
            "not_after": claims.not_after,
            "allow_ops": ops,
            "allow_prefix": claims.allow_prefix,
            "max_bytes": claims.max_bytes,
        }),
        &format!(
            "token {}\n  principal {}\n  vault {} epoch {}\n  valid {}..{}\n  ops {}\n  prefixes {}\n  max-bytes {}",
            cmd::hex(&claims.token_id.0),
            claims.principal_id.0,
            cmd::hex(&claims.vault_id.0),
            claims.epoch.0,
            claims.not_before,
            claims.not_after,
            ops.join(","),
            claims.allow_prefix.join(","),
            claims.max_bytes,
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------
// G1 (v0.2.2): token-gated list / read / write + stdio MCP server.
// ---------------------------------------------------------------------

/// Resolve the caller's sealed token for the agent verbs: `--token` (agent
/// verbs only — never a global flag, so it cannot reach `geode tui`,
/// 14-tui 1.4), else `GEODE_TOKEN` (06-agent-plane 3). Stdin is NOT a
/// token source here: `write` owns stdin for the body. The hex-armored
/// form is accepted because env vars cannot carry binary NULs.
fn resolve_agent_token(flag: Option<&str>) -> Result<Vec<u8>> {
    let raw = flag
        .map(str::to_owned)
        .or_else(|| std::env::var_os("GEODE_TOKEN").map(|v| v.to_string_lossy().into_owned()))
        .filter(|t| !t.trim().is_empty())
        .ok_or_else(|| {
            Error::Format(
                "missing token: pass --token or set GEODE_TOKEN (06-agent-plane 3)".into(),
            )
        })?;
    normalize_sealed(raw.as_bytes())
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
    token_flag: Option<&str>,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_flag)?;
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
        "sha256": cmd::hex(&outcome.sha256),
    });
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
    token_flag: Option<&str>,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_flag)?;
    let ctx = vault_ctx(vault, global)?;
    let outcome = agent_ops::read(
        &ctx.ek,
        vault,
        &sealed,
        now_secs(),
        path,
        None,
        ReadMode::Text,
        false,
    )?;
    match out {
        OutMode::Json => {
            cmd::emit(out, "agent_read", read_doc(&outcome, ReadMode::Text), "");
        }
        OutMode::Text => {
            let mut stdout = std::io::stdout().lock();
            match &outcome.body {
                ReadBody::Full(bytes) | ReadBody::Preview { bytes, .. } => {
                    stdout.write_all(bytes).map_err(Error::Io)?;
                }
                ReadBody::None => {}
            }
            stdout.flush().map_err(Error::Io)?;
            if let ReadBody::Preview { bytes, .. } = &outcome.body {
                eprintln!(
                    "truncated: {} bytes shown of {} (sha256 {})",
                    bytes.len(),
                    outcome.plain_len,
                    cmd::hex(&outcome.sha256),
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
    token_flag: Option<&str>,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let sealed = resolve_agent_token(token_flag)?;
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
fn rpc_ok(id: &serde_json::Value, result: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({"jsonrpc": "2.0", "id": id, "result": result})
}

/// JSON-RPC error frame.
fn rpc_error(id: &serde_json::Value, code: i64, message: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {"code": code, "message": message},
    })
}

/// Error family names mirroring `cmd::fail` (05-cli 3) for MCP tool
/// errors — the process never exits mid-session on a tool failure.
fn mcp_error_code(err: &Error) -> &'static str {
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

/// The stdio MCP server (06-agent-plane 3). One process, one token; EK is
/// unwrapped once per vault and cached — the ISK is dropped after each
/// unwrap and never held across requests.
struct StdioServer<'g> {
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
                        "intent": {"type": "string", "description": "Optional declared remainder (public text; never a token). Shadow Jev only."},
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
                        "mode": {"type": "string", "enum": ["text", "hex", "hash"], "description": "Rendering mode (default text)"},
                        "intent": {"type": "string", "description": "Optional declared remainder (public text; never a token). Shadow Jev only."},
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
                        "intent": {"type": "string", "description": "Optional declared remainder (public text; never a token). Shadow Jev only."},
                    },
                    "required": ["vault", "path"],
                },
            }),
        ]
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
            "geode_list" => Self::list_tool(
                self.facet_events,
                ctx,
                &claims,
                &self.sealed,
                now,
                vault,
                args,
            ),
            "geode_read" => Self::read_tool(
                self.facet_events,
                ctx,
                &claims,
                &self.sealed,
                now,
                vault,
                args,
            ),
            "geode_write" => Self::write_tool(
                self.facet_events,
                ctx,
                &claims,
                &self.sealed,
                now,
                vault,
                args,
            ),
            other => Err(Error::Format(format!("unknown tool '{other}'"))),
        }
    }

    /// `geode_list` (06-agent-plane 3): entries under a covered prefix.
    #[allow(clippy::too_many_arguments)]
    fn list_tool(
        facet_events: bool,
        ctx: &cmd::VaultCtx,
        claims: &Token,
        sealed: &[u8],
        now: i64,
        vault: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let prefix = match args.get("prefix").and_then(|p| p.as_str()) {
            Some(p) => p.to_owned(),
            None => claims
                .allow_prefix
                .first()
                .cloned()
                .ok_or_else(|| Error::Format("token grants no prefix to list".into()))?,
        };
        let entries = agent_ops::list(&ctx.ek, Path::new(vault), sealed, now, &prefix, false)?;
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
        Self::facet_event(facet_events, ctx, claims, "list", &prefix, None);
        let jev = remainder_annotation("list", &prefix, claims, args, None);
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
    #[allow(clippy::too_many_arguments)]
    fn read_tool(
        facet_events: bool,
        ctx: &cmd::VaultCtx,
        claims: &Token,
        sealed: &[u8],
        now: i64,
        vault: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = args
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::Format("missing argument 'path'".into()))?;
        let max_bytes = args.get("max_bytes").and_then(serde_json::Value::as_u64);
        let mode = match args.get("mode").and_then(|m| m.as_str()).unwrap_or("text") {
            "text" => ReadMode::Text,
            "hex" => ReadMode::Hex,
            "hash" => ReadMode::Hash,
            other => {
                return Err(Error::Format(format!("bad mode '{other}' (text|hex|hash)")));
            }
        };
        let outcome = agent_ops::read(
            &ctx.ek,
            Path::new(vault),
            sealed,
            now,
            path,
            max_bytes,
            mode,
            false,
        )?;
        Self::facet_event(facet_events, ctx, claims, "read", &outcome.path, None);
        let mut doc = read_doc(&outcome, mode);
        doc["ok"] = serde_json::json!(true);
        doc["verb"] = serde_json::json!("read");
        Ok(with_jev(
            doc,
            remainder_annotation("read", &outcome.path, claims, args, None),
        ))
    }

    /// `geode_write` (06-agent-plane 3, 4): seal `body`/`body_hex` at path.
    #[allow(clippy::too_many_arguments)]
    fn write_tool(
        facet_events: bool,
        ctx: &cmd::VaultCtx,
        claims: &Token,
        sealed: &[u8],
        now: i64,
        vault: &str,
        args: &serde_json::Value,
    ) -> Result<serde_json::Value> {
        let path = args
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| Error::Format("missing argument 'path'".into()))?;
        let body: Vec<u8> = match (args.get("body"), args.get("body_hex")) {
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
        let outcome = agent_ops::write(&ctx.ek, Path::new(vault), sealed, now, path, &body, false)?;
        Self::facet_event(
            facet_events,
            ctx,
            claims,
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
            remainder_annotation("write", &outcome.path, claims, args, Some(&body)),
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
        if !matches!(name, "geode_list" | "geode_read" | "geode_write") {
            return rpc_error(id, -32602, &format!("unknown tool '{name}'"));
        }
        if !self.rate_allow() {
            return rpc_error(
                id,
                -32000,
                "rate_limited: 128 tool calls / 10 s per token (06-agent-plane 6.5)",
            );
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

/// Write one NDJSON frame to stdout (the only bytes serve puts there).
fn write_frame(stdout: &mut impl std::io::Write, frame: &serde_json::Value) -> Result<()> {
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
    token_flag: Option<&str>,
    global: &GlobalArgs,
) -> Result<()> {
    match (stdio, socket) {
        (false, None) | (true, Some(_)) => Err(Error::NotImplemented),
        (true, None) => {
            let sealed = resolve_agent_token(token_flag)?;
            StdioServer::new(global, sealed).run_loop()
        }
        (false, Some(path)) => {
            let sealed = resolve_agent_token(token_flag)?;
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
