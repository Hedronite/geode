//! `geode agent` — agent plane verbs (G2b, v0.2.1; 06-agent-plane). Thin
//! adapter over `geode_grotto::token`: the CLI authenticates the vault
//! (`load_vault`), builds the token claims, and delegates sealing/parsing
//! to core. The clap shape is frontend's chrome (`crate::AgentArgs`); this
//! module is the behavior.
//!
//! Secret discipline: the ISK is dropped right after vault authentication,
//! the EK never leaves `load_vault`'s scope, and neither is ever printed.
//! Stdout carries only the sealed token (`GTOK...`) and the public token
//! id. `serve` and the `read`/`write`/`list` tool verbs land with the core
//! token/session work and exit 1 (usage) by design.

use std::io::{Read as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use geode_grotto::policy::{Op, PrincipalId};
use geode_grotto::token::{self, Token, TokenId};
use geode_grotto::{Error, Result};

use crate::{cmd, AgentArgs, AgentCmd, GlobalArgs, OutMode, TokenCmd};

/// Default per-token byte cap when `--max-bytes` is omitted (06-agent-plane
/// 4 read discipline: agents are steered to hash large artifacts).
const DEFAULT_MAX_BYTES: u64 = 1_048_576;

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
            TokenCmd::Inspect { token, vault } => {
                inspect(token.as_deref(), vault, global, out)
            }
        },
        // Documented exit 1 (usage): MCP serve and the tool verbs land with
        // the core token/session work, not in this CLI-glue step.
        AgentCmd::Serve { .. }
        | AgentCmd::Read { .. }
        | AgentCmd::Write { .. }
        | AgentCmd::List { .. } => Err(Error::NotImplemented),
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
    let sealed = token::issue(&claims, &ctx.ek)?;
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
    std::io::stdin().lock().read_to_end(&mut buf).map_err(Error::Io)?;
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
