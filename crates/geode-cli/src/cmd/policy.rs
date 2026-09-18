//! `geode policy` — policy document verbs (10-policy). Thin adapter over
//! `geode_grotto::policy`: the CLI authenticates the vault (`load_vault`),
//! derives the `MetaKey` from the EK, and delegates seal/load/evaluate to
//! core. The clap shape lives in `main.rs` (`PolicyArgs`); help prose is
//! frontend's G2 chrome.
//!
//! Secret discipline: the ISK is dropped right after vault authentication;
//! the EK and `MetaKey` never leave this module and are never printed.
//!
//! G1 (v0.2.3): `show` prints the effective policy (the default when no
//! `policy.json.sealed` exists, 10-policy 3); `set` seals a JSON policy
//! (rewriting an existing sealed policy requires `--yes --break-glass`,
//! printed loudly, 10-policy 4 — there is no break-glass for tokens);
//! `check` dry-runs `evaluate` and exits 3 (`policy_deny`) on deny.

use std::path::Path;

use geode_grotto::kdf;
use geode_grotto::policy::{self, Op, Policy, PrincipalId, Verdict};
use geode_grotto::{Error, Result};

use crate::{cmd, GlobalArgs, OutMode, PolicyArgs, PolicyCmd};

pub fn run(args: &PolicyArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        PolicyCmd::Show { vault } => show(vault, global, out),
        PolicyCmd::Set {
            vault,
            file,
            yes,
            break_glass,
        } => set(vault, file, *yes, *break_glass, global, out),
        PolicyCmd::Check {
            vault,
            principal,
            op,
            path,
        } => check(vault, principal, op, path, global, out),
    }
}

/// Authenticate the vault and derive the `MetaKey`. The ISK is dropped
/// immediately after `load_vault`; nothing secret is ever printed.
fn meta_ctx(vault: &Path, global: &GlobalArgs) -> Result<(cmd::VaultCtx, [u8; 32])> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(vault, &isk)?;
    drop(isk);
    let mk = kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
    Ok((ctx, mk))
}

/// Parse an op name for `policy check`. All six ops are checkable — this
/// is a dry-run, not a grant (contrast `agent token issue`, which never
/// grants mount/admin to a token).
fn parse_op(s: &str) -> Result<Op> {
    match s {
        "list" => Ok(Op::List),
        "read" => Ok(Op::Read),
        "write" => Ok(Op::Write),
        "mount" => Ok(Op::Mount),
        "verify" => Ok(Op::Verify),
        "admin" => Ok(Op::Admin),
        _ => Err(Error::Format(format!(
            "unknown op '{s}' (list|read|write|mount|verify|admin)"
        ))),
    }
}

/// `geode policy show` (10-policy 3): the effective policy. Text mode
/// prints the policy document (pretty JSON) on stdout, pipe-clean; the
/// source (`sealed` vs `default`) goes to stderr.
fn show(vault: &Path, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (ctx, mk) = meta_ctx(vault, global)?;
    let source = if policy::policy_path(vault).is_file() {
        "sealed"
    } else {
        "default"
    };
    // `load_policy` returns the default policy when the file is missing;
    // tamper / wrong MetaKey is `Error::AuthFail` (exit 2) — the body is
    // parsed only after the tag verifies.
    let pol = policy::load_policy(vault, &mk, ctx.vault_id, ctx.epoch)?;
    let doc =
        serde_json::to_value(&pol).map_err(|e| Error::Format(format!("policy serialize: {e}")))?;
    match out {
        OutMode::Json => {
            cmd::emit(
                out,
                "policy_show",
                serde_json::json!({
                    "vault": vault.display().to_string(),
                    "source": source,
                    "policy": doc,
                }),
                "",
            );
        }
        OutMode::Text => {
            let text = serde_json::to_string_pretty(&doc)
                .map_err(|e| Error::Format(format!("policy serialize: {e}")))?;
            println!("{text}");
            eprintln!(
                "source: {source} ({})",
                policy::policy_path(vault).display()
            );
        }
    }
    Ok(())
}

/// Validate a policy document before sealing (usage errors, exit 1):
/// version 1, `vault_id` matches this vault, principal ids valid, ops
/// non-empty, prefixes carry no `..` / NUL / absolute form.
fn validate_policy(pol: &Policy, ctx: &cmd::VaultCtx) -> Result<()> {
    if pol.version != 1 {
        return Err(Error::Format(format!(
            "unsupported policy version {} (want 1)",
            pol.version
        )));
    }
    let want = cmd::hex(&ctx.vault_id.0);
    if pol.vault_id != want {
        return Err(Error::Format(format!(
            "policy vault_id {} does not match this vault {want}",
            pol.vault_id
        )));
    }
    for grant in &pol.principals {
        grant.id.validate()?;
        if grant.ops.is_empty() {
            return Err(Error::Format(format!(
                "principal {} has an empty ops list",
                grant.id.0
            )));
        }
        for prefix in &grant.prefixes {
            if prefix.contains('\0')
                || prefix.starts_with('/')
                || prefix.split('/').any(|seg| seg == "..")
            {
                return Err(Error::Format(format!(
                    "bad prefix '{prefix}' for principal {}",
                    grant.id.0
                )));
            }
        }
        if grant.max_bytes == Some(0) {
            return Err(Error::Format(format!(
                "principal {} max_bytes must be > 0",
                grant.id.0
            )));
        }
    }
    Ok(())
}

/// `geode policy set` (10-policy 3, 4): seal `--file` as
/// `policy.json.sealed`. The first seal needs no flags; rewriting an
/// existing sealed policy is the human override and requires
/// `--yes --break-glass`, printed loudly. There is no break-glass for
/// tokens (token issue narrows policy via `token::issue_narrow`).
fn set(
    vault: &Path,
    file: &Path,
    yes: bool,
    break_glass: bool,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let raw = std::fs::read(file).map_err(Error::Io)?;
    let pol: Policy =
        serde_json::from_slice(&raw).map_err(|e| Error::Format(format!("policy parse: {e}")))?;
    let (ctx, mk) = meta_ctx(vault, global)?;
    validate_policy(&pol, &ctx)?;
    let rewrite = policy::policy_path(vault).is_file();
    if rewrite {
        if !(yes && break_glass) {
            return Err(Error::Format(
                "policy.json.sealed exists; rewriting requires --yes --break-glass (10-policy 4)"
                    .into(),
            ));
        }
        eprintln!(
            "BREAK-GLASS: rewriting sealed policy for vault {} epoch {} (10-policy 4)",
            cmd::hex(&ctx.vault_id.0),
            ctx.epoch.0,
        );
    }
    let path = policy::seal_policy(vault, &pol, &mk, ctx.vault_id, ctx.epoch)?;
    cmd::emit(
        out,
        "policy_set",
        serde_json::json!({
            "vault": vault.display().to_string(),
            "path": path.display().to_string(),
            "principals": pol.principals.len(),
            "break_glass": rewrite,
        }),
        &format!(
            "sealed policy into {} ({} principals{})",
            path.display(),
            pol.principals.len(),
            if rewrite { ", break-glass rewrite" } else { "" },
        ),
    );
    Ok(())
}

/// `geode policy check` (10-policy 2): dry-run `evaluate`. Allow exits 0;
/// deny is `Error::PolicyDeny` (exit 3, JSON code `policy_deny`).
fn check(
    vault: &Path,
    principal: &str,
    op: &str,
    path: &str,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let principal = PrincipalId(principal.to_owned());
    principal.validate()?;
    let op = parse_op(op)?;
    let (ctx, mk) = meta_ctx(vault, global)?;
    let pol = policy::load_policy(vault, &mk, ctx.vault_id, ctx.epoch)?;
    match policy::evaluate(&pol, &principal, op, path)? {
        Verdict::Allow => {
            let op_name = format!("{op:?}").to_lowercase();
            cmd::emit(
                out,
                "policy_check",
                serde_json::json!({
                    "vault": vault.display().to_string(),
                    "principal": principal.0,
                    "op": op_name,
                    "path": path,
                    "verdict": "allow",
                }),
                &format!("allow {} {op_name} {path}", principal.0),
            );
            Ok(())
        }
        Verdict::Deny => cmd::fail(out, "policy_check", &Error::PolicyDeny),
    }
}
