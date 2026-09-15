//! `geode snapshot` / `geode gc` — named manifest snapshots and object
//! garbage collection (G1b, v0.2.1; 04-vault 7). Thin adapter over
//! `geode_grotto::snapshot`: the CLI authenticates the vault (`load_vault`),
//! derives the `ManifestKey`, and delegates all format/MAC/filesystem work
//! to core. Snapshot envelopes are MAC'd with AD `geode/v1/snapshot`;
//! `gc` only runs after the live manifest and every snapshot verify.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use geode_grotto::kdf;
use geode_grotto::snapshot as coresnap;
use geode_grotto::Result;

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct SnapshotArgs {
    #[command(subcommand)]
    pub cmd: SnapshotCmd,
}

#[derive(Subcommand, Debug)]
pub enum SnapshotCmd {
    /// Snapshot the current manifest under a name (04-vault 7).
    Create(CreateArgs),
    /// List named snapshots, each MAC-verified before display (04-vault 7).
    Ls(LsArgs),
}

#[derive(Args, Debug)]
pub struct CreateArgs {
    /// Vault to snapshot.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Snapshot name: 1-64 chars, alphanumeric start, then `[A-Za-z0-9._-]`.
    #[arg(long, value_name = "NAME")]
    pub name: String,
}

#[derive(Args, Debug)]
pub struct LsArgs {
    /// Vault to inspect.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
}

#[derive(Args, Debug)]
pub struct GcArgs {
    /// Vault to garbage-collect.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
}

pub fn run(args: &SnapshotArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        SnapshotCmd::Create(a) => create(a, global, out),
        SnapshotCmd::Ls(a) => ls(a, global, out),
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// Load + authenticate the vault and derive the `ManifestKey` (shared leg).
fn open_vault(vault: &std::path::Path, global: &GlobalArgs) -> Result<(cmd::VaultCtx, [u8; 32])> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(vault, &isk)?;
    let mk = kdf::derive_manifest_key(&ctx.ek, ctx.vault_id, ctx.epoch);
    Ok((ctx, mk))
}

fn create(args: &CreateArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    // Name validation is a usage error (exit 1) and happens before any
    // vault I/O; core re-validates before writing.
    coresnap::validate_snapshot_name(&args.name)?;
    let (ctx, mk) = open_vault(&args.vault, global)?;
    let path = coresnap::create_snapshot(&args.vault, ctx.epoch, &args.name, &mk, now_ms())?;
    cmd::emit(
        out,
        "snapshot_create",
        serde_json::json!({
            "vault": args.vault.display().to_string(),
            "name": args.name,
            "epoch": ctx.epoch.0,
            "entries": ctx.manifest.entry_count,
            "path": path.display().to_string(),
        }),
        &format!(
            "snapshot '{}' created (epoch {}, {} entries)",
            args.name, ctx.epoch.0, ctx.manifest.entry_count
        ),
    );
    Ok(())
}

fn ls(args: &LsArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (ctx, mk) = open_vault(&args.vault, global)?;
    let names = coresnap::list_snapshots(&args.vault, ctx.epoch)?;
    // Fail-closed: every listed snapshot is MAC-verified before its
    // metadata is shown. A tampered envelope is `Error::AuthFail` (exit 2),
    // never a silently-skipped entry.
    let mut metas = Vec::with_capacity(names.len());
    for name in &names {
        let env = coresnap::read_snapshot(&args.vault, ctx.epoch, name, &mk)?;
        let entries = env
            .manifest
            .get("entry_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        metas.push(serde_json::json!({
            "name": env.name,
            "epoch": env.epoch,
            "created_at": env.created_at,
            "entries": entries,
        }));
    }
    let text = if metas.is_empty() {
        "no snapshots".to_string()
    } else {
        metas
            .iter()
            .map(|m| {
                format!(
                    "{}\tepoch {}\t{} entries\tcreated {} ms",
                    m["name"].as_str().unwrap_or("?"),
                    m["epoch"],
                    m["entries"],
                    m["created_at"]
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    cmd::emit(
        out,
        "snapshot_ls",
        serde_json::json!({
            "vault": args.vault.display().to_string(),
            "epoch": ctx.epoch.0,
            "snapshots": metas,
        }),
        &text,
    );
    Ok(())
}

/// `geode gc` — delete `.gobj` files unreferenced by the current manifest
/// and all named snapshots (04-vault 7). Core MAC-verifies the manifest and
/// every snapshot before any deletion, so a forged snapshot cannot pin or
/// target an object. Referenced (live) objects are untouched.
pub fn gc(args: &GcArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (ctx, mk) = open_vault(&args.vault, global)?;
    let report = coresnap::gc(&args.vault, ctx.epoch, &mk)?;
    cmd::emit(
        out,
        "gc",
        serde_json::json!({
            "vault": args.vault.display().to_string(),
            "epoch": ctx.epoch.0,
            "kept": report.kept,
            "dropped": report.dropped,
            "dropped_paths": report
                .dropped_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
        }),
        &format!(
            "gc: {} objects kept, {} unreferenced dropped",
            report.kept, report.dropped
        ),
    );
    Ok(())
}
