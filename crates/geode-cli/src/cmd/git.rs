//! `geode git` — git sidecar verbs (init, add, status, unlock, lock).
//!
//! Thin adapter over `geode_grotto::sidecar` (09-git; SPEC-v028 G1).
//! `--key` is required. `--token` is not a flag here; `GEODE_TOKEN` never
//! substitutes. Clap help chrome is G2.

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use geode_grotto::kdf::{self, Epoch};
use geode_grotto::policy;
use geode_grotto::recipients::{self, Recipients};
use geode_grotto::sidecar::{self, SidecarIndex};
use geode_grotto::{Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

const README: &str = "\
sealed by Geode; do not hand-edit

Ciphertext lives in vault/. GitHub still sees counts, sizes, tree, times,
and recipient key ids. That is not plaintext.
";

#[derive(Args, Debug)]
pub struct GitArgs {
    #[command(subcommand)]
    pub cmd: GitCmd,
}

#[derive(Subcommand, Debug)]
pub enum GitCmd {
    /// Create `.geode/vault` (`BIND_PATHS` git-mode) + README.
    Init(InitArgs),
    /// Seal PATH into `.geode/vault` and gitignore the plaintext.
    Add(AddArgs),
    /// List sealed vs unlocked working copies.
    Status(StatusArgs),
    /// Write one sealed path to the working tree.
    Unlock(UnlockArgs),
    /// Unlink working copies listed in the sidecar index (not a crypto op).
    Lock(LockArgs),
}

#[derive(Args, Debug)]
pub struct InitArgs {}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Working-tree paths to seal (repo-relative).
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,
}

#[derive(Args, Debug)]
pub struct StatusArgs {}

#[derive(Args, Debug)]
pub struct UnlockArgs {
    /// Sealed path to restore as a working copy.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
}

#[derive(Args, Debug)]
pub struct LockArgs {}

pub fn run(args: &GitArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        GitCmd::Init(_) => init(global, out),
        GitCmd::Add(a) => add(a, global, out),
        GitCmd::Status(_) => status(global, out),
        GitCmd::Unlock(a) => unlock(a, global, out),
        GitCmd::Lock(_) => lock(global, out),
    }
}

fn repo_cwd() -> Result<PathBuf> {
    std::env::current_dir().map_err(Error::Io)
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn rel_to_bind(path: &Path) -> Result<String> {
    let raw = path
        .to_str()
        .ok_or_else(|| Error::Format("path not utf-8".into()))?;
    let mut s = raw.replace('\\', "/");
    while let Some(stripped) = s.strip_prefix("./") {
        s = stripped.to_string();
    }
    let bytes = sidecar::bind_path(&s)?;
    String::from_utf8(bytes).map_err(|_| Error::Format("path not utf-8".into()))
}

fn rel_from_arg(repo: &Path, path: &Path) -> Result<String> {
    if path.is_absolute() {
        let repo = repo.canonicalize().map_err(Error::Io)?;
        let full = if path.exists() {
            path.canonicalize().map_err(Error::Io)?
        } else {
            path.to_path_buf()
        };
        let rel = full
            .strip_prefix(&repo)
            .map_err(|_| Error::Format("path is not under the repo".into()))?;
        rel_to_bind(rel)
    } else {
        rel_to_bind(path)
    }
}

fn load_sidecar(global: &GlobalArgs) -> Result<(PathBuf, cmd::VaultCtx)> {
    let repo = repo_cwd()?;
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&sidecar::vault_root(&repo), &isk)?;
    drop(isk);
    Ok((repo, ctx))
}

fn ensure_gitignore(repo: &Path, rels: &[String]) -> Result<()> {
    let path = repo.join(".gitignore");
    let mut text = if path.exists() {
        std::fs::read_to_string(&path).map_err(Error::Io)?
    } else {
        String::new()
    };
    let mut changed = false;
    for rel in rels {
        let already = text.lines().any(|line| {
            let t = line.trim();
            t == rel || t == format!("/{rel}")
        });
        if already {
            continue;
        }
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(rel);
        text.push('\n');
        changed = true;
    }
    if changed {
        geode_grotto::vault::write_atomic(&path, text.as_bytes())?;
    }
    Ok(())
}

fn try_stage(repo: &Path, paths: &[&str]) {
    if !repo.join(".git").exists() {
        return;
    }
    let mut cmd = std::process::Command::new("git");
    cmd.arg("add").arg("--").args(paths).current_dir(repo);
    let _ = cmd.status();
}

fn write_vault_docs(repo: &Path, vault_id_hex: &str) -> Result<()> {
    let geode = repo.join(".geode");
    geode_grotto::vault::write_atomic(&geode.join("README"), README.as_bytes())?;
    let sample = policy::default_policy(vault_id_hex);
    let text = serde_json::to_string_pretty(&sample)
        .map_err(|e| Error::Format(format!("sample policy: {e}")))?;
    geode_grotto::vault::write_atomic(geode.join("policy.sample.json").as_path(), text.as_bytes())
}

/// `geode git init` (09-git 2): `.geode/vault` + README. `--key` required.
fn init(global: &GlobalArgs, out: OutMode) -> Result<()> {
    let repo = repo_cwd()?;
    if repo.join(".geode").exists() {
        return Err(Error::Format(format!(
            "{} already has .geode",
            repo.display()
        )));
    }
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let vault_id = geode_grotto::vault::new_vault_id()?;
    let epoch = Epoch(1);
    let key_id = kdf::derive_key_id(&isk)?;
    let ek = kdf::derive_epoch_key(&isk, vault_id, epoch, "")?;
    let idx: SidecarIndex = sidecar::init_with(&repo, vault_id, epoch)?;
    let vault = sidecar::vault_root(&repo);
    let flags = sidecar::git_mode_flags();

    let recipient = recipients::wrap_symmetric(&ek, &isk, vault_id, epoch, key_id)?;
    let recs = Recipients {
        vault_id: cmd::hex(&vault_id.0),
        epoch: epoch.0,
        recipients: vec![recipient],
    };
    let recs_text = serde_json::to_string_pretty(&recs)
        .map_err(|e| Error::Format(format!("recipients serialize: {e}")))?;
    geode_grotto::vault::write_atomic(&vault.join("recipients.json"), recs_text.as_bytes())?;

    let mk = kdf::derive_manifest_key(&ek, vault_id, epoch);
    let header = serde_json::json!({
        "version": 1,
        "suite": geode_grotto::SUITE_0X01,
        "flags": flags,
        "vault_id": cmd::hex(&vault_id.0),
        "epoch": epoch.0,
        "chunk_size_default": geode_grotto::chunk::DEFAULT_CHUNK_SIZE,
        "creator_key_id": cmd::hex(&key_id.0),
        "created_unix_ms": now_ms(),
        "label": "git-sidecar",
    });
    cmd::write_header(&vault, header, &mk)?;

    let manifest = geode_grotto::manifest::Manifest {
        vault_id,
        epoch,
        suite: geode_grotto::SUITE_0X01,
        flags,
        generated_at: now_ms() / 1000,
        generator: format!("geode {}", env!("CARGO_PKG_VERSION")),
        root: geode_grotto::manifest::entries_root(&[]),
        entry_count: 0,
        total_plain_bytes: 0,
        total_cipher_bytes: 0,
        entries: vec![],
    };
    let ctx = cmd::VaultCtx {
        root: vault,
        vault_id,
        epoch,
        key_id,
        ek,
        manifest,
    };
    cmd::write_manifest(&ctx)?;
    write_vault_docs(&repo, &cmd::hex(&vault_id.0))?;
    drop(isk);

    cmd::emit(
        out,
        "git_init",
        serde_json::json!({
            "vault_id": cmd::hex(&vault_id.0),
            "epoch": epoch.0,
            "key_id": cmd::hex(&key_id.0),
            "flags": flags,
            "path": sidecar::vault_root(&repo).display().to_string(),
            "entries": idx.entries.len(),
        }),
        &format!(
            "git sidecar {} epoch 1 (key {}) at {}",
            cmd::hex(&vault_id.0),
            cmd::hex(&key_id.0),
            sidecar::vault_root(&repo).display()
        ),
    );
    Ok(())
}

/// `geode git add PATH...` (09-git 3): seal + gitignore plaintext.
fn add(args: &AddArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (repo, ctx) = load_sidecar(global)?;
    let mut sealed = Vec::new();
    for path in &args.paths {
        let rel = rel_from_arg(&repo, path)?;
        let full = repo.join(&rel);
        let plaintext = std::fs::read(&full).map_err(Error::Io)?;
        sidecar::seal(&ctx.ek, &repo, &rel, &plaintext)?;
        sealed.push(rel);
    }
    ensure_gitignore(&repo, &sealed)?;
    try_stage(&repo, &[".geode/vault", ".gitignore"]);
    cmd::emit(
        out,
        "git_add",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "sealed": sealed,
        }),
        &format!("sealed {} path(s) into .geode/vault", sealed.len()),
    );
    Ok(())
}

fn status(global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (repo, ctx) = load_sidecar(global)?;
    let listed = sidecar::list(&repo)?;
    let mut unlocked = Vec::new();
    let mut locked = Vec::new();
    for path in &listed {
        if repo.join(path).is_file() {
            unlocked.push(path.clone());
        } else {
            locked.push(path.clone());
        }
    }
    let mut lines = Vec::new();
    for p in &unlocked {
        lines.push(format!("unlocked {p}"));
    }
    for p in &locked {
        lines.push(format!("sealed {p}"));
    }
    let text = if lines.is_empty() {
        "no sealed paths".to_string()
    } else {
        lines.join("\n")
    };
    cmd::emit(
        out,
        "git_status",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "sealed": listed,
            "unlocked": unlocked,
        }),
        &text,
    );
    Ok(())
}

fn unlock(args: &UnlockArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (repo, ctx) = load_sidecar(global)?;
    let rel = rel_from_arg(&repo, &args.path)?;
    let dest = sidecar::unlock(&ctx.ek, &repo, &rel)?;
    cmd::emit(
        out,
        "git_unlock",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "path": rel,
            "dest": dest.display().to_string(),
        }),
        &format!("unlocked {rel}"),
    );
    Ok(())
}

fn lock(global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (repo, ctx) = load_sidecar(global)?;
    let report = sidecar::lock(&repo)?;
    cmd::emit(
        out,
        "git_lock",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "unlinked": report.unlinked,
            "missing": report.missing,
        }),
        &format!(
            "unlinked {} working cop{}, {} missing",
            report.unlinked.len(),
            if report.unlinked.len() == 1 { "y" } else { "ies" },
            report.missing.len()
        ),
    );
    Ok(())
}
