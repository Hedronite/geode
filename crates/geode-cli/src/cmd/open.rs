//! `geode open` — decrypt a vault (or prefix) out to a directory (04-vault 3).

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Args;
use geode_grotto::manifest::{Entry, EntryKind};
use geode_grotto::{object, vault as corevault, Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct OpenArgs {
    /// Source vault.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Destination directory for plaintext.
    #[arg(value_name = "DST")]
    pub dst: PathBuf,
    /// Only open entries under this vault-relative prefix.
    #[arg(long, value_name = "PATH")]
    pub prefix: Option<String>,
}

/// Manifest paths are authenticated, but defense in depth: no `..`, no
/// absolute components, no empties.
fn safe_rel(path: &str) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for part in path.split('/') {
        match part {
            "" | "." | ".." => {
                return Err(Error::Format(format!("unsafe manifest path {path}")));
            }
            p => out.push(p),
        }
    }
    Ok(out)
}

/// Normalize a user prefix: strip leading `./` / `/`, ensure trailing `/`.
#[must_use]
pub fn normalize_prefix(prefix: &str) -> String {
    let p = prefix.trim_start_matches("./").trim_start_matches('/');
    if p.is_empty() || p.ends_with('/') {
        p.to_string()
    } else {
        format!("{p}/")
    }
}

/// Read + authenticate + decrypt one entry's plaintext object (03-format 4).
///
/// Only `file` / `symlink` rows name a `.gobj`; a `kind: dir` row does not
/// (G0 v0.2.9 dir rows), so callers must not reach here for a directory.
fn read_entry_plaintext(ctx: &cmd::VaultCtx, vault: &Path, e: &Entry) -> Result<Vec<u8>> {
    let raw = corevault::read_object(vault, ctx.epoch, &e.object_id)?;
    let bind: &[u8] = if e.bind { e.path.as_bytes() } else { b"" };
    let (_, data) = object::open_object(
        &ctx.ek,
        &raw[..object::HEADER_SIZE],
        &raw[object::HEADER_SIZE..],
        bind,
    )?;
    Ok(data)
}

/// Owner-only mode for extracted plaintext: keep the owner bits of the
/// sealed mode (so an owner-executable stays executable), never group or
/// other, and always owner read+write. A 0644 entry lands as 0600.
#[cfg(unix)]
pub(crate) fn private_mode(sealed_mode: u32) -> u32 {
    (sealed_mode & 0o700) | 0o600
}

/// Write extracted plaintext atomically. On unix the temp file is created
/// 0600 before any byte is written, so the plaintext is never visible to
/// group/other, even transiently.
fn write_plaintext(target: &Path, data: &[u8], sealed_mode: u32) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let parent = target
            .parent()
            .ok_or_else(|| Error::Format("open target has no parent".into()))?;
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).map_err(|e| Error::Format(format!("rng: {e}")))?;
        let tmp = parent.join(format!(".gde-open-{}", cmd::hex(&nonce)));
        let res = (|| -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
            f.set_permissions(std::fs::Permissions::from_mode(private_mode(sealed_mode)))?;
            std::fs::rename(&tmp, target)
        })();
        if let Err(e) = res {
            let _ = std::fs::remove_file(&tmp);
            return Err(Error::Io(e));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = sealed_mode;
        corevault::write_atomic(target, data)
    }
}

pub fn run(args: &OpenArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&args.vault, &isk)?;

    // 04-vault 3: refuse to write plaintext inside the vault.
    let vault_c = args.vault.canonicalize().map_err(Error::Io)?;
    let dst_abs = if args.dst.exists() {
        args.dst.canonicalize().map_err(Error::Io)?
    } else {
        // Note: `Path::new("out").parent()` is Some("") — empty, not None.
        let parent = args
            .dst
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent_c = parent.canonicalize().map_err(Error::Io)?;
        parent_c.join(
            args.dst
                .file_name()
                .ok_or_else(|| Error::Format("bad destination".into()))?,
        )
    };
    if dst_abs.starts_with(&vault_c) {
        return Err(Error::Format("refusing to open a vault into itself".into()));
    }

    let prefix = args.prefix.as_deref().map(normalize_prefix);
    let start = Instant::now();
    let mut files = 0u64;
    let mut plain_bytes = 0u64;

    for e in &ctx.manifest.entries {
        // Operator-facing path: open sealed names (02-cryptography 5); the
        // user prefix and the extraction tree are plaintext.
        let plain = cmd::seal::display_path(&ctx, e)?;
        if let Some(p) = &prefix {
            if !plain.starts_with(p.as_str()) && plain != p.trim_end_matches('/') {
                continue;
            }
        }
        let target = args.dst.join(safe_rel(&plain)?);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
        match e.kind {
            // A `kind: dir` row names no `.gobj` (03-format 5): materialize
            // the directory and never read an object for it (G0 v0.2.9).
            EntryKind::Dir => {
                std::fs::create_dir_all(&target).map_err(Error::Io)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(e.mode))
                        .map_err(Error::Io)?;
                }
            }
            EntryKind::File => {
                let data = read_entry_plaintext(&ctx, &args.vault, e)?;
                write_plaintext(&target, &data, e.mode)?;
                files += 1;
                plain_bytes += data.len() as u64;
            }
            EntryKind::Symlink => {
                let data = read_entry_plaintext(&ctx, &args.vault, e)?;
                #[cfg(unix)]
                {
                    let target_str = String::from_utf8_lossy(&data).into_owned();
                    if target.exists() {
                        std::fs::remove_file(&target).map_err(Error::Io)?;
                    }
                    std::os::unix::fs::symlink(target_str, &target).map_err(Error::Io)?;
                }
                #[cfg(not(unix))]
                return Err(Error::Format(
                    "symlinks unsupported on this platform".into(),
                ));
                files += 1;
                plain_bytes += data.len() as u64;
            }
        }
    }

    cmd::emit(
        out,
        "open",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "files": files,
            "plain_bytes": plain_bytes,
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }),
        &format!(
            "opened {files} file(s), {plain_bytes} B into {}",
            args.dst.display()
        ),
    );
    Ok(())
}
