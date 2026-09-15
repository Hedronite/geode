//! `geode open` — decrypt a vault (or prefix) out to a directory (04-vault 3).

#![allow(clippy::cast_possible_truncation)]

use std::path::{Path, PathBuf};
use std::time::Instant;

use clap::Args;
use geode_grotto::manifest::EntryKind;
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
        return Err(Error::Format(
            "refusing to open a vault into itself".into(),
        ));
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
        let raw = corevault::read_object(&args.vault, ctx.epoch, &e.object_id)?;
        let bind: &[u8] = if e.bind { e.path.as_bytes() } else { b"" };
        let (_, data) = object::open_object(
            &ctx.ek,
            &raw[..object::HEADER_SIZE],
            &raw[object::HEADER_SIZE..],
            bind,
        )?;
        match e.kind {
            EntryKind::File => {
                corevault::write_atomic(&target, &data)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &target,
                        std::fs::Permissions::from_mode(e.mode),
                    )
                    .map_err(Error::Io)?;
                }
            }
            EntryKind::Symlink => {
                #[cfg(unix)]
                {
                    let target_str = String::from_utf8_lossy(&data).into_owned();
                    if target.exists() {
                        std::fs::remove_file(&target).map_err(Error::Io)?;
                    }
                    std::os::unix::fs::symlink(target_str, &target).map_err(Error::Io)?;
                }
                #[cfg(not(unix))]
                return Err(Error::Format("symlinks unsupported on this platform".into()));
            }
        }
        files += 1;
        plain_bytes += data.len() as u64;
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
