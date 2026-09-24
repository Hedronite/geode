//! `geode seal` — encrypt a file or tree into a vault (04-vault 2).

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_lines)]

use std::path::{Path, PathBuf};
use std::time::{Instant, UNIX_EPOCH};

use clap::Args;
use geode_grotto::manifest::{self, Entry, EntryKind};
use geode_grotto::{chunk, kdf, name, object, vault as corevault, Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct SealArgs {
    /// Source file or directory.
    #[arg(value_name = "SRC")]
    pub src: PathBuf,
    /// Destination vault.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Delete sources after the written objects verify (04-vault 2; default keep).
    #[arg(long)]
    pub consume: bool,
    /// Seal filenames with HCTR2-256 (suite 0x01) so the manifest stores
    /// ciphertext names instead of plaintext paths (02-cryptography 5).
    /// Default keeps plaintext names. No key material is printed; output
    /// carries only public identifiers (`vault_id`, `key_id`, `epoch`,
    /// hashes).
    #[arg(long)]
    pub seal_names: bool,
}

/// Vault-relative path with forward slashes (03-format 5).
fn rel_path(root: &Path, p: &Path) -> Result<String> {
    let rel = p
        .strip_prefix(root)
        .map_err(|_| Error::Format("walk prefix".into()))?;
    let mut parts = Vec::new();
    for c in rel.components() {
        if let std::path::Component::Normal(s) = c {
            parts.push(s.to_string_lossy().into_owned());
        }
    }
    Ok(parts.join("/"))
}

#[cfg(unix)]
fn entry_mode(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn entry_mode(_meta: &std::fs::Metadata) -> u32 {
    0o644
}

fn mtime_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// `parent_id` for one path component (02-cryptography 5.3).
///
/// Root components use `0x00*16`. Directory objects do not exist yet, so a
/// deeper component's `parent_id` is `BLAKE3(sealed parent path)[0..16]`.
/// INTERIM (G0b): must match backend G0a `vectors/v1/name.json`; if the
/// vectors pin a different derivation, change only this function.
fn parent_id(sealed_parent: Option<&str>) -> [u8; 16] {
    match sealed_parent {
        None => [0u8; 16],
        Some(p) => {
            let digest = blake3::hash(p.as_bytes());
            let mut id = [0u8; 16];
            id.copy_from_slice(&digest.as_bytes()[..16]);
            id
        }
    }
}

/// Name-sealing key: `NameKey` derived from `EK` (02-cryptography 3).
fn name_key(ctx: &cmd::VaultCtx) -> [u8; 32] {
    kdf::derive_name_key(&ctx.ek, ctx.vault_id, ctx.epoch)
}

/// Seal every component of a vault-relative plaintext path (02-cryptography
/// 5). Components join with `/`; each is sealed under its parent's id.
pub(crate) fn seal_rel_path(ctx: &cmd::VaultCtx, rel: &str) -> Result<String> {
    let nk = name_key(ctx);
    let mut sealed: Vec<String> = Vec::new();
    for comp in rel.split('/') {
        let pid = if sealed.is_empty() {
            parent_id(None)
        } else {
            parent_id(Some(&sealed.join("/")))
        };
        sealed.push(name::seal_name(&nk, &ctx.vault_id, ctx.epoch, &pid, comp)?);
    }
    Ok(sealed.join("/"))
}

/// Open a sealed vault-relative path back to plaintext components (for
/// `list` display and `open` extraction). Wrong key yields garbage names,
/// not an error (02-cryptography 5).
pub(crate) fn open_rel_path(ctx: &cmd::VaultCtx, sealed: &str) -> Result<String> {
    let nk = name_key(ctx);
    let mut plain: Vec<String> = Vec::new();
    let mut sealed_comps: Vec<String> = Vec::new();
    for comp in sealed.split('/') {
        let pid = if sealed_comps.is_empty() {
            parent_id(None)
        } else {
            parent_id(Some(&sealed_comps.join("/")))
        };
        plain.push(name::open_name(&nk, &ctx.vault_id, ctx.epoch, &pid, comp)?);
        sealed_comps.push(comp.to_string());
    }
    Ok(plain.join("/"))
}

/// Operator-facing path for a manifest entry: opens sealed names, passes
/// plaintext names through unchanged.
pub(crate) fn display_path(ctx: &cmd::VaultCtx, entry: &Entry) -> Result<String> {
    if entry.path_sealed {
        open_rel_path(ctx, &entry.path)
    } else {
        Ok(entry.path.clone())
    }
}

pub fn run(args: &SealArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let mut ctx = cmd::load_vault(&args.vault, &isk)?;

    let src_c = args.src.canonicalize().map_err(Error::Io)?;
    let vault_c = args.vault.canonicalize().map_err(Error::Io)?;
    if src_c.starts_with(&vault_c) || vault_c.starts_with(&src_c) {
        return Err(Error::Format(
            "source and vault must not contain each other".into(),
        ));
    }

    // Gather (abs, rel) pairs, sorted by rel path.
    let mut items: Vec<(PathBuf, String)> = Vec::new();
    if args.src.is_file() || args.src.is_symlink() {
        let name = args
            .src
            .file_name()
            .ok_or_else(|| Error::Format("bad source name".into()))?
            .to_string_lossy()
            .into_owned();
        items.push((args.src.clone(), name));
    } else if args.src.is_dir() {
        for e in walkdir::WalkDir::new(&args.src)
            .follow_links(false)
            .sort_by_file_name()
        {
            let e = e.map_err(|err| {
                Error::Io(
                    err.into_io_error()
                        .unwrap_or_else(|| std::io::Error::other("walk error")),
                )
            })?;
            if e.file_type().is_dir() {
                continue;
            }
            items.push((e.path().to_path_buf(), rel_path(&args.src, e.path())?));
        }
    } else {
        return Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} not found", args.src.display()),
        )));
    }

    // Resolve stored (possibly sealed) paths BEFORE any object write, so an
    // unsupported name-seal configuration fails closed without mutating the
    // vault (02-cryptography 5; G0b).
    let mut stored: Vec<String> = Vec::with_capacity(items.len());
    for (_, rel) in &items {
        stored.push(if args.seal_names {
            seal_rel_path(&ctx, rel)?
        } else {
            rel.clone()
        });
    }

    let start = Instant::now();
    let mut files = 0u64;
    let mut plain_bytes = 0u64;
    let mut cipher_bytes = 0u64;
    let mut new_entries: Vec<Entry> = Vec::new();
    let mut consumed: Vec<PathBuf> = Vec::new();

    for ((abs, _rel), stored_rel) in items.iter().zip(&stored) {
        let meta = std::fs::symlink_metadata(abs).map_err(Error::Io)?;
        let (kind, data) = if meta.file_type().is_symlink() {
            // Symlink target is sealed as content (01-threat-model 5).
            let target = std::fs::read_link(abs).map_err(Error::Io)?;
            (
                EntryKind::Symlink,
                target.as_os_str().to_string_lossy().as_bytes().to_vec(),
            )
        } else {
            (EntryKind::File, std::fs::read(abs).map_err(Error::Io)?)
        };
        let oid = corevault::new_object_id()?;
        let sealed = object::seal_object(
            &ctx.ek,
            ctx.vault_id,
            ctx.epoch,
            oid,
            chunk::DEFAULT_CHUNK_SIZE,
            b"",
            &data,
        )?;
        let header_bytes = sealed.header.to_bytes();
        corevault::write_object(&args.vault, ctx.epoch, &oid, &header_bytes, &sealed.chunks)?;
        cipher_bytes += (header_bytes.len() + sealed.chunks.len()) as u64;
        plain_bytes += data.len() as u64;
        files += 1;
        new_entries.push(Entry {
            path: stored_rel.clone(),
            path_sealed: args.seal_names,
            object_id: oid,
            kind,
            plain_len: data.len() as u64,
            chunk_count: sealed.header.chunk_count,
            mode: entry_mode(&meta),
            mtime_ms: mtime_ms(&meta),
            content_root: sealed.content_root,
            bind: false,
        });
        if args.consume {
            // 04-vault 2: delete only after the written object verifies.
            let raw = corevault::read_object(&args.vault, ctx.epoch, &oid)?;
            let (_, opened) = object::open_object(
                &ctx.ek,
                &raw[..object::HEADER_SIZE],
                &raw[object::HEADER_SIZE..],
                b"",
            )?;
            if opened != data {
                return Err(Error::AuthFail);
            }
            consumed.push(abs.clone());
        }
    }

    // Merge: mutation allocates a new object_id; same-path entries replaced.
    // Comparison is on the stored path (sealed form when `--seal-names`).
    ctx.manifest
        .entries
        .retain(|e| !stored.iter().any(|r| r == &e.path));
    ctx.manifest.entries.extend(new_entries);
    ctx.manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));
    ctx.manifest.root = manifest::entries_root(&ctx.manifest.entries);
    ctx.manifest.entry_count = u32::try_from(ctx.manifest.entries.len())
        .map_err(|_| Error::Format("too many entries".into()))?;
    ctx.manifest.total_plain_bytes = ctx.manifest.entries.iter().map(|e| e.plain_len).sum();
    let mut total_cipher = 0u64;
    for e in &ctx.manifest.entries {
        let p = corevault::object_path(&args.vault, ctx.epoch, &e.object_id)?;
        total_cipher += std::fs::metadata(&p).map_err(Error::Io)?.len();
    }
    ctx.manifest.total_cipher_bytes = total_cipher;
    ctx.manifest.generated_at = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX));
    cmd::write_manifest(&ctx)?;

    if args.consume {
        for p in &consumed {
            std::fs::remove_file(p).map_err(Error::Io)?;
        }
        if args.src.is_dir() {
            // Best-effort empty-directory cleanup, deepest first.
            for e in walkdir::WalkDir::new(&args.src)
                .contents_first(true)
                .into_iter()
                .flatten()
            {
                if e.file_type().is_dir() {
                    let _ = std::fs::remove_dir(e.path());
                }
            }
        }
    }

    cmd::emit(
        out,
        "seal",
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "files": files,
            "plain_bytes": plain_bytes,
            "cipher_bytes": cipher_bytes,
            "elapsed_ms": start.elapsed().as_millis() as u64,
            "content_root": cmd::hex(&ctx.manifest.root),
        }),
        &format!(
            "sealed {files} file(s), {plain_bytes} B plain -> {cipher_bytes} B cipher into {} (epoch {})",
            args.vault.display(),
            ctx.epoch.0
        ),
    );
    Ok(())
}
