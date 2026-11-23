//! `geode verify` — full / cheap / sample (04-vault 4).

#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_precision_loss)]

use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use geode_grotto::kdf::EpochKey;
use geode_grotto::object::{self, ObjectHeader};
use geode_grotto::{aead, vault as corevault, Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct VerifyArgs {
    /// Vault to verify.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Cheap: header + manifest MAC + first/last chunk per object.
    #[arg(long)]
    pub cheap: bool,
    /// Cheap plus a deterministic random fraction P of remaining chunks.
    #[arg(long, value_name = "P")]
    pub sample: Option<f64>,
}

enum Mode {
    Full,
    Cheap,
    Sample(f64),
}

/// Open one chunk record by index (record = `tag[16] || ciphertext`).
fn check_chunk(
    ek: &EpochKey,
    header: &ObjectHeader,
    chunks: &[u8],
    index: u32,
    bind: &[u8],
) -> Result<()> {
    let cs = u64::from(header.chunk_size);
    let mut offset = 0usize;
    for j in 0..=index {
        let this_plain = cs.min(header.plain_len - u64::from(j) * cs);
        let rec_len = 16 + this_plain as usize;
        if j == index {
            let rec = chunks
                .get(offset..offset + rec_len)
                .ok_or(Error::AuthFail)?;
            let ad = aead::ChunkAd {
                suite: header.suite,
                vault_id: header.vault_id,
                epoch: header.epoch,
                object_id: header.object_id,
                chunk_index: u64::from(index),
                plain_len: header.plain_len,
                chunk_size: header.chunk_size,
                path_bind: bind.to_vec(),
            };
            aead::open_chunk(ek, &ad, rec)?;
            return Ok(());
        }
        offset += rec_len;
    }
    Err(Error::AuthFail)
}

/// Deterministic sample selection: stable across runs for the same manifest
/// root, uniform over chunk indices.
fn sample_hit(root: &[u8; 32], header: &ObjectHeader, index: u32, prob: f64) -> bool {
    let mut hasher = blake3::Hasher::new();
    hasher.update(root);
    hasher.update(&header.object_id.0);
    hasher.update(&index.to_le_bytes());
    let out = hasher.finalize();
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&out.as_bytes()[..8]);
    let value = u64::from_le_bytes(bytes);
    (value as f64 / u64::MAX as f64) < prob
}

pub fn run(args: &VerifyArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let mode = if let Some(p) = args.sample {
        if !(0.0..=1.0).contains(&p) {
            return Err(Error::Format("--sample P must be in 0.0..=1.0".into()));
        }
        Mode::Sample(p)
    } else if args.cheap {
        Mode::Cheap
    } else {
        Mode::Full
    };

    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    // load_vault authenticates header.json, recipients.json, and the manifest
    // MAC — the manifest leg of every verify mode.
    let ctx = cmd::load_vault(&args.vault, &isk)?;

    let start = Instant::now();
    let mut chunks_checked = 0u64;

    // Merkle root consistency in every mode (04-vault 4).
    if geode_grotto::manifest::entries_root(&ctx.manifest.entries)? != ctx.manifest.root {
        return Err(Error::AuthFail);
    }
    // N-4: full verify authenticates a sealed policy when one exists.
    if matches!(mode, Mode::Full) && geode_grotto::policy::policy_path(&args.vault).is_file() {
        let mk = geode_grotto::kdf::derive_meta_key(&ctx.ek, ctx.vault_id, ctx.epoch);
        geode_grotto::policy::load_policy(&args.vault, &mk, ctx.vault_id, ctx.epoch)?;
    }
    let mut files_checked = 0u64;

    for e in &ctx.manifest.entries {
        if e.kind == geode_grotto::manifest::EntryKind::Dir {
            // A `kind: dir` row names no `.gobj` (03-format 5); `open` and
            // rotate already skip it, and verify must too.
            continue;
        }
        files_checked += 1;
        let raw = corevault::read_object(&args.vault, ctx.epoch, &e.object_id)?;
        if raw.len() < object::HEADER_SIZE {
            return Err(Error::AuthFail);
        }
        let header_bytes = &raw[..object::HEADER_SIZE];
        let chunks = &raw[object::HEADER_SIZE..];
        let header = ObjectHeader::from_bytes(header_bytes)?;
        // Header tag (every mode).
        let want = object::compute_header_tag(&ctx.ek, &header);
        if !geode_grotto::zero::ct_eq(&want, &header.header_tag) {
            return Err(Error::AuthFail);
        }
        // Manifest/header consistency (every mode).
        if header.chunk_count != e.chunk_count
            || header.plain_len != e.plain_len
            || header.object_id != e.object_id
        {
            return Err(Error::AuthFail);
        }
        let bind: &[u8] = if e.bind { e.path.as_bytes() } else { b"" };
        // Trailing or truncated bytes fail every mode, not just full.
        if chunks.len() != object::expected_chunks_len(&header)? {
            return Err(Error::AuthFail);
        }
        let n = header.chunk_count;
        match mode {
            Mode::Full => {
                object::open_object(&ctx.ek, header_bytes, chunks, bind)?;
                if object::content_root(&header, chunks)? != e.content_root {
                    return Err(Error::AuthFail);
                }
                chunks_checked += u64::from(n);
            }
            Mode::Cheap | Mode::Sample(_) => {
                if n > 0 {
                    check_chunk(&ctx.ek, &header, chunks, 0, bind)?;
                    chunks_checked += 1;
                    if n > 1 {
                        check_chunk(&ctx.ek, &header, chunks, n - 1, bind)?;
                        chunks_checked += 1;
                    }
                }
                if let Mode::Sample(p) = mode {
                    for i in 1..n.saturating_sub(1) {
                        if sample_hit(&ctx.manifest.root, &header, i, p) {
                            check_chunk(&ctx.ek, &header, chunks, i, bind)?;
                            chunks_checked += 1;
                        }
                    }
                }
            }
        }
    }

    let mode_name = match mode {
        Mode::Full => "full",
        Mode::Cheap => "cheap",
        Mode::Sample(_) => "sample",
    };
    cmd::emit(
        out,
        "verify",
        event_json(&ctx, files_checked, start.elapsed().as_millis() as u64),
        &format!(
            "verify ok ({mode_name}): {files_checked} file(s), {chunks_checked} chunk(s) checked, vault {}",
            cmd::hex(&ctx.vault_id.0)
        ),
    );
    Ok(())
}

/// JSON event body. `manifest` is the schema field; `content_root` is the
/// 3.x backward-compatibility alias for the same verified manifest root.
fn event_json(ctx: &cmd::VaultCtx, files: u64, elapsed_ms: u64) -> serde_json::Value {
    serde_json::json!({
        "vault_id": cmd::hex(&ctx.vault_id.0),
        "epoch": ctx.epoch.0,
        "key_id": cmd::hex(&ctx.key_id.0),
        "files": files,
        "manifest": cmd::hex(&ctx.manifest.root),
        "content_root": cmd::hex(&ctx.manifest.root),
        "elapsed_ms": elapsed_ms,
    })
}

#[cfg(test)]
mod r_apply_oracle_tests {
    use super::*;
    use geode_grotto::kdf::ObjectId;
    use geode_grotto::kdf::{Epoch, EpochKey, VaultId};
    use geode_grotto::object;

    #[test]
    fn verify_event_uses_schema_manifest_and_alias() {
        use geode_grotto::kdf::{Epoch, EpochKey, KeyId, VaultId};
        use geode_grotto::manifest::Manifest;
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        let root = [0x09u8; 32];
        let ctx = cmd::VaultCtx {
            root: std::path::PathBuf::new(),
            vault_id: vid,
            epoch,
            key_id: KeyId([0x02; 16]),
            ek: EpochKey::from_bytes([0x03; 32]),
            manifest: Manifest {
                vault_id: vid,
                epoch,
                suite: geode_grotto::SUITE_0X01,
                flags: 0,
                generated_at: 0,
                generator: "test".into(),
                root,
                entry_count: 0,
                total_plain_bytes: 0,
                total_cipher_bytes: 0,
                entries: Vec::new(),
            },
        };
        let doc = event_json(&ctx, 2, 3);
        let hex = cmd::hex(&root);
        assert_eq!(doc["manifest"], hex);
        assert_eq!(doc["content_root"], hex);
        assert!(doc.get("manifest_root").is_none());
    }

    #[test]
    fn check_chunk_rejects_flipped_ciphertext_bit() {
        let ek = EpochKey::from_bytes([9u8; 32]);
        let oid = ObjectId([3u8; 16]);
        let plain = b"oracle-chunk-bytes";
        let sealed = object::seal_object(
            &ek,
            &object::ObjectSpec {
                vault_id: VaultId([1u8; 16]),
                epoch: Epoch(1),
                object_id: oid,
                chunk_size: geode_grotto::chunk::DEFAULT_CHUNK_SIZE,
                path_bind: b"",
            },
            plain,
        )
        .unwrap();
        let header = sealed.header;
        let mut chunks = sealed.chunks;
        if let Some(b) = chunks.get_mut(20) {
            *b ^= 1;
        }
        assert!(matches!(
            check_chunk(&ek, &header, &chunks, 0, b""),
            Err(Error::AuthFail)
        ));
    }
}
