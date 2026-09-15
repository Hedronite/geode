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
            let rec = chunks.get(offset..offset + rec_len).ok_or(Error::AuthFail)?;
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

    for e in &ctx.manifest.entries {
        let raw = corevault::read_object(&args.vault, ctx.epoch, &e.object_id)?;
        if raw.len() < object::HEADER_SIZE {
            return Err(Error::AuthFail);
        }
        let header_bytes = &raw[..object::HEADER_SIZE];
        let chunks = &raw[object::HEADER_SIZE..];
        let header = ObjectHeader::from_bytes(header_bytes)?;
        // Header tag (every mode).
        let want = object::compute_header_tag(&ctx.ek, &header);
        if want != header.header_tag {
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
        let n = header.chunk_count;
        match mode {
            Mode::Full => {
                object::open_object(&ctx.ek, header_bytes, chunks, bind)?;
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
        serde_json::json!({
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "files": ctx.manifest.entries.len(),
            "content_root": cmd::hex(&ctx.manifest.root),
            "elapsed_ms": start.elapsed().as_millis() as u64,
        }),
        &format!(
            "verify ok ({mode_name}): {} file(s), {chunks_checked} chunk(s) checked, vault {}",
            ctx.manifest.entries.len(),
            cmd::hex(&ctx.vault_id.0)
        ),
    );
    Ok(())
}
