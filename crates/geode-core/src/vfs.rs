//! Kernel-free VFS read (08-mount 3; 02-cryptography 4.4).
//!
//! G0 (v0.2.5): a shipped core function `read_range` that maps
//! `(vault_root, epoch, object_id, path_bind, off, len)` to a plaintext
//! slice **without** `/dev/fuse` or any kernel backend. It decrypts only
//! the chunk(s) the byte range touches, not the whole object -- a one-byte
//! read at offset 1 GiB of a multi-GiB object decrypts one chunk, not the
//! whole file (08-mount 8: the difference between a demo and a workstation
//! tool).
//!
//! Read-only this pack. Writes / create / unlink are `Error::NotImplemented`
//! (08-mount 3 lands write/copy-on-write in a later pack). Missing path =
//! `Error::Io(NotFound)`. No ISK in errors; no new `Error` variant.
//!
//! The on-disk object layout is `header(108) || chunk_records`, where each
//! chunk record is `tag(16) || ciphertext` and `ciphertext.len() ==
//! min(chunk_size, remaining_plain)` (02-cryptography 4.4; 03-format 4).
//! `read_range` parses the header, verifies the header tag, locates the
//! touched chunk record(s) by counting forward from chunk 0, decrypts
//! each with `aead::open_chunk` under the chunk AD, and slices the joined
//! plaintext to the requested `[off, off+len)`.

use crate::aead::{open_chunk, ChunkAd};
use crate::kdf::{Epoch, EpochKey, ObjectId};
use crate::object::{compute_header_tag, path_bind_hash, ObjectHeader, HEADER_SIZE};
use crate::vault as corevault;
use crate::{Error, Result};
use std::path::Path;

/// Maximum bytes a single `read_range` call will return. Guards against a
/// caller asking for `u64::MAX` bytes and forcing a huge allocation; the
/// VFS layer pages reads anyway. 1 GiB is far above any reasonable single
/// read for v1.
pub const MAX_READ_LEN: u64 = 1 << 30;

/// Read a plaintext byte range from a sealed object without mounting.
///
/// `off` is the byte offset into the plaintext; `len` is the requested
/// length. The call decrypts only the chunk(s) the range touches
/// (`first_chunk = off / chunk_size`, `last_chunk = (off+len-1) / chunk_size`),
/// not the whole object. Returns the sliced plaintext
/// `plaintext[off .. off + actual_len]`, where `actual_len` is clamped to
/// `plain_len - off` and `MAX_READ_LEN`.
///
/// Errors:
/// - `off >= plain_len` or `len == 0` -> empty `Vec` (not an error).
/// - Missing object file -> `Error::Io(NotFound)`.
/// - Bad header / tag mismatch / path-bind mismatch / corrupt chunk ->
///   `Error::AuthFail`.
/// - Truncated file -> `Error::Format`.
/// - `len > MAX_READ_LEN` -> `Error::Format` (caller should page).
///
/// No ISK or key bytes appear in any error `Display`. No new `Error` variant.
#[allow(clippy::cast_possible_truncation)]
pub fn read_range(
    ek: &EpochKey,
    vault_root: &Path,
    epoch: Epoch,
    object_id: ObjectId,
    path_bind: &[u8],
    off: u64,
    len: u64,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_READ_LEN {
        return Err(Error::Format(format!(
            "read_range len {len} exceeds MAX_READ_LEN {MAX_READ_LEN}; page the read"
        )));
    }

    // Read the whole object file (header + chunk records). The *decryption*
    // is bounded to the touched chunks; the *read* is the whole file because
    // the chunk records are contiguous and we must seek forward from chunk
    // 0 to find chunk `i` (no per-chunk index on disk). A future index is
    // out of scope for G0.
    let raw = corevault::read_object(vault_root, epoch, &object_id)?;
    if raw.len() < HEADER_SIZE {
        return Err(Error::Format(format!(
            "object file too short: {} < {HEADER_SIZE}",
            raw.len()
        )));
    }
    let (header_bytes, chunk_bytes) = raw.split_at(HEADER_SIZE);
    let header = ObjectHeader::from_bytes(header_bytes)?;

    // Header tag (every read).
    let want = compute_header_tag(ek, &header);
    // TODO(G5): constant-time compare. Correct for G0; harden later.
    if want != header.header_tag {
        return Err(Error::AuthFail);
    }
    if header.object_id != object_id {
        return Err(Error::AuthFail);
    }

    // Path bind: if the header was sealed with a bind, the caller MUST supply
    // the matching path. A moved object fails open (02 4.3).
    let effective_bind: Vec<u8> = if header.path_bind_hash == [0u8; 32] {
        Vec::new()
    } else {
        if header.path_bind_hash != path_bind_hash(path_bind) {
            return Err(Error::AuthFail);
        }
        path_bind.to_vec()
    };

    let cs = u64::from(header.chunk_size);
    if cs == 0 {
        return Err(Error::Format("chunk_size 0 in header".into()));
    }
    let plain_len = header.plain_len;

    // Clamp the range to the plaintext.
    if off >= plain_len {
        return Ok(Vec::new());
    }
    let end = off.saturating_add(len).min(plain_len);
    if end <= off {
        return Ok(Vec::new());
    }
    let want_len = end - off;

    let first_chunk = off / cs;
    let last_chunk = (end - 1) / cs;
    let chunk_count = u64::from(header.chunk_count);
    if first_chunk >= chunk_count {
        return Ok(Vec::new());
    }
    let last_chunk = last_chunk.min(chunk_count.saturating_sub(1));

    // Walk chunk records from 0 to last_chunk, decrypting only the touched
    // ones. Records are `tag(16) || ciphertext` with
    // `ct_len = min(chunk_size, remaining_plain)`.
    let mut decrypted: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    let mut touched_started = false;
    for i in 0..=last_chunk {
        if offset + 16 > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let remaining_plain = plain_len - i * cs;
        let this_plain = cs.min(remaining_plain);
        let rec_len = 16 + this_plain as usize;
        if offset + rec_len > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let rec = &chunk_bytes[offset..offset + rec_len];
        if i >= first_chunk {
            if !touched_started {
                touched_started = true;
            }
            let ad = ChunkAd {
                suite: header.suite,
                vault_id: header.vault_id,
                epoch: header.epoch,
                object_id: header.object_id,
                chunk_index: i,
                plain_len: header.plain_len,
                chunk_size: header.chunk_size,
                path_bind: effective_bind.clone(),
            };
            let pt = open_chunk(ek, &ad, rec)?;
            decrypted.extend_from_slice(&pt);
        }
        offset += rec_len;
    }

    // Slice within the touched-chunk plaintext.
    let local_off = (off - first_chunk * cs) as usize;
    let local_end = local_off + want_len as usize;
    if local_end > decrypted.len() {
        return Err(Error::AuthFail);
    }
    Ok(decrypted[local_off..local_end].to_vec())
}

/// `read_range` at offset 0 -- convenience for whole-object reads that
/// still only decrypt touched chunks (here, all of them).
pub fn read_all(
    ek: &EpochKey,
    vault_root: &Path,
    epoch: Epoch,
    object_id: ObjectId,
    path_bind: &[u8],
) -> Result<Vec<u8>> {
    read_range(ek, vault_root, epoch, object_id, path_bind, 0, MAX_READ_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::DEFAULT_CHUNK_SIZE;
    use crate::kdf::{Epoch, IdentitySecret, VaultId};
    use crate::object;
    use crate::vault as corevault;
    use tempfile::tempdir;

    fn ek() -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    /// Seal `body` into a vault object and write it; return (dir, `object_id`).
    fn fixture(body: &[u8], chunk_size: u32) -> (tempfile::TempDir, ObjectId) {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let sealed = object::seal_object(
            &ek(),
            VaultId([0x01; 16]),
            Epoch(1),
            oid,
            chunk_size,
            b"",
            body,
        )
        .unwrap();
        let hb = sealed.header.to_bytes();
        corevault::write_object(&root, Epoch(1), &oid, &hb, &sealed.chunks).unwrap();
        (d, oid)
    }

    #[test]
    fn read_range_offset_zero_small_object() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_offset_zero_exact_chunk_boundary() {
        let cs = 64 << 10;
        let body = vec![0x5a; cs as usize];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, u64::from(cs)).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_mid_chunk_small() {
        // 11-byte object. Read [4, 8) -- mid-chunk, offset > 0.
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 4, 4).unwrap();
        assert_eq!(got, b"o wo");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn read_range_mid_chunk_large_object() {
        // Multi-chunk object (3 chunks + tail). Read a slice that starts
        // mid-chunk in chunk 1 and ends mid-chunk in chunk 2 -- the VFS
        // path that proves we decrypt only the touched chunks.
        let cs = 64 << 10;
        let body = vec![0x5a; (cs as usize) * 3 + 10];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let off = u64::from(cs) + 100;
        let len: u64 = u64::from(cs) - 50 + 5;
        let want = &body[off as usize..(off + len) as usize];
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", off, len).unwrap();
        assert_eq!(got, want);
        assert_eq!(got.len() as u64, len);
    }

    #[test]
    fn read_range_clamps_to_plain_len() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 4, 100).unwrap();
        assert_eq!(got, b"o world");
    }

    #[test]
    fn read_range_off_past_end_is_empty() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 100, 10).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn read_range_zero_len_is_empty() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, 0).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn read_range_missing_object_is_not_found() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, 10);
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn read_range_flipped_chunk_bit_is_auth_fail() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[HEADER_SIZE + 16] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn read_range_flipped_header_tag_is_auth_fail() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[92] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn read_range_wrong_object_id_is_not_found() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let mut other = oid;
        other.0[0] ^= 0x01;
        let r = read_range(&ek(), &root, Epoch(1), other, b"", 0, body.len() as u64);
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn read_range_path_bind_mismatch_is_auth_fail() {
        let cs = 64 << 10;
        let body = vec![0x41; cs as usize];
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let sealed = object::seal_object(
            &ek(),
            VaultId([0x01; 16]),
            Epoch(1),
            oid,
            cs,
            b"docs/plan.md",
            &body,
        )
        .unwrap();
        let hb = sealed.header.to_bytes();
        corevault::write_object(&root, Epoch(1), &oid, &hb, &sealed.chunks).unwrap();
        let r = read_range(
            &ek(),
            &root,
            Epoch(1),
            oid,
            b"docs/other.md",
            0,
            u64::from(cs),
        );
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
        let got = read_range(
            &ek(),
            &root,
            Epoch(1),
            oid,
            b"docs/plan.md",
            0,
            u64::from(cs),
        )
        .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_all_roundtrips() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_all(&ek(), &root, Epoch(1), oid, b"").unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_all_multi_chunk() {
        let cs = 64 << 10;
        let body = vec![0x5a; (cs as usize) * 3 + 10];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let got = read_all(&ek(), &root, Epoch(1), oid, b"").unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_over_max_len_is_format_error() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, MAX_READ_LEN + 1);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn errors_never_contain_isk() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[92] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "leaks ISK: {s}");
        assert!(!s.contains('\u{7}'), "leaks key bytes: {s}");
    }
}
