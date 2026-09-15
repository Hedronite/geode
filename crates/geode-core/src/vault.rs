//! Vault directory layout and atomic writes (03-format 2, 10).
//!
//! G2: a vault is a directory (GEODE, header.json, recipients.json, epochs/).
//! Writes are temp + fsync + rename. Mutation allocates a new `object_id`.

use crate::kdf::{Epoch, ObjectId, VaultId};
use crate::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// One-line GEODE sentinel file contents (03-format 11).
pub const GEODE_SENTINEL: &str = "GDE1 vault\nhttps://hedronite.com\nThis directory is a Geode ciphertext tree. It is useless without a recipient.\n";

const HEX_CHARS: &[u8] = b"0123456789abcdef";

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode a lowercase-hex string into bytes (len must be even, >=0).
pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Format(format!("odd-length hex: {s}")));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    Ok(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return Err(Error::Format(format!("bad hex char {c:?}"))),
    })
}

/// Path of the manifest for an epoch (03-format 2).
#[must_use]
pub fn manifest_path(root: &Path, epoch: Epoch) -> PathBuf {
    root.join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("manifest.json")
}

/// Object files are sharded by the first 2 hex chars of `object_id`
/// (03-format 2): `epochs/N/objects/xx/<object_id>.gobj`
fn shard_dir(objects_root: &Path, object_id: &ObjectId) -> PathBuf {
    let hex = hex_encode(&object_id.0);
    objects_root.join(&hex[..2])
}

/// Atomic write: temp + fsync(file) + fsync(dir) + rename (03-format 10).
///
/// The temp file is created in the same directory as dest so the rename is
/// atomic on the same filesystem. On failure the temp file is removed.
pub fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    let parent = dest
        .parent()
        .ok_or_else(|| Error::Format("dest has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".gde-tmp-{}", hex_encode(&random_bytes(8)?)));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    if std::fs::rename(&tmp, dest).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(b)
}

/// Allocate a fresh 16-byte `object_id` via the OS CSPRNG (03-format 10).
pub fn new_object_id() -> Result<ObjectId> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(ObjectId(b))
}

/// Allocate a fresh 16-byte `vault_id` (02-cryptography 3).
pub fn new_vault_id() -> Result<VaultId> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(VaultId(b))
}

/// Initialize a vault directory (03-format 2; 04-vault 1).
///
/// Creates GEODE and epochs/<NNNNNNNN>/objects/. The caller writes
/// header.json, recipients.json, and manifest.json via their own modules.
pub fn init_vault_dir(root: &Path, _vault_id: VaultId, epoch: Epoch) -> Result<()> {
    std::fs::create_dir_all(root)?;
    write_atomic(&root.join("GEODE"), GEODE_SENTINEL.as_bytes())?;
    let epoch_dir = root.join("epochs").join(format!("{:08}", epoch.0));
    std::fs::create_dir_all(epoch_dir.join("objects"))?;
    Ok(())
}

/// Path for an object file inside a vault epoch (03-format 2).
pub fn object_path(vault_root: &Path, epoch: Epoch, object_id: &ObjectId) -> Result<PathBuf> {
    let objects = vault_root
        .join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("objects");
    let dir = shard_dir(&objects, object_id);
    std::fs::create_dir_all(&dir)?;
    Ok(dir.join(format!("{}.gobj", hex_encode(&object_id.0))))
}

/// Write a sealed object (header bytes + chunk bytes) atomically to the
/// vault. A new `object_id` is allocated by the caller before sealing; this
/// function never overwrites in place (03-format 10).
pub fn write_object(
    vault_root: &Path,
    epoch: Epoch,
    object_id: &ObjectId,
    header_bytes: &[u8],
    chunk_bytes: &[u8],
) -> Result<PathBuf> {
    let p = object_path(vault_root, epoch, object_id)?;
    let mut buf = Vec::with_capacity(header_bytes.len() + chunk_bytes.len());
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(chunk_bytes);
    write_atomic(&p, &buf)?;
    Ok(p)
}

/// Read an object file bytes (header + chunks) from the vault.
pub fn read_object(vault_root: &Path, epoch: Epoch, object_id: &ObjectId) -> Result<Vec<u8>> {
    let p = object_path(vault_root, epoch, object_id)?;
    Ok(std::fs::read(&p)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_layout() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        assert!(root.join("GEODE").exists());
        assert!(root
            .join("epochs")
            .join("00000001")
            .join("objects")
            .exists());
        let sentinel = std::fs::read_to_string(root.join("GEODE")).unwrap();
        assert!(sentinel.starts_with("GDE1 vault"));
    }

    #[test]
    fn write_then_read_object() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        let oid = new_object_id().unwrap();
        let hdr =
            b"GDE1placeholderheaderbytespaddingto108bytes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        let chunks = b"tag+ciphertext";
        let p = write_object(&root, Epoch(1), &oid, hdr, chunks).unwrap();
        assert!(p.exists());
        let read = read_object(&root, Epoch(1), &oid).unwrap();
        assert_eq!(&read[..hdr.len()], hdr);
        assert_eq!(&read[hdr.len()..], chunks);
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let d = tempdir().unwrap();
        let dest = d.path().join("f.txt");
        write_atomic(&dest, b"v1").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"v1");
        write_atomic(&dest, b"v2").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"v2");
    }

    #[test]
    fn new_ids_are_unique() {
        let a = new_object_id().unwrap();
        let b = new_object_id().unwrap();
        assert_ne!(a.0, b.0);
    }
}
