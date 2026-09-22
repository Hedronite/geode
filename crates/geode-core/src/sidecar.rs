//! Git sidecar core (09-git): `BIND_PATHS` git-mode seal + sidecar index.
//!
//! G0 (v0.2.8): git-mode seals with vault flag [`FLAG_BIND_PATHS`] on. The
//! original relative path is bound into every chunk AD (`path_bind`); a
//! stolen `.gobj` opened without that path returns [`Error::AuthFail`].
//! The sidecar index lists sealed paths. `lock` unlinks working copies
//! listed in the index — not a cryptographic operation (no EK). Hybrid
//! recipients stay [`Error::NotImplemented`].
//!
//! Not CLI. Not TUI. Not Jev. No new [`Error`] variant; errors never
//! contain ISK.

use crate::chunk::DEFAULT_CHUNK_SIZE;
use crate::kdf::{Epoch, EpochKey, ObjectId, VaultId};
use crate::object::{self, HEADER_SIZE};
use crate::vault::{self, hex_decode, hex_encode};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Filename sealing (03-format 3 bit 0). Off in git-mode this pack.
pub const FLAG_SEAL_NAMES: u16 = 1 << 0;
/// Object AD includes the vault-relative path (03-format 3 bit 1).
/// Git-mode default: on.
pub const FLAG_BIND_PATHS: u16 = 1 << 1;
/// Ed25519 required on manifests (03-format 3 bit 2). Off in git-mode.
pub const FLAG_SIGNED_MANIFESTS: u16 = 1 << 2;
/// At least one ML-KEM wrap present (03-format 3 bit 3). Git-mode refuses.
pub const FLAG_HYBRID_RECIPIENTS: u16 = 1 << 3;
/// `geode list` omits names (03-format 3 bit 4). Off in git-mode.
pub const FLAG_HIDDEN: u16 = 1 << 4;

/// Git-mode vault flags: `BIND_PATHS` on, hybrid off (09-git 3).
#[must_use]
pub fn git_mode_flags() -> u16 {
    FLAG_BIND_PATHS
}

/// One sealed working-tree path recorded in the sidecar index.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct IndexEntry {
    /// Vault-relative UTF-8 path bound into chunk AD.
    pub path: String,
    /// Hex-encoded 16-byte `object_id` (public).
    pub object_id: String,
    pub epoch: u32,
}

/// Sidecar index: sealed paths + git-mode flags. Not a crypto object.
/// `lock` reads this list and unlinks working copies; it does not need EK.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct SidecarIndex {
    pub flags: u16,
    /// Hex-encoded 16-byte `vault_id` (public).
    pub vault_id: String,
    pub epoch: u32,
    #[serde(default)]
    pub entries: Vec<IndexEntry>,
}

/// Report from [`lock`]: unlink of working copies, not a crypto op.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LockReport {
    pub unlinked: Vec<String>,
    pub missing: Vec<String>,
}

/// `.geode/vault` under `repo_root`.
#[must_use]
pub fn vault_root(repo_root: &Path) -> PathBuf {
    repo_root.join(".geode").join("vault")
}

/// Sidecar index path: `.geode/vault/sidecar-index.json`.
#[must_use]
pub fn index_path(repo_root: &Path) -> PathBuf {
    vault_root(repo_root).join("sidecar-index.json")
}

/// Normalize a git-mode relative path. This exact UTF-8 string is `path_bind`.
///
/// Rejects empty, NUL, absolute, and any `.` / `..` segment (02-cryptography
/// 5.1; 09-git path bind). Mixed bind/unbound in one epoch is forbidden:
/// git-mode never seals with an empty bind.
pub fn bind_path(relative: &str) -> Result<Vec<u8>> {
    if relative.is_empty() {
        return Err(Error::Format("git-mode path_bind must be non-empty".into()));
    }
    if relative.contains('\0') {
        return Err(Error::Format("git-mode path has NUL".into()));
    }
    let trimmed = relative.replace('\\', "/");
    if trimmed.starts_with('/') {
        return Err(Error::Format("git-mode path must be relative".into()));
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in trimmed.split('/') {
        match seg {
            "" | "." => {
                return Err(Error::Format(
                    "git-mode path must not contain empty or '.' segments".into(),
                ));
            }
            ".." => {
                return Err(Error::Format("git-mode path must not contain '..'".into()));
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return Err(Error::Format("git-mode path_bind must be non-empty".into()));
    }
    Ok(parts.join("/").into_bytes())
}

fn parse_hex16(hex: &str, what: &str) -> Result<[u8; 16]> {
    let b = hex_decode(hex)?;
    if b.len() != 16 {
        return Err(Error::Format(format!("{what} must be 16 bytes")));
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&b);
    Ok(out)
}

fn parse_vault_id(hex: &str) -> Result<VaultId> {
    Ok(VaultId(parse_hex16(hex, "vault_id")?))
}

fn parse_object_id(hex: &str) -> Result<ObjectId> {
    Ok(ObjectId(parse_hex16(hex, "object_id")?))
}

fn assert_git_mode(flags: u16) -> Result<()> {
    if flags & FLAG_HYBRID_RECIPIENTS != 0 {
        return Err(Error::NotImplemented);
    }
    if flags & FLAG_BIND_PATHS == 0 {
        return Err(Error::Format(
            "git-mode requires BIND_PATHS (vault flag bit 1)".into(),
        ));
    }
    Ok(())
}

fn working_copy(repo_root: &Path, relative: &str) -> Result<PathBuf> {
    let bind = bind_path(relative)?;
    let rel = std::str::from_utf8(&bind).map_err(|_| Error::Format("path not utf-8".into()))?;
    let p = repo_root.join(rel);
    if !p.starts_with(repo_root) {
        return Err(Error::Format("path escapes repo root".into()));
    }
    Ok(p)
}

/// Load the sidecar index. Missing file ⇒ `Error::Io(NotFound)`.
pub fn load_index(repo_root: &Path) -> Result<SidecarIndex> {
    let path = index_path(repo_root);
    let text = std::fs::read_to_string(&path)?;
    let idx: SidecarIndex =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("sidecar index: {e}")))?;
    Ok(idx)
}

/// Persist the sidecar index (atomic). Not MAC'd: lock is not a crypto op.
pub fn store_index(repo_root: &Path, index: &SidecarIndex) -> Result<()> {
    let path = index_path(repo_root);
    let data =
        serde_json::to_vec(index).map_err(|e| Error::Format(format!("sidecar index: {e}")))?;
    vault::write_atomic(&path, &data)
}

/// Create `.geode/vault` with `BIND_PATHS` git-mode and an empty sidecar index.
///
/// Allocates a fresh `vault_id`, epoch 1. Hybrid flag is never set.
pub fn init(repo_root: &Path) -> Result<SidecarIndex> {
    init_with(repo_root, vault::new_vault_id()?, Epoch(1))
}

/// `init` with a caller-supplied `vault_id` / epoch (tests, G1 adapters).
pub fn init_with(repo_root: &Path, vault_id: VaultId, epoch: Epoch) -> Result<SidecarIndex> {
    if index_path(repo_root).exists() {
        let idx = load_index(repo_root)?;
        assert_git_mode(idx.flags)?;
        return Ok(idx);
    }
    let root = vault_root(repo_root);
    vault::init_vault_dir(&root, vault_id, epoch)?;
    let idx = SidecarIndex {
        flags: git_mode_flags(),
        vault_id: hex_encode(&vault_id.0),
        epoch: epoch.0,
        entries: Vec::new(),
    };
    assert_git_mode(idx.flags)?;
    store_index(repo_root, &idx)?;
    Ok(idx)
}

fn upsert(index: &mut SidecarIndex, entry: IndexEntry) {
    if let Some(existing) = index.entries.iter_mut().find(|e| e.path == entry.path) {
        *existing = entry;
    } else {
        index.entries.push(entry);
    }
}

/// Seal `plaintext` into the sidecar vault under `relative_path`.
///
/// Git-mode: `path_bind` is the normalized relative path (`BIND_PATHS`).
/// Updates the sidecar index. Hybrid vaults refuse with [`Error::NotImplemented`].
pub fn seal(
    ek: &EpochKey,
    repo_root: &Path,
    relative_path: &str,
    plaintext: &[u8],
) -> Result<ObjectId> {
    let bind = bind_path(relative_path)?;
    let mut idx = load_index(repo_root)?;
    assert_git_mode(idx.flags)?;
    let vault_id = parse_vault_id(&idx.vault_id)?;
    let epoch = Epoch(idx.epoch);
    let object_id = vault::new_object_id()?;
    let sealed = object::seal_object(
        ek,
        vault_id,
        epoch,
        object_id,
        DEFAULT_CHUNK_SIZE,
        &bind,
        plaintext,
    )?;
    vault::write_object(
        &vault_root(repo_root),
        epoch,
        &object_id,
        &sealed.header.to_bytes(),
        &sealed.chunks,
    )?;
    let rel = std::str::from_utf8(&bind).map_err(|_| Error::Format("path not utf-8".into()))?;
    upsert(
        &mut idx,
        IndexEntry {
            path: rel.to_owned(),
            object_id: hex_encode(&object_id.0),
            epoch: epoch.0,
        },
    );
    store_index(repo_root, &idx)?;
    Ok(object_id)
}

/// Open a sealed sidecar path. The original relative path is the AD.
///
/// Missing index entry ⇒ `Error::Io(NotFound)`. Wrong path AD ⇒ [`Error::AuthFail`].
pub fn open(ek: &EpochKey, repo_root: &Path, relative_path: &str) -> Result<Vec<u8>> {
    let bind = bind_path(relative_path)?;
    let idx = load_index(repo_root)?;
    assert_git_mode(idx.flags)?;
    let rel = std::str::from_utf8(&bind).map_err(|_| Error::Format("path not utf-8".into()))?;
    let entry = idx.entries.iter().find(|e| e.path == rel).ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "sidecar path not in index",
        ))
    })?;
    let object_id = parse_object_id(&entry.object_id)?;
    let epoch = Epoch(entry.epoch);
    let bytes = vault::read_object(&vault_root(repo_root), epoch, &object_id)?;
    open_bytes(ek, &bytes, &bind)
}

/// Open raw object bytes under a claimed path AD (stolen-object / G0b).
///
/// Git-mode objects have a non-zero `path_bind_hash`. Empty or wrong
/// `claimed_path` ⇒ [`Error::AuthFail`]. Errors never contain ISK.
pub fn open_bytes(ek: &EpochKey, object_bytes: &[u8], claimed_path: &[u8]) -> Result<Vec<u8>> {
    if object_bytes.len() < HEADER_SIZE {
        return Err(Error::AuthFail);
    }
    let header = &object_bytes[..HEADER_SIZE];
    let chunks = &object_bytes[HEADER_SIZE..];
    let (_h, pt) = object::open_object(ek, header, chunks, claimed_path)?;
    Ok(pt)
}

/// Sealed relative paths in index order.
pub fn list(repo_root: &Path) -> Result<Vec<String>> {
    let idx = load_index(repo_root)?;
    assert_git_mode(idx.flags)?;
    Ok(idx.entries.into_iter().map(|e| e.path).collect())
}

/// Write one sealed path's plaintext to the working tree (`geode git unlock`).
pub fn unlock(ek: &EpochKey, repo_root: &Path, relative_path: &str) -> Result<PathBuf> {
    let pt = open(ek, repo_root, relative_path)?;
    let dest = working_copy(repo_root, relative_path)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&dest, pt)?;
    Ok(dest)
}

/// Unlink working copies listed in the sidecar index (`geode git lock`).
///
/// Not a crypto op: does not take EK, does not touch `.gobj` files, does
/// not rewrite the index. Missing working copies are reported, not errors.
pub fn lock(repo_root: &Path) -> Result<LockReport> {
    let idx = load_index(repo_root)?;
    assert_git_mode(idx.flags)?;
    let mut report = LockReport::default();
    for entry in &idx.entries {
        let dest = working_copy(repo_root, &entry.path)?;
        match std::fs::remove_file(&dest) {
            Ok(()) => report.unlinked.push(entry.path.clone()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.missing.push(entry.path.clone());
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{IdentitySecret, KeyId};
    use crate::recipients;
    use tempfile::tempdir;

    fn ek_for(vault_id: VaultId, epoch: Epoch) -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, vault_id, epoch, "git").unwrap()
    }

    fn assert_no_isk(err: &Error) {
        let s = err.to_string();
        assert!(!s.contains("ISK"), "Display leaks ISK: {s}");
        assert!(!s.contains("isk"), "Display leaks isk: {s}");
        let d = format!("{err:?}");
        assert!(!d.contains("ISK"), "Debug leaks ISK: {d}");
        // AuthFail is a unit variant: no payload that could hold key bytes.
        assert_eq!(s, "geode-core: authentication / integrity failure");
    }

    #[test]
    fn git_mode_flags_are_bind_paths_only() {
        let f = git_mode_flags();
        assert_eq!(f & FLAG_BIND_PATHS, FLAG_BIND_PATHS);
        assert_eq!(f & FLAG_HYBRID_RECIPIENTS, 0);
        assert_eq!(f, FLAG_BIND_PATHS);
    }

    #[test]
    fn git_mode_seal_roundtrip_bind_paths() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x11; 16]);
        let epoch = Epoch(1);
        let idx = init_with(repo, vid, epoch).unwrap();
        assert_eq!(idx.flags, FLAG_BIND_PATHS);
        assert_eq!(idx.entries.len(), 0);
        assert!(vault_root(repo).join("GEODE").exists());

        let ek = ek_for(vid, epoch);
        let oid = seal(&ek, repo, "NOTES.md", b"secret notes").unwrap();
        let pt = open(&ek, repo, "NOTES.md").unwrap();
        assert_eq!(pt, b"secret notes");

        let bytes = vault::read_object(&vault_root(repo), epoch, &oid).unwrap();
        let header = object::ObjectHeader::from_bytes(&bytes[..HEADER_SIZE]).unwrap();
        assert_eq!(header.path_bind_hash, object::path_bind_hash(b"NOTES.md"));
        assert_ne!(header.path_bind_hash, [0u8; 32]);
    }

    #[test]
    fn stolen_object_wrong_path_ad_is_auth_fail() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x22; 16]);
        let epoch = Epoch(1);
        init_with(repo, vid, epoch).unwrap();
        let ek = ek_for(vid, epoch);
        let oid = seal(&ek, repo, "NOTES.md", b"do not move").unwrap();
        let stolen = vault::read_object(&vault_root(repo), epoch, &oid).unwrap();

        let wrong = open_bytes(&ek, &stolen, b"stolen/NOTES.md");
        assert!(
            matches!(wrong, Err(Error::AuthFail)),
            "wrong path AD MUST AuthFail, got {wrong:?}"
        );
        assert_no_isk(wrong.as_ref().unwrap_err());

        let empty = open_bytes(&ek, &stolen, b"");
        assert!(
            matches!(empty, Err(Error::AuthFail)),
            "empty path AD MUST AuthFail, got {empty:?}"
        );
        assert_no_isk(empty.as_ref().unwrap_err());

        let pt = open_bytes(&ek, &stolen, b"NOTES.md").unwrap();
        assert_eq!(pt, b"do not move");
    }

    #[test]
    fn remapped_index_path_does_not_open() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x33; 16]);
        let epoch = Epoch(1);
        init_with(repo, vid, epoch).unwrap();
        let ek = ek_for(vid, epoch);
        seal(&ek, repo, "NOTES.md", b"bound").unwrap();

        let mut idx = load_index(repo).unwrap();
        idx.entries[0].path = "other.md".into();
        store_index(repo, &idx).unwrap();

        let r = open(&ek, repo, "other.md");
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "stolen remap MUST AuthFail, got {r:?}"
        );
        assert_no_isk(r.as_ref().unwrap_err());
    }

    #[test]
    fn index_lists_sealed_paths() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x44; 16]);
        init_with(repo, vid, Epoch(1)).unwrap();
        let ek = ek_for(vid, Epoch(1));
        seal(&ek, repo, "NOTES.md", b"a").unwrap();
        seal(&ek, repo, "ops/runbook.md", b"b").unwrap();
        let listed = list(repo).unwrap();
        assert_eq!(
            listed,
            vec!["NOTES.md".to_string(), "ops/runbook.md".to_string()]
        );
    }

    #[test]
    fn lock_unlinks_working_copies_not_objects() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x55; 16]);
        let epoch = Epoch(1);
        init_with(repo, vid, epoch).unwrap();
        let ek = ek_for(vid, epoch);
        let oid = seal(&ek, repo, "NOTES.md", b"working").unwrap();
        let dest = unlock(&ek, repo, "NOTES.md").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"working");

        // lock takes no EK — unlink only.
        let report = lock(repo).unwrap();
        assert_eq!(report.unlinked, vec!["NOTES.md".to_string()]);
        assert!(report.missing.is_empty());
        assert!(!dest.exists(), "lock MUST unlink the working copy");

        // ciphertext still opens
        let pt = open(&ek, repo, "NOTES.md").unwrap();
        assert_eq!(pt, b"working");
        let obj = vault::read_object(&vault_root(repo), epoch, &oid).unwrap();
        assert!(obj.len() >= HEADER_SIZE);

        let again = lock(repo).unwrap();
        assert!(again.unlinked.is_empty());
        assert_eq!(again.missing, vec!["NOTES.md".to_string()]);
        assert_eq!(list(repo).unwrap(), vec!["NOTES.md".to_string()]);
    }

    #[test]
    fn hybrid_stays_not_implemented() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x66; 16]);
        let idx = init_with(repo, vid, Epoch(1)).unwrap();
        assert_eq!(idx.flags & FLAG_HYBRID_RECIPIENTS, 0);

        let ek = ek_for(vid, Epoch(1));
        let r = recipients::wrap_hybrid(
            &ek,
            &[0u8; 32],
            &[0u8; 32],
            vid,
            Epoch(1),
            KeyId([0xab; 16]),
        );
        assert!(
            matches!(r, Err(Error::NotImplemented)),
            "hybrid MUST stay stub, got {r:?}"
        );
        let s = r.unwrap_err().to_string();
        assert!(!s.contains("ISK"), "hybrid error leaks ISK: {s}");
    }

    #[test]
    fn bind_path_rejects_dotdot() {
        let r = bind_path("../secret");
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
        let r = bind_path("/abs.md");
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
        let r = bind_path("");
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn missing_index_path_is_not_found_not_authfail() {
        let d = tempdir().unwrap();
        let repo = d.path();
        let vid = VaultId([0x77; 16]);
        init_with(repo, vid, Epoch(1)).unwrap();
        let ek = ek_for(vid, Epoch(1));
        let r = open(&ek, repo, "nope.md");
        match r {
            Err(Error::Io(e)) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound),
            other => panic!("expected Io(NotFound), got {other:?}"),
        }
    }
}
