//! OS keyring storage + 0600 file fallback (02-cryptography 6.2; G1a v0.2.0).
//!
//! `keyring.json` is an **index only**: it records key ids, file paths,
//! labels, and flags. It **never** contains secret material (ISK or wrap
//! passphrase). Secret material lives either in the OS keyring (via the
//! [`keyring`] crate) keyed by the `KeyId` hex, or in a 0600 file at the
//! recorded `path`.
//!
//! # Layout
//!
//! - OS keyring entry: service `hedronite.geode`, username = `KeyId` hex.
//! - File fallback: 0600 file at the key `path` (atomic write + fsync).
//! - `keyring.json`: keyring.schema.json.
//!
//! # Fail-closed
//!
//! A group/world-readable fallback file is refused before any byte is read
//! (reuses [`crate::keyfile`]). An unknown `keyring.json` schema aborts.

use crate::{keyfile, vault, Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Service name under which Geode entries are stored in the OS keyring.
pub const KEYRING_SERVICE: &str = "hedronite.geode";

/// Schema tag written into `keyring.json` (keyring.schema.json).
pub const KEYRING_SCHEMA: &str = "geode.keyring.v1";

const HEX_CHARS: &[u8] = b"0123456789abcdef";

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    s
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(b)
}

/// One indexed key in `keyring.json`. Paths/labels only — never secret material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyringKey {
    /// 32-hex `KeyId` (16 bytes). Used as the OS-keyring username.
    pub id: String,
    /// Canonical key file path (0600 fallback / export location).
    pub path: String,
    /// Human-readable label (max 64 chars per schema).
    pub label: String,
    /// Hybrid (post-quantum) key. Future; `false` for v0.2.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hybrid: Option<bool>,
    /// `true` when the stored blob is a passphrase-wrapped `GKEY` (needs
    /// unwrap) rather than raw ISK bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub has_passphrase: Option<bool>,
}

impl KeyringKey {
    /// Validate against keyring.schema.json: `id` is 32 lowercase hex, `label`
    /// is at most 64 chars, `path` is non-empty.
    pub fn validate(&self) -> Result<()> {
        if self.path.is_empty() {
            return Err(Error::Format("keyring key: path is empty".into()));
        }
        if self.label.chars().count() > 64 {
            return Err(Error::Format(format!(
                "keyring key {}: label exceeds 64 chars",
                self.id
            )));
        }
        if !is_key_id_hex(&self.id) {
            return Err(Error::Format(format!(
                "keyring key: id {} is not 32 lowercase hex chars",
                self.id
            )));
        }
        Ok(())
    }
}

/// The `keyring.json` index. No secret material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Keyring {
    /// Schema tag. Must be [`KEYRING_SCHEMA`].
    pub schema: String,
    /// `id` of the default key, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    /// Indexed keys.
    pub keys: Vec<KeyringKey>,
}

impl Default for Keyring {
    fn default() -> Self {
        Self {
            schema: KEYRING_SCHEMA.to_string(),
            default: None,
            keys: Vec::new(),
        }
    }
}

impl Keyring {
    /// Find a key by `id`.
    #[must_use]
    pub fn find(&self, id: &str) -> Option<&KeyringKey> {
        self.keys.iter().find(|k| k.id == id)
    }

    /// Validate every key, the schema tag, id uniqueness, and the default pointer.
    pub fn validate(&self) -> Result<()> {
        if self.schema != KEYRING_SCHEMA {
            return Err(Error::Format(format!(
                "keyring.json: unknown schema {}",
                self.schema
            )));
        }
        let mut seen = std::collections::HashSet::new();
        for k in &self.keys {
            k.validate()?;
            if !seen.insert(k.id.clone()) {
                return Err(Error::Format(format!(
                    "keyring.json: duplicate key id {}",
                    k.id
                )));
            }
        }
        if let Some(d) = &self.default {
            if self.find(d).is_none() {
                return Err(Error::Format(format!(
                    "keyring.json: default {d} is not present in keys"
                )));
            }
        }
        Ok(())
    }
}

/// `true` when `s` is exactly 32 lowercase hex chars (a `KeyId` hex).
#[must_use]
pub fn is_key_id_hex(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()) && s == s.to_ascii_lowercase()
}

/// Load a `keyring.json` index. A missing file yields an empty keyring
/// (not an error); a present-but-malformed file aborts.
pub fn load_keyring(path: &Path) -> Result<Keyring> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let kr: Keyring = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Format(format!("keyring.json: {e}")))?;
            kr.validate()?;
            Ok(kr)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Keyring::default()),
        Err(e) => Err(Error::Io(e)),
    }
}

/// Save a `keyring.json` index atomically (temp + fsync + rename) after
/// validating it. Pretty-printed for human readability / diffs.
pub fn save_keyring(path: &Path, kr: &Keyring) -> Result<()> {
    kr.validate()?;
    let text = serde_json::to_string_pretty(kr)
        .map_err(|e| Error::Format(format!("keyring.json: {e}")))?;
    vault::write_atomic(path, text.as_bytes())
}

/// Where the secret for a key is stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Storage {
    /// OS keyring (Keychain / Credential Manager / Secret Service).
    Os,
    /// 0600 file on disk.
    File,
}

// ---------------------------------------------------------------------------
// OS keyring
// ---------------------------------------------------------------------------

fn map_keyring_err(e: &keyring::Error) -> Error {
    Error::Crypto(format!("keyring: {e}"))
}

fn entry_for(key_id_hex: &str) -> Result<keyring::Entry> {
    keyring::Entry::new(KEYRING_SERVICE, key_id_hex).map_err(|e| map_keyring_err(&e))
}

/// Store `secret` (ISK bytes or wrap passphrase) in the OS keyring under
/// `key_id_hex`. Fails when no platform store is available or the store
/// rejects the write.
pub fn store_secret_os(key_id_hex: &str, secret: &[u8]) -> Result<()> {
    let entry = entry_for(key_id_hex)?;
    entry.set_secret(secret).map_err(|e| map_keyring_err(&e))
}

/// Load the secret for `key_id_hex` from the OS keyring.
pub fn load_secret_os(key_id_hex: &str) -> Result<Vec<u8>> {
    let entry = entry_for(key_id_hex)?;
    entry.get_secret().map_err(|e| map_keyring_err(&e))
}

/// Delete the secret for `key_id_hex` from the OS keyring. A missing entry
/// is not an error.
pub fn delete_secret_os(key_id_hex: &str) -> Result<()> {
    let entry = entry_for(key_id_hex)?;
    match entry.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(map_keyring_err(&e)),
    }
}

/// `true` when a platform keyring store initialized successfully. Calling
/// this initializes the store if it has not been already.
#[must_use]
pub fn os_store_available() -> bool {
    keyring::Entry::store_status().is_ok()
}

// ---------------------------------------------------------------------------
// File fallback (0600)
// ---------------------------------------------------------------------------

/// Store `secret` in a 0600 file at `path` (atomic: temp + fsync + rename).
/// The temp file is created in the same directory so the rename is atomic.
pub fn store_secret_file(path: &Path, secret: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| Error::Format("key path has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".gkey-tmp-{}", hex_encode(&random_bytes(8)?)));
    write_file_0600(&tmp, secret)?;
    if let Ok(d) = std::fs::File::open(parent) {
        let _ = d.sync_all();
    }
    if std::fs::rename(&tmp, path).is_err() {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(unix)]
fn write_file_0600(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn write_file_0600(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .truncate(true)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Load a secret from a 0600 file, refusing group/world-readable files
/// (delegates to [`crate::keyfile::load_key_file_bytes`]).
pub fn load_secret_file(path: &Path) -> Result<Vec<u8>> {
    keyfile::load_key_file_bytes(path)
}

// ---------------------------------------------------------------------------
// try-OS-then-fallback
// ---------------------------------------------------------------------------

/// Store `secret` preferring the OS keyring; fall back to a 0600 file at
/// `path` when no OS store is available (or the OS write fails). Returns
/// where the secret landed. The operator is never left without a usable key.
pub fn store_secret_with_fallback(key_id_hex: &str, path: &Path, secret: &[u8]) -> Result<Storage> {
    if os_store_available() && store_secret_os(key_id_hex, secret).is_ok() {
        return Ok(Storage::Os);
    }
    store_secret_file(path, secret)?;
    Ok(Storage::File)
}

/// Load a secret: try the OS keyring first, then the 0600 file at `path`.
///
/// Returns the secret and where it came from. A missing OS entry falls
/// through to the file; a missing file surfaces its IO error.
pub fn load_secret_with_fallback(key_id_hex: &str, path: &Path) -> Result<(Vec<u8>, Storage)> {
    if os_store_available() {
        if let Ok(secret) = load_secret_os(key_id_hex) {
            return Ok((secret, Storage::Os));
        }
    }
    let secret = load_secret_file(path)?;
    Ok((secret, Storage::File))
}

/// Default on-disk location for the `keyring.json` index:
/// `$XDG_CONFIG_HOME/hedronite/geode/keyring.json`, or
/// `~/.config/hedronite/geode/keyring.json` when `XDG_CONFIG_HOME` is unset,
/// empty, or relative. Returns `None` when no config/home dir is resolvable.
#[must_use]
pub fn default_keyring_path() -> Option<PathBuf> {
    let mut p = crate::keyfile::default_key_path()?;
    p.set_file_name("keyring.json");
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD_ID: &str = "0123456789abcdef0123456789abcdef";

    fn key(id: &str, path: &str, label: &str) -> KeyringKey {
        KeyringKey {
            id: id.to_string(),
            path: path.to_string(),
            label: label.to_string(),
            hybrid: None,
            has_passphrase: None,
        }
    }

    #[test]
    fn is_key_id_hex_accepts_32_lower() {
        assert!(is_key_id_hex("0123456789abcdef0123456789abcdef"));
    }

    #[test]
    fn is_key_id_hex_rejects_upper() {
        assert!(!is_key_id_hex("0123456789ABCDEF0123456789ABCDEF"));
    }

    #[test]
    fn is_key_id_hex_rejects_wrong_len() {
        assert!(!is_key_id_hex("00"));
        assert!(!is_key_id_hex("0123456789abcdef0123456789abcdeff"));
    }

    #[test]
    fn keyring_default_schema_ok() {
        let kr = Keyring::default();
        assert_eq!(kr.schema, KEYRING_SCHEMA);
        assert!(kr.keys.is_empty());
        assert!(kr.validate().is_ok());
    }

    #[test]
    fn keyring_rejects_bad_schema() {
        let kr = Keyring {
            schema: "something.else".into(),
            default: None,
            keys: vec![],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_rejects_bad_id() {
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: None,
            keys: vec![key("nothex", "/tmp/k", "lbl")],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_rejects_empty_path() {
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: None,
            keys: vec![key(GOOD_ID, "", "lbl")],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_rejects_long_label() {
        let label = "x".repeat(65);
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: None,
            keys: vec![key(GOOD_ID, "/tmp/k", &label)],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_rejects_duplicate_ids() {
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: None,
            keys: vec![key(GOOD_ID, "/tmp/k1", "a"), key(GOOD_ID, "/tmp/k2", "b")],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_rejects_dangling_default() {
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: Some("deadbeefdeadbeefdeadbeefdeadbeef".into()),
            keys: vec![key(GOOD_ID, "/tmp/k", "a")],
        };
        assert!(kr.validate().is_err());
    }

    #[test]
    fn keyring_accepts_valid_default() {
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: Some(GOOD_ID.into()),
            keys: vec![key(GOOD_ID, "/tmp/k", "a")],
        };
        assert!(kr.validate().is_ok());
        assert!(kr.find(GOOD_ID).is_some());
    }

    #[test]
    fn load_missing_keyring_is_empty() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("keyring.json");
        let kr = load_keyring(&p).expect("missing => default");
        assert_eq!(kr, Keyring::default());
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("keyring.json");
        let kr = Keyring {
            schema: KEYRING_SCHEMA.into(),
            default: Some(GOOD_ID.into()),
            keys: vec![KeyringKey {
                id: GOOD_ID.into(),
                path: "/home/evan/.config/hedronite/geode/default.gkey".into(),
                label: "default".into(),
                hybrid: Some(false),
                has_passphrase: Some(true),
            }],
        };
        save_keyring(&p, &kr).expect("save");
        let back = load_keyring(&p).expect("load");
        assert_eq!(back, kr);
        // No secret material in the file.
        let text = std::fs::read_to_string(&p).expect("read text");
        assert!(!text.contains("ISK"));
        assert!(text.contains("\"schema\": \"geode.keyring.v1\""));
    }

    #[test]
    fn load_rejects_unknown_schema() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("keyring.json");
        std::fs::write(&p, b"{\"schema\":\"nope\",\"keys\":[]}").expect("write");
        assert!(load_keyring(&p).is_err());
    }

    // ---- file fallback round-trip (GHA has no Keychain) ----

    #[cfg(unix)]
    #[test]
    fn file_fallback_roundtrip_0600() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("default.gkey");
        let secret = b"the quick brown fox";
        let where_ = store_secret_with_fallback(GOOD_ID, &p, secret).expect("store");
        // On CI (no OS store) this lands on File; on a mac with Keychain it
        // may land on Os. Either way the file must exist and be 0600 when used.
        if where_ == Storage::File {
            use std::os::unix::fs::MetadataExt;
            let md = std::fs::metadata(&p).expect("meta");
            assert_eq!(md.mode() & 0o777, 0o600, "fallback file must be 0600");
        }
        let (got, src) = load_secret_with_fallback(GOOD_ID, &p).expect("load");
        assert_eq!(got, secret);
        // If it came from the file, the source must agree.
        if where_ == Storage::File {
            assert_eq!(src, Storage::File);
        }
    }

    #[cfg(unix)]
    #[test]
    fn file_fallback_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("default.gkey");
        std::fs::write(&p, b"secret").expect("write");
        let mut perm = std::fs::metadata(&p).expect("meta").permissions();
        perm.set_mode(0o644);
        std::fs::set_permissions(&p, perm).expect("chmod");
        // Direct load must refuse; fallback load (no OS entry) must also refuse.
        assert!(load_secret_file(&p).is_err());
        assert!(load_secret_with_fallback(GOOD_ID, &p).is_err());
    }

    #[test]
    fn store_secret_file_then_load_file_roundtrip() {
        let dir = tempfile::tempdir().expect("tmpdir");
        let p = dir.path().join("default.gkey");
        let secret = vec![0u8; 32];
        store_secret_file(&p, &secret).expect("store file");
        let got = load_secret_file(&p).expect("load file");
        assert_eq!(got, secret);
    }

    #[test]
    fn default_keyring_path_swaps_filename() {
        // default_key_path() => .../geode/default.gkey
        // default_keyring_path() => .../geode/keyring.json
        if let Some(kp) = crate::keyfile::default_key_path() {
            let kr = default_keyring_path().expect("keyring path");
            assert_eq!(kr.file_name().unwrap(), "keyring.json");
            assert_eq!(kr.parent(), kp.parent());
        }
    }
}
