//! Manifest authentication and merklization (02-cryptography 8; 03-format 5).
//!
//! G0b: defines the entry + manifest types. MAC / merkle / parse stubs fail
//! closed. No BLAKE3 is called yet.

use crate::kdf::{Epoch, ObjectId, VaultId};
use crate::{Error, Result};

/// Manifest entry (03-format 5).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub path: String,
    pub path_sealed: bool,
    pub object_id: ObjectId,
    pub kind: EntryKind,
    pub plain_len: u64,
    pub chunk_count: u32,
    pub mode: u32,
    pub mtime_ms: i64,
    pub content_root: [u8; 32],
    pub bind: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Symlink,
}

/// Vault manifest header (03-format 5).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub suite: u8,
    pub flags: u16,
    pub generated_at: i64,
    pub generator: String,
    pub root: [u8; 32],
    pub entry_count: u32,
    pub total_plain_bytes: u64,
    pub total_cipher_bytes: u64,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// Canonicalize JSON for MAC (RFC 8785 JCS) (02-cryptography 8; 03-format 6).
///
/// G0b stub. G2 will implement JCS serialization + BLAKE3 merkle root +
/// AEGIS-256-X2 MAC under `ManifestKey` (`geode/v1/manifest`).
pub fn canonicalize(_value: &serde_json::Value) -> Result<Vec<u8>> {
    Err(Error::NotImplemented)
}

/// Compute the manifest MAC over canonical body (02-cryptography 8).
///
/// G0b stub. G2 returns the 16-byte MAC. Readers MUST verify it.
pub fn manifest_mac(_manifest_key: &[u8; 32], _body: &[u8]) -> Result<[u8; 16]> {
    Err(Error::NotImplemented)
}
