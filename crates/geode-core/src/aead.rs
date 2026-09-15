//! AEAD seal/open (02-cryptography 4).
//!
//! Suite 0x01 = AEGIS-256-X2 (32-byte key, 32-byte nonce, 16-byte tag).
//! G0b: stubs fail closed. No AEGIS is called; no ciphertext is produced.

use crate::kdf::{Epoch, EpochKey, ObjectId, VaultId};
use crate::{Error, Result};

/// Associated data commitment for a chunk seal (02-cryptography 4.3).
///
/// `AD_i = suite || vault_id || le32(epoch) || object_id || le64(i)`
/// `      || le64(N) || le32(chunk_size) || path_bind`
#[derive(Clone, Debug)]
pub struct ChunkAd {
    pub suite: u8,
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub object_id: ObjectId,
    pub chunk_index: u64,
    pub plain_len: u64,
    pub chunk_size: u32,
    pub path_bind: Vec<u8>,
}

/// Seal `plaintext` under `EK` with `ad`. Returns ciphertext + 16-byte tag.
///
/// G0b stub. G1 will use AEGIS-256-X2 with a derived (not stored) nonce:
/// `nonce_i = BLAKE3-XOF-32(key=EK, data="geode/v1/chunk-nonce"`
/// `          || object_id || le64(i) || le32(epoch))`.
pub fn seal_chunk(_ek: &EpochKey, _ad: &ChunkAd, _plaintext: &[u8]) -> Result<Vec<u8>> {
    Err(Error::NotImplemented)
}

/// Open `ciphertext_with_tag` under `EK` with `ad`.
///
/// G0b stub. G1 returns plaintext or [`Error::AuthFail`] on tag mismatch.
/// A single flipped bit MUST yield `AuthFail` (G1c).
pub fn open_chunk(_ek: &EpochKey, _ad: &ChunkAd, _ciphertext_with_tag: &[u8]) -> Result<Vec<u8>> {
    Err(Error::NotImplemented)
}
