//! AEAD seal/open (02-cryptography 4).
//!
//! Suite 0x01 = AEGIS-256-X2 (32-byte key, 32-byte nonce, 16-byte tag). G1:
//! real seal/open with a derived (not stored) per-chunk nonce.

use crate::kdf::{domains, Epoch, EpochKey, ObjectId, VaultId};
use crate::{Error, Result};
use aegis::aegis256x2::{Aegis256X2, Key, Nonce};

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

impl ChunkAd {
    /// Serialize the AD to the exact byte layout bound into the AEAD
    /// (02-cryptography 4.3).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ad = Vec::with_capacity(1 + 16 + 4 + 16 + 8 + 8 + 4 + self.path_bind.len());
        ad.push(self.suite);
        ad.extend_from_slice(&self.vault_id.0);
        ad.extend_from_slice(&self.epoch.0.to_le_bytes());
        ad.extend_from_slice(&self.object_id.0);
        ad.extend_from_slice(&self.chunk_index.to_le_bytes());
        ad.extend_from_slice(&self.plain_len.to_le_bytes());
        ad.extend_from_slice(&self.chunk_size.to_le_bytes());
        ad.extend_from_slice(&self.path_bind);
        ad
    }
}

/// Derive the per-chunk nonce (02-cryptography 4.2).
///
/// `nonce_i = BLAKE3-XOF-32(key=EK, data="geode/v1/chunk-nonce"`
/// `          || object_id || le64(i) || le32(epoch))`
///
/// No nonce is stored; reuse is forbidden by construction provided
/// `object_id` is unique per EK.
fn derive_nonce(ek: &EpochKey, object_id: &ObjectId, i: u64, epoch: Epoch) -> Nonce {
    let mut h = blake3::Hasher::new_keyed(ek.as_bytes());
    h.update(domains::CHUNK_NONCE.as_bytes());
    h.update(&object_id.0);
    h.update(&i.to_le_bytes());
    h.update(&epoch.0.to_le_bytes());
    let out = h.finalize();
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(out.as_bytes());
    nonce
}

fn ek_to_key(ek: &EpochKey) -> Key {
    *ek.as_bytes()
}

/// Seal `plaintext` under `EK` with `ad`.
///
/// Returns `tag(16) || ciphertext` (matches the on-disk chunk layout in
/// 02-cryptography 4.4: `Chunk[i] = tag[16] || ciphertext`).
pub fn seal_chunk(ek: &EpochKey, ad: &ChunkAd, plaintext: &[u8]) -> Result<Vec<u8>> {
    crate::assert_suite(ad.suite)?;
    let nonce = derive_nonce(ek, &ad.object_id, ad.chunk_index, ad.epoch);
    let key = ek_to_key(ek);
    let ctx = Aegis256X2::<16>::new(&key, &nonce);
    let (ct, tag) = ctx.encrypt(plaintext, &ad.to_bytes());
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Open `tag_and_ciphertext` (`tag(16) || ciphertext`) under `EK` with `ad`.
///
/// Returns the plaintext, or [`Error::AuthFail`] on tag mismatch / tamper.
/// A single flipped ciphertext or tag bit MUST yield `AuthFail`.
pub fn open_chunk(ek: &EpochKey, ad: &ChunkAd, tag_and_ciphertext: &[u8]) -> Result<Vec<u8>> {
    crate::assert_suite(ad.suite)?;
    if tag_and_ciphertext.len() < 16 {
        return Err(Error::AuthFail);
    }
    let (tag_bytes, ct) = tag_and_ciphertext.split_at(16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(tag_bytes);
    let nonce = derive_nonce(ek, &ad.object_id, ad.chunk_index, ad.epoch);
    let key = ek_to_key(ek);
    let ctx = Aegis256X2::<16>::new(&key, &nonce);
    ctx.decrypt(ct, &tag, &ad.to_bytes())
        .map_err(|_| Error::AuthFail)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ek() -> EpochKey {
        let isk = crate::kdf::IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn ad(idx: u64, plain_len: u64) -> ChunkAd {
        ChunkAd {
            suite: crate::SUITE_0X01,
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            object_id: ObjectId([0xab; 16]),
            chunk_index: idx,
            plain_len,
            chunk_size: 1 << 20,
            path_bind: Vec::new(),
        }
    }

    #[test]
    fn seal_open_roundtrip() {
        let ek = ek();
        let ad = ad(0, 5);
        let pt = b"hello";
        let sealed = seal_chunk(&ek, &ad, pt).unwrap();
        assert_eq!(sealed.len(), 16 + pt.len());
        let opened = open_chunk(&ek, &ad, &sealed).unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn flipped_ciphertext_bit_is_auth_fail() {
        let ek = ek();
        let ad = ad(0, 5);
        let pt = b"hello";
        let mut sealed = seal_chunk(&ek, &ad, pt).unwrap();
        // Flip one bit in the ciphertext (after the 16-byte tag).
        sealed[16] ^= 0x01;
        let r = open_chunk(&ek, &ad, &sealed);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "flipped bit MUST be auth_fail, got {r:?}"
        );
    }

    #[test]
    fn flipped_tag_bit_is_auth_fail() {
        let ek = ek();
        let ad = ad(0, 5);
        let pt = b"hello";
        let mut sealed = seal_chunk(&ek, &ad, pt).unwrap();
        sealed[0] ^= 0x01; // flip a tag bit
        let r = open_chunk(&ek, &ad, &sealed);
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn wrong_ad_is_auth_fail() {
        let ek = ek();
        let ad = ad(0, 5);
        let sealed = seal_chunk(&ek, &ad, b"hello").unwrap();
        let mut ad2 = ad.clone();
        ad2.chunk_index = 1; // different AD
        let r = open_chunk(&ek, &ad2, &sealed);
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn empty_plaintext_roundtrips() {
        let ek = ek();
        let ad = ad(0, 0);
        let sealed = seal_chunk(&ek, &ad, b"").unwrap();
        assert_eq!(sealed.len(), 16);
        let opened = open_chunk(&ek, &ad, &sealed).unwrap();
        assert!(opened.is_empty());
    }
}
