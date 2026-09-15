//! Recipients: wrap EK for one or more holders (02-cryptography 7; 03-format 6).
//!
//! G2: real symmetric recipient wrap. X25519 / hybrid stay stubbed (Phase 3/4).

use crate::kdf::{Epoch, EpochKey, IdentitySecret, KeyId, VaultId};
use crate::{Error, Result};
use aegis::aegis256x2::{Aegis256X2, Nonce};
use base64ct::{Base64, Encoding};

/// Recipient kind (03-format 6).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Recipient {
    Symmetric {
        key_id: KeyId,
        wrap: String,
    },
    X25519 {
        key_id: KeyId,
        public: String,
        wrap: String,
    },
    Hybrid {
        key_id: KeyId,
        x25519_public: String,
        mlkem_public: String,
        wrap: String,
    },
}

/// Recipients file (03-format 6).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Recipients {
    pub vault_id: String,
    pub epoch: u32,
    pub recipients: Vec<Recipient>,
}

fn random_nonce() -> Result<Nonce> {
    let mut n = [0u8; 32];
    getrandom::fill(&mut n).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(n)
}

/// Derive the symmetric recipient wrap key from ISK (02-cryptography 7.1;
/// 03-format 6: "a key derived from ISK"). Uses the identity domain.
fn sym_wrap_key(isk: &IdentitySecret, vault_id: VaultId, epoch: Epoch) -> [u8; 32] {
    let mut km = Vec::with_capacity(32 + 16 + 4);
    km.extend_from_slice(isk.as_bytes());
    km.extend_from_slice(&vault_id.0);
    km.extend_from_slice(&epoch.0.to_le_bytes());
    blake3::derive_key("geode/v1/identity", &km)
}

/// Wrap EK for the identity itself (symmetric recipient) (02-cryptography 7.1).
///
/// Produces a `sym:key_id` recipient with a base64 AEGIS blob of EK under a
/// key derived from ISK. Random nonce per wrap.
pub fn wrap_symmetric(
    ek: &EpochKey,
    isk: &IdentitySecret,
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
) -> Result<Recipient> {
    let wk = sym_wrap_key(isk, vault_id, epoch);
    let nonce = random_nonce()?;
    let ad = sym_ad(vault_id, epoch, key_id);
    let ctx = Aegis256X2::<16>::new(&wk, &nonce);
    let (ct, tag) = ctx.encrypt(ek.as_bytes(), &ad);
    let mut blob = Vec::with_capacity(32 + ct.len() + 16);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&tag);
    blob.extend_from_slice(&ct);
    Ok(Recipient::Symmetric {
        key_id,
        wrap: Base64::encode_string(&blob),
    })
}

/// Unwrap EK from a symmetric recipient blob using ISK (02-cryptography 7.1).
pub fn unwrap_symmetric(
    recipient: &Recipient,
    isk: &IdentitySecret,
    vault_id: VaultId,
    epoch: Epoch,
) -> Result<EpochKey> {
    let (key_id, blob) = match recipient {
        Recipient::Symmetric { key_id, wrap } => (
            *key_id,
            Base64::decode_vec(wrap).map_err(|e| Error::Format(format!("base64: {e}")))?,
        ),
        _ => return Err(Error::Format("not a symmetric recipient".into())),
    };
    if blob.len() < 32 + 16 {
        return Err(Error::AuthFail);
    }
    let nonce = blob[..32].try_into().unwrap_or([0u8; 32]);
    let tag: [u8; 16] = blob[32..48].try_into().unwrap_or([0u8; 16]);
    let ct = &blob[48..];
    let wk = sym_wrap_key(isk, vault_id, epoch);
    let ad = sym_ad(vault_id, epoch, key_id);
    let ctx = Aegis256X2::<16>::new(&wk, &nonce);
    let pt = ctx.decrypt(ct, &tag, &ad).map_err(|_| Error::AuthFail)?;
    if pt.len() != 32 {
        return Err(Error::AuthFail);
    }
    let mut ek_bytes = [0u8; 32];
    ek_bytes.copy_from_slice(&pt);
    Ok(EpochKey::from_bytes(ek_bytes))
}

fn sym_ad(vault_id: VaultId, epoch: Epoch, key_id: KeyId) -> Vec<u8> {
    let mut ad = Vec::with_capacity(16 + 4 + 16);
    ad.extend_from_slice(&vault_id.0);
    ad.extend_from_slice(&epoch.0.to_le_bytes());
    ad.extend_from_slice(&key_id.0);
    ad
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x5e; 32])
    }
    fn ek() -> EpochKey {
        crate::kdf::derive_epoch_key(&isk(), VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }
    fn kid() -> KeyId {
        crate::kdf::derive_key_id(&isk()).unwrap()
    }

    #[test]
    fn sym_wrap_unwrap_roundtrip() {
        let ek = ek();
        let r = wrap_symmetric(&ek, &isk(), VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let unwrapped = unwrap_symmetric(&r, &isk(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        assert_eq!(unwrapped.as_bytes(), ek.as_bytes());
    }

    #[test]
    fn sym_unwrap_wrong_epoch_is_auth_fail() {
        let ek = ek();
        let r = wrap_symmetric(&ek, &isk(), VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let bad = unwrap_symmetric(&r, &isk(), VaultId([0x01; 16]), Epoch(2));
        assert!(matches!(bad, Err(Error::AuthFail)));
    }

    #[test]
    fn sym_wrap_is_sym_type() {
        let ek = ek();
        let r = wrap_symmetric(&ek, &isk(), VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        assert!(matches!(r, Recipient::Symmetric { .. }));
    }
}
