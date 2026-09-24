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

// ---- G0 (v0.2.6): X25519 recipient wrap/unwrap (02-cryptography 7.2) ----

use x25519_dalek::{PublicKey, StaticSecret};

/// HKDF-SHA256 info string bound into the wrap-key derivation (02 7.2).
const HPKE_INFO: &[u8] = b"geode/v1/hpke";
/// Domain string bound into the AEGIS wrap AD (02 7.2).
const HPKE_AD_DOMAIN: &[u8] = b"geode/v1/hpke";

/// Derive the X25519 wrap key via HKDF-SHA256 (02-cryptography 7.2).
///
/// `wrap_key = HKDF-SHA256(shared, salt=ephemeral_pk||recipient_pk, info="geode/v1/hpke")`
///
/// No XOR of shared secrets; HKDF is the combiner. Output is 32 bytes
/// (matches AEGIS-256-X2 key length).
fn x25519_wrap_key(
    shared: &[u8; 32],
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(ephemeral_pk);
    salt.extend_from_slice(recipient_pk);
    let h = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    h.expand(HPKE_INFO, &mut okm)
        .map_err(|e| Error::Crypto(format!("hkdf expand: {e}")))?;
    Ok(okm)
}

/// AEGIS wrap AD for an X25519 recipient (02 7.2). Binds `vault_id`, epoch,
/// `key_id`, and both public keys so a blob cannot be replayed across
/// recipients or vaults.
fn x25519_ad(
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
    ephemeral_pk: &[u8; 32],
    recipient_pk: &[u8; 32],
) -> Vec<u8> {
    let mut ad = Vec::with_capacity(HPKE_AD_DOMAIN.len() + 16 + 4 + 16 + 32 + 32);
    ad.extend_from_slice(HPKE_AD_DOMAIN);
    ad.extend_from_slice(&vault_id.0);
    ad.extend_from_slice(&epoch.0.to_le_bytes());
    ad.extend_from_slice(&key_id.0);
    ad.extend_from_slice(ephemeral_pk);
    ad.extend_from_slice(recipient_pk);
    ad
}

/// Wrap EK for an X25519 recipient (02-cryptography 7.2).
///
/// HPKE-style: fresh ephemeral X25519 keypair, `shared = X25519(eph_sk, recipient_pk)`,
/// `wrap_key = HKDF-SHA256(shared, salt=eph_pk||recipient_pk, info="geode/v1/hpke")`,
/// `blob = ephemeral_pk || AEGIS_wrap(EK, wrap_key)`. The `public` field
/// carries the recipient's static public key (base64); the `wrap` field
/// carries `base64(ephemeral_pk || nonce || tag || ct)`. Random ephemeral
/// key + random nonce per wrap.
pub fn wrap_x25519(
    ek: &EpochKey,
    recipient_pk_bytes: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
) -> Result<Recipient> {
    let mut eph_sk_bytes = [0u8; 32];
    getrandom::fill(&mut eph_sk_bytes).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    let nonce = random_nonce()?;
    wrap_x25519_with(
        ek,
        &eph_sk_bytes,
        recipient_pk_bytes,
        vault_id,
        epoch,
        key_id,
        nonce,
    )
}

/// Deterministic X25519 wrap with caller-supplied ephemeral secret + nonce.
///
/// For golden-vector generation and recovery tooling. Production callers
/// SHOULD use [`wrap_x25519`], which draws both from the OS CSPRNG.
#[allow(clippy::similar_names)]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // wire/format shape
pub fn wrap_x25519_with(
    ek: &EpochKey,
    ephemeral_sk_bytes: &[u8; 32],
    recipient_pk_bytes: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
    nonce: [u8; 32],
) -> Result<Recipient> {
    let eph_sk = StaticSecret::from(*ephemeral_sk_bytes);
    let recipient_pk = PublicKey::from(*recipient_pk_bytes);
    let eph_pk = PublicKey::from(&eph_sk);
    let shared = eph_sk.diffie_hellman(&recipient_pk);
    let shared_bytes = shared.to_bytes();
    let eph_pk_bytes = eph_pk.to_bytes();
    let wk = x25519_wrap_key(&shared_bytes, &eph_pk_bytes, recipient_pk_bytes)?;
    let ad = x25519_ad(vault_id, epoch, key_id, &eph_pk_bytes, recipient_pk_bytes);
    let ctx = Aegis256X2::<16>::new(&wk, &nonce);
    let (ct, tag) = ctx.encrypt(ek.as_bytes(), &ad);
    let mut blob = Vec::with_capacity(32 + 32 + 16 + ct.len());
    blob.extend_from_slice(&eph_pk_bytes);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&tag);
    blob.extend_from_slice(&ct);
    Ok(Recipient::X25519 {
        key_id,
        public: Base64::encode_string(recipient_pk_bytes),
        wrap: Base64::encode_string(&blob),
    })
}

/// Unwrap EK from an X25519 recipient blob using the recipient's static
/// secret key (02-cryptography 7.2).
///
/// Parses `ephemeral_pk` from the blob, computes
/// `shared = X25519(recipient_sk, ephemeral_pk)`, derives `wrap_key` via
/// HKDF-SHA256, and AEGIS-decrypts the EK. Wrong `recipient_sk` / tampered
/// blob / wrong vault => [`Error::AuthFail`]. No ISK in errors.
#[allow(clippy::similar_names)]
pub fn unwrap_x25519(
    recipient: &Recipient,
    recipient_sk_bytes: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
) -> Result<EpochKey> {
    let (key_id, recipient_pk_str, blob) = match recipient {
        Recipient::X25519 {
            key_id,
            public,
            wrap,
        } => (
            *key_id,
            public.clone(),
            Base64::decode_vec(wrap).map_err(|e| Error::Format(format!("base64: {e}")))?,
        ),
        _ => return Err(Error::Format("not an x25519 recipient".into())),
    };
    let recipient_pk_bytes: [u8; 32] = Base64::decode_vec(&recipient_pk_str)
        .map_err(|e| Error::Format(format!("base64: {e}")))?
        .try_into()
        .map_err(|_| Error::Format("x25519 public key not 32 bytes".into()))?;
    if blob.len() < 32 + 32 + 16 + 32 {
        return Err(Error::AuthFail);
    }
    let eph_pk_bytes: [u8; 32] = blob[..32].try_into().map_err(|_| Error::AuthFail)?;
    let nonce: [u8; 32] = blob[32..64].try_into().map_err(|_| Error::AuthFail)?;
    let tag: [u8; 16] = blob[64..80].try_into().map_err(|_| Error::AuthFail)?;
    let ct = &blob[80..];
    let recipient_sk = StaticSecret::from(*recipient_sk_bytes);
    let eph_pk = PublicKey::from(eph_pk_bytes);
    let shared = recipient_sk.diffie_hellman(&eph_pk);
    let shared_bytes = shared.to_bytes();
    let wk = x25519_wrap_key(&shared_bytes, &eph_pk_bytes, &recipient_pk_bytes)?;
    let ad = x25519_ad(vault_id, epoch, key_id, &eph_pk_bytes, &recipient_pk_bytes);
    let ctx = Aegis256X2::<16>::new(&wk, &nonce);
    let pt = ctx.decrypt(ct, &tag, &ad).map_err(|_| Error::AuthFail)?;
    if pt.len() != 32 {
        return Err(Error::AuthFail);
    }
    let mut ek_bytes = [0u8; 32];
    ek_bytes.copy_from_slice(&pt);
    Ok(EpochKey::from_bytes(ek_bytes))
}

/// Wrap EK for a hybrid (X25519 + ML-KEM) recipient (02-cryptography 7.3).
///
/// **Not implemented this pack.** PQ hybrid is a Phase 4 deliverable gated
/// behind the `pq` feature flag (02 11.8). Returns [`Error::NotImplemented`]
/// so a build without `pq` refuses rather than silently dropping the recipient.
/// No XOR of shared secrets: the spec combiner is a one-step BLAKE3 hash.
pub fn wrap_hybrid(
    _ek: &EpochKey,
    _x25519_public: &[u8; 32],
    _mlkem_public: &[u8],
    _vault_id: VaultId,
    _epoch: Epoch,
    _key_id: KeyId,
) -> Result<Recipient> {
    Err(Error::NotImplemented)
}

/// Unwrap EK from a hybrid recipient blob (02-cryptography 7.3).
///
/// **Not implemented this pack.** Returns [`Error::NotImplemented`].
pub fn unwrap_hybrid(
    _recipient: &Recipient,
    _x25519_secret: &[u8; 32],
    _mlkem_secret: &[u8],
    _vault_id: VaultId,
    _epoch: Epoch,
) -> Result<EpochKey> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
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

#[cfg(test)]
mod x25519_tests {
    use super::*;
    use crate::kdf::{derive_epoch_key, Epoch, IdentitySecret, KeyId, VaultId};
    use serde_json::Value;
    use std::path::Path;

    // hex helper for the vector test
    fn hex_decode(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x5e; 32])
    }
    fn ek() -> EpochKey {
        crate::kdf::derive_epoch_key(&isk(), VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }
    fn kid() -> KeyId {
        crate::kdf::derive_key_id(&isk()).unwrap()
    }

    /// Deterministic recipient keypair for reproducible tests.
    fn recipient_keypair() -> ([u8; 32], [u8; 32]) {
        let sk = StaticSecret::from([0xa1; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        ([0xa1; 32], pk)
    }

    #[test]
    fn x25519_wrap_unwrap_roundtrip() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        assert!(matches!(r, Recipient::X25519 { .. }));
        let unwrapped = unwrap_x25519(&r, &rsk, VaultId([0x01; 16]), Epoch(1)).unwrap();
        assert_eq!(unwrapped.as_bytes(), ek.as_bytes());
    }

    #[test]
    fn x25519_wrap_is_x25519_type() {
        let ek = ek();
        let (_rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        match r {
            Recipient::X25519 { public, .. } => {
                assert_eq!(public.len(), 44); // base64 of 32 bytes ~ 44 chars
            }
            _ => panic!("expected X25519"),
        }
    }

    #[test]
    fn x25519_unwrap_wrong_sk_is_auth_fail() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let wrong_sk = [0xb2; 32];
        let bad = unwrap_x25519(&r, &wrong_sk, VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
        // right sk still works
        let ok = unwrap_x25519(&r, &rsk, VaultId([0x01; 16]), Epoch(1)).unwrap();
        assert_eq!(ok.as_bytes(), ek.as_bytes());
    }

    #[test]
    fn x25519_unwrap_wrong_vault_is_auth_fail() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let bad = unwrap_x25519(&r, &rsk, VaultId([0x02; 16]), Epoch(1));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
    }

    #[test]
    fn x25519_unwrap_wrong_epoch_is_auth_fail() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let bad = unwrap_x25519(&r, &rsk, VaultId([0x01; 16]), Epoch(2));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
    }

    #[test]
    fn x25519_unwrap_flipped_bit_is_auth_fail() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        // Tamper the wrap blob.
        let blob = match &r {
            Recipient::X25519 { wrap, .. } => {
                let mut b = Base64::decode_vec(wrap).unwrap();
                let last = b.len() - 1;
                b[last] ^= 0x01;
                Base64::encode_string(&b)
            }
            _ => unreachable!(),
        };
        let r2 = Recipient::X25519 {
            key_id: kid(),
            public: Base64::encode_string(&rpk),
            wrap: blob,
        };
        let bad = unwrap_x25519(&r2, &rsk, VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
    }

    #[test]
    fn sym_and_x25519_both_unwrap_same_ek() {
        let ek = ek();
        let (rsk, rpk) = recipient_keypair();
        let sym = wrap_symmetric(&ek, &isk(), VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let x25 = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let from_sym = unwrap_symmetric(&sym, &isk(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        let from_x25 = unwrap_x25519(&x25, &rsk, VaultId([0x01; 16]), Epoch(1)).unwrap();
        assert_eq!(from_sym.as_bytes(), from_x25.as_bytes());
        assert_eq!(from_sym.as_bytes(), ek.as_bytes());
    }

    #[test]
    fn x25519_wrap_with_is_deterministic() {
        let ek = ek();
        let eph_sk = [0xee; 32];
        let (_rsk, rpk) = recipient_keypair();
        let nonce = [0x11; 32];
        let a = wrap_x25519_with(
            &ek,
            &eph_sk,
            &rpk,
            VaultId([0x01; 16]),
            Epoch(1),
            kid(),
            nonce,
        )
        .unwrap();
        let b = wrap_x25519_with(
            &ek,
            &eph_sk,
            &rpk,
            VaultId([0x01; 16]),
            Epoch(1),
            kid(),
            nonce,
        )
        .unwrap();
        let (ka, wa, pa) = match (&a, &b) {
            (
                Recipient::X25519 {
                    key_id: ka,
                    wrap: wa,
                    public: pa,
                },
                Recipient::X25519 {
                    key_id: kb,
                    wrap: wb,
                    public: pb,
                },
            ) => {
                assert_eq!(ka, kb);
                assert_eq!(wa, wb);
                assert_eq!(pa, pb);
                (ka, wa, pa)
            }
            _ => panic!("expected X25519"),
        };
        let _ = (ka, wa, pa);
    }

    #[test]
    fn x25519_errors_never_contain_isk() {
        let ek = ek();
        let (_rsk, rpk) = recipient_keypair();
        let r = wrap_x25519(&ek, &rpk, VaultId([0x01; 16]), Epoch(1), kid()).unwrap();
        let wrong_sk = [0xb2; 32];
        let bad = unwrap_x25519(&r, &wrong_sk, VaultId([0x01; 16]), Epoch(1));
        let s = format!("{}", bad.unwrap_err());
        assert!(!s.contains("ISK"), "leaks ISK: {s}");
        assert!(!s.contains('\u{5e}'), "leaks key bytes: {s}");
    }

    /// Load the golden vector `vectors/v1/x25519.json` and replay the
    /// deterministic wrap, asserting the on-disk blob matches. The
    /// vector is generated by the shipped `wrap_x25519_with` so the test
    /// drives the shipped function, not a copy.
    #[test]
    #[allow(clippy::similar_names)]
    fn x25519_vector_matches_shipped_wrap() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("vectors")
            .join("v1")
            .join("x25519.json");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|_| panic!("vector file missing: {}", path.display()));
        let v: Value = serde_json::from_str(&text).expect("vector json");

        let isk_bytes = hex_decode(v["isk"].as_str().unwrap());
        assert_eq!(isk_bytes.len(), 32);
        let mut isk_arr = [0u8; 32];
        isk_arr.copy_from_slice(&isk_bytes);
        let isk = IdentitySecret::from_bytes(isk_arr);

        let vault_id_bytes = hex_decode(v["vault_id"].as_str().unwrap());
        assert_eq!(vault_id_bytes.len(), 16);
        let mut vid = [0u8; 16];
        vid.copy_from_slice(&vault_id_bytes);

        let epoch = Epoch(u32::try_from(v["epoch"].as_u64().unwrap()).unwrap());
        let key_id_bytes = hex_decode(v["key_id"].as_str().unwrap());
        assert_eq!(key_id_bytes.len(), 16);
        let mut kid_arr = [0u8; 16];
        kid_arr.copy_from_slice(&key_id_bytes);
        let key_id = KeyId(kid_arr);

        let context_label = v["context_label"].as_str().unwrap();
        let ek = derive_epoch_key(&isk, VaultId(vid), epoch, context_label).unwrap();

        let eph_sk_bytes = hex_decode(v["ephemeral_sk"].as_str().unwrap());
        assert_eq!(eph_sk_bytes.len(), 32);
        let mut eph_sk_arr = [0u8; 32];
        eph_sk_arr.copy_from_slice(&eph_sk_bytes);

        let recipient_pk_bytes = hex_decode(v["recipient_pk"].as_str().unwrap());
        assert_eq!(recipient_pk_bytes.len(), 32);
        let mut rpk_arr = [0u8; 32];
        rpk_arr.copy_from_slice(&recipient_pk_bytes);

        let nonce_bytes = hex_decode(v["wrap_nonce"].as_str().unwrap());
        assert_eq!(nonce_bytes.len(), 32);
        let mut nonce_arr = [0u8; 32];
        nonce_arr.copy_from_slice(&nonce_bytes);

        let r = wrap_x25519_with(
            &ek,
            &eph_sk_arr,
            &rpk_arr,
            VaultId(vid),
            epoch,
            key_id,
            nonce_arr,
        )
        .unwrap();

        // The shipped wrap blob must match the vector's recorded blob.
        let want_wrap = v["wrap"].as_str().unwrap();
        let got_wrap = match &r {
            Recipient::X25519 { wrap, .. } => wrap.as_str(),
            _ => unreachable!(),
        };
        assert_eq!(got_wrap, want_wrap, "shipped wrap diverged from vector");

        // And the public field must match the recipient pk in the vector.
        let want_public = v["recipient_public"].as_str().unwrap();
        let got_public = match &r {
            Recipient::X25519 { public, .. } => public.as_str(),
            _ => unreachable!(),
        };
        assert_eq!(got_public, want_public);

        // Unwrap with the recipient sk from the vector recovers the EK.
        let recipient_sk_bytes = hex_decode(v["recipient_sk"].as_str().unwrap());
        assert_eq!(recipient_sk_bytes.len(), 32);
        let mut rsk_arr = [0u8; 32];
        rsk_arr.copy_from_slice(&recipient_sk_bytes);
        let unwrapped = unwrap_x25519(&r, &rsk_arr, VaultId(vid), epoch).unwrap();
        assert_eq!(unwrapped.as_bytes(), ek.as_bytes());
    }

    #[test]
    fn hybrid_wrap_and_unwrap_are_not_implemented() {
        let ek = ek();
        let (_rsk, rpk) = recipient_keypair();
        let w = wrap_hybrid(
            &ek,
            &rpk,
            &[0u8; 1568],
            VaultId([0x01; 16]),
            Epoch(1),
            kid(),
        );
        assert!(matches!(w, Err(Error::NotImplemented)), "got {w:?}");
        // A synthetic hybrid recipient (never produced this pack) still refuses.
        let r = Recipient::Hybrid {
            key_id: kid(),
            x25519_public: Base64::encode_string(&rpk),
            mlkem_public: Base64::encode_string(&[0u8; 1568]),
            wrap: Base64::encode_string(&[0u8; 80]),
        };
        let u = unwrap_hybrid(&r, &[0u8; 32], &[0u8; 32], VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(u, Err(Error::NotImplemented)), "got {u:?}");
    }
}
