//! Key derivation and domain separation (02-cryptography 2, 3).
//!
//! G1: real BLAKE3 KDF. Domain strings are the exact normative prefixes from
//! 13-implementation-sketch. EK is `blake3::derive_key`; the per-chunk nonce
//! is keyed-BLAKE3 XOF (see [`crate::aead`]); `key_id` is plain `blake3::hash`.

use crate::zero::Secret32;
use crate::Result;

/// Exact domain-string prefixes (02-cryptography 2, 13-implementation-sketch).
///
/// Implementations MUST hash these exact UTF-8 strings. Editing them breaks
/// cross-implementation compatibility and requires a suite bump.
pub mod domains {
    pub const IDENTITY: &str = "geode/v1/identity";
    pub const EPOCH_FEK: &str = "geode/v1/epoch-fek";
    pub const NAME_KEY: &str = "geode/v1/name-key";
    pub const META_KEY: &str = "geode/v1/meta-key";
    pub const CHUNK_NONCE: &str = "geode/v1/chunk-nonce";
    pub const WRAP: &str = "geode/v1/wrap";
    pub const MANIFEST: &str = "geode/v1/manifest";
    pub const TOKEN: &str = "geode/v1/token";
    pub const POLICY: &str = "geode/v1/policy";
    pub const HPKE: &str = "geode/v1/hpke";
    pub const HYBRID: &str = "geode/v1/hybrid";
    pub const KEYID: &str = "geode/v1/keyid";
    pub const OBJECT_HDR: &str = "geode/v1/object-hdr";
}

/// Vault identifier: 16 random public bytes (02-cryptography 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VaultId(pub [u8; 16]);

/// Epoch number (uint32, starts at 1) (02-cryptography 3).
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct Epoch(pub u32);

/// Object identifier: 16 random bytes, unique per EK (02-cryptography 4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ObjectId(pub [u8; 16]);

/// Public key identifier: `BLAKE3("geode/v1/keyid" || ISK)[0..16]`
/// (02-cryptography 6.3). Safe to log.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct KeyId(pub [u8; 16]);

/// Identity Secret Key (32 bytes) - the root of the hierarchy.
pub struct IdentitySecret(Secret32);

impl IdentitySecret {
    /// Wrap raw 32 bytes as the ISK. Caller is responsible for sourcing them
    /// (key file unwrap in G2, or `getrandom` for `keygen`). The bytes are
    /// copied into a zeroizing buffer.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret32::new_unchecked(bytes))
    }

    /// Borrow the raw ISK bytes. Crate-private: no leak across the API.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentitySecret(**redacted**)")
    }
}

/// Epoch Key (EK) - 32 bytes, one per (`vault_id`, `epoch`, `context_label`).
pub struct EpochKey(Secret32);

impl EpochKey {
    /// Wrap raw 32 bytes as the EK (recipient unwrap path). The bytes
    /// are copied into a zeroizing buffer.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Secret32::new_unchecked(bytes))
    }

    /// Borrow the raw EK bytes. Crate-private: consumed by AEAD / wrap / nonce.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochKey(**redacted**)")
    }
}

/// Derive `EK` from `ISK` + `vault_id` + `epoch` + `context_label` (02-cryptography 3).
///
/// `EK = BLAKE3-KDF(ctx="geode/v1/epoch-fek",`
/// `              key_material = ISK || vault_id || le32(epoch) || context_label)`
///
/// Two contexts with the same `ISK` + `vault_id` + `epoch` MUST yield different `EK`
/// because `context_label` is bound into the key material.
pub fn derive_epoch_key(
    isk: &IdentitySecret,
    vault_id: VaultId,
    epoch: Epoch,
    context_label: &str,
) -> Result<EpochKey> {
    let mut km = Vec::with_capacity(32 + 16 + 4 + context_label.len());
    km.extend_from_slice(isk.as_bytes());
    km.extend_from_slice(&vault_id.0);
    km.extend_from_slice(&epoch.0.to_le_bytes());
    km.extend_from_slice(context_label.as_bytes());
    let ek = blake3::derive_key(domains::EPOCH_FEK, &km);
    Ok(EpochKey(Secret32::new_unchecked(ek)))
}

/// Derive a child key of `EK` under `domain` over `extra` binding data
/// (02-cryptography 3: `NameKey` / `MetaKey` / `ManifestKey`).
fn derive_child(ek: &EpochKey, domain: &str, extra: &[u8]) -> [u8; 32] {
    let mut km = Vec::with_capacity(32 + extra.len());
    km.extend_from_slice(ek.as_bytes());
    km.extend_from_slice(extra);
    blake3::derive_key(domain, &km)
}

/// `NameKey = BLAKE3-KDF(EK, "geode/v1/name-key", vault_id || le32(epoch))`
#[must_use]
pub fn derive_name_key(ek: &EpochKey, vault_id: VaultId, epoch: Epoch) -> [u8; 32] {
    let mut extra = Vec::with_capacity(20);
    extra.extend_from_slice(&vault_id.0);
    extra.extend_from_slice(&epoch.0.to_le_bytes());
    derive_child(ek, domains::NAME_KEY, &extra)
}

/// `MetaKey = BLAKE3-KDF(EK, "geode/v1/meta-key", vault_id || le32(epoch))`
#[must_use]
pub fn derive_meta_key(ek: &EpochKey, vault_id: VaultId, epoch: Epoch) -> [u8; 32] {
    let mut extra = Vec::with_capacity(20);
    extra.extend_from_slice(&vault_id.0);
    extra.extend_from_slice(&epoch.0.to_le_bytes());
    derive_child(ek, domains::META_KEY, &extra)
}

/// `ManifestKey = BLAKE3-KDF(EK, "geode/v1/manifest", vault_id || le32(epoch))`
#[must_use]
pub fn derive_manifest_key(ek: &EpochKey, vault_id: VaultId, epoch: Epoch) -> [u8; 32] {
    let mut extra = Vec::with_capacity(20);
    extra.extend_from_slice(&vault_id.0);
    extra.extend_from_slice(&epoch.0.to_le_bytes());
    derive_child(ek, domains::MANIFEST, &extra)
}

/// Derive the public `key_id` from ISK (02-cryptography 6.3).
///
/// `key_id = BLAKE3("geode/v1/keyid" || ISK)[0..16]`. Safe to print and log.
pub fn derive_key_id(isk: &IdentitySecret) -> Result<KeyId> {
    let mut h = Vec::with_capacity(domains::KEYID.len() + 32);
    h.extend_from_slice(domains::KEYID.as_bytes());
    h.extend_from_slice(isk.as_bytes());
    let full = blake3::hash(&h);
    let mut id = [0u8; 16];
    id.copy_from_slice(&full.as_bytes()[..16]);
    Ok(KeyId(id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x42; 32])
    }

    #[test]
    fn two_contexts_yield_different_ek() {
        let v = VaultId([0x11; 16]);
        let e = Epoch(1);
        let ek_a = derive_epoch_key(&isk(), v, e, "alpha").unwrap();
        let ek_b = derive_epoch_key(&isk(), v, e, "beta").unwrap();
        assert_ne!(
            ek_a.as_bytes(),
            ek_b.as_bytes(),
            "context_label MUST bind EK"
        );
    }

    #[test]
    fn same_context_is_stable() {
        let v = VaultId([0x11; 16]);
        let e = Epoch(1);
        let ek_a = derive_epoch_key(&isk(), v, e, "alpha").unwrap();
        let ek_b = derive_epoch_key(&isk(), v, e, "alpha").unwrap();
        assert_eq!(ek_a.as_bytes(), ek_b.as_bytes());
    }

    #[test]
    fn different_epoch_yields_different_ek() {
        let v = VaultId([0x11; 16]);
        let ek1 = derive_epoch_key(&isk(), v, Epoch(1), "").unwrap();
        let ek2 = derive_epoch_key(&isk(), v, Epoch(2), "").unwrap();
        assert_ne!(ek1.as_bytes(), ek2.as_bytes());
    }

    #[test]
    fn key_id_is_stable_and_public_size() {
        let id = derive_key_id(&isk()).unwrap();
        let id2 = derive_key_id(&isk()).unwrap();
        assert_eq!(id.0, id2.0);
        assert_eq!(id.0.len(), 16);
    }
}
