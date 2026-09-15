//! Key derivation and domain separation (02-cryptography 2, 3).
//!
//! G0b: defines the exact domain strings (normative, see 13-implementation-
//! sketch "Domain-string test table") and the key hierarchy *types*. All
//! derivation returns [`Error::NotImplemented`]; no BLAKE3 is called yet.

use crate::zero::Secret32;
use crate::{Error, Result};

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
#[allow(dead_code)] // G0b: inner bytes consumed by G1 KDF / wrap.
pub struct IdentitySecret(pub(crate) Secret32);

impl IdentitySecret {
    /// G0b stub. Real construction (from `GKEY` file, raw or passphrase-wrapped)
    /// lands in G1 / G2.
    pub fn from_bytes(_: [u8; 32]) -> Result<Self> {
        Err(Error::NotImplemented)
    }
}

impl std::fmt::Debug for IdentitySecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IdentitySecret(**redacted**)")
    }
}

/// Epoch Key (`EK`) - 32 bytes, one per (`vault_id`, `epoch`, `context_label`).
#[allow(dead_code)] // G0b: inner bytes consumed by G1 seal/open/wrap.
pub struct EpochKey(pub(crate) Secret32);

impl std::fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EpochKey(**redacted**)")
    }
}

/// Derive `EK` from `ISK` + `vault_id` + `epoch` + `context_label` (02-cryptography 3).
///
/// G0b stub. G1 will implement:
/// `EK = BLAKE3-KDF(key=ISK, ctx="geode/v1/epoch-fek",`
/// `              data = vault_id || le32(epoch) || utf8(context_label))`
///
/// Two contexts with the same `ISK` + `vault_id` + `epoch` MUST yield different `EK`.
pub fn derive_epoch_key(
    _isk: &IdentitySecret,
    _vault_id: VaultId,
    _epoch: Epoch,
    _context_label: &str,
) -> Result<EpochKey> {
    Err(Error::NotImplemented)
}

/// Derive the public `key_id` from ISK (02-cryptography 6.3).
///
/// G0b stub. G1 will implement
/// `key_id = BLAKE3("geode/v1/keyid" || ISK)[0..16]`.
pub fn derive_key_id(_isk: &IdentitySecret) -> Result<KeyId> {
    Err(Error::NotImplemented)
}
