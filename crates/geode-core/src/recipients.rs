//! Recipients: wrap EK for one or more holders (02-cryptography 7; 03-format 6).
//!
//! G0b: defines the recipient enum. Wrap/unwrap stubs fail closed. No X25519,
//! no ML-KEM, no symmetric wrap is performed yet. PQ hybrid is Phase 4 and
//! is not in the v0.1 dependency set.

use crate::kdf::{EpochKey, KeyId};
use crate::{Error, Result};

/// Recipient kind (03-format 6).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum Recipient {
    Symmetric {
        key_id: KeyId,
        /// Base64 AEGIS blob of EK under a key derived from ISK.
        wrap: String,
    },
    X25519 {
        key_id: KeyId,
        /// Base64 32-byte public key.
        public: String,
        /// Base64 `eph_pk || blob`.
        wrap: String,
    },
    /// Hybrid X25519 + ML-KEM-768 (Phase 4 / `pq` feature). v0.1 build does
    /// not produce or accept these; a vault with a hybrid recipient sets the
    /// `HYBRID_RECIPIENTS` flag and a build without `pq` MUST refuse.
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

/// Wrap EK for the identity itself (symmetric recipient) (02-cryptography 7.1).
///
/// G0b stub. G1 will produce `sym:key_id` wrap under a key derived from ISK.
pub fn wrap_symmetric(_ek: &EpochKey, _isk_key_id: KeyId) -> Result<Recipient> {
    Err(Error::NotImplemented)
}

/// Unwrap EK from a recipient blob using the identity's secret material.
///
/// G0b stub. G1 returns the EK or [`Error::AuthFail`].
pub fn unwrap(_recipient: &Recipient) -> Result<EpochKey> {
    Err(Error::NotImplemented)
}
