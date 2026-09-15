//! Key wrap: passphrase + recipients (02-cryptography 6, 7).
//!
//! G0b: stubs fail closed. **No XOR.** No hardcoded salt. No fake AEAD.
//! Real Argon2id + AEGIS-256-X2 wrap lands in G1.

use crate::kdf::IdentitySecret;
use crate::zero::Secret32;
use crate::{Error, Result};

/// Argon2id parameters stored in the `GKEY` file (02-cryptography 6.2).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct Argon2Params {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Argon2Params {
    /// Desktop default: 64 MiB, t=3, p=4 (02-cryptography 6.2).
    pub const DEFAULT_DESKTOP: Self = Self {
        m_kib: 65536,
        t: 3,
        p: 4,
    };
    /// Constrained-host default (`--cheap`): 16 MiB (02-cryptography 6.2).
    pub const DEFAULT_CHEAP: Self = Self {
        m_kib: 16384,
        t: 3,
        p: 4,
    };
}

/// 16-byte random salt for passphrase wrap (02-cryptography 6.2).
/// Random per key file. NEVER the literal `"turbocrypt"` or any fixed string.
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct WrapSalt(pub [u8; 16]);

/// Passphrase-wrapped `GKEY` body (02-cryptography 6.2).
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WrappedKey {
    pub salt: WrapSalt,
    pub argon2_m_kib: u32,
    pub argon2_t: u32,
    pub argon2_p: u32,
    pub wrap_nonce: [u8; 32],
    pub wrap_tag: [u8; 16],
    pub wrapped_isk: [u8; 32],
}

/// Wrap ISK with a passphrase + fresh random 16-byte salt (02-cryptography 6.2).
///
/// G0b stub. G1 will:
/// `WK = Argon2id(passphrase, salt, m, t, p, out=32)`
/// `wrapped = AEGIS-256-X2.encrypt(ISK, key=WK, nonce=wrap_nonce,`
/// `            AD="geode/v1/wrap"||salt||params)`
///
/// There is no XOR path. There is no fixed-salt path.
pub fn wrap_identity_passphrase(
    _isk: &IdentitySecret,
    _passphrase: &Secret32,
    _salt: WrapSalt,
    _params: Argon2Params,
) -> Result<WrappedKey> {
    Err(Error::NotImplemented)
}

/// Unwrap ISK from a passphrase-wrapped `GKEY` body.
///
/// G0b stub. G1 returns the ISK or [`Error::AuthFail`] on wrong passphrase /
/// tampered wrap. No partial output, no "best-effort" decode.
pub fn unwrap_identity_passphrase(
    _wrapped: &WrappedKey,
    _passphrase: &Secret32,
) -> Result<IdentitySecret> {
    Err(Error::NotImplemented)
}
