//! Key wrap: passphrase + recipients (02-cryptography 6, 7).
//!
//! G1: real passphrase wrap. **No XOR.** Random 16-byte salt per key file
//! (via OS CSPRNG). Argon2id parameters stored in the file. AEGIS-256-X2
//! AEAD of ISK. Recipient (X25519 / hybrid) wrap stays stubbed until G2/G4.
//!
//! G5a: the passphrase is taken as a variable-length `&[u8]` (Argon2id accepts
//! arbitrary password lengths). The deterministic `_with` variant lets vector
//! generators and recovery tooling fix the salt/nonce; the CLI path uses the
//! random variant. `Secret32` is no longer required to construct a passphrase
//! input, so `Secret32::new_unchecked` stays crate-private.

use crate::kdf::domains;
use crate::kdf::IdentitySecret;
use crate::{Error, Result};
use aegis::aegis256x2::{Aegis256X2, Key, Nonce};

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
/// Random per key file. NEVER a fixed string.
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

fn random_bytes(out: &mut [u8]) -> Result<()> {
    getrandom::fill(out).map_err(|e| Error::Crypto(format!("getrandom: {e}")))
}

fn random_salt() -> Result<WrapSalt> {
    let mut s = [0u8; 16];
    random_bytes(&mut s)?;
    Ok(WrapSalt(s))
}

fn random_nonce() -> Result<Nonce> {
    let mut n = [0u8; 32];
    random_bytes(&mut n)?;
    Ok(n)
}

/// Build the wrap AD: `"geode/v1/wrap" || salt || params` (02-cryptography 6.2).
fn wrap_ad(salt: &WrapSalt, params: Argon2Params) -> Vec<u8> {
    let mut ad = Vec::with_capacity(domains::WRAP.len() + 16 + 12);
    ad.extend_from_slice(domains::WRAP.as_bytes());
    ad.extend_from_slice(&salt.0);
    ad.extend_from_slice(&params.m_kib.to_le_bytes());
    ad.extend_from_slice(&params.t.to_le_bytes());
    ad.extend_from_slice(&params.p.to_le_bytes());
    ad
}

/// Derive the wrap key via Argon2id (02-cryptography 6.2).
fn derive_wrap_key(passphrase: &[u8], salt: &WrapSalt, params: Argon2Params) -> Result<Key> {
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
            .map_err(|e| Error::Crypto(format!("argon2 params: {e}")))?,
    );
    let mut wk = [0u8; 32];
    argon
        .hash_password_into(passphrase, &salt.0, &mut wk)
        .map_err(|e| Error::Crypto(format!("argon2: {e}")))?;
    Ok(wk)
}

/// Wrap ISK with a passphrase + fresh random 16-byte salt (02-cryptography 6.2).
///
/// `WK = Argon2id(passphrase, salt, m, t, p, out=32)`
/// `wrapped = AEGIS-256-X2.encrypt(ISK, key=WK, nonce=wrap_nonce,`
/// `           AD="geode/v1/wrap"||salt||params)`
///
/// There is no XOR path. There is no fixed-salt path. The caller supplies the
/// `Argon2Params`; both `DEFAULT_DESKTOP` and `DEFAULT_CHEAP` are available.
/// The passphrase is consumed as raw bytes; Argon2id handles variable length.
pub fn wrap_identity_passphrase(
    isk: &IdentitySecret,
    passphrase: &[u8],
    params: Argon2Params,
) -> Result<WrappedKey> {
    let salt = random_salt()?;
    let nonce = random_nonce()?;
    wrap_identity_passphrase_with(isk, passphrase, salt, nonce, params)
}

/// Deterministic passphrase wrap with caller-supplied salt and nonce.
///
/// For golden-vector generation and recovery tooling where the salt/nonce
/// must be reproducible. Production callers SHOULD use
/// [`wrap_identity_passphrase`], which draws both from the OS CSPRNG. A reused
/// `(salt, nonce)` pair under the same passphrase leaks the ISK; this
/// function does not check that.
pub fn wrap_identity_passphrase_with(
    isk: &IdentitySecret,
    passphrase: &[u8],
    salt: WrapSalt,
    wrap_nonce: [u8; 32],
    params: Argon2Params,
) -> Result<WrappedKey> {
    let wk = derive_wrap_key(passphrase, &salt, params)?;
    let ad = wrap_ad(&salt, params);
    let ctx = Aegis256X2::<16>::new(&wk, &wrap_nonce);
    let mut wrapped = *isk.as_bytes();
    let tag = ctx.encrypt_in_place(&mut wrapped, &ad);
    Ok(WrappedKey {
        salt,
        argon2_m_kib: params.m_kib,
        argon2_t: params.t,
        argon2_p: params.p,
        wrap_nonce,
        wrap_tag: tag,
        wrapped_isk: wrapped,
    })
}

/// Unwrap ISK from a passphrase-wrapped `GKEY` body.
///
/// Returns the ISK, or [`Error::AuthFail`] on wrong passphrase / tampered
/// wrap. No partial output, no "best-effort" decode.
pub fn unwrap_identity_passphrase(
    wrapped: &WrappedKey,
    passphrase: &[u8],
) -> Result<IdentitySecret> {
    let params = Argon2Params {
        m_kib: wrapped.argon2_m_kib,
        t: wrapped.argon2_t,
        p: wrapped.argon2_p,
    };
    let wk = derive_wrap_key(passphrase, &wrapped.salt, params)?;
    let ad = wrap_ad(&wrapped.salt, params);
    let ctx = Aegis256X2::<16>::new(&wk, &wrapped.wrap_nonce);
    let mut buf = wrapped.wrapped_isk;
    ctx.decrypt_in_place(&mut buf, &wrapped.wrap_tag, &ad)
        .map_err(|_| Error::AuthFail)?;
    Ok(IdentitySecret::from_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x5e; 32])
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        let isk = isk();
        let passphrase = b"correct horse battery staple";
        let wrapped =
            wrap_identity_passphrase(&isk, passphrase, Argon2Params::DEFAULT_CHEAP).unwrap();
        let unwrapped = unwrap_identity_passphrase(&wrapped, passphrase).unwrap();
        assert_eq!(unwrapped.as_bytes(), isk.as_bytes());
    }

    #[test]
    fn wrong_passphrase_is_auth_fail() {
        let isk = isk();
        let wrapped =
            wrap_identity_passphrase(&isk, b"right", Argon2Params::DEFAULT_CHEAP).unwrap();
        let r = unwrap_identity_passphrase(&wrapped, b"wrong");
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn flipped_wrapped_bit_is_auth_fail() {
        let isk = isk();
        let passphrase = b"right";
        let mut wrapped =
            wrap_identity_passphrase(&isk, passphrase, Argon2Params::DEFAULT_CHEAP).unwrap();
        wrapped.wrapped_isk[0] ^= 0x01;
        let r = unwrap_identity_passphrase(&wrapped, passphrase);
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn each_wrap_has_random_salt() {
        let isk = isk();
        let passphrase = b"x";
        let a = wrap_identity_passphrase(&isk, passphrase, Argon2Params::DEFAULT_CHEAP).unwrap();
        let b = wrap_identity_passphrase(&isk, passphrase, Argon2Params::DEFAULT_CHEAP).unwrap();
        assert_ne!(a.salt.0, b.salt.0, "salt MUST be random per wrap");
        assert_ne!(a.wrap_nonce, b.wrap_nonce, "nonce MUST be random per wrap");
    }

    #[test]
    fn deterministic_with_roundtrips() {
        let isk = isk();
        let passphrase = b"deterministic passphrase";
        let salt = WrapSalt([0x11; 16]);
        let nonce = [0x22; 32];
        let w = wrap_identity_passphrase_with(
            &isk,
            passphrase,
            salt,
            nonce,
            Argon2Params::DEFAULT_CHEAP,
        )
        .unwrap();
        assert_eq!(w.salt.0, [0x11; 16]);
        assert_eq!(w.wrap_nonce, [0x22; 32]);
        let unwrapped = unwrap_identity_passphrase(&w, passphrase).unwrap();
        assert_eq!(unwrapped.as_bytes(), isk.as_bytes());
    }
}
