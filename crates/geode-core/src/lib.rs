//! `geode-core` - GDE1 custody core.
//!
//! Library API for the `geode` CLI and later adapters (MCP, TUI). Implements
//! the `core` profile of the GDE1 spec 2: format, crypto, vault init,
//! seal/open/verify/list, key files.
//!
//! # G1 status
//!
//! Suite `0x01` (AEGIS-256-X2 + BLAKE3 + Argon2id + HCTR2-256) is real for
//! KDF, AEAD seal/open, and passphrase wrap. HCTR2 name-seal stays stubbed
//! until G2 (the suite identifier and unknown-suite abort are real now).
//! Vault directory / object I/O is G2.
//!
//! Reference: SPEC-v010 G1, CHECKLIST-v010 G1a-G1c, 02-cryptography.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
// G1: silence pedantic doc-lints on thin crypto wrappers. Tighten in G2.
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod aead;
pub mod chunk;
pub mod kdf;
pub mod manifest;
pub mod name;
pub mod policy;
pub mod recipients;
pub mod token;
pub mod wrap;
pub mod zero;

/// Crate-wide error.
///
/// Exit-code mapping (05-cli 3) is owned by the CLI adapter; the library only
/// classifies. `AuthFail` is the integrity / authentication failure family
/// (CLI exit 2).
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Still-stubbed paths (HCTR2 name seal, manifest MAC, recipient wrap,
    /// token issue) until G2. Removed once each lands.
    #[error("geode-core: not implemented yet (stub)")]
    NotImplemented,

    #[error("geode-core: authentication / integrity failure")]
    AuthFail,

    #[error("geode-core: usage / IO: {0}")]
    Io(#[from] std::io::Error),

    #[error("geode-core: format: {0}")]
    Format(String),

    #[error("geode-core: policy deny")]
    PolicyDeny,

    #[error("geode-core: token expired or invalid")]
    TokenInvalid,

    #[error("geode-core: crypto: {0}")]
    Crypto(String),
}

/// Crate-wide result.
pub type Result<T> = std::result::Result<T, Error>;

/// Suite identifier for GDE1 v1 (02-cryptography 1.1).
pub const SUITE_0X01: u8 = 0x01;

/// Magic bytes (03-format 1).
pub const MAGIC_GDE1: &[u8; 4] = b"GDE1";
pub const MAGIC_GKEY: &[u8; 4] = b"GKEY";
pub const MAGIC_GTOK: &[u8; 4] = b"GTOK";
pub const MAGIC_GMFT: &[u8; 4] = b"GMFT";

/// Abort on unknown suite (02-cryptography 1.1; SPEC 4.2).
///
/// v0.1 only knows suite `0x01`. Any other value is a hard failure, never a
/// silent fallback.
pub fn assert_suite(suite: u8) -> Result<()> {
    if suite == SUITE_0X01 {
        Ok(())
    } else {
        Err(Error::Format(format!(
            "unknown cipher suite 0x{suite:02x}; only 0x01 is defined"
        )))
    }
}

/// Abort on unknown magic (03-format 1; SPEC 4.2).
pub fn assert_magic(actual: &[u8; 4], expected: &[u8; 4]) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::Format(format!(
            "unknown magic {actual:?}; expected {expected:?}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suite_0x01_accepted() {
        assert!(assert_suite(SUITE_0X01).is_ok());
    }

    #[test]
    fn unknown_suite_aborts() {
        assert!(assert_suite(0x02).is_err());
        assert!(assert_suite(0xff).is_err());
    }

    #[test]
    fn magic_match_accepted() {
        assert!(assert_magic(b"GDE1", MAGIC_GDE1).is_ok());
    }

    #[test]
    fn unknown_magic_aborts() {
        assert!(assert_magic(b"XXXX", MAGIC_GDE1).is_err());
        assert!(assert_magic(b"GDE2", MAGIC_GDE1).is_err());
    }
}
