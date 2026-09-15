//! `geode-core` - GDE1 custody core.
//!
//! Library API for the `geode` CLI and later adapters (MCP, TUI). Implements
//! the `core` profile of the GDE1 spec 2: format, crypto, vault init,
//! seal/open/verify/list, key files.
//!
//! # G2 status
//!
//! Suite 0x01 crypto (G1) plus GDE1 object seal/open with content root, vault
//! directory layout with atomic writes, JCS canonicalization + manifest MAC,
//! and symmetric recipient wrap. Path-bind is enforced: a bound object moved
//! to a different path fails open. HCTR2 name-seal and token issue stay
//! stubbed (G3/agent plane).
//!
//! Reference: SPEC-v010 G2, CHECKLIST-v010 G2a-G2c, 02-cryptography, 03-format.
//!
//! # v0.2.0 / G1a
//!
//! Package renamed to `geode-grotto` (Rust import `geode_grotto`); the
//! directory stays `crates/geode-core`. OS keyring storage for ISK / wrap
//! passphrase via the `keyring` crate (Keychain / Credential Manager /
//! Secret Service), with a 0600 file fallback. `keyring.json` is an index
//! of paths/labels only — never ISK (02-cryptography 6.2).
//!
//! # v0.2.0 / G4
//!
//! `session` types (06 §2; 14-tui §3): unlock loads ISK, derives EK, and
//! **zeroizes ISK** before returning; the session holds only EK plus public
//! ids. `lock` drops EK (zeroized on drop). Idle lock (default 15 min, `0` =
//! never) is polled by the host. No TUI crate lives in `geode-grotto` —
//! `ratatui` / `crossterm` stay out of core so this module is testable headless.
//!
//! # v0.2.0 / G5a
//!
//! Session polish: confirmed the G4 zeroization contract (ISK zeroized on
//! unlock via `drop(isk)` + `Secret32::Drop`; EK zeroized on `lock` and on
//! session drop). Filled the synthetic-clock hole — `touch` and
//! `unlock_wrapped` now have `_at` variants (`touch_at`, `unlock_wrapped_at`)
//! matching `unlock_at` / `lock_if_idle`, so the whole session API is drivable
//! by a synthetic clock. No `ratatui` / `crossterm` in `geode-grotto`.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

pub mod aead;
pub mod chunk;
pub mod kdf;
pub mod keyfile;
pub mod keyring;
pub mod manifest;
pub mod name;
pub mod object;
pub mod policy;
pub mod recipients;
pub mod session;
pub mod token;
pub mod vault;
pub mod wrap;
pub mod zero;

/// Crate-wide error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Still-stubbed paths (HCTR2 name seal, token issue) until G3/agent.
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

    /// Session is locked: EK has been dropped (06 §2; 14-tui §3).
    #[error("geode-core: session is locked (EK dropped)")]
    Locked,

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
