//! `geode-core` - GDE1 custody core.
//!
//! Library API for the `geode` CLI and later adapters (MCP, TUI). Implements
//! the `core` profile of the GDE1 spec 2: format, crypto, vault init,
//! seal/open/verify/list, key files.
//!
//! # G0b status
//!
//! Module files exist per the implementation sketch (13). All crypto and I/O
//! paths are **stubs that fail closed** - they return [`Error::NotImplemented`]
//! rather than performing or pretending any cryptography. No XOR wrap. No
//! hardcoded salt. No fake AEAD. Real implementations land in G1 (crypto) and
//! G2 (format + vault).
//!
//! Reference: SPEC-v010 G0b, CHECKLIST-v010 G0b.

#![forbid(unsafe_code)]
#![deny(missing_debug_implementations)]
// G0b stubs: silence pedantic doc-lints that would otherwise force premature
// `# Errors` / `# Panics` sections on fail-closed stubs. G1 will tighten these
// when the stubs become real implementations.
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
/// (CLI exit 2). `NotImplemented` is the G0b stub state and MUST NOT be
/// returned once G1 lands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("geode-core: not implemented (G0b stub - no crypto performed)")]
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
