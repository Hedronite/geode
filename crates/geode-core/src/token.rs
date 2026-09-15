//! Unwrap tokens (02-cryptography 9; 06-agent-plane 2).
//!
//! A token is **not the ISK**. `TokenKey = BLAKE3-KDF(EK, "geode/v1/token",
//! token_id)`. Tokens only narrow policy (10-policy 2). TTL 15m default /
//! 12h max. Killing the daemon destroys tokens.
//!
//! G0b: defines the token type. Issue/inspect stubs fail closed. No AEGIS
//! is called yet.

use crate::kdf::{Epoch, VaultId};
use crate::policy::{Op, PrincipalId};
use crate::{Error, Result};

/// Default token TTL: 15 minutes (02-cryptography 9).
pub const DEFAULT_TTL_SECS: u64 = 15 * 60;

/// Maximum token TTL: 12 hours (02-cryptography 9).
pub const MAX_TTL_SECS: u64 = 12 * 60 * 60;

/// Token id (16 bytes).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenId(pub [u8; 16]);

/// Allowed operations on a token (02-cryptography 9).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Token {
    pub token_id: TokenId,
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub principal_id: PrincipalId,
    pub not_before: i64,
    pub not_after: i64,
    pub allow_ops: Vec<Op>,
    pub allow_prefix: Vec<String>,
    pub max_bytes: u64,
}

/// Issue a sealed token (`GTOK...`) (06-agent-plane 2).
///
/// G0b stub. G2 will:
/// - validate `token ⊆ policy` (10-policy 2: tokens only narrow, never widen)
/// - clamp TTL to `[0, MAX_TTL_SECS]`
/// - seal canonical JSON with AEGIS-256-X2 under `TokenKey`
///
/// A token asking for `keys/` when policy does not allow it MUST NOT issue.
pub fn issue(_token: &Token) -> Result<Vec<u8>> {
    Err(Error::NotImplemented)
}

/// Inspect a sealed token: parse and return the (untrusted) claims.
///
/// G0b stub. G2 verifies the MAC and expiry; expired tokens return
/// [`Error::TokenInvalid`].
pub fn inspect(_sealed: &[u8]) -> Result<Token> {
    Err(Error::NotImplemented)
}
