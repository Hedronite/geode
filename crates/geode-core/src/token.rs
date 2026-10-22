//! Unwrap tokens (02-cryptography 9; 06-agent-plane 2).
//!
//! A token is **not the ISK**. `TokenKey = BLAKE3-KDF(EK, "geode/v1/token",
//! token_id)`. Tokens only narrow policy (10-policy 2). TTL 15m default /
//! 12h max. Killing the daemon destroys tokens.
//!
//! G2a: real issue/inspect. The sealed wire format is
//! `GTOK(4) || suite(1) || token_id(16) || tag(16) || ciphertext`, where the
//! AEGIS-256-X2 nonce is derived deterministically from `TokenKey` +
//! `token_id` (`token_id` is unique per issuance, so nonce reuse is forbidden
//! by construction). AD is the exact domain string `geode/v1/token`.
//! `inspect` verifies the tag and rejects expired tokens with
//! [`Error::TokenInvalid`]. `issue` fails closed if no `EpochKey` is supplied
//! (the session holds EK from an unlock; a locked session has none and MUST
//! NOT issue).

use crate::kdf::{domains, Epoch, EpochKey, VaultId};
use crate::manifest::canonicalize;
use crate::policy::{Op, PrincipalId};
use crate::{assert_magic, assert_suite, Error, Result, MAGIC_GTOK, SUITE_0X01};
use aegis::aegis256x2::{Aegis256X2, Key, Nonce};
use secrecy::{ExposeSecret, SecretBox};

/// Default token TTL: 15 minutes (02-cryptography 9).
pub const DEFAULT_TTL_SECS: u64 = 15 * 60;

/// Maximum token TTL: 12 hours (02-cryptography 9).
pub const MAX_TTL_SECS: u64 = 12 * 60 * 60;

/// Exact associated-data domain string bound into the AEAD (02-cryptography 9).
const TOKEN_AD: &[u8] = b"geode/v1/token";

/// Token id (16 bytes).
#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenId(pub [u8; 16]);

/// One absolute command allowed to receive an injected secret.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CmdRule {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args_prefix: Vec<String>,
}

/// How a redactor names a hit. Absent JSON means [`RedactLevel::Strict`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RedactLevel {
    #[default]
    Strict,
    Hidden,
}

/// How broad a token is. Absent JSON is the legacy [`TokenKind::Full`].
///
/// [`TokenKind::Run`] may list, inject, and hash-read. It cannot include
/// [`Op::Read`]. Text and hex on a run token are `plaintext_denied`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    /// Legacy token. Plaintext reads follow `allow_ops`.
    #[default]
    Full,
    /// Run-only. No plaintext body.
    Run,
}

/// Unwrap token claims (02-cryptography 9).
///
/// A token is **not the ISK** and never carries key material; it only narrows
/// the issuing principal's policy (10-policy 2).
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
    /// Empty unless the token lists commands. An empty list denies inject.
    #[serde(default)]
    pub allow_cmds: Vec<CmdRule>,
    /// Empty means no host restriction is claimed.
    #[serde(default)]
    pub allow_hosts: Vec<String>,
    /// Absent unless the token is bound to a socket peer uid.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_uid: Option<u32>,
    /// Absent JSON decodes as [`RedactLevel::Strict`].
    #[serde(default)]
    pub redact: RedactLevel,
    /// Absent JSON decodes as [`TokenKind::Full`].
    #[serde(default)]
    pub kind: TokenKind,
}

impl Token {
    /// Inject requires `Op::Inject` and a non-empty `allow_cmds`.
    ///
    /// An old token has neither, so inject is denied.
    #[must_use]
    pub fn allows_inject(&self) -> bool {
        self.allow_ops.contains(&Op::Inject) && !self.allow_cmds.is_empty()
    }
}

/// `TokenKey = BLAKE3-KDF(EK, "geode/v1/token", token_id)` (02-cryptography 9).
///
/// Distinct from `NameKey` / `ManifestKey` by domain string, so a token key
/// cannot be replayed as a manifest or name key.
fn derive_token_key(ek: &EpochKey, token_id: &TokenId) -> [u8; 32] {
    let mut km = Vec::with_capacity(32 + 16);
    km.extend_from_slice(ek.as_bytes());
    km.extend_from_slice(&token_id.0);
    blake3::derive_key(domains::TOKEN, &km)
}

/// Per-token AEGIS-256-X2 nonce, derived from `TokenKey` + `token_id`.
///
/// `token_id` is unique per issuance (16 random bytes), so the derived nonce
/// is never reused under the same `TokenKey`.
fn derive_token_nonce(token_key: &[u8; 32], token_id: &TokenId) -> Nonce {
    let mut h = blake3::Hasher::new_keyed(token_key);
    h.update(b"geode/v1/token-nonce");
    h.update(&token_id.0);
    let mut n = [0u8; 32];
    n.copy_from_slice(h.finalize().as_bytes());
    n
}

/// Validate the token's intrinsic fields before any crypto.
///
/// - `principal_id` must match `06-agent-plane 1` (`[a-z0-9:._-]{1,64}`).
/// - TTL must be in `[0, MAX_TTL_SECS]`.
/// - `max_bytes` must be > 0 (a zero-byte token can do no work and only
///   confuses policy accounting).
fn validate(token: &Token) -> Result<()> {
    token.principal_id.validate()?;
    let ttl = token.not_after - token.not_before;
    if ttl < 0 {
        return Err(Error::Format("token ttl is negative".into()));
    }
    if u64::try_from(ttl).unwrap_or(0) > MAX_TTL_SECS {
        return Err(Error::Format(format!(
            "token ttl {ttl}s exceeds max {MAX_TTL_SECS}s"
        )));
    }
    if token.max_bytes == 0 {
        return Err(Error::Format("token max_bytes must be > 0".into()));
    }
    if token.kind == TokenKind::Run && token.allow_ops.contains(&Op::Read) {
        return Err(Error::Format("run-only token cannot include read".into()));
    }
    Ok(())
}

/// Sealed `GTOK` bytes. `Debug` does not print them. `Deref` to `[u8]` is
/// the borrow inspect and the CLI already use.
pub struct SealedToken(SecretBox<Vec<u8>>);

impl SealedToken {
    fn new(bytes: Vec<u8>) -> Self {
        Self(SecretBox::new(Box::new(bytes)))
    }

    /// Copy the sealed bytes out. Tamper tests in this module flip bits
    /// on the copy. Callers borrow through `Deref` to `[u8]`.
    #[cfg(test)]
    fn into_vec(self) -> Vec<u8> {
        self.0.expose_secret().clone()
    }
}

impl std::fmt::Debug for SealedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SealedToken(**redacted**)")
    }
}

impl std::ops::Deref for SealedToken {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.expose_secret()
    }
}

impl AsRef<[u8]> for SealedToken {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl PartialEq for SealedToken {
    fn eq(&self, other: &Self) -> bool {
        self.as_ref() == other.as_ref()
    }
}

impl Eq for SealedToken {}

impl Clone for SealedToken {
    fn clone(&self) -> Self {
        Self::new(self.0.expose_secret().clone())
    }
}

/// Issue a sealed token (`GTOK...`) (06-agent-plane 2).
///
/// Seals canonical (RFC 8785) JSON of `token` with AEGIS-256-X2 under
/// `TokenKey` derived from `ek` + `token.token_id`. AD is the exact domain
/// string `geode/v1/token`. Fails closed if no `EpochKey` is supplied — the
/// caller holds EK from an unlocked session; a locked session has no EK and
/// MUST NOT issue. Validates `principal_id` and TTL in `[0, MAX_TTL_SECS]`
/// before any crypto runs. The returned bytes sit in a [`SealedToken`].
pub fn issue(token: &Token, ek: &EpochKey) -> Result<SealedToken> {
    validate(token)?;
    let value =
        serde_json::to_value(token).map_err(|e| Error::Format(format!("token serialize: {e}")))?;
    let body = canonicalize(&value)?;
    let token_key = derive_token_key(ek, &token.token_id);
    let nonce = derive_token_nonce(&token_key, &token.token_id);
    let key: Key = token_key;
    let ctx = Aegis256X2::<16>::new(&key, &nonce);
    let (ct, tag) = ctx.encrypt(&body, TOKEN_AD);
    let mut out = Vec::with_capacity(4 + 1 + 16 + 16 + ct.len());
    out.extend_from_slice(MAGIC_GTOK);
    out.push(SUITE_0X01);
    out.extend_from_slice(&token.token_id.0);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    Ok(SealedToken::new(out))
}

/// Inspect a sealed token: verify the MAC and return the claims.
///
/// `now` is unix seconds. A token whose `now` is outside
/// `[not_before, not_after]` returns [`Error::TokenInvalid`]. Tag mismatch /
/// tamper / wrong EK returns [`Error::AuthFail`]. The token body is parsed
/// only after the tag verifies, so untrusted bytes are never interpreted
/// before authentication.
pub fn inspect(sealed: &[u8], ek: &EpochKey, now: i64) -> Result<Token> {
    const HEADER_LEN: usize = 4 + 1 + 16 + 16;
    if sealed.len() < HEADER_LEN {
        return Err(Error::Format("token too short".into()));
    }
    let magic: &[u8; 4] = sealed[..4]
        .try_into()
        .map_err(|_| Error::Format("token magic slice".into()))?;
    assert_magic(magic, MAGIC_GTOK)?;
    let suite = sealed[4];
    assert_suite(suite)?;
    let mut token_id = [0u8; 16];
    token_id.copy_from_slice(&sealed[5..21]);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&sealed[21..37]);
    let ct = &sealed[37..];
    let tid = TokenId(token_id);
    let token_key = derive_token_key(ek, &tid);
    let nonce = derive_token_nonce(&token_key, &tid);
    let key: Key = token_key;
    let ctx = Aegis256X2::<16>::new(&key, &nonce);
    let body = ctx
        .decrypt(ct, &tag, TOKEN_AD)
        .map_err(|_| Error::AuthFail)?;
    let token: Token =
        serde_json::from_slice(&body).map_err(|e| Error::Format(format!("token parse: {e}")))?;
    if now < token.not_before || now > token.not_after {
        return Err(Error::TokenInvalid);
    }
    Ok(token)
}

// ---- G0c (v0.2.3): token-issue narrowing ----

/// Does `token`'s grant narrow `policy` for its principal? (10-policy 2.5.)
///
/// A token may only narrow, never widen. Checks `allow_ops` / `allow_prefix`
/// / `max_bytes` against the matching `PrincipalGrant` in `policy`:
///
/// - The principal MUST be in `policy` (else [`Error::PolicyDeny`]).
/// - `token.allow_ops` must be a subset of `grant.ops`.
/// - Each `token.allow_prefix` must be covered by some `grant.prefixes`
///   (via [`crate::policy::prefix_covers`]).
/// - If `grant.max_bytes` is `Some(n)`, `token.max_bytes` must be `<= n`.
///
/// Returns `Ok(())` if the token narrows policy, [`Error::PolicyDeny`] if
/// it would widen. Errors never contain ISK or key material.
pub fn narrows_policy(token: &Token, policy: &crate::policy::Policy) -> Result<()> {
    crate::policy::token_narrows_policy(token, policy)
}

/// Issue a sealed token that is verified to narrow `policy` (10-policy 2.5).
///
/// Calls [`narrows_policy`] first; if the token would widen policy (or the
/// principal is not in policy), returns [`Error::PolicyDeny`] without
/// sealing. Otherwise delegates to [`issue`]. The caller holds `EK` from an
/// unlocked session; a locked session has no EK and cannot construct the
/// call.
pub fn issue_narrow(
    token: &Token,
    ek: &EpochKey,
    policy: &crate::policy::Policy,
) -> Result<SealedToken> {
    narrows_policy(token, policy)?;
    issue(token, ek)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ek() -> EpochKey {
        let isk = crate::kdf::IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn token(now: i64, ttl_secs: u64) -> Token {
        Token {
            token_id: TokenId([0xa5; 16]),
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            principal_id: PrincipalId("agent:facet-coder-3".into()),
            not_before: now,
            not_after: now,
            allow_ops: vec![Op::List, Op::Read, Op::Write],
            allow_prefix: vec!["scratch/".into(), "out/".into()],
            max_bytes: 1 << 20,
            allow_cmds: Vec::new(),
            allow_hosts: Vec::new(),
            peer_uid: None,
            redact: RedactLevel::Strict,
            kind: TokenKind::Full,
        }
        .with_ttl(ttl_secs)
    }

    impl Token {
        fn with_ttl(mut self, ttl_secs: u64) -> Self {
            self.not_after = self.not_before + i64::try_from(ttl_secs).unwrap_or(i64::MAX);
            self
        }
    }

    #[test]
    fn issue_inspect_roundtrip() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let sealed = issue(&t, &ek).unwrap();
        assert_eq!(&sealed[..4], MAGIC_GTOK);
        assert_eq!(sealed[4], SUITE_0X01);
        let opened = inspect(&sealed, &ek, 1_700_000_000).unwrap();
        assert_eq!(opened.principal_id.0, "agent:facet-coder-3");
        assert_eq!(opened.allow_prefix, t.allow_prefix);
        assert_eq!(opened.token_id.0, t.token_id.0);
    }

    #[test]
    fn issue_is_deterministic() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let a = issue(&t, &ek).unwrap();
        let b = issue(&t, &ek).unwrap();
        assert_eq!(a, b, "same (token, ek) MUST yield identical sealed bytes");
        let shown = format!("{a:?}");
        assert!(!shown.contains("GTOK"), "{shown}");
    }

    #[test]
    fn expired_token_is_token_invalid() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let sealed = issue(&t, &ek).unwrap();
        let r = inspect(&sealed, &ek, 1_700_000_000 + 901);
        assert!(matches!(r, Err(Error::TokenInvalid)), "got {r:?}");
    }

    #[test]
    fn not_yet_valid_is_token_invalid() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let sealed = issue(&t, &ek).unwrap();
        let r = inspect(&sealed, &ek, 1_700_000_000 - 1);
        assert!(matches!(r, Err(Error::TokenInvalid)), "got {r:?}");
    }

    #[test]
    fn flipped_ciphertext_bit_is_auth_fail() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let mut sealed = issue(&t, &ek).unwrap().into_vec();
        let last = sealed.len() - 1;
        sealed[last] ^= 0x01;
        let r = inspect(&sealed, &ek, 1_700_000_000);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn flipped_tag_bit_is_auth_fail() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let mut sealed = issue(&t, &ek).unwrap().into_vec();
        sealed[21] ^= 0x01;
        let r = inspect(&sealed, &ek, 1_700_000_000);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn wrong_ek_is_auth_fail() {
        let ek = ek();
        let isk2 = crate::kdf::IdentitySecret::from_bytes([0x08; 32]);
        let ek2 =
            crate::kdf::derive_epoch_key(&isk2, VaultId([0x02; 16]), Epoch(1), "test").unwrap();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let sealed = issue(&t, &ek).unwrap();
        let r = inspect(&sealed, &ek2, 1_700_000_000);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn swapped_token_id_is_auth_fail() {
        let ek = ek();
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let mut sealed = issue(&t, &ek).unwrap().into_vec();
        sealed[5] ^= 0x01;
        let r = inspect(&sealed, &ek, 1_700_000_000);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn ttl_over_max_is_rejected() {
        let ek = ek();
        let t = token(1_700_000_000, MAX_TTL_SECS + 1);
        let r = issue(&t, &ek);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn negative_ttl_is_rejected() {
        let ek = ek();
        let mut t = token(1_700_000_000, DEFAULT_TTL_SECS);
        t.not_after = t.not_before - 1;
        let r = issue(&t, &ek);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn zero_max_bytes_is_rejected() {
        let ek = ek();
        let mut t = token(1_700_000_000, DEFAULT_TTL_SECS);
        t.max_bytes = 0;
        let r = issue(&t, &ek);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn bad_principal_id_is_rejected() {
        let ek = ek();
        let mut t = token(1_700_000_000, DEFAULT_TTL_SECS);
        t.principal_id = PrincipalId("Agent X".into());
        let r = issue(&t, &ek);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn truncated_token_is_format_error() {
        let ek = ek();
        let r = inspect(b"GTOK\x01", &ek, 1_700_000_000);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn bad_magic_is_format_error() {
        let ek = ek();
        let r = inspect(
            b"XXXX\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            &ek,
            1_700_000_000,
        );
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn old_token_json_defaults_deny_inject_and_keep_suite() {
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let mut value = serde_json::to_value(&t).unwrap();
        let obj = value.as_object_mut().unwrap();
        obj.remove("allow_cmds");
        obj.remove("allow_hosts");
        obj.remove("peer_uid");
        obj.remove("redact");
        obj.remove("kind");
        let old: Token = serde_json::from_value(value).unwrap();
        assert!(old.allow_cmds.is_empty());
        assert!(old.allow_hosts.is_empty());
        assert!(old.peer_uid.is_none());
        assert_eq!(old.redact, RedactLevel::Strict);
        assert_eq!(old.kind, TokenKind::Full);
        assert!(!old.allow_ops.contains(&Op::Inject));
        assert!(!old.allows_inject());
        let sealed = issue(&old, &ek()).unwrap();
        assert_eq!(sealed[4], SUITE_0X01);
        let opened = inspect(&sealed, &ek(), 1_700_000_000).unwrap();
        assert!(!opened.allows_inject());
    }

    #[test]
    fn inject_without_allow_cmds_is_denied() {
        let mut t = token(1_700_000_000, DEFAULT_TTL_SECS);
        t.allow_ops = vec![Op::Inject];
        assert!(!t.allows_inject());
        t.allow_cmds.push(CmdRule {
            path: "/bin/true".into(),
            sha256: None,
            args_prefix: Vec::new(),
        });
        assert!(t.allows_inject());
        assert!(!t.allow_ops.contains(&Op::Read));
    }

    #[test]
    fn absent_kind_parses_as_full_and_run_rejects_read() {
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        let mut value = serde_json::to_value(&t).unwrap();
        value.as_object_mut().unwrap().remove("kind");
        let old: Token = serde_json::from_value(value).unwrap();
        assert_eq!(old.kind, TokenKind::Full);
        let sealed = issue(&old, &ek()).unwrap();
        assert_eq!(sealed[4], SUITE_0X01);
        let opened = inspect(&sealed, &ek(), 1_700_000_000).unwrap();
        assert_eq!(opened.kind, TokenKind::Full);

        let mut run = token(1_700_000_000, DEFAULT_TTL_SECS);
        run.kind = TokenKind::Run;
        run.allow_ops = vec![Op::List, Op::Read];
        let denied = issue(&run, &ek());
        assert!(
            matches!(denied, Err(Error::Format(ref m)) if m.contains("cannot include read")),
            "got {denied:?}"
        );

        run.allow_ops = vec![Op::List, Op::Inject];
        let sealed = issue(&run, &ek()).unwrap();
        assert_eq!(sealed[4], SUITE_0X01);
        let opened = inspect(&sealed, &ek(), 1_700_000_000).unwrap();
        assert_eq!(opened.kind, TokenKind::Run);
        assert!(!opened.allow_ops.contains(&Op::Read));
    }

    #[test]
    fn read_does_not_grant_inject() {
        let t = token(1_700_000_000, DEFAULT_TTL_SECS);
        assert!(t.allow_ops.contains(&Op::Read));
        assert!(!t.allow_ops.contains(&Op::Inject));
        assert!(!t.allows_inject());
    }

    use proptest::prelude::*;
    fn tw(nb: i64, na: i64) -> Token {
        Token {
            token_id: TokenId([0x31; 16]),
            vault_id: VaultId([1; 16]),
            epoch: Epoch(1),
            principal_id: PrincipalId("agent:test".into()),
            not_before: nb,
            not_after: na,
            allow_ops: vec![Op::Read],
            allow_prefix: vec!["scratch/".into()],
            max_bytes: 4096,
            allow_cmds: Vec::new(),
            allow_hosts: Vec::new(),
            peer_uid: None,
            redact: RedactLevel::Strict,
            kind: TokenKind::Full,
        }
    }
    proptest! {
        #[test]
        fn rp5_ttl_window_is_inclusive(nb in 0i64..1000, len in 0i64..1000, outside in 1i64..100) {
            let na=nb+len; let ek=EpochKey::from_bytes([0x07;32]); let sealed=issue(&tw(nb,na),&ek).unwrap();
            prop_assert!(inspect(&sealed,&ek,nb).is_ok()); prop_assert!(inspect(&sealed,&ek,na).is_ok());
            prop_assert!(matches!(inspect(&sealed,&ek,na+outside), Err(Error::TokenInvalid)));
        }
    }
}
