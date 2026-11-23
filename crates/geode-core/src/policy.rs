//! Policy document and evaluation (10-policy; `SPEC` 6).
//!
//! G0b (v0.2.2): types + default-deny `evaluate` + `default_policy`.
//! G0 (v0.2.3): seal/load `policy.json.sealed` under `MetaKey` with AD
//! `geode/v1/policy || vault_id || le32(epoch)`; token-issue narrowing.
//!
//! Evaluation is the reference monitor's question: "may this principal do
//! this op on this path?" A vault with no `policy.json.sealed` behaves as
//! `default_policy` -- `human:local` admin on `""`, everyone else deny
//! (10-policy 3).

use crate::kdf::{domains, Epoch, VaultId};
use crate::manifest::canonicalize;
use crate::vault::{self, write_atomic};
use crate::{Error, Result, MAGIC_GPO2, MAGIC_GPOL, SUITE_0X01};
use aegis::aegis256x2::{Aegis256X2, Key};
use std::path::{Path, PathBuf};

/// Principal id: ASCII, 1-64 chars, `[a-z0-9:._-]+` (06-agent-plane 1).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    /// Validate the principal id format (06-agent-plane 1).
    pub fn validate(&self) -> Result<()> {
        let s = &self.0;
        if s.is_empty() || s.len() > 64 {
            return Err(Error::Format("principal id length out of [1,64]".into()));
        }
        if !s
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b':' | b'.' | b'_' | b'-'))
        {
            return Err(Error::Format(
                "principal id has chars outside [a-z0-9:._-]".into(),
            ));
        }
        Ok(())
    }
}

/// Operation a principal may perform (10-policy 1; 05-cli verbs).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Op {
    List,
    Read,
    Inject,
    Write,
    Mount,
    Verify,
    Admin,
}

/// A principal's grant (10-policy 1).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PrincipalGrant {
    pub id: PrincipalId,
    pub ops: Vec<Op>,
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub max_bytes: Option<u64>,
    #[serde(default)]
    pub max_calls_per_10s: Option<u32>,
}

/// Policy document (10-policy 1).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Policy {
    pub version: u32,
    pub vault_id: String,
    pub default: DefaultVerdict,
    pub principals: Vec<PrincipalGrant>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultVerdict {
    Deny,
    Allow,
}

/// Evaluation verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// Normalize a vault-relative path before policy check (06-agent-plane 6.2).
///
/// G0b: minimal normalization (strip leading `/`, collapse `//`, reject `..`).
/// Agent ops use a stricter normalizer (`agent_ops::normalize_strict`) that
/// denies any `..` before open; this human-path normalizer pops `..`.
pub fn normalize_path(path: &str) -> Result<String> {
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                parts
                    .pop()
                    .ok_or_else(|| Error::Format("path escapes vault root".into()))?;
            }
            s => parts.push(s),
        }
    }
    Ok(parts.join("/"))
}

/// Does `prefix` cover `path` (after normalization)? Empty prefix = whole vault
/// (10-policy 2.4). Boundary is respected: `scratch` does not cover `scratchy`.
#[must_use]
pub fn prefix_covers(prefix: &str, normalized_path: &str) -> bool {
    if prefix.is_empty() {
        return true;
    }
    if normalized_path == prefix {
        return true;
    }
    if let Some(rest) = normalized_path.strip_prefix(prefix) {
        return prefix.ends_with('/') || rest.starts_with('/');
    }
    false
}

/// Evaluate `op` on `path` for `principal` under `policy` (10-policy 2).
///
/// Default deny. Match principal exact id. Op in `ops`. Path (normalized)
/// equal to or under one prefix. `max_bytes` is enforced by the caller for
/// read/write size; this function checks only the path/op grant. The `default`
/// field is serialized for fidelity but evaluation is always deny-by-default
/// (10-policy 2.1).
pub fn evaluate(policy: &Policy, principal: &PrincipalId, op: Op, path: &str) -> Result<Verdict> {
    let normalized = normalize_path(path)?;
    for g in &policy.principals {
        if &g.id == principal
            && g.ops.contains(&op)
            && g.prefixes.iter().any(|p| prefix_covers(p, &normalized))
        {
            return Ok(Verdict::Allow);
        }
    }
    Ok(Verdict::Deny)
}

/// Default policy when no `policy.json.sealed` exists (10-policy 3):
/// `human:local` admin on `""`, everyone else deny.
#[must_use]
pub fn default_policy(vault_id: &str) -> Policy {
    Policy {
        version: 1,
        vault_id: vault_id.to_string(),
        default: DefaultVerdict::Deny,
        principals: vec![PrincipalGrant {
            id: PrincipalId("human:local".to_string()),
            ops: vec![
                Op::List,
                Op::Read,
                Op::Inject,
                Op::Write,
                Op::Mount,
                Op::Verify,
                Op::Admin,
            ],
            prefixes: vec![String::new()],
            max_bytes: None,
            max_calls_per_10s: None,
        }],
    }
}
// ---- G0 (v0.2.3): sealed policy storage under MetaKey ----

/// On-disk path of the sealed policy (10-policy 3): `policy.json.sealed` at
/// the vault root, beside `header.json` / `recipients.json`.
#[must_use]
pub fn policy_path(vault_root: &Path) -> PathBuf {
    vault_root.join("policy.json.sealed")
}

/// Legacy per-epoch AEGIS-256-X2 nonce for `GPOL`, derived from `MetaKey`.
/// Only the legacy read path uses it; `GPO2` carries a random nonce.
fn policy_nonce(meta_key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(meta_key);
    h.update(b"geode/v1/policy-nonce");
    let mut n = [0u8; 32];
    n.copy_from_slice(h.finalize().as_bytes());
    n
}

/// Legacy `GPOL` associated data: `geode/v1/policy || vault_id || le32(epoch)`
/// (10-policy 3). Binds the sealed policy to a specific (`vault_id`, `epoch`).
fn policy_ad(vault_id: VaultId, epoch: Epoch) -> Vec<u8> {
    let mut ad = Vec::with_capacity(domains::POLICY.len() + 16 + 4);
    ad.extend_from_slice(domains::POLICY.as_bytes());
    ad.extend_from_slice(&vault_id.0);
    ad.extend_from_slice(&epoch.0.to_le_bytes());
    ad
}

/// `GPO2` associated data: the legacy domain plus magic, suite, vault id,
/// epoch, and the explicit nonce. Domain-separated from `GPOL` so a tag
/// cannot be transplanted between formats, epochs, vaults, or nonces.
fn policy_ad_gpo2(vault_id: VaultId, epoch: Epoch, nonce: &[u8; 32]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(domains::POLICY.len() + 4 + 1 + 16 + 4 + 32);
    ad.extend_from_slice(domains::POLICY.as_bytes());
    ad.extend_from_slice(MAGIC_GPO2);
    ad.push(SUITE_0X01);
    ad.extend_from_slice(&vault_id.0);
    ad.extend_from_slice(&epoch.0.to_le_bytes());
    ad.extend_from_slice(nonce);
    ad
}

/// Legacy wire format: `GPOL(4) || suite(1) || tag(16) || ciphertext`.
const GPOL_HEADER_LEN: usize = 4 + 1 + 16;

/// Current wire format:
/// `GPO2(4) || suite(1) || nonce(32) || tag(16) || ciphertext`.
const GPO2_HEADER_LEN: usize = 4 + 1 + 32 + 16;

fn random_policy_nonce() -> Result<[u8; 32]> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(nonce)
}

/// Seal `policy` to `policy.json.sealed` atomically under `MetaKey`.
///
/// Writes the current `GPO2` container with a fresh CSPRNG nonce. The
/// canonical (RFC 8785) JSON of `policy` is encrypted with AEGIS-256-X2;
/// AD binds `(magic, suite, vault_id, epoch, nonce)`. Cipher suite stays
/// `0x01`. Overwrites atomically.
pub fn seal_policy(
    vault_root: &Path,
    policy: &Policy,
    meta_key: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
) -> Result<PathBuf> {
    seal_policy_with_nonce(
        vault_root,
        policy,
        meta_key,
        vault_id,
        epoch,
        random_policy_nonce()?,
    )
}

/// Deterministic sealing seam for vectors and tests. Production
/// [`seal_policy`] always draws a fresh nonce.
fn seal_policy_with_nonce(
    vault_root: &Path,
    policy: &Policy,
    meta_key: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
    nonce: [u8; 32],
) -> Result<PathBuf> {
    let value = serde_json::to_value(policy)
        .map_err(|e| Error::Format(format!("policy serialize: {e}")))?;
    let body = canonicalize(&value)?;
    let key: Key = *meta_key;
    let ctx = Aegis256X2::<16>::new(&key, &nonce);
    let (ct, tag) = ctx.encrypt(&body, &policy_ad_gpo2(vault_id, epoch, &nonce));
    let mut out = Vec::with_capacity(GPO2_HEADER_LEN + ct.len());
    out.extend_from_slice(MAGIC_GPO2);
    out.push(SUITE_0X01);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&tag);
    out.extend_from_slice(&ct);
    let p = policy_path(vault_root);
    write_atomic(&p, &out)?;
    Ok(p)
}

/// Load + authenticate `policy.json.sealed`, accepting `GPO2` and legacy
/// `GPOL`. Missing file => `default_policy`; any malformed, truncated, or
/// unauthenticated container => [`Error::AuthFail`] (exit 2). The body is
/// parsed only after the tag verifies. Errors never contain key material.
pub fn load_policy(
    vault_root: &Path,
    meta_key: &[u8; 32],
    vault_id: VaultId,
    epoch: Epoch,
) -> Result<Policy> {
    let p = policy_path(vault_root);
    match std::fs::read(&p) {
        Ok(raw) => {
            if raw.len() < 5 {
                return Err(Error::AuthFail);
            }
            let magic: [u8; 4] = raw[..4].try_into().map_err(|_| Error::AuthFail)?;
            if raw[4] != SUITE_0X01 {
                return Err(Error::AuthFail);
            }
            let key: Key = *meta_key;
            let body = if magic == *MAGIC_GPO2 {
                if raw.len() < GPO2_HEADER_LEN {
                    return Err(Error::AuthFail);
                }
                let nonce: [u8; 32] = raw[5..37].try_into().map_err(|_| Error::AuthFail)?;
                let tag: [u8; 16] = raw[37..53].try_into().map_err(|_| Error::AuthFail)?;
                let ct = &raw[53..];
                let ctx = Aegis256X2::<16>::new(&key, &nonce);
                ctx.decrypt(ct, &tag, &policy_ad_gpo2(vault_id, epoch, &nonce))
                    .map_err(|_| Error::AuthFail)?
            } else if magic == *MAGIC_GPOL {
                if raw.len() < GPOL_HEADER_LEN {
                    return Err(Error::AuthFail);
                }
                let tag: [u8; 16] = raw[5..21].try_into().map_err(|_| Error::AuthFail)?;
                let ct = &raw[21..];
                let nonce = policy_nonce(meta_key);
                let ctx = Aegis256X2::<16>::new(&key, &nonce);
                ctx.decrypt(ct, &tag, &policy_ad(vault_id, epoch))
                    .map_err(|_| Error::AuthFail)?
            } else {
                return Err(Error::AuthFail);
            };
            let policy: Policy = serde_json::from_slice(&body)
                .map_err(|e| Error::Format(format!("policy parse: {e}")))?;
            Ok(policy)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(default_policy(&vault::hex_encode(&vault_id.0)))
        }
        Err(e) => Err(Error::Io(e)),
    }
}

// ---- G0c (v0.2.3): token-issue narrowing ----

/// Does `token`'s grant narrow `policy` for its principal? (10-policy 2.5.)
///
/// A token may only narrow, never widen. Checks the token's `allow_ops` /
/// `allow_prefix` / `max_bytes` against the matching `PrincipalGrant`:
///
/// - The principal MUST be in `policy` (else [`Error::PolicyDeny`]).
/// - `token.allow_ops` must be a subset of `grant.ops`.
/// - Each `token.allow_prefix` must be covered by some `grant.prefixes`.
/// - If `grant.max_bytes` is `Some(n)`, `token.max_bytes` must be `<= n`.
///
/// Returns `Ok(())` if the token narrows policy, [`Error::PolicyDeny`] if
/// it would widen. Errors never contain ISK or key material.
pub fn token_narrows_policy(token: &crate::token::Token, policy: &Policy) -> Result<()> {
    let grant = policy
        .principals
        .iter()
        .find(|g| g.id == token.principal_id)
        .ok_or(Error::PolicyDeny)?;
    for &op in &token.allow_ops {
        if !grant.ops.contains(&op) {
            return Err(Error::PolicyDeny);
        }
    }
    for tp in &token.allow_prefix {
        if !grant.prefixes.iter().any(|gp| prefix_covers(gp, tp)) {
            return Err(Error::PolicyDeny);
        }
    }
    if let Some(cap) = grant.max_bytes {
        if token.max_bytes > cap {
            return Err(Error::PolicyDeny);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{Epoch, EpochKey, IdentitySecret, VaultId};
    use crate::token::{inspect, issue_narrow, Token, TokenId, TokenKind};
    use tempfile::tempdir;

    const NOW: i64 = 1_700_000_000;

    fn ek() -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn meta_key() -> [u8; 32] {
        crate::kdf::derive_meta_key(&ek(), VaultId([0x01; 16]), Epoch(1))
    }

    fn agent_token(ops: &[Op], prefixes: &[&str], max_bytes: u64) -> Token {
        Token {
            token_id: TokenId([0xa5; 16]),
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            principal_id: PrincipalId("agent:facet-coder-3".into()),
            not_before: NOW,
            not_after: NOW + 900,
            allow_ops: ops.to_vec(),
            allow_prefix: prefixes.iter().map(|s| (*s).to_string()).collect(),
            max_bytes,
            allow_cmds: Vec::new(),
            allow_hosts: Vec::new(),
            peer_uid: None,
            redact: crate::token::RedactLevel::Strict,
            kind: TokenKind::Full,
        }
    }

    fn agent_policy(ops: &[Op], prefixes: &[&str], max_bytes: Option<u64>) -> Policy {
        Policy {
            version: 1,
            vault_id: "01010101010101010101010101010101".into(),
            default: DefaultVerdict::Deny,
            principals: vec![PrincipalGrant {
                id: PrincipalId("agent:facet-coder-3".into()),
                ops: ops.to_vec(),
                prefixes: prefixes.iter().map(|s| (*s).to_string()).collect(),
                max_bytes,
                max_calls_per_10s: None,
            }],
        }
    }

    // ---- G0a: shipped evaluate + default_policy ----

    #[test]
    fn default_denies_non_human() {
        let p = default_policy("v");
        let agent = PrincipalId("agent:facet-coder-3".into());
        assert_eq!(
            evaluate(&p, &agent, Op::Read, "scratch/x").unwrap(),
            Verdict::Deny
        );
    }

    #[test]
    fn default_allows_human_local() {
        let p = default_policy("v");
        let human = PrincipalId("human:local".into());
        assert_eq!(
            evaluate(&p, &human, Op::Read, "anywhere/x").unwrap(),
            Verdict::Allow
        );
    }

    #[test]
    fn default_allows_human_local_admin() {
        let p = default_policy("v");
        let human = PrincipalId("human:local".into());
        assert_eq!(
            evaluate(&p, &human, Op::Admin, "anywhere").unwrap(),
            Verdict::Allow
        );
    }

    #[test]
    fn prefix_narrowing_denies_outside() {
        let p = agent_policy(&[Op::Read], &["scratch/"], None);
        let agent = PrincipalId("agent:facet-coder-3".into());
        assert_eq!(
            evaluate(&p, &agent, Op::Read, "scratch/plan.md").unwrap(),
            Verdict::Allow
        );
        assert_eq!(
            evaluate(&p, &agent, Op::Read, "keys/prod.pem").unwrap(),
            Verdict::Deny
        );
    }

    #[test]
    fn normalize_rejects_dotdot() {
        assert!(normalize_path("../escape").is_err());
        assert_eq!(normalize_path("a//b/./c").unwrap(), "a/b/c");
    }

    #[test]
    fn prefix_respects_boundary() {
        assert!(prefix_covers("scratch", "scratch"));
        assert!(prefix_covers("scratch", "scratch/plan.md"));
        assert!(!prefix_covers("scratch", "scratchy"));
        assert!(prefix_covers("scratch/", "scratch/plan.md"));
        assert!(!prefix_covers("scratch/", "scratch"));
    }

    #[test]
    fn principal_id_validates() {
        assert!(PrincipalId("agent:facet-coder-3".into()).validate().is_ok());
        assert!(PrincipalId("Agent X".into()).validate().is_err());
    }

    // ---- G0b: sealed policy round-trip + tamper ----

    #[test]
    fn load_missing_policy_returns_default() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        crate::vault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let p = load_policy(&root, &meta_key(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        // default: human:local admin on ""
        let human = PrincipalId("human:local".into());
        assert_eq!(
            evaluate(&p, &human, Op::Admin, "anywhere").unwrap(),
            Verdict::Allow
        );
        let agent = PrincipalId("agent:facet-coder-3".into());
        assert_eq!(evaluate(&p, &agent, Op::Read, "x").unwrap(), Verdict::Deny);
    }

    #[test]
    fn seal_load_roundtrips() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        crate::vault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let p = agent_policy(
            &[Op::List, Op::Read, Op::Write],
            &["scratch/", "out/"],
            Some(1 << 20),
        );
        seal_policy(&root, &p, &meta_key(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        let loaded = load_policy(&root, &meta_key(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        assert_eq!(loaded.principals.len(), 1);
        assert_eq!(loaded.principals[0].id.0, "agent:facet-coder-3");
        assert_eq!(loaded.principals[0].ops, p.principals[0].ops);
        assert_eq!(loaded.principals[0].prefixes, p.principals[0].prefixes);
        assert_eq!(loaded.principals[0].max_bytes, Some(1 << 20));
    }

    #[test]
    fn flipped_ciphertext_bit_is_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        crate::vault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let p = agent_policy(&[Op::Read], &["scratch/"], None);
        seal_policy(&root, &p, &meta_key(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        let mut raw = std::fs::read(policy_path(&root)).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        std::fs::write(policy_path(&root), &raw).unwrap();
        let r = load_policy(&root, &meta_key(), VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    /// Golden containers for both formats: legacy GPOL and current GPO2.
    #[test]
    fn policy_vectors_replay() {
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/v1/policy.json")).unwrap();
        let vid = VaultId(
            vault::hex_decode(doc["vault_id"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap(),
        );
        let epoch = Epoch(u32::try_from(doc["epoch"].as_u64().unwrap()).unwrap());
        let mk: [u8; 32] = vault::hex_decode(doc["meta_key"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let expected = doc["policy"].clone();
        let d = tempdir().unwrap();
        let root = d.path();
        let gpol = vault::hex_decode(doc["gpol"].as_str().unwrap()).unwrap();
        std::fs::write(policy_path(root), &gpol).unwrap();
        assert_eq!(
            serde_json::to_value(load_policy(root, &mk, vid, epoch).unwrap()).unwrap(),
            expected
        );
        let gpo2 = vault::hex_decode(doc["gpo2"]["container"].as_str().unwrap()).unwrap();
        let nonce = vault::hex_decode(doc["gpo2"]["nonce"].as_str().unwrap()).unwrap();
        assert_eq!(&gpo2[..4], MAGIC_GPO2);
        assert_eq!(gpo2[4], SUITE_0X01);
        assert_eq!(&gpo2[5..37], nonce.as_slice());
        std::fs::write(policy_path(root), &gpo2).unwrap();
        assert_eq!(
            serde_json::to_value(load_policy(root, &mk, vid, epoch).unwrap()).unwrap(),
            expected
        );
    }

    #[test]
    fn truncated_policy_containers_are_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path();
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        seal_policy(
            root,
            &default_policy(&vault::hex_encode(&vid.0)),
            &meta_key(),
            vid,
            epoch,
        )
        .unwrap();
        let container = std::fs::read(policy_path(root)).unwrap();
        for len in [0usize, 4, 5, GPO2_HEADER_LEN - 1, container.len() - 1] {
            std::fs::write(policy_path(root), &container[..len]).unwrap();
            let r = load_policy(root, &meta_key(), vid, epoch);
            assert!(matches!(r, Err(Error::AuthFail)), "GPO2 len {len}: {r:?}");
        }
        let mut longer = container.clone();
        longer.push(0);
        std::fs::write(policy_path(root), &longer).unwrap();
        assert!(matches!(
            load_policy(root, &meta_key(), vid, epoch),
            Err(Error::AuthFail)
        ));
        let doc: serde_json::Value =
            serde_json::from_str(include_str!("../../../vectors/v1/policy.json")).unwrap();
        let gpol = vault::hex_decode(doc["gpol"].as_str().unwrap()).unwrap();
        for len in [0usize, 4, 5, GPOL_HEADER_LEN - 1, gpol.len() - 1] {
            std::fs::write(policy_path(root), &gpol[..len]).unwrap();
            let r = load_policy(root, &meta_key(), vid, epoch);
            assert!(matches!(r, Err(Error::AuthFail)), "GPOL len {len}: {r:?}");
        }
    }

    #[test]
    fn bad_magic_and_suite_are_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path();
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        seal_policy(
            root,
            &default_policy(&vault::hex_encode(&vid.0)),
            &meta_key(),
            vid,
            epoch,
        )
        .unwrap();
        let good = std::fs::read(policy_path(root)).unwrap();
        let mut bad_magic = good.clone();
        bad_magic[0] ^= 0x01;
        std::fs::write(policy_path(root), &bad_magic).unwrap();
        assert!(matches!(
            load_policy(root, &meta_key(), vid, epoch),
            Err(Error::AuthFail)
        ));
        let mut bad_suite = good.clone();
        bad_suite[4] = 0x02;
        std::fs::write(policy_path(root), &bad_suite).unwrap();
        assert!(matches!(
            load_policy(root, &meta_key(), vid, epoch),
            Err(Error::AuthFail)
        ));
    }

    #[test]
    fn gpo2_nonce_or_tag_bit_flip_is_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path();
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        seal_policy(
            root,
            &default_policy(&vault::hex_encode(&vid.0)),
            &meta_key(),
            vid,
            epoch,
        )
        .unwrap();
        let good = std::fs::read(policy_path(root)).unwrap();
        for index in [5usize, 37] {
            let mut flipped = good.clone();
            flipped[index] ^= 0x01;
            std::fs::write(policy_path(root), &flipped).unwrap();
            let r = load_policy(root, &meta_key(), vid, epoch);
            assert!(matches!(r, Err(Error::AuthFail)), "byte {index}: {r:?}");
        }
    }

    #[test]
    fn gpo2_is_bound_to_vault_and_epoch() {
        let d = tempdir().unwrap();
        let root = d.path();
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        seal_policy(
            root,
            &default_policy(&vault::hex_encode(&vid.0)),
            &meta_key(),
            vid,
            epoch,
        )
        .unwrap();
        assert!(matches!(
            load_policy(root, &meta_key(), vid, Epoch(2)),
            Err(Error::AuthFail)
        ));
        assert!(matches!(
            load_policy(root, &meta_key(), VaultId([0x02; 16]), epoch),
            Err(Error::AuthFail)
        ));
    }

    #[test]
    fn gpo2_fresh_nonce_breaks_keystream_reuse() {
        let d = tempdir().unwrap();
        let root = d.path();
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        let mut p1 = default_policy(&vault::hex_encode(&vid.0));
        let mut p2 = default_policy(&vault::hex_encode(&vid.0));
        p1.principals[0].prefixes = vec!["aaaaaaaaaaaaaaaa".into()];
        p2.principals[0].prefixes = vec!["bbbbbbbbbbbbbbbb".into()];
        seal_policy(root, &p1, &meta_key(), vid, epoch).unwrap();
        let c1 = std::fs::read(policy_path(root)).unwrap();
        let l1 = load_policy(root, &meta_key(), vid, epoch).unwrap();
        assert_eq!(l1.principals[0].prefixes, p1.principals[0].prefixes);
        seal_policy(root, &p2, &meta_key(), vid, epoch).unwrap();
        let c2 = std::fs::read(policy_path(root)).unwrap();
        let l2 = load_policy(root, &meta_key(), vid, epoch).unwrap();
        assert_eq!(l2.principals[0].prefixes, p2.principals[0].prefixes);
        let n1 = &c1[5..37];
        let n2 = &c2[5..37];
        assert_ne!(n1, n2, "GPO2 must draw a fresh nonce per seal");
        let pt1 = canonicalize(&serde_json::to_value(&p1).unwrap()).unwrap();
        let pt2 = canonicalize(&serde_json::to_value(&p2).unwrap()).unwrap();
        let ct1 = &c1[GPO2_HEADER_LEN..];
        let ct2 = &c2[GPO2_HEADER_LEN..];
        let overlap = pt1.len().min(pt2.len()).min(ct1.len()).min(ct2.len());
        let first = (0..overlap).find(|&i| pt1[i] != pt2[i]).unwrap();
        let xor_ct: Vec<u8> = (first..overlap).map(|i| ct1[i] ^ ct2[i]).collect();
        let xor_pt: Vec<u8> = (first..overlap).map(|i| pt1[i] ^ pt2[i]).collect();
        assert_ne!(
            xor_ct, xor_pt,
            "ciphertext XOR still reveals plaintext XOR after the first difference"
        );
    }

    #[test]
    fn wrong_meta_key_is_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        crate::vault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let p = agent_policy(&[Op::Read], &["scratch/"], None);
        seal_policy(&root, &p, &meta_key(), VaultId([0x01; 16]), Epoch(1)).unwrap();
        let wrong = [0x42u8; 32];
        let r = load_policy(&root, &wrong, VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn bad_magic_is_auth_fail() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        crate::vault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        std::fs::write(
            policy_path(&root),
            b"XXXX\x01aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
        let r = load_policy(&root, &meta_key(), VaultId([0x01; 16]), Epoch(1));
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    // ---- G0c: token narrows policy ----

    #[test]
    fn token_within_policy_issues() {
        let policy = agent_policy(
            &[Op::List, Op::Read, Op::Write],
            &["scratch/", "out/"],
            Some(1 << 20),
        );
        let t = agent_token(&[Op::Read, Op::Write], &["scratch/"], 1 << 16);
        let sealed = issue_narrow(&t, &ek(), &policy).unwrap();
        assert_eq!(&sealed[..4], crate::MAGIC_GTOK);
        let opened = inspect(&sealed, &ek(), NOW).unwrap();
        assert_eq!(opened.allow_ops, t.allow_ops);
    }

    #[test]
    fn token_op_not_in_policy_is_deny() {
        let policy = agent_policy(&[Op::List, Op::Read], &["scratch/"], None);
        let t = agent_token(&[Op::Read, Op::Write], &["scratch/"], 1 << 20);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn token_prefix_not_in_policy_is_deny() {
        let policy = agent_policy(&[Op::Read], &["scratch/"], None);
        let t = agent_token(&[Op::Read], &["keys/"], 1 << 20);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn token_max_bytes_over_policy_is_deny() {
        let policy = agent_policy(&[Op::Read], &["scratch/"], Some(1024));
        let t = agent_token(&[Op::Read], &["scratch/"], 2048);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn token_principal_not_in_policy_is_deny() {
        let policy = default_policy("v");
        let t = agent_token(&[Op::Read], &["scratch/"], 1 << 20);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn token_max_bytes_ok_when_policy_none() {
        let policy = agent_policy(&[Op::Read], &["scratch/"], None);
        let t = agent_token(&[Op::Read], &["scratch/"], 1 << 30);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(r.is_ok(), "got {r:?}");
    }

    #[test]
    fn narrows_policy_checks_subset_not_superset() {
        // token with admin when policy only grants read => deny
        let policy = agent_policy(&[Op::Read], &["scratch/"], None);
        let t = agent_token(&[Op::Read, Op::Admin], &["scratch/"], 1 << 20);
        let r = issue_narrow(&t, &ek(), &policy);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn errors_never_contain_isk() {
        let policy = agent_policy(&[Op::Read], &["scratch/"], Some(1024));
        let t = agent_token(&[Op::Read], &["scratch/"], 2048);
        let r = issue_narrow(&t, &ek(), &policy);
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "error leaks ISK: {s}");
        assert!(!s.contains('\u{7}'), "error leaks key bytes: {s}");
    }

    #[test]
    fn inject_and_read_do_not_imply_each_other() {
        let read_only = agent_policy(&[Op::Read], &["scratch/"], None);
        let who = PrincipalId("agent:facet-coder-3".into());
        assert_eq!(
            evaluate(&read_only, &who, Op::Read, "scratch/a").unwrap(),
            Verdict::Allow
        );
        assert_eq!(
            evaluate(&read_only, &who, Op::Inject, "scratch/a").unwrap(),
            Verdict::Deny
        );
        let inject_only = agent_policy(&[Op::Inject], &["scratch/"], None);
        assert_eq!(
            evaluate(&inject_only, &who, Op::Inject, "scratch/a").unwrap(),
            Verdict::Allow
        );
        assert_eq!(
            evaluate(&inject_only, &who, Op::Read, "scratch/a").unwrap(),
            Verdict::Deny
        );
    }

    #[test]
    fn default_policy_grants_inject_to_human_local_only() {
        let policy = default_policy("v");
        assert_eq!(policy.principals.len(), 1);
        assert_eq!(policy.principals[0].id.0, "human:local");
        assert!(policy.principals[0].ops.contains(&Op::Inject));
        assert!(policy.principals.iter().all(|g| g.id.0 == "human:local"));
        let mut human = agent_token(&[Op::Inject], &[""], 1 << 20);
        human.principal_id = PrincipalId("human:local".into());
        assert!(token_narrows_policy(&human, &policy).is_ok());
        let agent = agent_token(&[Op::Inject], &["scratch/"], 1 << 20);
        assert!(matches!(
            token_narrows_policy(&agent, &policy),
            Err(Error::PolicyDeny)
        ));
    }

    #[test]
    fn sealed_grant_is_not_widened_for_inject() {
        let policy = agent_policy(&[Op::List, Op::Read], &["scratch/"], None);
        let inject = agent_token(&[Op::Inject], &["scratch/"], 1 << 20);
        assert!(matches!(
            token_narrows_policy(&inject, &policy),
            Err(Error::PolicyDeny)
        ));
        let read = agent_token(&[Op::Read], &["scratch/"], 1 << 20);
        assert!(token_narrows_policy(&read, &policy).is_ok());
        assert!(!read.allow_ops.contains(&Op::Inject));
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn rp4_prefix_covers_boundary_algebra(segs in prop::collection::vec("[a-z]{1,6}",0..4)) {
            let path = segs.join("/"); prop_assert!(prefix_covers(&path,&path)); prop_assert!(prefix_covers("",&path));
        }
    }
}
