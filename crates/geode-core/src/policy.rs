//! Policy document and evaluation (10-policy; `SPEC` 6).
//!
//! G0b: defines the policy types and the default-deny evaluation. The
//! storage path (`policy.json.sealed` under `MetaKey`) lands in G2; token
//! narrowing lands in G2/agent plane. Evaluation here is the reference
//! monitor's question: "may this principal do this op on this path?"

use crate::{Error, Result};

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
/// G2 will tighten to the full spec normalization.
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn prefix_narrowing_denies_outside() {
        let p = Policy {
            version: 1,
            vault_id: "v".into(),
            default: DefaultVerdict::Deny,
            principals: vec![PrincipalGrant {
                id: PrincipalId("agent:facet-coder-3".into()),
                ops: vec![Op::Read],
                prefixes: vec!["scratch/".into()],
                max_bytes: None,
                max_calls_per_10s: None,
            }],
        };
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
}
