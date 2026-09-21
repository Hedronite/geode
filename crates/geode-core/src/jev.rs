//! Soft Jev remainder: Choice `{allow, deny, ask}` on non-prefix intent.
//!
//! Facet `TypeSafe` / System One is the transport; this module classifies.
//! It never seals, opens, or verifies, and it never sees a `GTOK` or ISK.
//! Prefix / `../` / TTL / MAC stay in [`crate::agent_ops`] / [`crate::token`].

use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::agent_ops::code_scope_path;
use crate::policy::PrincipalId;
use crate::{Error, Result};

/// Bundled Facet `OpenCollection` (scope-remainder recipe).
pub const FACET_COLLECTION: &str =
    include_str!("../embedded/opencollection.yml");
pub const FACET_SELECTOR: &str = "items/0/items/0";
pub const FACET_ENVIRONMENT: &str = "typesafe";

const CONFIDENCE_FLOOR: f64 = 0.6;
const ESCALATE_HOLD: f64 = 0.6;
const INTENT_MAX: usize = 4000;
const DIGEST_MAX: usize = 128;

/// Shipped System One questions (Choice + Noul).
#[must_use]
pub fn questions() -> Value {
    json!({
        "scope": {
            "type": "choice",
            "instructions": "Given this non-prefix remainder (declared intent vs granted prefix/path/op), should the agent proceed? Code already owns prefix, '..', TTL, and MAC. Shadow only — do not seal, open, or verify.",
            "criteria": {
                "allow": "Intent matches the grant; a human may proceed later. Not a write grant and not a token decision.",
                "deny": "Odd, out of semantic scope, or looks like a secret leak — do not treat as allow",
                "ask": "Ambiguous or high-stakes — need a human. Not allow."
            }
        },
        "escalate": {
            "type": "noul",
            "instructions": "Is this an odd grant that should be held for a human before write?",
            "criteria": {
                "true": "Unusual path, surprising write, or the declared intent does not match the grant",
                "false": "Ordinary in-grant work; no hold"
            }
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Choice {
    Allow,
    Deny,
    Ask,
}

impl Choice {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Choice::Allow => "allow",
            Choice::Deny => "deny",
            Choice::Ask => "ask",
        }
    }

    fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "allow" => Some(Choice::Allow),
            "deny" => Some(Choice::Deny),
            "ask" => Some(Choice::Ask),
            _ => None,
        }
    }
}

/// Public remainder fields. Never a token, ISK, or raw body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemainderAsk {
    pub verb: String,
    pub path: String,
    pub principal: String,
    pub allow_prefix: Vec<String>,
    pub intent: String,
    pub body_digest: Option<String>,
}

/// Shadow report for one remainder. Never persisted. Never a write grant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub shadow: bool,
    /// Shadow: a Jev Choice is never a write / token grant.
    pub auto_allow: bool,
    pub choice: Choice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalate: Option<f64>,
    pub status: String,
    pub transport: String,
    pub verb: String,
    pub path: String,
    pub intent: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Decision {
    fn ask(
        transport: &str,
        status: &str,
        ask: &RemainderAsk,
        confidence: Option<f64>,
        escalate: Option<f64>,
        reason: Option<String>,
    ) -> Self {
        Self {
            shadow: true,
            auto_allow: false,
            choice: Choice::Ask,
            confidence,
            escalate,
            status: status.to_string(),
            transport: transport.to_string(),
            verb: ask.verb.clone(),
            path: ask.path.clone(),
            intent: ask.intent.clone(),
            reason,
        }
    }
}

/// How to reach System One. Never holds a token, ISK, or a key value.
pub enum Transport {
    None {
        reason: &'static str,
    },
    Facet {
        bin: PathBuf,
    },
    Fixture {
        path: PathBuf,
    },
    #[cfg(test)]
    Fake(FakeScript),
}

impl std::fmt::Debug for Transport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Transport::None { reason } => f.debug_struct("None").field("reason", reason).finish(),
            Transport::Facet { bin } => f.debug_struct("Facet").field("bin", bin).finish(),
            Transport::Fixture { path } => f.debug_struct("Fixture").field("path", path).finish(),
            #[cfg(test)]
            Transport::Fake(_) => write!(f, "Fake"),
        }
    }
}

/// Canned System One body. Offline tests only.
#[cfg(test)]
#[derive(Clone, Debug)]
pub struct FakeScript {
    reply: Value,
}

#[cfg(test)]
impl FakeScript {
    #[must_use]
    pub fn reply(reply: Value) -> Self {
        Self { reply }
    }
}

impl Transport {
    /// MCP wrapper: only when `GEODE_JEV_TRANSPORT` is set. Never reads
    /// `$TYPESAFE_API_KEY` or `$GEODE_TOKEN`.
    #[must_use]
    pub fn resolve() -> Self {
        match std::env::var("GEODE_JEV_TRANSPORT") {
            Ok(v) if v.eq_ignore_ascii_case("none") => Transport::None {
                reason: "GEODE_JEV_TRANSPORT=none",
            },
            Ok(v) if v.eq_ignore_ascii_case("facet") => match find_on_path("facet") {
                Some(bin) => Transport::Facet { bin },
                None => Transport::None {
                    reason: "facet_not_on_path",
                },
            },
            Ok(v) if v.eq_ignore_ascii_case("fixture") => {
                match std::env::var("GEODE_JEV_FIXTURE") {
                    Ok(path) if !path.trim().is_empty() => Transport::Fixture {
                        path: PathBuf::from(path),
                    },
                    _ => Transport::None {
                        reason: "fixture_path_absent",
                    },
                }
            },
            Ok(_) => Transport::None {
                reason: "unknown_GEODE_JEV_TRANSPORT",
            },
            Err(_) => Transport::None {
                reason: "GEODE_JEV_TRANSPORT unset",
            },
        }
    }

    /// Named-ask CLI: explicit env, else `facet` on `$PATH`, else none.
    #[must_use]
    pub fn resolve_cli() -> Self {
        if std::env::var_os("GEODE_JEV_TRANSPORT").is_some() {
            return Self::resolve();
        }
        if let Some(bin) = find_on_path("facet") {
            return Transport::Facet { bin };
        }
        Transport::None {
            reason: "facet_not_on_path",
        }
    }

    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Transport::None { .. } => "none",
            Transport::Facet { .. } => "facet",
            Transport::Fixture { .. } => "fixture",
            #[cfg(test)]
            Transport::Fake(_) => "fake",
        }
    }

    #[must_use]
    pub fn is_configured() -> bool {
        std::env::var_os("GEODE_JEV_TRANSPORT").is_some()
    }

    fn decide(&self, state: &str) -> std::result::Result<Value, String> {
        match self {
            Transport::None { reason } => Err((*reason).into()),
            Transport::Facet { bin } => facet_decide(bin, state),
            Transport::Fixture { path } => fixture_decide(path),
            #[cfg(test)]
            Transport::Fake(script) => Ok(script.reply.clone()),
        }
    }
}

fn find_on_path(name: &str) -> Option<PathBuf> {
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// BLAKE3 hex of `body`. Public digest — never the body itself.
#[must_use]
pub fn body_digest(body: &[u8]) -> String {
    blake3::hash(body).to_hex().to_string()
}

/// Bound remainder state. No token, ISK, GTOK, or raw body.
pub fn remainder_state(ask: &RemainderAsk) -> Result<String> {
    reject_secret_text(&ask.intent, "intent")?;
    reject_secret_text(&ask.path, "path")?;
    reject_secret_text(&ask.principal, "principal")?;
    if let Some(d) = &ask.body_digest {
        reject_secret_text(d, "body_digest")?;
    }
    let extra = json!({
        "verb": ask.verb,
        "path": ask.path,
        "principal": ask.principal,
        "allow_prefix": ask.allow_prefix,
        "intent": clip(&ask.intent, INTENT_MAX),
        "body_digest": ask.body_digest.as_deref().map(|d| clip(d, DIGEST_MAX)),
    });
    crate::event::assert_event_safe(&extra)?;
    let prefixes = ask.allow_prefix.join(", ");
    let digest = ask
        .body_digest
        .as_deref()
        .map_or_else(|| "(none)".into(), |d| clip(d, DIGEST_MAX));
    Ok(format!(
        "Non-prefix remainder (code already owns prefix, '..', TTL, MAC).\n\
         Jev does not seal, open, or verify. Shadow: classify only.\n\n\
         Verb: {}\nPath: {}\nPrincipal: {}\nAllow prefixes: {prefixes}\n\
         Intent:\n{}\nBody digest: {digest}\n\n\
         ask/deny/low-conf is not allow. Never a token or key.",
        ask.verb,
        ask.path,
        ask.principal,
        clip(&ask.intent, INTENT_MAX),
    ))
}

fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end])
}

fn fixture_decide(path: &Path) -> std::result::Result<Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str(&text).map_err(|e| format!("fixture json: {e}"))
}

fn facet_decide(bin: &Path, state: &str) -> std::result::Result<Value, String> {
    let dir = tempfile_dir()?;
    let yaml = dir.join("opencollection.yml");
    std::fs::write(&yaml, FACET_COLLECTION).map_err(|e| e.to_string())?;
    let out = Command::new(bin)
        .arg("--json")
        .arg("request")
        .arg("run")
        .arg(&yaml)
        .arg(FACET_SELECTOR)
        .arg("--environment")
        .arg(FACET_ENVIRONMENT)
        .arg("--no-record")
        .arg("--var")
        .arg(format!("state={state}"))
        .output()
        .map_err(|e| e.to_string())?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        return Err(format!(
            "facet exit {}: {}",
            out.status,
            clip(&format!("{err}{stdout}"), 300)
        ));
    }
    let v: Value = serde_json::from_slice(&out.stdout).map_err(|e| format!("facet json: {e}"))?;
    parse_facet_answers(&v)
}

fn tempfile_dir() -> std::result::Result<PathBuf, String> {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("geode-jev-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    Ok(dir)
}

fn parse_facet_answers(v: &Value) -> std::result::Result<Value, String> {
    let content = v
        .pointer("/response/body/content")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            if v.get("error").is_some() {
                format!("facet error: {}", v["error"])
            } else {
                "facet response missing body".into()
            }
        })?;
    serde_json::from_str(content).map_err(|e| format!("facet body json: {e}"))
}

fn parse_remainder_op(verb: &str) -> Result<()> {
    match verb {
        "list" | "read" | "write" => Ok(()),
        "seal" | "open" | "verify" | "mount" | "admin" => Err(Error::Format(
            "Jev remainder is not consulted for seal/open/verify (or mount/admin)".into(),
        )),
        other => Err(Error::Format(format!(
            "unknown remainder op '{other}' (list|read|write)"
        ))),
    }
}

/// Classify one remainder. Code path/prefix first; Jev never overrides.
/// Missing transport / low confidence / empty → `ask`. `auto_allow` is always false.
pub fn ask(ask: &RemainderAsk, transport: &Transport) -> Result<Decision> {
    parse_remainder_op(&ask.verb)?;
    let principal = PrincipalId(ask.principal.clone());
    principal.validate()?;
    if ask.allow_prefix.is_empty() {
        return Err(Error::Format(
            "missing --allow-prefix (code owns the prefix gate)".into(),
        ));
    }
    // Code-owned: any `..` or prefix miss is not a Jev question.
    let _norm = code_scope_path(&ask.path, &ask.allow_prefix)?;
    let state = remainder_state(ask)?;

    if let Transport::None { reason } = &transport {
        return Ok(Decision::ask(
            "none",
            "unavailable",
            ask,
            None,
            None,
            Some((*reason).into()),
        ));
    }

    match transport.decide(&state) {
        Ok(body) => Ok(decision_from_answers(transport.name(), ask, &body)),
        Err(reason) => Ok(Decision::ask(
            transport.name(),
            "unavailable",
            ask,
            None,
            None,
            Some(reason),
        )),
    }
}

/// Parse a System One `answers` object. Empty / low confidence → ask.
#[must_use]
pub fn decision_from_answers(transport: &str, ask: &RemainderAsk, body: &Value) -> Decision {
    let answers = body.get("answers").unwrap_or(body);
    let choice_raw = answers.pointer("/scope/choice").and_then(Value::as_str);
    let choice_conf = answers.pointer("/scope/confidence").and_then(Value::as_f64);
    let escalate = answers.pointer("/escalate/noul").and_then(Value::as_f64);
    let escalate_conf = answers
        .pointer("/escalate/confidence")
        .and_then(Value::as_f64);
    let confidence = [choice_conf, escalate_conf]
        .into_iter()
        .flatten()
        .reduce(f64::min);
    let parsed = choice_raw.and_then(Choice::parse);
    let empty = parsed.is_none();
    let low = confidence.is_some_and(|c| c < CONFIDENCE_FLOOR);

    if empty || low {
        let status = if empty { "uncertain" } else { "low_confidence" };
        let reason = if empty {
            Some("empty_or_unknown_choice".into())
        } else {
            Some(format!("confidence below {CONFIDENCE_FLOOR}"))
        };
        return Decision::ask(transport, status, ask, confidence, escalate, reason);
    }

    let mut choice = parsed.expect("parsed after empty check");
    let mut status = "judged".to_string();
    let write = ask.verb == "write";
    if write && choice == Choice::Allow && escalate.is_some_and(|n| n >= ESCALATE_HOLD) {
        choice = Choice::Ask;
        status = "escalate".into();
    }

    Decision {
        shadow: true,
        auto_allow: false,
        choice,
        confidence,
        escalate,
        status,
        transport: transport.to_string(),
        verb: ask.verb.clone(),
        path: ask.path.clone(),
        intent: ask.intent.clone(),
        reason: None,
    }
}

fn reject_secret_text(text: &str, field: &str) -> Result<()> {
    let lower = text.to_ascii_lowercase();
    let trimmed = text.trim();
    if lower.contains("sk-")
        || lower.contains("bearer ")
        || lower.contains("typesafe_api_key")
        || lower.contains("api_key=")
        || lower.contains("geode_token")
        || lower.contains("geode_passphrase")
        || lower.contains("isk=")
        || lower.contains("isk:")
        || trimmed.starts_with("GTOK")
        || looks_like_gtok_hex(text)
    {
        return Err(Error::Format(format!(
            "{field} must not carry a token, ISK, TypeSafe key, or Authorization material"
        )));
    }
    Ok(())
}

fn looks_like_gtok_hex(s: &str) -> bool {
    let t = s.trim();
    t.len() >= 8 && t.len() % 2 == 0 && t.to_ascii_lowercase().starts_with("47544f4b")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> RemainderAsk {
        RemainderAsk {
            verb: "write".into(),
            path: "scratch/note.md".into(),
            principal: "agent:test".into(),
            allow_prefix: vec!["scratch/".into()],
            intent: "seal a scratch note".into(),
            body_digest: Some("abc123".into()),
        }
    }

    fn judged_body(choice: &str, noul: f64, conf: f64) -> Value {
        json!({
            "answers": {
                "scope": { "type": "choice", "choice": choice, "confidence": conf },
                "escalate": { "type": "noul", "noul": noul, "confidence": conf }
            }
        })
    }

    #[test]
    fn collection_is_secret_and_shadow_and_has_no_key() {
        assert!(!FACET_COLLECTION.contains("sk-"));
        assert!(!FACET_COLLECTION.contains("Bearer ts_"));
        assert!(!FACET_COLLECTION.contains("GTOK"));
        assert!(
            FACET_COLLECTION.contains("$TYPESAFE_API_KEY"),
            "comments may name the env var; the YAML must not bake a value"
        );
        let body = FACET_COLLECTION.split("data: |-").nth(1).unwrap_or("");
        assert!(
            !body.contains("TYPESAFE_API_KEY"),
            "recipe JSON must not mention the key"
        );
        assert!(FACET_COLLECTION.contains("secret: true"));
        assert!(FACET_COLLECTION.contains("typesafeApiKey"));
        assert!(FACET_COLLECTION.contains("jevShadow"));
        assert!(FACET_COLLECTION.contains("\"allow\""));
        assert!(FACET_COLLECTION.contains("\"deny\""));
        assert!(FACET_COLLECTION.contains("\"ask\""));
        assert!(FACET_COLLECTION.contains("\"type\": \"choice\""));
        assert!(FACET_COLLECTION.contains("\"type\": \"noul\""));
        assert!(!questions().to_string().contains("TYPESAFE"));
        assert!(!FACET_COLLECTION.to_ascii_lowercase().contains("stanley"));
        assert!(!FACET_COLLECTION.to_ascii_lowercase().contains(" pi "));
    }

    #[test]
    fn empty_or_low_confidence_asks_and_never_auto_allows() {
        let a = sample();
        let empty = decision_from_answers("fake", &a, &json!({}));
        assert_eq!(empty.choice, Choice::Ask);
        assert_eq!(empty.status, "uncertain");
        assert!(!empty.auto_allow && empty.shadow);

        let low = decision_from_answers("fake", &a, &judged_body("allow", 0.0, 0.2));
        assert_eq!(low.choice, Choice::Ask);
        assert_eq!(low.status, "low_confidence");
        assert!(!low.auto_allow);

        let ok = decision_from_answers("fake", &a, &judged_body("allow", 0.0, 0.95));
        assert_eq!(ok.choice, Choice::Allow);
        assert_eq!(ok.status, "judged");
        assert!(!ok.auto_allow && ok.shadow);
        assert_eq!(ok.confidence, Some(0.95));
        assert_eq!(ok.escalate, Some(0.0));
    }

    #[test]
    fn deny_and_ask_are_not_remapped_to_allow() {
        let a = sample();
        let deny = decision_from_answers("fake", &a, &judged_body("deny", 0.0, 0.99));
        assert_eq!(deny.choice, Choice::Deny);
        assert!(!deny.auto_allow);
        let ask_c = decision_from_answers("fake", &a, &judged_body("ask", 0.1, 0.9));
        assert_eq!(ask_c.choice, Choice::Ask);
        assert!(!ask_c.auto_allow);
    }

    #[test]
    fn unknown_choice_asks() {
        let a = sample();
        let d = decision_from_answers("fake", &a, &judged_body("merge", 1.0, 0.99));
        assert_eq!(d.choice, Choice::Ask);
        assert_eq!(d.status, "uncertain");
        assert!(!d.auto_allow);
    }

    #[test]
    fn write_noul_hold_remaps_allow_to_ask() {
        let a = sample();
        let d = decision_from_answers("fake", &a, &judged_body("allow", 0.9, 0.95));
        assert_eq!(d.choice, Choice::Ask);
        assert_eq!(d.status, "escalate");
        assert!(!d.auto_allow);
        let read = RemainderAsk {
            verb: "read".into(),
            ..a
        };
        let r = decision_from_answers("fake", &read, &judged_body("allow", 0.9, 0.95));
        assert_eq!(r.choice, Choice::Allow);
        assert_eq!(r.status, "judged");
    }

    #[test]
    fn remainder_state_binds_public_fields_and_clips() {
        let mut a = sample();
        a.intent = "α".repeat(5000);
        let s = remainder_state(&a).unwrap();
        assert!(s.contains("Path: scratch/note.md"));
        assert!(s.contains("Allow prefixes: scratch/"));
        assert!(s.contains("Body digest: abc123"));
        assert!(s.contains("Jev does not seal, open, or verify"));
        assert!(s.len() < 5000 + 800, "intent clipped, got {}", s.len());
        assert!(!s.contains("TYPESAFE"));
        assert!(!s.contains("GTOK"));
        assert!(!s.contains("GEODE_TOKEN"));
    }

    #[test]
    fn missing_transport_asks_without_allow() {
        let d = ask(
            &sample(),
            &Transport::None {
                reason: "facet_not_on_path",
            },
        )
        .unwrap();
        assert_eq!(d.choice, Choice::Ask);
        assert_eq!(d.status, "unavailable");
        assert!(!d.auto_allow && d.shadow);
        assert_eq!(d.reason.as_deref(), Some("facet_not_on_path"));
    }

    #[test]
    fn fake_allow_is_shadow_only() {
        let d = ask(
            &sample(),
            &Transport::Fake(FakeScript::reply(judged_body("deny", 0.0, 0.9))),
        )
        .unwrap();
        assert_eq!(d.choice, Choice::Deny);
        assert!(!d.auto_allow && d.shadow);
        assert_eq!(d.transport, "fake");
    }

    #[test]
    fn secret_material_is_rejected() {
        let mut a = sample();
        a.intent = "use TYPESAFE_API_KEY=sk-live".into();
        let err = ask(
            &a,
            &Transport::None {
                reason: "x",
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("must not carry"));
    }

    #[test]
    fn gtok_hex_in_intent_is_rejected() {
        let mut a = sample();
        a.intent = "47544f4b0101a5a5".into();
        let err = ask(&a, &Transport::None { reason: "x" }).unwrap_err();
        assert!(err.to_string().contains("must not carry"));
    }

    #[test]
    fn dotdot_is_code_deny_without_jev() {
        let mut a = sample();
        a.path = "scratch/../keys/x".into();
        let err = ask(
            &a,
            &Transport::Fake(FakeScript::reply(judged_body("allow", 0.0, 0.99))),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Format(_)), "got {err:?}");
    }

    #[test]
    fn outside_prefix_is_code_policy_deny_without_jev() {
        let mut a = sample();
        a.path = "keys/prod.pem".into();
        let err = ask(
            &a,
            &Transport::Fake(FakeScript::reply(judged_body("allow", 0.0, 0.99))),
        )
        .unwrap_err();
        assert!(matches!(err, Error::PolicyDeny), "got {err:?}");
    }

    #[test]
    fn seal_open_verify_are_not_remainder_ops() {
        for verb in ["seal", "open", "verify"] {
            let mut a = sample();
            a.verb = verb.into();
            let err = ask(&a, &Transport::None { reason: "x" }).unwrap_err();
            assert!(matches!(err, Error::Format(_)), "{verb}: {err:?}");
        }
    }

    #[test]
    fn resolve_without_env_is_none_and_ignores_typesafe_key() {
        let old_force = std::env::var_os("GEODE_JEV_TRANSPORT");
        let old_key = std::env::var_os("TYPESAFE_API_KEY");
        let old_tok = std::env::var_os("GEODE_TOKEN");
        std::env::remove_var("GEODE_JEV_TRANSPORT");
        std::env::set_var("TYPESAFE_API_KEY", "sk-must-not-be-read");
        std::env::set_var("GEODE_TOKEN", "47544f4b00");
        let t = Transport::resolve();
        match old_force {
            Some(v) => std::env::set_var("GEODE_JEV_TRANSPORT", v),
            None => std::env::remove_var("GEODE_JEV_TRANSPORT"),
        }
        match old_key {
            Some(v) => std::env::set_var("TYPESAFE_API_KEY", v),
            None => std::env::remove_var("TYPESAFE_API_KEY"),
        }
        match old_tok {
            Some(v) => std::env::set_var("GEODE_TOKEN", v),
            None => std::env::remove_var("GEODE_TOKEN"),
        }
        assert!(matches!(t, Transport::None { reason } if reason == "GEODE_JEV_TRANSPORT unset"));
    }

    #[test]
    fn facet_response_body_is_unwrapped() {
        let inner = judged_body("ask", 0.0, 0.91);
        let wrapped = json!({
            "response": { "body": { "content": inner.to_string() } }
        });
        let answers = parse_facet_answers(&wrapped).unwrap();
        let d = decision_from_answers("facet", &sample(), &answers);
        assert_eq!(d.choice, Choice::Ask);
        assert!(!d.auto_allow);
    }

    #[test]
    fn body_digest_is_blake3() {
        assert_eq!(body_digest(b"hello"), blake3::hash(b"hello").to_hex().to_string());
    }
}
