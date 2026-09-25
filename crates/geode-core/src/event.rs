//! Facet / JSON event payloads (07-hedronite-integration 2; 05-cli 4).
//!
//! G0 (v0.2.4): a shipped core builder for `geode.event.v1` payloads that
//! carries ONLY public identifiers -- never ISK, EK, raw `GTOK`, `.gkey`
//! bytes, or passphrases. Facet still MUST redact anything matching the
//! names in [`FACET_REDACT_NAMES`] (07 2), but Geode JSON already omits
//! secrets; this module is the contract that guarantees it and lets the
//! CLI / adapters route event construction through one audited path.
//!
//! Public event fields: `schema`, `verb`, `ok`, `vault_id`, `epoch`,
//! `principal`, `path`, `content_root`, `plain_bytes`, `object_id`,
//! `files`, `key_id`, `truncated`, `sha256`, `error`. Never present: ISK,
//! EK, FEK, Name/Meta/Manifest/Token Key, passphrases, raw `GTOK` bytes,
//! `.gkey` file bytes. [`assert_event_safe`] is the guard; [`build_event`]
//! calls it before returning a payload.

use crate::{Error, Result};
use serde_json::{json, Map, Value};

/// Schema version bound into every event (05-cli 4).
pub const EVENT_SCHEMA: &str = "geode.event.v1";

/// Facet redact names (07-hedronite-integration 2). Facet MUST redact
/// anything matching these. Geode JSON already omits the corresponding
/// secrets; this const documents the contract for Facet collection
/// authors and adapters so a YAML author knows what `secret: true` covers.
///
/// These are matched as literal strings by Facet (the names `GKEY`,
/// `GTOK`, `PEM`, `GEODE_PASSPHRASE`), not as substrings of arbitrary
/// field values -- a path like `scratch/GTOK.log` is a public path, not a
/// leaked token.
pub const FACET_REDACT_NAMES: &[&str] = &["GKEY", "GTOK", "PEM", "GEODE_PASSPHRASE"];

/// Field names that MUST NEVER appear in an event payload (lowercase).
///
/// These are the secret-material names from 02-cryptography 2-3 and the
/// agent plane. An event carrying any of these (under any casing) is a
/// contract violation; [`assert_event_safe`] rejects it.
const FORBIDDEN_FIELDS: &[&str] = &[
    "isk",
    "identity_secret",
    "ek",
    "epoch_key",
    "fek",
    "name_key",
    "meta_key",
    "manifest_key",
    "token_key",
    "passphrase",
    "password",
    "secret",
    "private_key",
    "private_bytes",
    "key_bytes",
    "gkey_bytes",
    "token_bytes",
    "raw_token",
    "sealed_token",
    "session_key",
];

/// Magic prefixes that, when a string value hex-decodes to bytes starting
/// with one of these, mark the value as smuggled sealed material (a raw
/// `GTOK`, a `.gkey` file, a sealed manifest/policy). Catches a token/key
/// even if it lands under a benign field name like `notes`.
const SEALED_MAGIC_PREFIXES: &[&[u8]] = &[b"GDE1", b"GKEY", b"GTOK", b"GMFT", b"GPOL"];

/// True if `name` (case-insensitive) is a forbidden event field.
fn is_forbidden_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    FORBIDDEN_FIELDS.iter().any(|f| *f == lower)
}

/// True if `s` is a hex string whose decoded bytes start with a sealed
/// magic. Catches raw `GTOK` / `.gkey` bytes smuggled as a hex value.
fn looks_like_sealed_material(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < 8 || !trimmed.len().is_multiple_of(2) {
        return false;
    }
    if !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        return false;
    }
    let bytes = trimmed.as_bytes();
    let mut out = [0u8; 4];
    let mut i = 0;
    while i < 8 {
        out[i / 2] = (hex_nibble(bytes[i]) << 4) | hex_nibble(bytes[i + 1]);
        i += 2;
    }
    SEALED_MAGIC_PREFIXES.iter().any(|m| out.starts_with(m))
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => 0,
    }
}

/// Assert that a JSON event payload carries no secret material.
///
/// Recursively walks objects and arrays. Rejects if:
/// - any object key (case-insensitive) is a forbidden field name
///   ([`FORBIDDEN_FIELDS`]);
/// - any string value hex-decodes to bytes starting with a sealed magic
///   ([`SEALED_MAGIC_PREFIXES`]) -- i.e. a raw `GTOK` or `.gkey` smuggled
///   as a value.
///
/// Returns `Ok(())` if the payload is safe to emit to Facet / stdout.
/// Errors are [`Error::Format`] (no new `Error` variant) and never contain
/// ISK or key bytes -- the message names the offending field, not its value.
pub fn assert_event_safe(value: &Value) -> Result<()> {
    walk(value, "")
}

fn walk(value: &Value, path: &str) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                let field_path = if path.is_empty() {
                    k.clone()
                } else {
                    format!("{path}.{k}")
                };
                if is_forbidden_field(k) {
                    return Err(Error::Format(format!(
                        "event payload has forbidden field `{field_path}` (secret material)"
                    )));
                }
                walk(v, &field_path)?;
            }
        }
        Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                walk(v, &format!("{path}[{i}]"))?;
            }
        }
        Value::String(s) if looks_like_sealed_material(s) => {
            return Err(Error::Format(format!(
                "event payload value at `{path}` looks like sealed material (raw GTOK/GKEY)"
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Build a `geode.event.v1` event payload from public fields.
///
/// `verb` is the CLI verb (`"seal"`, `"agent_read"`, ...). `ok` is the
/// success flag. `extra` is a JSON object of public fields to merge
/// (`vault_id`, `epoch`, `principal`, `path`, `content_root`, ...). The
/// builder:
/// 1. asserts `extra` (and the merged doc) carry no secret material via
///    [`assert_event_safe`];
/// 2. returns the merged `geode.event.v1` payload.
///
/// Returns [`Error::Format`] (no new variant) if `extra` is not an object
/// or contains a forbidden field / sealed-material value. The error
/// message names the offending field, never the secret value.
pub fn build_event(verb: &str, ok: bool, extra: Value) -> Result<Value> {
    if !extra.is_object() {
        return Err(Error::Format(
            "event extra must be a JSON object of public fields".into(),
        ));
    }
    assert_event_safe(&extra)?;
    let mut doc = json!({
        "schema": EVENT_SCHEMA,
        "verb": verb,
        "ok": ok,
    });
    // Consume `extra` by moving its object out -- avoids cloning the
    // field values and satisfies clippy::needless_pass_by_value.
    if let Value::Object(x) = extra {
        if let Some(base) = doc.as_object_mut() {
            for (k, v) in x {
                base.insert(k, v);
            }
        }
    }
    assert_event_safe(&doc)?;
    Ok(doc)
}

/// Build an error event payload (`ok: false`) with an `error` object.
///
/// `code` is the machine code (`"auth_fail"`, `"policy_deny"`, ...);
/// `message` is `err.to_string()` from the caller. The message is
/// screened by [`assert_event_safe`]; a secret leaking into an error
/// string is rejected (errors never contain ISK -- 12 secret discipline).
pub fn build_error_event(verb: &str, code: &str, message: &str) -> Result<Value> {
    let extra = json!({
        "error": {"code": code, "message": message},
    });
    build_event(verb, false, extra)
}

/// Construct a Facet agent-plane event (06-agent-plane 5) from the public
/// fields a tool call produces. This is the shape the CLI `facet_event`
/// helper SHOULD route through so one audited path builds Facet events.
///
/// All arguments are public identifiers. `content_root` is hex-encoded
/// (it is a public hash, not a key). `principal` is the token's
/// `principal_id` (public). No ISK / EK / raw `GTOK` is accepted by this
/// function; the sealed token is never an event field.
#[allow(clippy::too_many_arguments)]
pub fn build_facet_event(
    vault_id_hex: &str,
    epoch: u32,
    verb: &str,
    principal: &str,
    path: &str,
    content_root_hex: Option<&str>,
    extra: Option<Value>,
) -> Result<Value> {
    let mut fields = Map::new();
    fields.insert("vault_id".into(), json!(vault_id_hex));
    fields.insert("epoch".into(), json!(epoch));
    fields.insert("principal".into(), json!(principal));
    fields.insert("path".into(), json!(path));
    if let Some(root) = content_root_hex {
        fields.insert("content_root".into(), json!(root));
    }
    if let Some(x) = extra {
        match x {
            Value::Object(o) => {
                for (k, v) in o {
                    fields.insert(k, v);
                }
            }
            _ => return Err(Error::Format("facet event extra must be an object".into())),
        }
    }
    build_event(verb, true, Value::Object(fields))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn safe_event() -> Value {
        build_event(
            "agent_read",
            true,
            json!({
                "vault_id": "01010101010101010101010101010101",
                "epoch": 1,
                "principal": "agent:facet-coder-3",
                "path": "scratch/plan.md",
                "content_root": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                "plain_bytes": 11,
            }),
        )
        .unwrap()
    }

    // ---- G0b: FACET_REDACT_NAMES ----

    #[test]
    fn facet_redact_names_lists_all_four() {
        assert_eq!(
            FACET_REDACT_NAMES,
            &["GKEY", "GTOK", "PEM", "GEODE_PASSPHRASE"]
        );
    }

    // ---- G0a: shipped build_event / assert_event_safe ----

    #[test]
    fn build_event_produces_schema_v1() {
        let e = safe_event();
        assert_eq!(e["schema"], "geode.event.v1");
        assert_eq!(e["verb"], "agent_read");
        assert_eq!(e["ok"], true);
        assert_eq!(e["principal"], "agent:facet-coder-3");
    }

    #[test]
    fn safe_event_passes_guard() {
        let e = safe_event();
        assert!(assert_event_safe(&e).is_ok());
    }

    #[test]
    fn build_event_rejects_non_object_extra() {
        let r = build_event("seal", true, json!(["not", "an", "object"]));
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn build_event_rejects_isk_field() {
        let r = build_event("seal", true, json!({"vault_id": "01", "isk": "deadbeef"}));
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
        let s = format!("{}", r.unwrap_err());
        assert!(s.contains("isk"), "names the field: {s}");
        assert!(!s.contains("deadbeef"), "leaks value: {s}");
    }

    #[test]
    fn build_event_rejects_passphrase_field_case_insensitive() {
        let r = build_event("seal", true, json!({"Passphrase": "x"}));
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn build_event_rejects_epoch_key_field() {
        let r = build_event("seal", true, json!({"epoch_key": "ab"}));
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn build_event_rejects_raw_gtok_hex_value() {
        // "GTOK" magic = 47 54 4f 4b
        let r = build_event(
            "agent_token_issue",
            true,
            json!({"token": "47544f4b0101a5a5a5a5a5a5a5a5a5a5"}),
        );
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
        let s = format!("{}", r.unwrap_err());
        assert!(s.contains("sealed material"), "names the issue: {s}");
        assert!(!s.contains("47544f4b"), "leaks value: {s}");
    }

    #[test]
    fn build_event_rejects_raw_gkey_hex_value() {
        // "GKEY" magic = 47 4b 45 59
        let r = build_event("keygen", true, json!({"key": "474b4559010203"}));
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn build_event_allows_normal_hex_content_root() {
        // content_root is a public hash, not a key; must not be rejected
        let r = build_event(
            "seal",
            true,
            json!({"content_root": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"}),
        );
        assert!(r.is_ok(), "got {r:?}");
    }

    #[test]
    fn build_event_allows_path_containing_gtok_substring() {
        // a path like scratch/GTOK.log is public, not a leaked token
        let r = build_event("agent_read", true, json!({"path": "scratch/GTOK.log"}));
        assert!(r.is_ok(), "got {r:?}");
    }

    #[test]
    fn build_error_event_works() {
        let e = build_error_event("seal", "auth_fail", "authentication failure").unwrap();
        assert_eq!(e["ok"], false);
        assert_eq!(e["error"]["code"], "auth_fail");
        assert_eq!(e["error"]["message"], "authentication failure");
    }

    #[test]
    fn build_error_event_rejects_sealed_material_in_message() {
        // a raw GTOK hex leaking into an error string is rejected by the guard
        let r = build_error_event("seal", "auth_fail", "47544f4b0101a5a5a5a5a5a5a5a5a5a5");
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn build_facet_event_works() {
        let e = build_facet_event(
            "01010101010101010101010101010101",
            1,
            "agent_read",
            "agent:facet-coder-3",
            "scratch/plan.md",
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"),
            None,
        )
        .unwrap();
        assert_eq!(e["schema"], "geode.event.v1");
        assert_eq!(e["verb"], "agent_read");
        assert_eq!(e["principal"], "agent:facet-coder-3");
        assert_eq!(
            e["content_root"],
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        );
    }

    #[test]
    fn build_facet_event_rejects_secret_extra() {
        let r = build_facet_event(
            "01",
            1,
            "agent_read",
            "agent:x",
            "scratch/x",
            None,
            Some(json!({"passphrase": "hunter2"})),
        );
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn assert_event_safe_rejects_nested_secret() {
        let v = json!({
            "vault_id": "01",
            "error": {"code": "x", "message": "ok", "secret": "deadbeef"},
        });
        let r = assert_event_safe(&v);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn assert_event_safe_rejects_array_secret() {
        let v = json!({"items": [{"isk": "ab"}]});
        let r = assert_event_safe(&v);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn errors_never_contain_isk_bytes() {
        let r = build_event("seal", true, json!({"isk": "deadbeef"}));
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "leaks ISK: {s}");
        assert!(!s.contains("deadbeef"), "leaks value: {s}");
    }
}
