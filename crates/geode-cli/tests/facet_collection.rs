//! G1 (v0.2.4) — the shipped Facet collection `examples/facet-geode.yaml`
//! is well-formed and carries no literal secrets (07-hedronite-integration).
//!
//! Opens THAT file (no string copy): parses it as YAML, asserts the
//! required requests exist (`verify --output json`, `agent list` under a
//! prefix), and asserts every `secret: true` var is hydrated
//! `from: env:…` with no `value:` literal. A collection that hardcodes a
//! token, key path, or ISK fails here.

use std::path::PathBuf;

fn collection_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("examples")
        .join("facet-geode.yaml")
}

fn load() -> serde_yaml::Value {
    let text = std::fs::read_to_string(collection_path()).expect("read examples/facet-geode.yaml");
    serde_yaml::from_str(&text).expect("facet-geode.yaml parses as YAML")
}

fn request<'d>(doc: &'d serde_yaml::Value, name: &str) -> &'d serde_yaml::Value {
    doc["requests"]
        .as_sequence()
        .expect("requests is a list")
        .iter()
        .find(|r| r["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("request {name} present"))
}

fn args_of(request: &serde_yaml::Value) -> Vec<String> {
    request["args"]
        .as_sequence()
        .expect("args is a list")
        .iter()
        .map(|a| a.as_str().expect("arg is a string").to_owned())
        .collect()
}

#[test]
fn collection_parses_and_names_requests() {
    let doc = load();
    assert_eq!(doc["name"].as_str(), Some("geode-workstation"));
    for name in ["verify-vault", "list-scratch", "policy-check"] {
        let _ = request(&doc, name);
    }
}

#[test]
fn verify_request_is_json() {
    let doc = load();
    let args = args_of(request(&doc, "verify-vault"));
    assert!(args.iter().any(|a| a == "verify"), "args: {args:?}");
    assert!(args.iter().any(|a| a == "--output"), "args: {args:?}");
    assert!(args.iter().any(|a| a == "json"), "args: {args:?}");
}

#[test]
fn agent_list_request_lists_under_prefix() {
    let doc = load();
    let req = request(&doc, "list-scratch");
    let args = args_of(req);
    let agent = args.iter().position(|a| a == "agent").expect("agent verb");
    let list = args.iter().position(|a| a == "list").expect("list verb");
    assert!(agent < list, "agent precedes list: {args:?}");
    assert!(
        args.iter().any(|a| a.ends_with('/')),
        "a prefix arg (trailing /): {args:?}"
    );
    // The token rides the request env, never argv.
    assert_eq!(
        req["env"]["GEODE_TOKEN"].as_str(),
        Some("${geode_token}"),
        "GEODE_TOKEN from the secret var"
    );
    assert!(
        !args
            .iter()
            .any(|a| a.contains("GEODE_TOKEN") || a == "--token"),
        "token never in argv: {args:?}"
    );
}

#[test]
fn secret_vars_are_env_sourced_and_literal_free() {
    let doc = load();
    for req_name in ["verify-vault", "list-scratch", "policy-check"] {
        let vars = request(&doc, req_name)["vars"]
            .as_mapping()
            .expect("vars is a map");
        for (k, var) in vars {
            let key = k.as_str().expect("var name");
            let secret = var["secret"].as_bool() == Some(true);
            let has_value = !var["value"].is_null();
            let from_env = var["from"].as_str().is_some_and(|f| f.starts_with("env:"));
            if secret {
                assert!(from_env, "{req_name}:{key} secret var must be from: env:…");
                assert!(
                    !has_value,
                    "{req_name}:{key} secret var must not carry value:"
                );
            }
        }
    }
    // The two named secrets the brief requires.
    let list_vars = request(&doc, "list-scratch")["vars"]
        .as_mapping()
        .expect("vars");
    for key in ["geode_token", "geode_key_file"] {
        let var = list_vars
            .get(serde_yaml::Value::String(key.into()))
            .unwrap_or_else(|| panic!("list-scratch var {key}"));
        assert_eq!(var["secret"].as_bool(), Some(true), "{key} secret: true");
    }
}

#[test]
fn no_secret_literals_in_file_text() {
    let text = std::fs::read_to_string(collection_path()).expect("read examples/facet-geode.yaml");
    assert!(!text.contains("GTOK"), "no raw token magic");
    for line in text.lines() {
        let t = line.trim();
        if t.starts_with("value:") {
            assert!(!t.contains(".gkey"), "literal key path: {t}");
            assert!(!t.contains("/Users/"), "literal home path: {t}");
        }
    }
}
