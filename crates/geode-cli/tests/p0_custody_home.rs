//! P0 G1 — lint the checked-in `geode run` argv for `FACET_SECRET_KEY`.
//!
//! The fixture is interim argv and nothing else. This test reads that file
//! and fails when a SPEC rule breaks. It does not spawn.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const FIXTURE: &str = "tests/fixtures/p0-facet-secret-key.args";
const PREFIX: [&str; 3] = ["request", "run", "--no-record"];

fn raw() -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(FIXTURE);
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

fn argv(text: &str) -> Vec<String> {
    assert!(text.ends_with('\n'), "fixture must end in a newline");
    text.lines()
        .enumerate()
        .map(|(i, line)| {
            let n = i + 1;
            assert!(!line.is_empty(), "line {n} is blank");
            assert!(!line.starts_with('#'), "line {n} is a comment");
            assert_eq!(line.trim(), line, "line {n} has surrounding whitespace");
            line.to_string()
        })
        .collect()
}

fn values<'a>(args: &'a [String], flag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < args.len() {
        if args[i] == flag {
            let next = args
                .get(i + 1)
                .unwrap_or_else(|| panic!("{flag} has no value"));
            assert!(
                !next.starts_with('-'),
                "{flag} value looks like another flag: {next}"
            );
            out.push(next.as_str());
            i += 2;
        } else {
            i += 1;
        }
    }
    out
}

fn vault_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('$')
        && !path
            .split('/')
            .any(|seg| seg.is_empty() || seg == "." || seg == "..")
        && path.contains('/')
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '.' | '_' | '-'))
}

fn has_secret_bytes(text: &str) -> bool {
    const MARKERS: [&str; 6] = ["sk-", "AKIA", "ghp_", "github_pat_", "xox", "BEGIN PRIVATE"];
    MARKERS.iter().any(|m| text.contains(m))
}

/// Every SPEC rule `text` breaks. Empty means the argv is valid.
fn broken_rules(text: &str) -> BTreeSet<&'static str> {
    let mut bad = BTreeSet::new();
    if text.contains('\0') {
        bad.insert("nul");
    }
    if text.contains("FACET_DATA_DIR") {
        bad.insert("facet-data-dir");
    }
    if text.contains("FACET_CONFIG_DIR") {
        bad.insert("facet-config-dir");
    }
    if text.contains("$HOME") || text.contains("${HOME}") {
        bad.insert("dollar-home");
    }
    if has_secret_bytes(text) {
        bad.insert("secret-bytes");
    }

    let args = argv(text);
    let homes = values(&args, "--home");
    match homes.as_slice() {
        [home] => {
            let path = Path::new(home);
            if !path.is_absolute() || home.contains("..") {
                bad.insert("home-absolute");
            }
            if let Ok(caller) = std::env::var("HOME") {
                if !caller.is_empty() && (*home == caller || path == Path::new(&caller)) {
                    bad.insert("home-is-caller");
                }
            }
        }
        _ => {
            bad.insert("home-missing");
        }
    }

    let hosts = values(&args, "--allow-host");
    if hosts.is_empty()
        || hosts.iter().any(|host| {
            host.is_empty()
                || !host.is_ascii()
                || host.contains("://")
                || host
                    .chars()
                    .any(|c| c.is_ascii_whitespace() || c == '/' || c == '@')
        })
    {
        bad.insert("allow-host");
    }

    let cmds = values(&args, "--allow-cmd");
    match cmds.as_slice() {
        [raw] => match serde_json::from_str::<serde_json::Value>(raw) {
            Ok(serde_json::Value::Object(obj)) => {
                let path = obj.get("path").and_then(|v| v.as_str()).unwrap_or("");
                if !Path::new(path).is_absolute()
                    || path.contains("..")
                    || !path.starts_with("/usr/local/libexec/hedronite/")
                {
                    bad.insert("allow-cmd-path");
                }
                let sha = obj.get("sha256").and_then(|v| v.as_str()).unwrap_or("");
                if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                    bad.insert("allow-cmd-sha256");
                }
                let prefix: Vec<&str> = obj
                    .get("args_prefix")
                    .and_then(|v| v.as_array())
                    .map(|items| items.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                if !prefix.starts_with(&PREFIX) {
                    bad.insert("allow-cmd-prefix");
                }
            }
            _ => {
                bad.insert("allow-cmd-json");
            }
        },
        _ => {
            bad.insert("allow-cmd-json");
        }
    }

    let mut named = false;
    for spec in values(&args, "--secret") {
        let Some((name, path)) = spec.split_once('=') else {
            bad.insert("secret-vault-path");
            continue;
        };
        if name == "FACET_SECRET_KEY" {
            named = true;
            if !vault_path(path) {
                bad.insert("secret-vault-path");
            }
        }
    }
    if !named {
        bad.insert("facet-secret-key");
    }
    bad
}

#[test]
fn fixture_satisfies_every_rule() {
    let bad = broken_rules(&raw());
    assert!(bad.is_empty(), "fixture breaks {bad:?}");
}

#[test]
fn each_broken_rule_fails() {
    let base = raw();
    let caller = std::env::var("HOME").expect("HOME");
    assert_ne!(caller, "/var/empty/geode-facet-home");
    let cases = [
        ("home-missing", "--home\n/var/empty/geode-facet-home\n", ""),
        ("home-absolute", "/var/empty/geode-facet-home", "rel/home"),
        ("home-is-caller", "/var/empty/geode-facet-home", caller.as_str()),
        ("dollar-home", "/var/empty/geode-facet-home", "$HOME"),
        ("allow-host", "--allow-host\napi.example.test\n", ""),
        (
            "allow-cmd-json",
            "{\"path\":\"/usr/local/libexec/hedronite/facet\",\"sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"args_prefix\":[\"request\",\"run\",\"--no-record\"]}",
            "/usr/local/libexec/hedronite/facet",
        ),
        (
            "allow-cmd-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "abcd",
        ),
        (
            "allow-cmd-prefix",
            "\"args_prefix\":[\"request\",\"run\",\"--no-record\"]",
            "\"args_prefix\":[\"request\",\"run\"]",
        ),
        (
            "allow-cmd-path",
            "\"path\":\"/usr/local/libexec/hedronite/facet\"",
            "\"path\":\"rel/facet\"",
        ),
        (
            "allow-cmd-path",
            "\"path\":\"/usr/local/libexec/hedronite/facet\"",
            "\"path\":\"/usr/local/bin/facet\"",
        ),
        (
            "facet-secret-key",
            "FACET_SECRET_KEY=cfg/facet-secret-key",
            "OTHER=cfg/facet-secret-key",
        ),
        (
            "secret-vault-path",
            "FACET_SECRET_KEY=cfg/facet-secret-key",
            "FACET_SECRET_KEY=/etc/passwd",
        ),
        (
            "secret-bytes",
            "FACET_SECRET_KEY=cfg/facet-secret-key",
            "FACET_SECRET_KEY=cfg/sk-example",
        ),
        ("facet-data-dir", "api.example.test", "FACET_DATA_DIR"),
        ("facet-config-dir", "api.example.test", "FACET_CONFIG_DIR"),
    ];
    for (rule, from, to) in cases {
        assert!(
            base.contains(from),
            "fixture has no {from:?} to break {rule}"
        );
        let got = broken_rules(&base.replace(from, to));
        assert!(got.contains(rule), "broken {rule} reported {got:?}");
    }
}
