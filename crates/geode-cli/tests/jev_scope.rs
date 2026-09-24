//! Soft Jev remainder — CLI + MCP wrapper fixtures (no live Jev).
//!
//! Prefix / `../` stay code. Shadow: ask/deny/low-conf ≠ auto-allow.
//! No GTOK / ISK in captured output.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("TYPESAFE_API_KEY")
        .output()
        .expect("spawn geode")
}

fn setup_vault(dir: &Path) {
    assert!(geode(dir, &["keygen", "k.gkey"]).status.success(), "keygen");
    assert!(
        geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"])
            .status
            .success(),
        "vault init"
    );
    let show = geode(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert!(show.status.success(), "policy show");
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    let vid = doc["policy"]["vault_id"].as_str().expect("vault_id");
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"agent:test","ops":["list","read","write"],"prefixes":["scratch/"],"max_bytes":1048576}}]}}"#
    );
    std::fs::write(dir.join("policy.json"), policy).expect("write policy.json");
    assert!(
        geode(
            dir,
            &[
                "--key",
                "k.gkey",
                "policy",
                "set",
                "v.geode",
                "--file",
                "policy.json",
            ],
        )
        .status
        .success(),
        "policy set"
    );
}

fn issue_token(dir: &Path) -> String {
    let issue = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "--output",
            "json",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:test",
            "--ops",
            "list,read,write",
            "--allow-prefix",
            "scratch/",
            "--ttl",
            "15m",
        ],
    );
    assert!(issue.status.success(), "token issue");
    let doc: serde_json::Value = serde_json::from_slice(&issue.stdout).expect("issue json");
    doc["token"].as_str().expect("token hex").to_owned()
}

fn write_fixture(dir: &Path, body: &str) -> std::path::PathBuf {
    let path = dir.join("systemone.json");
    std::fs::write(&path, body).expect("fixture");
    path
}

#[test]
fn scope_help_is_token_free() {
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["agent", "scope", "--help"])
        .output()
        .expect("help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "help failed");
    assert!(stdout.contains("geode agent scope") || stdout.contains("Classify non-prefix"));
    assert!(
        !stdout.contains("--token <") && !stdout.contains("--token <TOKEN>"),
        "scope must not take a --token flag: {stdout}"
    );
    assert!(!stdout.contains("GTOK"));
    assert!(!stdout.to_ascii_lowercase().contains("stanley"));
}

#[test]
fn tui_help_is_jev_free() {
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["tui", "--help"])
        .output()
        .expect("tui help");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stdout.to_ascii_lowercase().contains("jev")
            && !stderr.to_ascii_lowercase().contains("jev"),
        "TUI help mentions Jev"
    );
    assert!(
        !stdout.contains("--token <"),
        "TUI must not grow a --token flag: {stdout}"
    );
}

#[test]
fn none_transport_asks_and_does_not_auto_allow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "none")
        .env_remove("TYPESAFE_API_KEY")
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "scratch/note.md",
            "--op",
            "write",
            "--allow-prefix",
            "scratch/",
            "--principal",
            "agent:test",
            "--intent",
            "seal a scratch note",
        ])
        .current_dir(tmp.path())
        .output()
        .expect("scope none");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "scope failed: {stderr}{stdout}");
    assert!(stdout.contains("\"choice\":\"ask\"") || stdout.contains("\"choice\": \"ask\""));
    assert!(stdout.contains("\"auto_allow\":false") || stdout.contains("\"auto_allow\": false"));
    assert!(stdout.contains("\"shadow\":true") || stdout.contains("\"shadow\": true"));
    assert!(
        stdout.contains("\"status\":\"unavailable\"")
            || stdout.contains("\"status\": \"unavailable\"")
    );
    assert!(!stdout.contains("sk-") && !stderr.contains("sk-"));
    assert!(!stdout.contains("GTOK") && !stderr.contains("GTOK"));
}

#[test]
fn fixture_allow_stays_shadow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_fixture(
        tmp.path(),
        r#"{
          "answers": {
            "scope": { "type": "choice", "choice": "allow", "confidence": 0.94 },
            "escalate": { "type": "noul", "noul": 0.0, "confidence": 0.94 }
          }
        }"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "fixture")
        .env("GEODE_JEV_FIXTURE", &fixture)
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "scratch/note.md",
            "--op",
            "write",
            "--allow-prefix",
            "scratch/",
            "--intent",
            "seal a scratch note",
        ])
        .output()
        .expect("scope fixture");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "scope failed: {stderr}{stdout}");
    assert!(stdout.contains("\"choice\":\"allow\"") || stdout.contains("\"choice\": \"allow\""));
    assert!(stdout.contains("\"auto_allow\":false") || stdout.contains("\"auto_allow\": false"));
    assert!(stdout.contains("\"status\":\"judged\"") || stdout.contains("\"status\": \"judged\""));
}

#[test]
fn fixture_low_confidence_asks() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_fixture(
        tmp.path(),
        r#"{
          "answers": {
            "scope": { "type": "choice", "choice": "allow", "confidence": 0.2 },
            "escalate": { "type": "noul", "noul": 1.0, "confidence": 0.2 }
          }
        }"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "fixture")
        .env("GEODE_JEV_FIXTURE", &fixture)
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "scratch/note.md",
            "--op",
            "write",
            "--allow-prefix",
            "scratch/",
        ])
        .output()
        .expect("scope low");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("\"choice\":\"ask\"") || stdout.contains("\"choice\": \"ask\""));
    assert!(
        stdout.contains("\"status\":\"low_confidence\"")
            || stdout.contains("\"status\": \"low_confidence\"")
    );
    assert!(stdout.contains("\"auto_allow\":false") || stdout.contains("\"auto_allow\": false"));
}

#[test]
fn fixture_deny_is_not_allow() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let fixture = write_fixture(
        tmp.path(),
        r#"{
          "answers": {
            "scope": { "type": "choice", "choice": "deny", "confidence": 0.99 },
            "escalate": { "type": "noul", "noul": 0.0, "confidence": 0.99 }
          }
        }"#,
    );
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "fixture")
        .env("GEODE_JEV_FIXTURE", &fixture)
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "scratch/note.md",
            "--op",
            "write",
            "--allow-prefix",
            "scratch/",
        ])
        .output()
        .expect("scope deny");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success());
    assert!(stdout.contains("\"choice\":\"deny\"") || stdout.contains("\"choice\": \"deny\""));
    assert!(stdout.contains("\"auto_allow\":false") || stdout.contains("\"auto_allow\": false"));
}

#[test]
fn dotdot_is_code_usage_without_jev_choice() {
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "none")
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "scratch/../keys/x",
            "--op",
            "write",
            "--allow-prefix",
            "scratch/",
        ])
        .output()
        .expect("scope dotdot");
    assert_eq!(out.status.code(), Some(1), "dotdot is usage, not Jev");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("\"choice\":\"allow\""),
        "Jev must not decide .. : {stdout}"
    );
}

#[test]
fn outside_prefix_is_policy_deny_without_jev() {
    let out = Command::new(env!("CARGO_BIN_EXE_geode"))
        .env("GEODE_JEV_TRANSPORT", "none")
        .args([
            "--output",
            "json",
            "agent",
            "scope",
            "--path",
            "keys/prod.pem",
            "--op",
            "read",
            "--allow-prefix",
            "scratch/",
        ])
        .output()
        .expect("scope prefix");
    assert_eq!(out.status.code(), Some(3), "prefix miss is policy_deny");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("policy_deny") || String::from_utf8_lossy(&out.stderr).contains("policy"),
        "code deny: {stdout}"
    );
}

#[test]
fn mcp_write_stays_code_owned_and_can_annotate_jev() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let token = issue_token(dir);
    let fixture = write_fixture(
        dir,
        r#"{
          "answers": {
            "scope": { "type": "choice", "choice": "ask", "confidence": 0.91 },
            "escalate": { "type": "noul", "noul": 0.2, "confidence": 0.91 }
          }
        }"#,
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["--key", "k.gkey", "agent", "serve", "--stdio"])
        .current_dir(dir)
        .env("GEODE_TOKEN", &token)
        .env("GEODE_JEV_TRANSPORT", "fixture")
        .env("GEODE_JEV_FIXTURE", &fixture)
        .env_remove("TYPESAFE_API_KEY")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"geode_write","arguments":{"vault":"v.geode","path":"scratch/a.txt","body":"mcp body\n","intent":"scratch note"}}}"#,
        "\n",
    );
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(requests.as_bytes())
        .expect("write requests");
    let out = child.wait_with_output().expect("wait");
    assert!(
        out.status.success(),
        "serve exits 0: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mut frames: std::collections::HashMap<i64, serde_json::Value> =
        std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let frame: serde_json::Value = serde_json::from_str(line).expect("frame json");
        frames.insert(frame["id"].as_i64().expect("frame id"), frame);
    }
    let wtext = frames[&2]["result"]["content"][0]["text"]
        .as_str()
        .expect("write text");
    let wdoc: serde_json::Value = serde_json::from_str(wtext).expect("write doc");
    assert_eq!(wdoc["ok"], true, "code still writes: {wdoc}");
    assert_eq!(wdoc["path"], "scratch/a.txt");
    assert_eq!(wdoc["jev"]["choice"], "ask");
    assert_eq!(wdoc["jev"]["auto_allow"], false);
    assert_eq!(wdoc["jev"]["shadow"], true);
    let blob = format!("{wdoc}");
    assert!(!blob.contains("GTOK") && !blob.contains("47544f4b"));
}
