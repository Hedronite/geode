//! SPEC-v034 G4 — `token issue` inject flags, `token inspect` claims, and
//! the `geode agent read` default mode.
//!
//! 1. G4a: `--ops` stays required and the usage error names
//!    `--ops list,inject`. The allow, peer, and redact flags parse and
//!    validate. An `inject` grant the policy lacks is `policy_deny` (exit 3)
//!    and leaves the policy unchanged.
//! 2. G4b: `inspect` shows `allow_cmds`, `allow_hosts`, `peer_uid`, and
//!    `redact`, and never the sealed bytes.
//! 3. G4c: `agent read` follows G3c. A `Read` token defaults to `text`,
//!    inject-only defaults to `hash`, inject-only `text` is
//!    `plaintext_denied` with no body, a token with neither is
//!    `policy_deny`.
//!
//! Dummy values only.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BODY: &[u8] = b"sk-dummy-0000QA\n";

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .output()
        .expect("spawn geode")
}

fn geode_token(dir: &Path, args: &[&str], token: &str, stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env("GEODE_TOKEN", token)
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn geode");
    child
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(stdin_bytes)
        .expect("write stdin");
    child.wait_with_output().expect("wait")
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({:?}): {}",
        out.status.code(),
        stderr(out)
    );
}

fn assert_code(out: &Output, code: i32, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}: stdout {:?} stderr {}",
        String::from_utf8_lossy(&out.stdout),
        stderr(out)
    );
}

/// Vault with a sealed policy granting `agent:test` `agent_ops` on
/// `scratch/`, and one object at `scratch/note.md`.
fn setup(dir: &Path, agent_ops: &str) {
    assert_ok(&geode(dir, &["keygen", "k.gkey"]), "keygen");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]),
        "vault init",
    );
    let show = geode(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert_ok(&show, "policy show");
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    let vid = doc["policy"]["vault_id"].as_str().expect("vault_id");
    let ops = agent_ops
        .split(',')
        .map(|o| format!("\"{o}\""))
        .collect::<Vec<_>>()
        .join(",");
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","inject","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"agent:test","ops":[{ops}],"prefixes":["scratch/"],"max_bytes":1048576}}]}}"#
    );
    std::fs::write(dir.join("policy.json"), policy).expect("policy.json");
    assert_ok(
        &geode(
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
        ),
        "policy set",
    );
    let w = issue(dir, "write", &[]);
    assert_ok(
        &geode_token(
            dir,
            &[
                "--key",
                "k.gkey",
                "agent",
                "write",
                "v.geode",
                "scratch/note.md",
            ],
            &w,
            BODY,
        ),
        "agent write",
    );
}

fn issue_out(dir: &Path, ops: &str, extra: &[&str]) -> Output {
    let mut args = vec![
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
        ops,
        "--allow-prefix",
        "scratch/",
    ];
    args.extend_from_slice(extra);
    geode(dir, &args)
}

fn issue(dir: &Path, ops: &str, extra: &[&str]) -> String {
    let out = issue_out(dir, ops, extra);
    assert_ok(&out, &format!("issue {ops}"));
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("issue json");
    doc["token"].as_str().expect("token").to_owned()
}

fn inspect(dir: &Path, token: &str, json: bool) -> Output {
    let mut args = vec!["--key", "k.gkey"];
    if json {
        args.extend_from_slice(&["--output", "json"]);
    }
    args.extend_from_slice(&["agent", "token", "inspect", "--vault", "v.geode"]);
    geode_token(dir, &args, token, b"")
}

fn read(dir: &Path, token: &str, mode: Option<&str>) -> Output {
    let mut args = vec![
        "--key",
        "k.gkey",
        "agent",
        "read",
        "v.geode",
        "scratch/note.md",
    ];
    if let Some(m) = mode {
        args.extend_from_slice(&["--mode", m]);
    }
    geode_token(dir, &args, token, b"")
}

fn policy_doc(dir: &Path) -> Vec<u8> {
    let show = geode(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert_ok(&show, "policy show");
    show.stdout
}

#[test]
fn issue_without_ops_is_usage_and_names_list_inject() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let out = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:test",
            "--allow-prefix",
            "scratch/",
        ],
    );
    assert_code(&out, 1, "issue without --ops");
    assert!(
        stderr(&out).contains("--ops list,inject"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn issue_help_says_no_allow_cmd_runs_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = geode(tmp.path(), &["agent", "token", "issue", "--help"]);
    assert_ok(&out, "issue --help");
    let help = String::from_utf8_lossy(&out.stdout);
    for flag in [
        "--allow-cmd",
        "--allow-cmds-file",
        "--allow-host",
        "--peer-uid",
        "--redact",
        "list,inject",
        "cannot run anything",
    ] {
        assert!(help.contains(flag), "help lacks {flag}: {help}");
    }
}

#[test]
fn inject_grant_policy_lacks_is_policy_deny_and_policy_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup(dir, "list,read,write");
    let before = policy_doc(dir);
    let out = issue_out(dir, "list,inject", &["--allow-cmd", "/bin/sh"]);
    assert_code(&out, 3, "inject outside policy");
    assert!(out.stdout.is_empty() || !String::from_utf8_lossy(&out.stdout).contains("\"token\""));
    assert_eq!(policy_doc(dir), before, "policy changed");
}

#[test]
fn issue_flags_round_trip_through_inspect() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup(dir, "list,read,write,inject");
    let sum = "AB".repeat(32);
    let rules =
        format!(r#"[{{"path":"/usr/bin/env","sha256":"{sum}","args_prefix":["printenv"]}}]"#);
    std::fs::write(dir.join("cmds.json"), rules).expect("cmds.json");
    let token = issue(
        dir,
        "list,inject",
        &[
            "--allow-cmd",
            "/bin/sh",
            "--allow-cmd",
            "/bin/sh",
            "--allow-cmds-file",
            "cmds.json",
            "--allow-host",
            "API.example.com",
            "--allow-host",
            "api.example.com",
            "--peer-uid",
            "501",
            "--redact",
            "hidden",
        ],
    );

    let j = inspect(dir, &token, true);
    assert_ok(&j, "inspect json");
    let doc: serde_json::Value = serde_json::from_slice(&j.stdout).expect("inspect json");
    let cmds = doc["allow_cmds"].as_array().expect("allow_cmds");
    assert_eq!(cmds.len(), 2, "{doc}");
    assert_eq!(cmds[0]["path"], "/bin/sh");
    assert!(cmds[0].get("sha256").is_none());
    assert_eq!(cmds[1]["path"], "/usr/bin/env");
    assert_eq!(cmds[1]["sha256"], "ab".repeat(32));
    assert_eq!(cmds[1]["args_prefix"], serde_json::json!(["printenv"]));
    assert_eq!(doc["allow_hosts"], serde_json::json!(["api.example.com"]));
    assert_eq!(doc["peer_uid"], 501);
    assert_eq!(doc["redact"], "hidden");
    assert_eq!(doc["allow_ops"], serde_json::json!(["list", "inject"]));

    let t = inspect(dir, &token, false);
    assert_ok(&t, "inspect text");
    let text = String::from_utf8_lossy(&t.stdout).into_owned() + &stderr(&t);
    for want in [
        "allow-cmds /bin/sh, /usr/bin/env sha256=",
        "args=printenv",
        "allow-hosts api.example.com",
        "peer-uid 501",
        "redact hidden",
    ] {
        assert!(text.contains(want), "inspect text lacks {want}: {text}");
    }

    // No sealed bytes in either form.
    for out in [&j, &t] {
        let all = String::from_utf8_lossy(&out.stdout).into_owned() + &stderr(out);
        assert!(!all.contains(&token), "sealed token printed: {all}");
        assert!(!all.contains(&token[..16]), "sealed prefix printed: {all}");
        assert!(!all.contains("GTOK"), "GTOK printed: {all}");
    }
}

#[test]
fn issue_defaults_are_empty_and_strict() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup(dir, "list,read,write,inject");
    let out = issue_out(dir, "list,inject", &[]);
    assert_ok(&out, "issue list,inject");
    assert!(
        stderr(&out).contains("cannot run anything"),
        "{}",
        stderr(&out)
    );
    let doc: serde_json::Value = serde_json::from_slice(&out.stdout).expect("json");
    let token = doc["token"].as_str().expect("token");
    let j = inspect(dir, token, true);
    assert_ok(&j, "inspect");
    let doc: serde_json::Value = serde_json::from_slice(&j.stdout).expect("json");
    assert_eq!(doc["allow_cmds"], serde_json::json!([]));
    assert_eq!(doc["allow_hosts"], serde_json::json!([]));
    assert!(doc["peer_uid"].is_null());
    assert_eq!(doc["redact"], "strict");
}

#[test]
fn bad_inject_flags_are_usage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup(dir, "list,read,write,inject");
    std::fs::write(dir.join("unk.json"), r#"[{"path":"/bin/sh","glob":"*"}]"#).unwrap();
    std::fs::write(
        dir.join("sha.json"),
        r#"[{"path":"/bin/sh","sha256":"xyz"}]"#,
    )
    .unwrap();
    std::fs::write(dir.join("obj.json"), r#"{"path":"/bin/sh"}"#).unwrap();
    for (extra, what) in [
        (vec!["--allow-cmd", "sh"], "relative"),
        (vec!["--allow-cmd", "/bin/../bin/sh"], "non-canonical"),
        (vec!["--allow-cmd", "/nonexistent/geode-cmd"], "missing"),
        (vec!["--allow-cmd", "/etc/hosts"], "not executable"),
        (vec!["--allow-cmds-file", "unk.json"], "unknown key"),
        (vec!["--allow-cmds-file", "sha.json"], "bad sha256"),
        (vec!["--allow-cmds-file", "obj.json"], "not a list"),
        (vec!["--allow-host", "https://x.example"], "scheme"),
        (vec!["--allow-host", ""], "empty host"),
        (vec!["--peer-uid", "-1"], "negative uid"),
        (vec!["--redact", "loud"], "bad redact"),
    ] {
        let out = issue_out(dir, "list,inject", &extra);
        assert_code(&out, 1, what);
    }
}

#[test]
fn agent_read_follows_g3_defaults() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup(dir, "list,read,write,inject");

    // `Read` token: default stays `text`.
    let reader = issue(dir, "list,read", &[]);
    let r = read(dir, &reader, None);
    assert_ok(&r, "read token default");
    assert_eq!(r.stdout, BODY);

    // Inject-only: default is `hash` — digest, no body.
    let injector = issue(dir, "list,inject", &["--allow-cmd", "/bin/sh"]);
    let h = read(dir, &injector, None);
    assert_ok(&h, "inject-only default");
    let line = String::from_utf8(h.stdout.clone()).expect("utf8");
    let digest = line.trim_end();
    assert_eq!(digest.len(), 64, "sha256 hex: {line:?}");
    assert!(digest.bytes().all(|b| b.is_ascii_hexdigit()));
    assert!(!line.contains("sk-dummy"), "body leaked: {line}");
    let explicit = read(dir, &injector, Some("hash"));
    assert_ok(&explicit, "inject-only hash");
    assert_eq!(explicit.stdout, h.stdout);
    // The `Read` token's hash agrees.
    let rh = read(dir, &reader, Some("hash"));
    assert_ok(&rh, "read token hash");
    assert_eq!(rh.stdout, h.stdout);

    // Inject-only explicit text/hex: plaintext_denied, no body.
    for mode in ["text", "hex"] {
        let d = read(dir, &injector, Some(mode));
        assert_code(&d, 1, &format!("inject-only {mode}"));
        assert!(d.stdout.is_empty(), "{mode} body: {:?}", d.stdout);
        assert!(stderr(&d).contains("plaintext_denied"), "{}", stderr(&d));
        assert!(!stderr(&d).contains("sk-dummy"));
    }

    // Old shape without Read or Inject: policy_deny, default and hash.
    let lister = issue(dir, "list,write", &[]);
    for mode in [None, Some("hash"), Some("text")] {
        let d = read(dir, &lister, mode);
        assert_code(&d, 3, &format!("list,write {mode:?}"));
        assert!(d.stdout.is_empty());
    }

    // Read token hex mode is the hex of the body.
    let x = read(dir, &reader, Some("hex"));
    assert_ok(&x, "read hex");
    let hex: String = BODY.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(String::from_utf8_lossy(&x.stdout).trim_end(), hex);
}
