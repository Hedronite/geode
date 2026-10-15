//! SPEC-v034 G2 — CLI credential hygiene on the existing agent verbs.
//!
//! 1. G2a: `--token-file` (0600, caller-owned) reads; a 0644 file exits 1
//!    and the error names the path and mode, never the token. `--token-fd`
//!    reads from an open fd.
//! 2. G2b: raw `--token` warns once, never echoes the value, still works.
//!    `geode tui --token` is an unexpected argument.
//! 3. G2c: `--passphrase-fd` unlocks a wrapped key. `GEODE_PASSPHRASE`
//!    still works on an existing verb and prints the upgraded warning.
//!
//! Dummy passphrases only. No key bytes in any captured output.

use std::io::Write as _;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const PASS: &str = "dummy-pass-0000QA";

fn cmd(dir: &Path, args: &[&str]) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_geode"));
    c.args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE");
    c
}

fn run(c: &mut Command) -> Output {
    c.output().expect("spawn geode")
}

fn run_stdin(c: &mut Command, stdin_bytes: &[u8]) -> Output {
    let mut child = c
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

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed ({:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Vault + policy granting `agent:test` list/read/write on `scratch/`, one
/// object written, and a token. `pass` wraps the key when set.
fn setup(dir: &Path, pass: Option<&str>) -> String {
    let with_pass = |c: &mut Command| {
        if let Some(p) = pass {
            c.env("GEODE_PASSPHRASE", p);
        }
    };
    let mut kg = cmd(dir, &["keygen", "k.gkey"]);
    if pass.is_some() {
        kg.args(["--password", "--cheap"]);
    }
    with_pass(&mut kg);
    assert_ok(&run(&mut kg), "keygen");

    let mut init = cmd(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    with_pass(&mut init);
    assert_ok(&run(&mut init), "vault init");

    let mut show = cmd(
        dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    with_pass(&mut show);
    let show = run(&mut show);
    assert_ok(&show, "policy show");
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    let vid = doc["policy"]["vault_id"].as_str().expect("vault_id");
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"agent:test","ops":["list","read","write"],"prefixes":["scratch/"],"max_bytes":1048576}}]}}"#
    );
    std::fs::write(dir.join("policy.json"), policy).expect("policy.json");
    let mut set = cmd(
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
    );
    with_pass(&mut set);
    assert_ok(&run(&mut set), "policy set");

    let mut issue = cmd(
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
        ],
    );
    with_pass(&mut issue);
    let issue = run(&mut issue);
    assert_ok(&issue, "token issue");
    let doc: serde_json::Value = serde_json::from_slice(&issue.stdout).expect("issue json");
    let token = doc["token"].as_str().expect("token").to_owned();

    let mut w = cmd(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "write",
            "v.geode",
            "scratch/note.md",
        ],
    );
    w.env("GEODE_TOKEN", &token);
    with_pass(&mut w);
    assert_ok(&run_stdin(&mut w, b"hello agent\n"), "agent write");
    token
}

fn write_token_file(dir: &Path, name: &str, token: &str, mode: u32) {
    let p = dir.join(name);
    std::fs::write(&p, token).expect("token file");
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).expect("chmod");
}

const READ: [&str; 6] = [
    "--key",
    "k.gkey",
    "agent",
    "read",
    "v.geode",
    "scratch/note.md",
];

#[test]
fn token_file_0600_reads_and_0644_exits_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let token = setup(dir, None);

    write_token_file(dir, "t.ok", &token, 0o600);
    let ok = run(cmd(dir, &READ).args(["--token-file", "t.ok"]));
    assert_ok(&ok, "agent read --token-file");
    assert_eq!(ok.stdout, b"hello agent\n");
    assert!(
        !stderr(&ok).contains("warning: --token"),
        "--token-file must not warn: {}",
        stderr(&ok)
    );

    for (name, mode) in [("t.644", 0o644), ("t.640", 0o640), ("t.400", 0o400)] {
        write_token_file(dir, name, &token, mode);
        let bad = run(cmd(dir, &READ).args(["--token-file", name]));
        let err = stderr(&bad);
        assert_eq!(bad.status.code(), Some(1), "{name}: {err}");
        assert!(bad.stdout.is_empty(), "{name}: no body on refusal");
        assert!(err.contains(name), "{name}: error names the path: {err}");
        assert!(
            err.contains(&format!("0o{mode:03o}")),
            "{name}: error names the mode: {err}"
        );
        assert!(!err.contains(&token), "{name}: token leaked: {err}");
    }

    // Missing file: exit 1, path named.
    let missing = run(cmd(dir, &READ).args(["--token-file", "nope"]));
    assert_eq!(missing.status.code(), Some(1), "{}", stderr(&missing));
    assert!(stderr(&missing).contains("nope"));
}

#[test]
fn token_fd_reads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let token = setup(dir, None);
    // `read` does not own stdin, so fd 0 can carry the token.
    let out = run_stdin(cmd(dir, &READ).args(["--token-fd", "0"]), token.as_bytes());
    assert_ok(&out, "agent read --token-fd 0");
    assert_eq!(out.stdout, b"hello agent\n");
}

#[test]
fn token_sources_conflict_is_usage() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let out = run(cmd(dir, &READ).args(["--token", "x", "--token-file", "t"]));
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn raw_token_warns_once_without_value_and_works() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let token = setup(dir, None);
    let out = run(cmd(dir, &READ).args(["--token", token.as_str()]));
    assert_ok(&out, "agent read --token");
    assert_eq!(out.stdout, b"hello agent\n");
    let err = stderr(&out);
    assert_eq!(
        err.matches("--token on argv is visible").count(),
        1,
        "warns exactly once: {err}"
    );
    assert!(!err.contains(&token), "warning echoed the token: {err}");

    // A bad raw token still does not echo.
    let bad = run(cmd(dir, &READ).args(["--token", "deadbeefcafe"]));
    assert_ne!(bad.status.code(), Some(0));
    assert!(!stderr(&bad).contains("deadbeefcafe"), "{}", stderr(&bad));
}

#[test]
fn tui_token_is_unexpected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    for flag in ["--token", "--token-file", "--token-fd", "--passphrase-fd"] {
        let out = run(&mut cmd(dir, &["tui", flag, "x"]));
        assert_eq!(out.status.code(), Some(1), "tui {flag}: {}", stderr(&out));
        assert!(
            stderr(&out).contains("unexpected argument"),
            "tui {flag}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn passphrase_env_still_works_and_warns_upgraded() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let token = setup(dir, Some(PASS));
    let out = run(cmd(dir, &READ)
        .env("GEODE_TOKEN", &token)
        .env("GEODE_PASSPHRASE", PASS));
    assert_ok(&out, "agent read with GEODE_PASSPHRASE");
    assert_eq!(out.stdout, b"hello agent\n");
    let err = stderr(&out);
    assert!(
        err.contains("GEODE_PASSPHRASE is deprecated") && err.contains("--passphrase-fd"),
        "upgraded warning: {err}"
    );
    assert!(!err.contains(PASS), "passphrase leaked: {err}");
}

#[test]
fn passphrase_fd_unlocks_wrapped_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let token = setup(dir, Some(PASS));
    write_token_file(dir, "t.ok", &token, 0o600);

    let ok = run_stdin(
        cmd(dir, &READ).args(["--token-file", "t.ok", "--passphrase-fd", "0"]),
        format!("{PASS}\n").as_bytes(),
    );
    assert_ok(&ok, "agent read --passphrase-fd 0");
    assert_eq!(ok.stdout, b"hello agent\n");
    assert!(!stderr(&ok).contains("GEODE_PASSPHRASE"), "{}", stderr(&ok));

    // The fd is really used: a wrong passphrase on it is an auth failure.
    let bad = run_stdin(
        cmd(dir, &READ).args(["--token-file", "t.ok", "--passphrase-fd", "0"]),
        b"wrong-pass-0000QA\n",
    );
    assert_eq!(bad.status.code(), Some(2), "{}", stderr(&bad));
    assert!(!stderr(&bad).contains("wrong-pass-0000QA"));
}
