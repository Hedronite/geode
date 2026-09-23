//! G1 (v0.2.2) — agent plane CLI + stdio MCP fixtures against the shipped
//! `geode` binary (06-agent-plane).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `agent_verbs_roundtrip` — keygen -> vault init -> token issue
//!    (`--output json` hex armor) -> `agent write` (stdin body) ->
//!    `agent list` under `GEODE_TOKEN` -> `agent read` byte-compare, plus
//!    `--token` on the verb. Fail-closed: read outside the grant exits 1
//!    (`not_found`), a list-only token cannot write (exit 3, `policy_deny`),
//!    a tampered token exits 2 (`auth_fail`), an expired token exits 4
//!    (`token_invalid`), and no token at all exits 1 (usage).
//! 2. `serve_stdio_mcp` — `agent serve --stdio` answers `initialize`,
//!    `tools/list` (exactly `geode_list`/`geode_read`/`geode_write` —
//!    never keygen / mount / `cat_key`), and `tools/call` for write/list/read.
//!    Unknown tool -> -32602; unknown method -> -32601; EOF -> exit 0.
//!    Serving without a token exits 1.
//!
//! No passphrases, no key bytes, no ISK in any captured output.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .output()
        .expect("spawn geode")
}

/// Run `geode` with `GEODE_TOKEN` set and `stdin_bytes` on stdin.
fn geode_token(dir: &Path, args: &[&str], token_hex: &str, stdin_bytes: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env("GEODE_TOKEN", token_hex)
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
        "{what} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn setup_vault(dir: &Path) {
    assert_ok(&geode(dir, &["keygen", "k.gkey"]), "keygen");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]),
        "vault init",
    );
    // v0.2.3: token issue always narrows policy (10-policy 2.5). A
    // policy-less vault's default policy grants `human:local` only, so the
    // fixtures seal a policy granting `agent:test` list/read/write on
    // `scratch/` (cap 1 MiB, matching the CLI default `--max-bytes`).
    let show = geode(
        dir,
        &["--key", "k.gkey", "--output", "json", "policy", "show", "v.geode"],
    );
    assert_ok(&show, "policy show (id)");
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    let vid = doc["policy"]["vault_id"].as_str().expect("vault_id");
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"agent:test","ops":["list","read","write"],"prefixes":["scratch/"],"max_bytes":1048576}}]}}"#
    );
    std::fs::write(dir.join("policy.json"), policy).expect("write policy.json");
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
}

/// Issue a token on the fixture vault; returns the hex armor (the
/// `--output json` `token` field) so it can ride `GEODE_TOKEN`.
fn issue_token(dir: &Path, ops: &str, ttl: &str) -> String {
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
            ops,
            "--allow-prefix",
            "scratch/",
            "--ttl",
            ttl,
        ],
    );
    assert_ok(&issue, "token issue");
    let doc: serde_json::Value = serde_json::from_slice(&issue.stdout).expect("issue json");
    doc["token"].as_str().expect("token hex field").to_owned()
}

/// Flip one hex char near the end (tag region) of a hex-armored token.
fn tamper(token_hex: &str) -> String {
    let mut bad = token_hex.to_owned();
    let idx = bad.len() - 8;
    let flipped = if bad.as_bytes()[idx] == b'0' {
        "1"
    } else {
        "0"
    };
    bad.replace_range(idx..=idx, flipped);
    bad
}

#[test]
fn agent_verbs_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let token = issue_token(dir, "list,read,write", "15m");

    // write (stdin body) -> list -> read byte-compare.
    let w = geode_token(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "write",
            "v.geode",
            "scratch/note.md",
        ],
        &token,
        b"hello agent\n",
    );
    assert_ok(&w, "agent write");
    let l = geode_token(
        dir,
        &["--key", "k.gkey", "agent", "list", "v.geode"],
        &token,
        b"",
    );
    assert_ok(&l, "agent list");
    let listing = String::from_utf8_lossy(&l.stdout);
    assert!(
        listing.contains("scratch/note.md"),
        "list shows the write: {listing}"
    );
    let r = geode_token(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "read",
            "v.geode",
            "scratch/note.md",
        ],
        &token,
        b"",
    );
    assert_ok(&r, "agent read");
    assert_eq!(r.stdout, b"hello agent\n");

    // `--token` on the verb works the same as GEODE_TOKEN.
    let r2 = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "read",
            "v.geode",
            "scratch/note.md",
            "--token",
            token.as_str(),
        ],
    );
    assert_ok(&r2, "agent read --token");
    assert_eq!(r2.stdout, b"hello agent\n");

}

#[test]
fn agent_verbs_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let token = issue_token(dir, "list,read,write", "15m");

    // Outside the grant -> not_found (exit 1; leak_denies off).
    let denied = geode_token(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "read",
            "v.geode",
            "keys/prod.pem",
        ],
        &token,
        b"",
    );
    assert_eq!(
        denied.status.code(),
        Some(1),
        "outside grant: {}",
        String::from_utf8_lossy(&denied.stderr)
    );

    // Fail closed: a list-only token cannot write -> policy_deny (exit 3).
    let list_only = issue_token(dir, "list", "15m");
    let no_write = geode_token(
        dir,
        &[
            "--key",
            "k.gkey",
            "agent",
            "write",
            "v.geode",
            "scratch/x.md",
        ],
        &list_only,
        b"nope\n",
    );
    assert_eq!(
        no_write.status.code(),
        Some(3),
        "list-only write: {}",
        String::from_utf8_lossy(&no_write.stderr)
    );

    // Fail closed: tampered token -> auth_fail (exit 2).
    let bad = tamper(&token);
    let tampered = geode_token(
        dir,
        &["--key", "k.gkey", "agent", "list", "v.geode"],
        &bad,
        b"",
    );
    assert_eq!(
        tampered.status.code(),
        Some(2),
        "tampered token: {}",
        String::from_utf8_lossy(&tampered.stderr)
    );

    // Fail closed: expired token -> token_invalid (exit 4).
    let short = issue_token(dir, "list", "1s");
    std::thread::sleep(std::time::Duration::from_secs(2));
    let expired = geode_token(
        dir,
        &["--key", "k.gkey", "agent", "list", "v.geode"],
        &short,
        b"",
    );
    assert_eq!(
        expired.status.code(),
        Some(4),
        "expired token: {}",
        String::from_utf8_lossy(&expired.stderr)
    );

    // Fail closed: no token at all -> usage (exit 1).
    let none = geode(dir, &["--key", "k.gkey", "agent", "list", "v.geode"]);
    assert_eq!(
        none.status.code(),
        Some(1),
        "missing token: {}",
        String::from_utf8_lossy(&none.stderr)
    );
}

#[test]
fn serve_stdio_mcp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let token = issue_token(dir, "list,read,write", "15m");

    // No token: fail closed, exit 1 (no MCP without GEODE_TOKEN).
    let no_tok = geode(dir, &["--key", "k.gkey", "agent", "serve", "--stdio"]);
    assert_eq!(
        no_tok.status.code(),
        Some(1),
        "serve without token: {}",
        String::from_utf8_lossy(&no_tok.stderr)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["--key", "k.gkey", "agent", "serve", "--stdio"])
        .current_dir(dir)
        .env("GEODE_TOKEN", &token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve");
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"geode_write","arguments":{"vault":"v.geode","path":"scratch/a.txt","body":"mcp body\n"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"geode_list","arguments":{"vault":"v.geode","prefix":"scratch/"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"geode_read","arguments":{"vault":"v.geode","path":"scratch/a.txt"}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"geode_mount","arguments":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":7,"method":"bogus_method"}"#,
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
        "serve exits 0 on EOF: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let mut frames: std::collections::HashMap<i64, serde_json::Value> =
        std::collections::HashMap::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        let frame: serde_json::Value = serde_json::from_str(line).expect("frame json");
        frames.insert(frame["id"].as_i64().expect("frame id"), frame);
    }

    // initialize handshake.
    assert_eq!(frames[&1]["result"]["serverInfo"]["name"], "geode");
    assert!(frames[&1]["result"]["protocolVersion"].is_string());

    // tools/list: exactly the three agent tools (06-agent-plane 3). No
    // keygen, no cat_key, no mount in the default toolset.
    let tools = frames[&2]["result"]["tools"].as_array().expect("tools");
    let mut names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    names.sort_unstable();
    assert_eq!(names, ["geode_list", "geode_read", "geode_write"]);

    // tools/call geode_write.
    let wtext = frames[&3]["result"]["content"][0]["text"]
        .as_str()
        .expect("write text");
    let wdoc: serde_json::Value = serde_json::from_str(wtext).expect("write doc");
    assert_eq!(wdoc["ok"], true);
    assert_eq!(wdoc["verb"], "write");
    assert_eq!(wdoc["path"], "scratch/a.txt");

    // tools/call geode_list shows the write.
    let ltext = frames[&4]["result"]["content"][0]["text"]
        .as_str()
        .expect("list text");
    let ldoc: serde_json::Value = serde_json::from_str(ltext).expect("list doc");
    assert_eq!(ldoc["ok"], true);
    let paths: Vec<&str> = ldoc["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["path"].as_str().expect("entry path"))
        .collect();
    assert!(paths.contains(&"scratch/a.txt"), "entries: {paths:?}");

    // tools/call geode_read returns the body + full-plaintext sha256.
    let rtext = frames[&5]["result"]["content"][0]["text"]
        .as_str()
        .expect("read text");
    let rdoc: serde_json::Value = serde_json::from_str(rtext).expect("read doc");
    assert_eq!(rdoc["ok"], true);
    assert_eq!(rdoc["text"], "mcp body\n");
    assert_eq!(rdoc["truncated"], false);
    assert_eq!(rdoc["sha256"].as_str().expect("sha256").len(), 64);

    // Unknown tool -> -32602; unknown method -> -32601.
    assert_eq!(frames[&6]["error"]["code"], -32602);
    assert_eq!(frames[&7]["error"]["code"], -32601);
}

/// G0 — `agent serve --socket agent.sock` from a temp cwd: binds with
/// mode 0600 (parent exists, cwd-relative path), serves the same MCP
/// toolset as `--stdio` (`tools/list` names + `tools/call geode_list`
/// parity for the same token), keeps MCP bytes off process stdout, and
/// unlinks the socket on exit.
#[test]
fn serve_socket_mcp() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let token = issue_token(dir, "list,read,write", "15m");

    // Seed before any server runs, so the single socket listing contains
    // the entry.
    let seeded = geode_token(
        dir,
        &["--key", "k.gkey", "agent", "write", "v.geode", "scratch/s.txt"],
        &token,
        b"socket body\n",
    );
    assert_ok(&seeded, "agent write (seed)");

    // No token: fail closed, exit 1, and no socket file is left behind.
    let no_tok = geode(
        dir,
        &["--key", "k.gkey", "agent", "serve", "--socket", "agent.sock"],
    );
    assert_eq!(
        no_tok.status.code(),
        Some(1),
        "serve without token: {}",
        String::from_utf8_lossy(&no_tok.stderr)
    );
    assert!(!dir.join("agent.sock").exists(), "no socket without token");

    // Serve from `dir` with a cwd-relative socket path (parent is Some("")
    // — the bind must succeed).
    let mut child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["--key", "k.gkey", "agent", "serve", "--socket", "agent.sock"])
        .current_dir(dir)
        .env("GEODE_TOKEN", &token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn serve --socket");

    let sock = dir.join("agent.sock");
    let mut bound = false;
    for _ in 0..50 {
        if sock.exists() {
            bound = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(bound, "socket never bound");
    let mode = std::os::unix::fs::MetadataExt::mode(&std::fs::metadata(&sock).expect("meta"));
    assert_eq!(mode & 0o777, 0o600, "socket mode: {:o}", mode);

    // One connection, one session: initialize, notifications/initialized,
    // tools/list, tools/call geode_list.
    use std::io::BufRead as _;
    let mut stream = std::os::unix::net::UnixStream::connect(&sock).expect("connect");
    let requests = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"geode_list","arguments":{"vault":"v.geode","prefix":"scratch/"}}}"#,
        "\n",
    );
    stream.write_all(requests.as_bytes()).expect("write requests");
    let mut reader = std::io::BufReader::new(
        stream.try_clone().expect("try_clone"),
    );
    let mut frames: std::collections::HashMap<i64, serde_json::Value> =
        std::collections::HashMap::new();
    for _ in 0..3 {
        let mut line = String::new();
        reader.read_line(&mut line).expect("read frame");
        let frame: serde_json::Value = serde_json::from_str(line.trim()).expect("frame json");
        frames.insert(frame["id"].as_i64().expect("frame id"), frame);
    }
    assert_eq!(frames[&1]["result"]["serverInfo"]["name"], "geode");
    let tools = frames[&2]["result"]["tools"].as_array().expect("tools");
    let mut names: Vec<&str> = tools
        .iter()
        .map(|t| t["name"].as_str().expect("tool name"))
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        ["geode_list", "geode_read", "geode_write"],
        "tools/list over socket matches --stdio"
    );
    let text = frames[&3]["result"]["content"][0]["text"].as_str().expect("call text");
    let doc: serde_json::Value = serde_json::from_str(text).expect("call doc");
    assert_eq!(doc["ok"], true);
    let paths: Vec<&str> = doc["entries"]
        .as_array()
        .expect("entries")
        .iter()
        .map(|e| e["path"].as_str().expect("entry path"))
        .collect();
    assert!(paths.contains(&"scratch/s.txt"), "entries: {paths:?}");

    // Drop the single stream: server sees EOF, exits, unlinks.
    drop(reader);
    drop(stream);
    let out = child.wait_with_output().expect("wait serve");
    assert!(
        out.status.success(),
        "serve exits 0 on socket EOF: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(!sock.exists(), "socket must be unlinked after exit");
    assert!(
        String::from_utf8_lossy(&out.stdout).trim().is_empty(),
        "serve --socket must not write MCP frames to stdout"
    );

    // Parity: a --stdio server speaking the same handshake + tools/call
    // geode_list for the same token returns the same entry set.
    let mut stdio_child = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["--key", "k.gkey", "agent", "serve", "--stdio"])
        .current_dir(dir)
        .env("GEODE_TOKEN", &token)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn stdio for parity");
    let parity_req = concat!(
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}"#,
        "\n",
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        "\n",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"geode_list","arguments":{"vault":"v.geode","prefix":"scratch/"}}}"#,
        "\n",
    );
    stdio_child
        .stdin
        .take()
        .expect("stdio stdin")
        .write_all(parity_req.as_bytes())
        .expect("write parity req");
    let parity_out = stdio_child.wait_with_output().expect("wait stdio");
    let mut parity_doc: Option<serde_json::Value> = None;
    for line in String::from_utf8_lossy(&parity_out.stdout).lines() {
        let frame: serde_json::Value = serde_json::from_str(line).expect("parity frame json");
        if frame["id"].as_i64() == Some(3) {
            let text = frame["result"]["content"][0]["text"].as_str().expect("parity text");
            parity_doc = Some(serde_json::from_str(text).expect("parity doc"));
            break;
        }
    }
    let parity_doc = parity_doc.expect("parity geode_list frame");
    let parity_paths: Vec<&str> = parity_doc["entries"]
        .as_array()
        .expect("parity entries")
        .iter()
        .map(|e| e["path"].as_str().expect("entry path"))
        .collect();
    assert_eq!(
        paths, parity_paths,
        "socket geode_list must match --stdio geode_list for the same token"
    );
}
