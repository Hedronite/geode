//! SPEC-v034 G7 — custody flags and client checks against the shipped
//! binary. The daemon's protocol is tested in-process in `cmd::custody`;
//! here a fake server stands in so no `geode` account, no root, and no
//! `/run/geode` is needed.
//!
//! G7a: `--custody --stdio` and `--custody --socket` exit 1. `--key` with
//!      a custody client exits 1. `GEODE_KEY_FILE` is ignored with one
//!      warning.
//! G7b: the daemon refuses to start as anyone but the custody user.
//! G7c: a custody peer that shares the caller's uid exits 1 before any
//!      passphrase is read or sent.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::thread;

fn geode(dir: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_geode"));
    c.current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .stdin(Stdio::null());
    c
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// A fake server on `path` that answers every request. `custody` sets the
/// `initialize` capability. Each request line is sent back to the test.
fn fake_server(path: &Path, custody: bool) -> mpsc::Receiver<String> {
    let listener = UnixListener::bind(path).unwrap();
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            let mut w = stream.try_clone().unwrap();
            for line in BufReader::new(stream).lines() {
                let Ok(line) = line else { break };
                let req: serde_json::Value = serde_json::from_str(&line).unwrap();
                let _ = tx.send(line.clone());
                let result = if req["method"] == "initialize" {
                    serde_json::json!({"capabilities": {"experimental": {"geode": {"custody": custody}}}})
                } else {
                    serde_json::json!({"locked": true})
                };
                let resp = serde_json::json!({"jsonrpc": "2.0", "id": req["id"], "result": result});
                if writeln!(w, "{resp}").is_err() {
                    break;
                }
            }
        }
    });
    rx
}

fn tmp() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().unwrap();
    let p = std::fs::canonicalize(t.path()).unwrap();
    (t, p)
}

#[test]
fn custody_serve_flag_refusals() {
    let (_t, dir) = tmp();
    for (args, want) in [
        (
            vec!["agent", "serve", "--custody", "--stdio", "--vault", "v"],
            "--stdio",
        ),
        (
            vec![
                "agent",
                "serve",
                "--custody",
                "--socket",
                "s.sock",
                "--vault",
                "v",
            ],
            "--socket",
        ),
        (vec!["agent", "serve", "--custody"], "--vault"),
        (
            vec![
                "agent",
                "serve",
                "--custody",
                "--vault",
                "v",
                "--token-file",
                "t",
            ],
            "per connection",
        ),
        (
            vec!["agent", "serve", "--socket", "s.sock", "--vault", "v"],
            "--custody",
        ),
    ] {
        let o = geode(&dir).args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", err(&o));
        assert!(err(&o).contains(want), "{args:?}: {}", err(&o));
    }
    assert!(!dir.join("s.sock").exists());
}

#[test]
fn custody_daemon_refuses_a_non_custody_user() {
    // The runner is never `geode` / `_geode`, and may be euid 0 in a
    // container or the console user on a desktop: each is a refusal.
    let (_t, dir) = tmp();
    let o = geode(&dir)
        .args(["agent", "serve", "--custody", "--vault", "v"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    let e = err(&o);
    assert!(
        ["euid 0", "console user", "runs only as", "does not exist"]
            .iter()
            .any(|w| e.contains(w)),
        "{e}"
    );
}

#[test]
fn passphrase_env_refused_for_custody_in_agent_context() {
    let (_t, dir) = tmp();
    let o = geode(&dir)
        .args(["agent", "serve", "--custody", "--vault", "v"])
        .env("GEODE_TOKEN", "deadbeef")
        .env("GEODE_PASSPHRASE", "dummy-pass-0000QA")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        err(&o).contains("GEODE_PASSPHRASE refused in an agent context"),
        "{}",
        err(&o)
    );
    let o = geode(&dir)
        .args(["custody", "status", "--socket", "nope.sock"])
        .env("GEODE_TOKEN", "deadbeef")
        .env("GEODE_PASSPHRASE", "dummy-pass-0000QA")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(
        err(&o).contains("GEODE_PASSPHRASE refused in an agent context"),
        "{}",
        err(&o)
    );
    assert!(!err(&o).contains("dummy-pass-0000QA"));
}

#[test]
fn key_with_socket_exits_1_and_key_file_env_is_ignored_once() {
    let (_t, dir) = tmp();
    let sock = dir.join("c.sock");
    let sock_s = sock.to_str().unwrap();
    let o = geode(&dir)
        .args(["--key", "k.gkey", "custody", "status", "--socket", sock_s])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("--key cannot be combined with --socket"),
        "{}",
        err(&o)
    );

    let o = geode(&dir)
        .args(["custody", "status", "--socket", sock_s])
        .env("GEODE_KEY_FILE", "k.gkey")
        .output()
        .unwrap();
    let e = err(&o);
    assert_eq!(
        e.matches("geode: warning: GEODE_KEY_FILE ignored in socket mode")
            .count(),
        1,
        "{e}"
    );
    // No daemon there: a connect failure, exit 1, not a key load.
    assert_eq!(o.status.code(), Some(1), "{e}");
    assert!(e.contains("cannot connect"), "{e}");
}

#[test]
fn same_uid_custody_peer_exits_1_before_any_passphrase() {
    let (_t, dir) = tmp();
    let sock = dir.join("c.sock");
    let rx = fake_server(&sock, true);
    let sock_s = sock.to_str().unwrap();

    let o = geode(&dir)
        .args(["custody", "status", "--socket", sock_s])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("custody peer shares caller uid"),
        "{}",
        err(&o)
    );

    // unlock with a passphrase on fd 0: the passphrase never reaches the peer.
    let mut child = geode(&dir)
        .args([
            "custody",
            "unlock",
            "--socket",
            sock_s,
            "--passphrase-fd",
            "0",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"dummy-pass-0000QA\n")
        .unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("custody peer shares caller uid"),
        "{}",
        err(&o)
    );
    let seen: Vec<String> = rx.try_iter().collect();
    assert!(
        seen.iter().all(|l| l.contains("\"initialize\"")),
        "{seen:?}"
    );
    assert!(
        seen.iter().all(|l| !l.contains("dummy-pass")),
        "passphrase sent: {seen:?}"
    );
}

#[test]
fn non_custody_socket_is_refused() {
    let (_t, dir) = tmp();
    let sock = dir.join("plain.sock");
    let _rx = fake_server(&sock, false);
    let o = geode(&dir)
        .args(["custody", "lock", "--socket", sock.to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("is not a custody socket"), "{}", err(&o));
}

#[test]
fn unlock_without_fd_or_tty_exits_1() {
    let (_t, dir) = tmp();
    let o = geode(&dir)
        .args(["custody", "unlock", "--socket", "nope.sock"])
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("--passphrase-fd N or a TTY"),
        "{}",
        err(&o)
    );
}

#[test]
fn custody_help_has_no_key_material_or_mount() {
    let (_t, dir) = tmp();
    for args in [
        vec!["custody", "--help"],
        vec!["custody", "status", "--help"],
        vec!["agent", "serve", "--help"],
    ] {
        let o = geode(&dir).args(&args).output().unwrap();
        assert_eq!(o.status.code(), Some(0));
        let h = String::from_utf8_lossy(&o.stdout);
        assert!(!h.contains("sk-dummy"), "{h}");
    }
    let o = geode(&dir).args(["custody", "mount"]).output().unwrap();
    assert_eq!(o.status.code(), Some(1), "custody has no mount verb");
}
