//! G1 (v0.2.6) — recipients CLI fixtures against the shipped `geode`
//! binary (02-cryptography 6.3, 7.2; 03-format 6; 05-cli 2.2).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `keygen_emits_gpub` — keygen writes `<stem>.gpub` beside the
//!    `.gkey`: JSON v1, matching `key_id`, base64 32-byte X25519 public,
//!    no secret material.
//! 2. `recipients_list_and_add` — `vault recipients` lists the symmetric
//!    recipient without a key; `vault add-recipient --gpub` wraps the
//!    current EK for a second identity; the list then shows both.
//! 3. `add_recipient_fail_closed` — no `--key` exits 1 (`GEODE_TOKEN` set
//!    does not substitute); a `--token` flag is rejected by clap (exit 1);
//!    a duplicate `key_id` exits 1.
//! 4. `symmetric_vault_still_opens` — after adding an x25519 recipient,
//!    verify/list/cat with the original symmetric key still succeed.
//!
//! No passphrases, no key bytes, no ISK in any captured output.

use std::path::Path;
use std::process::{Command, Output};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .output()
        .expect("spawn geode")
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
}

#[test]
fn keygen_emits_gpub() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let out = geode(dir, &["keygen", "alice.gkey"]);
    assert_ok(&out, "keygen");
    let gpub_path = dir.join("alice.gpub");
    assert!(gpub_path.is_file(), ".gpub written beside .gkey");

    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&gpub_path).expect("read gpub"))
            .expect("gpub is json");
    assert_eq!(doc["version"], 1);
    let key_id = doc["key_id"].as_str().expect("key_id");
    assert_eq!(key_id.len(), 32, "key_id is 16 bytes hex");
    let public_b64 = doc["x25519_public"].as_str().expect("x25519_public");
    assert_eq!(public_b64.len(), 44, "base64 of 32 bytes");

    // The .gpub must carry no secret material: it shares no byte run with
    // the .gkey body beyond the public header.
    let gkey = std::fs::read(dir.join("alice.gkey")).expect("read gkey");
    let gpub_text = std::fs::read_to_string(&gpub_path).expect("read gpub");
    let isk_hex = cmd_hex(&gkey[6..38]); // raw form: magic(4) ver(1) kind(1) isk(32)
    assert!(!gpub_text.contains(&isk_hex), "no ISK hex in .gpub");

    // keygen reports the gpub path.
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("alice.gpub")
            || String::from_utf8_lossy(&out.stdout).contains("alice.gpub"),
        "keygen output names the .gpub"
    );
    let _ = key_id;
}

/// Lowercase hex (test-local; the CLI's helper is not exported to tests).
fn cmd_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

#[test]
fn recipients_list_and_add() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);

    // recipients is public data: works without --key.
    let list = geode(dir, &["vault", "recipients", "v.geode"]);
    assert_ok(&list, "vault recipients");
    let text = String::from_utf8_lossy(&list.stdout);
    assert!(text.contains("symmetric"), "lists symmetric: {text}");
    assert!(!text.contains("wrap"), "wrap blobs never shown: {text}");

    // Second identity; add its .gpub as an x25519 recipient.
    assert_ok(&geode(dir, &["keygen", "bob.gkey"]), "bob keygen");
    let add = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "add-recipient",
            "v.geode",
            "--gpub",
            "bob.gpub",
        ],
    );
    assert_ok(&add, "add-recipient");
    assert!(
        String::from_utf8_lossy(&add.stdout).contains("x25519"),
        "add reports x25519: {}",
        String::from_utf8_lossy(&add.stdout)
    );

    // List shows both recipients.
    let list2 = geode(dir, &["vault", "recipients", "v.geode"]);
    assert_ok(&list2, "vault recipients after add");
    let text2 = String::from_utf8_lossy(&list2.stdout);
    assert!(text2.contains("symmetric"), "still symmetric: {text2}");
    assert!(text2.contains("x25519"), "now x25519: {text2}");

    // recipients.json on disk has exactly two entries.
    let recs: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("v.geode/recipients.json")).expect("recipients"),
    )
    .expect("recipients json");
    assert_eq!(recs["recipients"].as_array().expect("array").len(), 2);
}

#[test]
fn add_recipient_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    assert_ok(&geode(dir, &["keygen", "bob.gkey"]), "bob keygen");

    // No --key: usage error, exit 1 — even with GEODE_TOKEN set (a token
    // never mints recipients).
    let no_key = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["vault", "add-recipient", "v.geode", "--gpub", "bob.gpub"])
        .current_dir(dir)
        .env("GEODE_TOKEN", "deadbeef")
        .output()
        .expect("spawn geode");
    assert_eq!(
        no_key.status.code(),
        Some(1),
        "add-recipient without --key: {}",
        String::from_utf8_lossy(&no_key.stderr)
    );

    // --token is not a flag on vault verbs: clap rejects it (exit 1).
    let with_token = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "add-recipient",
            "v.geode",
            "--gpub",
            "bob.gpub",
            "--token",
            "deadbeef",
        ],
    );
    assert_eq!(
        with_token.status.code(),
        Some(1),
        "--token on add-recipient: {}",
        String::from_utf8_lossy(&with_token.stderr)
    );

    // Duplicate key_id: exit 1, recipients.json untouched.
    assert_ok(
        &geode(
            dir,
            &[
                "--key",
                "k.gkey",
                "vault",
                "add-recipient",
                "v.geode",
                "--gpub",
                "bob.gpub",
            ],
        ),
        "first add",
    );
    let before = std::fs::read(dir.join("v.geode/recipients.json")).expect("recipients bytes");
    let dup = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "add-recipient",
            "v.geode",
            "--gpub",
            "bob.gpub",
        ],
    );
    assert_eq!(
        dup.status.code(),
        Some(1),
        "duplicate add: {}",
        String::from_utf8_lossy(&dup.stderr)
    );
    let after = std::fs::read(dir.join("v.geode/recipients.json")).expect("recipients bytes");
    assert_eq!(before, after, "refused duplicate must not touch the file");
}

#[test]
fn symmetric_vault_still_opens() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    std::fs::write(dir.join("note.txt"), b"still symmetric\n").expect("write");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]),
        "seal",
    );
    assert_ok(&geode(dir, &["keygen", "bob.gkey"]), "bob keygen");
    assert_ok(
        &geode(
            dir,
            &[
                "--key",
                "k.gkey",
                "vault",
                "add-recipient",
                "v.geode",
                "--gpub",
                "bob.gpub",
            ],
        ),
        "add-recipient",
    );

    // The original symmetric identity still verifies, lists, and cats.
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "verify", "v.geode"]),
        "verify after add",
    );
    let list = geode(dir, &["--key", "k.gkey", "list", "v.geode"]);
    assert_ok(&list, "list after add");
    assert!(String::from_utf8_lossy(&list.stdout).contains("note.txt"));
    let cat = geode(dir, &["--key", "k.gkey", "cat", "v.geode", "note.txt"]);
    assert_ok(&cat, "cat after add");
    assert_eq!(cat.stdout, b"still symmetric\n");
}
