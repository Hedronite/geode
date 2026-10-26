//! G1 (v0.2.7) — `geode vault rotate` fixtures against the shipped binary
//! (04-vault 6; SPEC-v027 G1a–G1c).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `rotate_increments_epoch` — `--key` + `--yes` bumps epoch (footer +
//!    `header.json` / `recipients.json`).
//! 2. `rotate_drop_reseal_and_add` — drop+reseal is the complete path;
//!    `--add-recipient` wraps the new EK; drop without `--reseal` still
//!    succeeds (incomplete revocation).
//! 3. `rotate_token_rejected` — clap rejects `--token`; `GEODE_TOKEN`
//!    never substitutes for `--key`; symmetric and x25519 vaults still
//!    open after rotate.
//!
//! No passphrases, no key bytes, no ISK in any captured output.

use std::path::Path;
use std::process::{Command, Output};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        // Never resolve the operator's key, keyring or config.
        .env("HOME", dir.join(".iso/home"))
        .env("XDG_CONFIG_HOME", dir.join(".iso/config"))
        .env("XDG_DATA_HOME", dir.join(".iso/data"))
        .env("XDG_STATE_HOME", dir.join(".iso/state"))
        .env("XDG_CACHE_HOME", dir.join(".iso/cache"))
        .env("XDG_RUNTIME_DIR", dir.join(".iso/runtime"))
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .output()
        .expect("spawn geode")
}

fn assert_ok(out: &Output, what: &str) {
    assert!(
        out.status.success(),
        "{what} failed (code {:?}): stdout={} stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn combined(out: &Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

fn isk_hex(dir: &Path, gkey: &str) -> String {
    let raw = std::fs::read(dir.join(gkey)).expect("read gkey");
    raw[6..38].iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn assert_no_isk(out: &Output, dir: &Path, keys: &[&str], what: &str) {
    let text = combined(out);
    for k in keys {
        let hex = isk_hex(dir, k);
        assert!(
            !text.contains(&hex),
            "{what} leaked ISK hex from {k}: {text}"
        );
        assert!(!text.contains("ISK"), "{what} leaked ISK marker: {text}");
    }
}

fn gpub_key_id(dir: &Path, name: &str) -> String {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(name)).expect("read gpub"))
            .expect("gpub json");
    doc["key_id"].as_str().expect("key_id").to_string()
}

fn header_epoch(dir: &Path) -> u64 {
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("v.geode/header.json")).expect("header"),
    )
    .expect("header json");
    doc["epoch"].as_u64().expect("epoch")
}

fn recs_epoch_and_types(dir: &Path) -> (u64, Vec<String>) {
    let doc: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(dir.join("v.geode/recipients.json")).expect("recipients"),
    )
    .expect("recipients json");
    let epoch = doc["epoch"].as_u64().expect("epoch");
    let types = doc["recipients"]
        .as_array()
        .expect("array")
        .iter()
        .map(|r| r["type"].as_str().unwrap_or("").to_string())
        .collect();
    (epoch, types)
}

fn setup_vault(dir: &Path) {
    assert_ok(
        &geode(dir, &["keygen", "--insecure-plaintext", "k.gkey"]),
        "keygen",
    );
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]),
        "vault init",
    );
}

fn add_bob(dir: &Path) -> String {
    assert_ok(
        &geode(dir, &["keygen", "--insecure-plaintext", "bob.gkey"]),
        "bob keygen",
    );
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
        "add-recipient bob",
    );
    gpub_key_id(dir, "bob.gpub")
}

#[test]
fn rotate_increments_epoch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    assert_eq!(header_epoch(dir), 1);

    let no_yes = geode(dir, &["--key", "k.gkey", "vault", "rotate", "v.geode"]);
    assert_eq!(
        no_yes.status.code(),
        Some(1),
        "rotate without --yes: {}",
        combined(&no_yes)
    );

    let out = geode(
        dir,
        &["--key", "k.gkey", "vault", "rotate", "v.geode", "--yes"],
    );
    assert_ok(&out, "vault rotate --yes");
    assert_no_isk(&out, dir, &["k.gkey"], "rotate");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("epoch 2") || text.contains("epoch\":2"),
        "footer names epoch 2: {text}"
    );
    assert_eq!(header_epoch(dir), 2, "header.json epoch += 1");
    let (recs_epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(recs_epoch, 2);
    assert_eq!(types, vec!["symmetric".to_string()]);

    assert_ok(
        &geode(dir, &["--key", "k.gkey", "verify", "v.geode"]),
        "verify after rotate",
    );
}

#[test]
fn rotate_drop_reseal_complete() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    std::fs::write(dir.join("note.txt"), b"epoch-object\n").expect("write");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]),
        "seal",
    );
    let bob_id = add_bob(dir);
    let complete = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "rotate",
            "v.geode",
            "--yes",
            "--reseal",
            "--drop-recipient",
            &bob_id,
        ],
    );
    assert_ok(&complete, "rotate drop+reseal");
    assert_no_isk(&complete, dir, &["k.gkey", "bob.gkey"], "drop+reseal");
    let (epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(epoch, 2);
    assert_eq!(types, vec!["symmetric".to_string()]);
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "verify", "v.geode"]),
        "verify after reseal",
    );
    let cat = geode(dir, &["--key", "k.gkey", "cat", "v.geode", "note.txt"]);
    assert_ok(&cat, "cat after reseal");
    assert_eq!(cat.stdout, b"epoch-object\n");
    let bob_open = geode(dir, &["--key", "bob.gkey", "open", "v.geode", "out-bob"]);
    assert_eq!(
        bob_open.status.code(),
        Some(2),
        "dropped sk open: {}",
        combined(&bob_open)
    );
}

#[test]
fn rotate_drop_without_reseal_succeeds() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let bob_id = add_bob(dir);
    let drop_only = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "rotate",
            "v.geode",
            "--yes",
            "--drop-recipient",
            &bob_id,
        ],
    );
    assert_ok(&drop_only, "rotate drop without reseal");
    assert_no_isk(&drop_only, dir, &["k.gkey", "bob.gkey"], "drop no-reseal");
    let text = combined(&drop_only);
    assert!(
        text.contains("incomplete"),
        "names incomplete revocation: {text}"
    );
    let (epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(epoch, 2);
    assert_eq!(types, vec!["symmetric".to_string()]);
    assert!(
        dir.join("v.geode/epochs/00000001/recipients.json")
            .is_file(),
        "old epoch recipients snapshotted"
    );
}

#[test]
fn rotate_add_recipient_wraps_new_ek() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    assert_ok(
        &geode(dir, &["keygen", "--insecure-plaintext", "bob.gkey"]),
        "bob keygen",
    );
    let add = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "rotate",
            "v.geode",
            "--yes",
            "--add-recipient",
            "bob.gpub",
        ],
    );
    assert_ok(&add, "rotate --add-recipient");
    assert_no_isk(&add, dir, &["k.gkey", "bob.gkey"], "add-recipient rotate");
    let (epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(epoch, 2);
    assert!(
        types.iter().any(|t| t == "x25519"),
        "add wraps new EK: {types:?}"
    );
    assert!(types.iter().any(|t| t == "symmetric"));
}

#[test]
fn rotate_token_rejected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    std::fs::write(dir.join("note.txt"), b"still open\n").expect("write");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]),
        "seal",
    );
    let _ = add_bob(dir);

    // clap rejects --token on vault rotate (exit 1 usage).
    let with_token = geode(
        dir,
        &[
            "--key", "k.gkey", "vault", "rotate", "v.geode", "--yes", "--token", "deadbeef",
        ],
    );
    assert_eq!(
        with_token.status.code(),
        Some(1),
        "--token on rotate: {}",
        combined(&with_token)
    );

    // GEODE_TOKEN never substitutes for --key.
    let no_key = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["vault", "rotate", "v.geode", "--yes"])
        .current_dir(dir)
        .env("GEODE_TOKEN", "deadbeef")
        .env_remove("GEODE_KEY_FILE")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .output()
        .expect("spawn geode");
    assert_eq!(
        no_key.status.code(),
        Some(1),
        "GEODE_TOKEN without --key: {}",
        combined(&no_key)
    );

    // Symmetric + x25519 vault still opens after rotate (and reseal so
    // objects stay in the current epoch).
    let rot = geode(
        dir,
        &[
            "--key", "k.gkey", "vault", "rotate", "v.geode", "--yes", "--reseal",
        ],
    );
    assert_ok(&rot, "rotate x25519 vault");
    assert_no_isk(&rot, dir, &["k.gkey", "bob.gkey"], "rotate x25519");
    let (epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(epoch, 2);
    assert!(types.iter().any(|t| t == "symmetric"));
    assert!(types.iter().any(|t| t == "x25519"));

    assert_ok(
        &geode(dir, &["--key", "k.gkey", "verify", "v.geode"]),
        "verify after rotate",
    );
    let cat = geode(dir, &["--key", "k.gkey", "cat", "v.geode", "note.txt"]);
    assert_ok(&cat, "cat after rotate");
    assert_eq!(cat.stdout, b"still open\n");
    let list = geode(dir, &["--key", "k.gkey", "list", "v.geode"]);
    assert_ok(&list, "list after rotate");
    assert!(String::from_utf8_lossy(&list.stdout).contains("note.txt"));
}

// ---- Re-key lockout regressions ----

fn seal_note(dir: &Path) {
    std::fs::write(dir.join("note.txt"), b"rekey-object\n").expect("write");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]),
        "seal",
    );
}

fn assert_reads(dir: &Path, key: &str, what: &str) {
    assert_ok(&geode(dir, &["--key", key, "verify", "v.geode"]), what);
    assert_ok(&geode(dir, &["--key", key, "list", "v.geode"]), what);
    let cat = geode(dir, &["--key", key, "cat", "v.geode", "note.txt"]);
    assert_ok(&cat, what);
    assert_eq!(cat.stdout, b"rekey-object\n", "{what}");
}

fn vault_snapshot(root: &Path) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for ent in std::fs::read_dir(&d).expect("read_dir") {
            let p = ent.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p.strip_prefix(root).unwrap().display().to_string();
                out.push((rel, std::fs::read(&p).expect("read")));
            }
        }
    }
    out.sort();
    out
}

#[test]
fn add_recipient_new_key_reads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    seal_note(dir);
    add_bob(dir);
    assert_reads(dir, "bob.gkey", "added x25519 recipient reads");
    assert_reads(dir, "k.gkey", "original key still reads");
}

#[test]
fn rotate_drop_old_reseal_new_key_still_reads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    seal_note(dir);
    add_bob(dir);
    let old_id = gpub_key_id(dir, "k.gpub");
    let rot = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "vault",
            "rotate",
            "v.geode",
            "--yes",
            "--drop-recipient",
            &old_id,
            "--reseal",
        ],
    );
    assert_ok(&rot, "rotate drop old + reseal");
    assert_no_isk(&rot, dir, &["k.gkey", "bob.gkey"], "drop old");
    let (epoch, types) = recs_epoch_and_types(dir);
    assert_eq!(epoch, 2);
    assert_eq!(types, vec!["x25519".to_string()]);
    assert_reads(dir, "bob.gkey", "new key after rotate");
    let old = geode(dir, &["--key", "k.gkey", "cat", "v.geode", "note.txt"]);
    assert_eq!(old.status.code(), Some(2), "old key: {}", combined(&old));
    // The x25519 identity can now rotate the vault it holds alone.
    assert_ok(
        &geode(
            dir,
            &[
                "--key", "bob.gkey", "vault", "rotate", "v.geode", "--yes", "--reseal",
            ],
        ),
        "new key rotates",
    );
    assert_reads(dir, "bob.gkey", "new key after its own rotate");
}

#[test]
fn rotate_lockout_refused_vault_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    seal_note(dir);
    let bob_id = add_bob(dir);
    let before = vault_snapshot(&dir.join("v.geode"));
    // The x25519 identity cannot re-wrap the original symmetric recipient:
    // keeping it (with or without dropping itself) would lock it out.
    for drops in [vec![], vec!["--drop-recipient", bob_id.as_str()]] {
        let mut args = vec![
            "--key", "bob.gkey", "vault", "rotate", "v.geode", "--yes", "--reseal",
        ];
        args.extend(drops);
        let out = geode(dir, &args);
        assert_eq!(out.status.code(), Some(1), "refused: {}", combined(&out));
        assert!(combined(&out).contains("locked out"), "{}", combined(&out));
        assert_eq!(
            vault_snapshot(&dir.join("v.geode")),
            before,
            "vault unchanged after refused rotate"
        );
    }
    assert_reads(dir, "k.gkey", "original key after refusal");
    assert_reads(dir, "bob.gkey", "x25519 key after refusal");
}

#[cfg(unix)]
#[test]
fn open_writes_plaintext_0600() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    std::fs::write(dir.join("note.txt"), b"rekey-object\n").expect("write");
    std::fs::set_permissions(dir.join("note.txt"), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]),
        "seal",
    );
    assert_ok(
        &geode(dir, &["--key", "k.gkey", "open", "v.geode", "out"]),
        "open",
    );
    let mode = std::fs::metadata(dir.join("out/note.txt"))
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "open output mode {mode:o}");
    assert_eq!(
        std::fs::read(dir.join("out/note.txt")).expect("read"),
        b"rekey-object\n"
    );
}
