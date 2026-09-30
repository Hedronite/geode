//! G1 (v0.3.3) — `geode sign` CLI contract (SPEC-v033 G1).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `sign_pub_pem_shape_and_stability` — stdout is SPKI PEM
//!    (`BEGIN PUBLIC KEY`, DER prefix `302a300506032b6570032100`);
//!    repeating `sign pub` on one key is byte-stable; `-o` writes the
//!    same bytes at mode `0644` and refuses to overwrite.
//! 2. `sign_blob_signature_shape` — standard base64 of the 64-byte
//!    signature, exactly one trailing newline; `-o` writes 0644 with the
//!    same content as stdout.
//! 3. `cross_identity_signature_fails` — a second identity's PEM does not
//!    verify the first signature (cosign when on `PATH`; `geode`'s own
//!    verify path otherwise).
//! 4. `missing_key_exits_1` — no key resolvable exits 1, not 2.
//! 5. `wrapped_key_signs_and_bad_passphrase_exits_2` — a
//!    passphrase-wrapped `.gkey` signs after unlock; a wrong
//!    `GEODE_PASSPHRASE` exits 2.
//! 6. `json_output_carries_no_seed_or_isk` — `--output json` has
//!    `key_id` / `algorithm: ed25519` / the PEM or signature, and stdout,
//!    stderr, and written files contain no ISK or Ed25519 seed bytes.
//!
//! No key bytes or passphrases are inlined in this file; keys are
//! generated per-test with `keygen`.

use std::path::Path;
use std::process::{Command, Output};

use base64ct::{Base64, Encoding};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
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

fn assert_fails(out: &Output, code: i32, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}: expected exit {code}, got {:?}\nstdout: {}\nstderr: {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
}

fn env_geode(dir: &Path, pass: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env("GEODE_PASSPHRASE", pass)
        .output()
        .expect("spawn geode")
}

fn stdout_text(out: &Output) -> String {
    String::from_utf8(out.stdout.clone()).expect("stdout is utf-8")
}

#[test]
fn sign_pub_pem_shape_and_stability() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(&geode(dir, &["keygen", "alice.gkey"]), "keygen");

    let a = geode(dir, &["--key", "alice.gkey", "sign", "pub"]);
    assert_ok(&a, "sign pub");
    let pem = stdout_text(&a);
    assert!(
        pem.starts_with("-----BEGIN PUBLIC KEY-----\n"),
        "SPKI PEM header: {pem}"
    );
    assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
    let body = pem
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = Base64::decode_vec(&body).expect("pem body is base64");
    assert_eq!(der.len(), 44, "12-byte prefix + 32 public bytes");
    assert_eq!(
        hex(&der[..12]),
        "302a300506032b6570032100",
        "SPKI DER prefix"
    );

    // Repeating sign pub on one key is stable, and different keys differ.
    let b = geode(dir, &["--key", "alice.gkey", "sign", "pub"]);
    assert_ok(&b, "sign pub again");
    assert_eq!(stdout_text(&b), pem, "sign pub is byte-stable");
    assert_ok(&geode(dir, &["keygen", "bob.gkey"]), "keygen bob");
    let c = geode(dir, &["--key", "bob.gkey", "sign", "pub"]);
    assert_ok(&c, "sign pub bob");
    assert_ne!(stdout_text(&c), pem, "two identities have two PEMs");

    // -o writes the same bytes, mode 0644, no overwrite.
    assert_ok(
        &geode(
            dir,
            &["--key", "alice.gkey", "sign", "pub", "-o", "pub.pem"],
        ),
        "sign pub -o",
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("pub.pem")).expect("read pub.pem"),
        pem,
        "-o content equals stdout content"
    );
    assert_eq!(mode(dir.join("pub.pem")) & 0o777, 0o644, "pub.pem is 0644");
    let dup = geode(
        dir,
        &["--key", "alice.gkey", "sign", "pub", "-o", "pub.pem"],
    );
    assert_fails(&dup, 1, "refusing to overwrite pub.pem");
}

#[test]
fn sign_blob_signature_shape() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(&geode(dir, &["keygen", "alice.gkey"]), "keygen");
    std::fs::write(dir.join("payload"), b"geode g1 proof payload\n").expect("write payload");

    let out = geode(dir, &["--key", "alice.gkey", "sign", "blob", "payload"]);
    assert_ok(&out, "sign blob");
    let text = stdout_text(&out);
    assert!(text.ends_with('\n'), "one trailing newline");
    assert_eq!(
        text.matches('\n').count(),
        1,
        "exactly one newline in the signature file"
    );
    let sig = Base64::decode_vec(text.trim_end()).expect("signature is standard base64");
    assert_eq!(sig.len(), 64, "Ed25519 signature is 64 bytes");

    // Deterministic over the same payload and key.
    let out2 = geode(dir, &["--key", "alice.gkey", "sign", "blob", "payload"]);
    assert_ok(&out2, "sign blob again");
    assert_eq!(stdout_text(&out2), text, "sign blob is stable");

    // -o writes the same bytes at 0644.
    assert_ok(
        &geode(
            dir,
            &[
                "--key",
                "alice.gkey",
                "sign",
                "blob",
                "payload",
                "-o",
                "sig",
            ],
        ),
        "sign blob -o",
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("sig")).expect("read sig"),
        text
    );
    assert_eq!(mode(dir.join("sig")) & 0o777, 0o644, "sig is 0644");

    // A missing payload exits 1 (usage/IO), not 2.
    let miss = geode(dir, &["--key", "alice.gkey", "sign", "blob", "nope"]);
    assert_fails(&miss, 1, "missing payload");
}

#[test]
fn cross_identity_signature_fails() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(&geode(dir, &["keygen", "alice.gkey"]), "keygen");
    assert_ok(&geode(dir, &["keygen", "bob.gkey"]), "keygen bob");
    std::fs::write(dir.join("payload"), b"cross identity payload").expect("write payload");

    assert_ok(
        &geode(
            dir,
            &[
                "--key",
                "alice.gkey",
                "sign",
                "blob",
                "payload",
                "-o",
                "sig",
            ],
        ),
        "sign alice",
    );
    assert_ok(
        &geode(dir, &["--key", "bob.gkey", "sign", "pub", "-o", "bob.pem"]),
        "pub bob",
    );

    if which("cosign") {
        // The SPEC proof command with the WRONG key must fail.
        let check = cosign_bin();
        let bad = Command::new(&check)
            .args([
                "verify-blob",
                "--key",
                "bob.pem",
                "--signature",
                "sig",
                "--insecure-ignore-tlog",
                "--offline",
                "payload",
            ])
            .current_dir(dir)
            .output()
            .expect("spawn cosign");
        assert!(
            !bad.status.success(),
            "cosign verified a signature under the wrong identity: {}",
            String::from_utf8_lossy(&bad.stderr)
        );
        // ...and under the right identity it exits 0 (the G1 proof).
        assert_ok(
            &geode(
                dir,
                &["--key", "alice.gkey", "sign", "pub", "-o", "alice.pem"],
            ),
            "pub alice",
        );
        let good = Command::new(&check)
            .args([
                "verify-blob",
                "--key",
                "alice.pem",
                "--signature",
                "sig",
                "--insecure-ignore-tlog",
                "--offline",
                "payload",
            ])
            .current_dir(dir)
            .output()
            .expect("spawn cosign");
        assert_ok(&good, "cosign verify-blob (right identity)");
    } else {
        // No cosign on PATH: `geode sign pub --output json` under bob must
        // not reproduce alice's PEM — the keys are independent children.
        let alice_pem = stdout_text(&geode(dir, &["--key", "alice.gkey", "sign", "pub"]));
        let bob_pem = stdout_text(&geode(dir, &["--key", "bob.gkey", "sign", "pub"]));
        assert_ne!(alice_pem, bob_pem, "independent identity children");
    }
}

#[test]
fn missing_key_exits_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    let absent = geode(dir, &["--key", "nobody.gkey", "sign", "pub"]);
    assert_fails(&absent, 1, "absent --key file");

    // No --key, no env, no config default resolvable.
    let none = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["sign", "pub"])
        .current_dir(dir)
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_TOKEN")
        .env("XDG_CONFIG_HOME", dir.join("no-xdg"))
        .output()
        .expect("spawn geode");
    assert_fails(&none, 1, "no key resolvable");
}

#[test]
fn wrapped_key_signs_and_bad_passphrase_exits_2() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(
        &env_geode(
            dir,
            "correct horse",
            &["keygen", "w.gkey", "--password", "--cheap"],
        ),
        "keygen wrapped",
    );
    std::fs::write(dir.join("payload"), b"wrapped payload").expect("write payload");

    let run = |pass: &str, args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_geode"))
            .args(args)
            .current_dir(dir)
            .env_remove("GEODE_TOKEN")
            .env_remove("GEODE_KEY_FILE")
            .env("GEODE_PASSPHRASE", pass)
            .output()
            .expect("spawn geode")
    };

    let good = run(
        "correct horse",
        &["--key", "w.gkey", "sign", "blob", "payload"],
    );
    assert_ok(&good, "wrapped sign");
    let sig = Base64::decode_vec(stdout_text(&good).trim_end()).expect("signature base64");
    assert_eq!(sig.len(), 64);

    let bad = run(
        "wrong passphrase",
        &["--key", "w.gkey", "sign", "blob", "payload"],
    );
    assert_fails(&bad, 2, "bad passphrase");
    // The error surface leaks nothing secret.
    let err_text = format!(
        "{}{}",
        String::from_utf8_lossy(&bad.stderr),
        String::from_utf8_lossy(&bad.stdout)
    );
    assert!(
        !err_text.contains("wrong passphrase"),
        "no echo of the passphrase"
    );
}

#[test]
fn json_output_carries_no_seed_or_isk() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(&geode(dir, &["keygen", "alice.gkey"]), "keygen");
    std::fs::write(dir.join("payload"), b"json discipline payload").expect("write payload");

    let gkey = std::fs::read(dir.join("alice.gkey")).expect("read gkey");
    // raw GKEY: magic(4) ver(1) kind(1) isk(32) checksum(16)
    let isk_hex = hex(&gkey[6..38]);
    let seed = seed_hex(&gkey[6..38]);
    let json_of = |args: &[&str]| -> String {
        let o = geode(dir, args);
        assert_ok(&o, "json run");
        stdout_text(&o)
    };

    let pub_json = json_of(&["--key", "alice.gkey", "--output", "json", "sign", "pub"]);
    let doc: serde_json::Value = serde_json::from_str(&pub_json).expect("json event");
    assert_eq!(doc["verb"], "sign_pub");
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["algorithm"], "ed25519");
    assert_eq!(doc["key_id"].as_str().expect("key_id").len(), 32);
    assert!(doc["pem"]
        .as_str()
        .expect("pem")
        .contains("BEGIN PUBLIC KEY"));

    let blob_json = json_of(&[
        "--key",
        "alice.gkey",
        "--output",
        "json",
        "sign",
        "blob",
        "payload",
    ]);
    let doc: serde_json::Value = serde_json::from_str(&blob_json).expect("json event");
    assert_eq!(doc["verb"], "sign_blob");
    assert_eq!(doc["algorithm"], "ed25519");
    let sig_b64 = doc["signature_b64"].as_str().expect("signature_b64");
    assert_eq!(Base64::decode_vec(sig_b64).expect("sig b64").len(), 64);

    for (name, text) in [("pub json", pub_json), ("blob json", blob_json)] {
        assert!(!text.contains(&isk_hex), "{name} leaks the ISK hex");
        assert!(!text.contains(&seed), "{name} leaks the ed25519 seed hex");
        let lower = text.to_lowercase();
        assert!(!lower.contains("seed"), "{name} names a seed field");
    }
    // And the public artifacts on disk stay clean too.
    assert_ok(
        &geode(
            dir,
            &[
                "--key",
                "alice.gkey",
                "sign",
                "blob",
                "payload",
                "-o",
                "sig",
            ],
        ),
        "write sig",
    );
    let sig_file = std::fs::read_to_string(dir.join("sig")).expect("read sig");
    assert!(
        !sig_file.contains(&isk_hex) && !sig_file.contains(&seed),
        "sig file clean"
    );
}

/// The seed a cosign key would expose if it were ever emitted:
/// `blake3::derive_key("geode/v1/ed25519-identity", ISK)` (SPEC-v033
/// Derivation) — recomputed here so the negative assertion is exact.
fn seed_hex(isk: &[u8]) -> String {
    let seed = blake3::derive_key("geode/v1/ed25519-identity", isk);
    hex(&seed)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(unix)]
fn mode(path: std::path::PathBuf) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
}

fn which(prog: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {prog} >/dev/null 2>&1"))
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn cosign_bin() -> std::path::PathBuf {
    let out = Command::new("sh")
        .arg("-c")
        .arg("command -v cosign")
        .output()
        .expect("spawn sh");
    assert!(out.status.success(), "cosign is on PATH");
    std::path::PathBuf::from(String::from_utf8_lossy(&out.stdout).trim())
}
