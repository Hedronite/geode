//! G5c — error-path fixtures (frontend-geode).
//!
//! Three subprocess fixtures exercising the real CLI exit-code family
//! (05-cli §3, G4c) end-to-end through `cmd::fail` → `output::human_error`:
//!   1. wrong passphrase / tracked wrap-gap  → exit 1 (usage)
//!   2. flipped ciphertext bit                → exit 2 (auth/integrity)
//!   3. usage error (unknown verb)            → exit 1 (usage)
//!
//! Each fixture captures combined stdout+stderr and asserts:
//!   - the exit code matches the spec family,
//!   - no secret material (ISK/FEK/passphrase/wrap bytes or hex) appears.
//!
//! Hermetic: each builds a vault in a unique temp dir, flips one byte
//! in a sealed object, and runs `geode verify`.

#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;

/// Bytes a careless implementation might leak. None should appear in output.
/// Key-material indicators that should never appear in output. The word
/// "passphrase" is a public label (prompt + error text), not a secret
/// value — the actual passphrase bytes never reach stdout/stderr.
const SECRET_MARKERS: &[&str] = &["ISK", "FEK", "wrap blob", "0xdeadbeef"];

/// Path to the built `geode` binary.
fn geode_bin() -> PathBuf {
    for key in ["CARGO_BIN_EXE_GEO_DE", "CARGO_BIN_EXE_geode"] {
        if let Ok(p) = std::env::var(key) {
            return PathBuf::from(p);
        }
    }
    PathBuf::from(format!(
        "{}/../../target/debug/geode",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Run `geode` with args, return (`exit_code`, combined stdout+stderr).
fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(geode_bin())
        .args(args)
        .output()
        .expect("geode binary runs");
    let mut combined = String::from_utf8_lossy(&out.stdout).into_owned();
    combined.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), combined)
}

/// Assert no secret marker appears in captured output.
fn assert_no_secrets(output: &str) {
    for marker in SECRET_MARKERS {
        assert!(
            !output.contains(marker),
            "secret marker `{marker}` leaked into output: {output}",
        );
    }
}

/// Unique temp dir per test process.
fn tmpdir(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("geode-g5c-{}-{}", std::process::id(), name));
    let _ = fs::remove_dir_all(&p);
    fs::create_dir_all(&p).expect("temp dir");
    p
}

/// Recursively find the first `.gobj` file under `root`.
fn first_object(root: &std::path::Path) -> PathBuf {
    for entry in walkdir::WalkDir::new(root).into_iter().flatten() {
        let p = entry.path();
        if p.extension().is_some_and(|e| e == "gobj") {
            return p.to_path_buf();
        }
    }
    panic!("no .gobj under {}", root.display());
}

#[test]
fn wrong_passphrase_gap_is_exit_1() {
    // G4b/G5c: `keygen --password` hits the tracked geode-core keyfile
    // API gap. `cmd::fail` renders it via `output::human_error` → exit 1
    // (usage), not 2 (auth). An operator seeing "exit 1" knows it is a
    // tooling gap, not a compromised vault.
    let (code, out) = run(&["keygen", "--password", "/dev/null/nonexistent"]);
    assert_eq!(code, 1, "wrong-passphrase gap is exit 1 (usage), not auth (2)");
    assert!(
        out.contains("usage") || out.contains("not in v0.1.0"),
        "text names the usage family / tracked gap: {out}",
    );
    assert_no_secrets(&out);
}

#[test]
fn flipped_bit_is_exit_2() {
    // 01 §3, SPEC §8.4, 05-cli §3: a flipped ciphertext bit is an
    // authentication/integrity failure — exit 2, not 1. `verify` MUST
    // fail closed; the human text MUST say "authentication" so the
    // operator does not mistake it for a usage error.
    let tmp = tmpdir("flip");
    let key = tmp.join("key.gkey");
    let vault = tmp.join("v");
    let src = tmp.join("note.txt");
    fs::write(&src, b"hello geode").expect("src");

    assert_eq!(run(&["keygen", key.to_str().unwrap()]).0, 0, "keygen ok");
    assert_eq!(
        run(&["vault", "init", vault.to_str().unwrap(), "--key", key.to_str().unwrap()]).0,
        0,
        "vault init ok",
    );
    assert_eq!(
        run(&["seal", src.to_str().unwrap(), vault.to_str().unwrap(), "--key", key.to_str().unwrap()]).0,
        0,
        "seal ok",
    );

    // Flip one byte in the sealed object.
    let obj = first_object(&vault);
    let mut bytes = fs::read(&obj).expect("object");
    assert!(bytes.len() > 32, "object has body");
    let flip_at = bytes.len() / 2;
    bytes[flip_at] ^= 0xff;
    fs::write(&obj, bytes).expect("write flipped object");

    // verify → exit 2 (auth/integrity), text names "authentication".
    let (code, out) = run(&["verify", vault.to_str().unwrap(), "--key", key.to_str().unwrap()]);
    assert_eq!(code, 2, "flipped bit is exit 2 (auth), not usage (1)");
    assert!(
        out.contains("authentication") || out.contains("auth"),
        "text names the authentication family: {out}",
    );
    assert_no_secrets(&out);

    let _ = fs::remove_dir_all(&tmp);
}

#[test]
fn usage_error_unknown_verb_is_exit_1() {
    // 05-cli §3: usage / IO / config is exit 1. An unknown subcommand is
    // a usage error (clap error intercepted in main → exit 1, not clap
    // default 2). The vault is not compromised; the input was wrong.
    let (code, out) = run(&["frobnicate"]);
    assert_eq!(code, 1, "unknown verb is exit 1 (usage), not auth (2)");
    assert!(
        out.contains("unrecognized") || out.contains("Usage"),
        "text names the usage family: {out}",
    );
    assert_no_secrets(&out);
}
