//! `geode keygen` is protected by default (Fix 1).
//!
//! 1. No mode flag and a non-TTY stdin is refused: exit 1, no file.
//! 2. `GEODE_PASSPHRASE` (the test passphrase hook) writes kind 0x01; the
//!    right passphrase loads it, a wrong one exits 2.
//! 3. `--insecure-plaintext` writes kind 0x00 and warns on stderr.
//! 4. `0600` and `create_new` hold for every mode.
//! 5. A raw kind 0x00 key in the v1.2.1 layout still loads.
//! 6. `--keychain` (ignored: needs an OS keychain) unlocks with no prompt.

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn geode(dir: &Path, pass: Option<&str>, args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_geode"));
    c.args(args)
        .current_dir(dir)
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .env("XDG_CONFIG_HOME", dir.join("config"))
        .stdin(Stdio::null());
    if let Some(p) = pass {
        c.env("GEODE_PASSPHRASE", p);
    }
    c.output().expect("spawn geode")
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn assert_ok(o: &Output, what: &str) {
    assert!(o.status.success(), "{what}: {}", stderr(o));
}

fn kind(path: &Path) -> u8 {
    let b = std::fs::read(path).expect("key file");
    assert_eq!(&b[..4], b"GKEY");
    b[5]
}

#[cfg(unix)]
fn assert_0600(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).expect("key").permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "key file MUST be 0600");
}

#[test]
fn no_flag_non_tty_refuses_and_writes_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    for args in [
        &["keygen", "k.gkey"][..],
        &["keygen"],
        &["keygen", "--cheap", "k.gkey"],
        // --password is a no-op alias: it does not bypass the refusal.
        &["keygen", "--password", "k.gkey"],
    ] {
        let o = geode(dir, None, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", stderr(&o));
        assert!(
            stderr(&o).contains("--insecure-plaintext"),
            "{}",
            stderr(&o)
        );
    }
    let left: Vec<_> = std::fs::read_dir(dir).unwrap().flatten().collect();
    assert!(left.is_empty(), "refusal wrote {left:?}");
}

#[test]
fn passphrase_hook_writes_wrapped_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(
        &geode(dir, Some("correct horse"), &["keygen", "--cheap", "k.gkey"]),
        "keygen",
    );
    let key = dir.join("k.gkey");
    assert_eq!(kind(&key), 1, "default keygen is wrapped");
    assert_eq!(std::fs::metadata(&key).unwrap().len(), 114);
    #[cfg(unix)]
    assert_0600(&key);
    assert!(dir.join("k.gpub").exists());

    let pubk = &["--key", "k.gkey", "sign", "pub"];
    assert_ok(&geode(dir, Some("correct horse"), pubk), "right passphrase");
    let bad = geode(dir, Some("wrong horse"), pubk);
    assert_eq!(bad.status.code(), Some(2), "{}", stderr(&bad));
    assert!(!stderr(&bad).contains("wrong horse"));
}

#[test]
fn password_alias_is_accepted_and_deprecated() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let o = geode(
        dir,
        Some("pw"),
        &["keygen", "--password", "--cheap", "k.gkey"],
    );
    assert_ok(&o, "keygen --password");
    assert!(
        stderr(&o).contains("--password is deprecated"),
        "{}",
        stderr(&o)
    );
    assert_eq!(kind(&dir.join("k.gkey")), 1);
}

#[test]
fn empty_passphrase_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let o = geode(dir, Some(""), &["keygen", "--cheap", "k.gkey"]);
    assert_eq!(o.status.code(), Some(1), "{}", stderr(&o));
    assert!(!dir.join("k.gkey").exists());
}

#[test]
fn insecure_plaintext_writes_raw_and_warns() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let o = geode(dir, None, &["keygen", "--insecure-plaintext", "k.gkey"]);
    assert_ok(&o, "keygen --insecure-plaintext");
    assert!(
        stderr(&o).contains("--insecure-plaintext writes the identity key unwrapped"),
        "{}",
        stderr(&o)
    );
    let key = dir.join("k.gkey");
    assert_eq!(kind(&key), 0);
    assert_eq!(std::fs::metadata(&key).unwrap().len(), 54);
    #[cfg(unix)]
    assert_0600(&key);
    assert_ok(
        &geode(dir, None, &["--key", "k.gkey", "sign", "pub"]),
        "load",
    );
}

#[test]
fn cheap_does_not_apply_to_other_modes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    for flag in ["--insecure-plaintext", "--keychain"] {
        let o = geode(dir, None, &["keygen", flag, "--cheap", "k.gkey"]);
        assert_eq!(o.status.code(), Some(1), "{flag}: {}", stderr(&o));
        assert!(stderr(&o).contains("does not apply"), "{}", stderr(&o));
    }
    assert!(!dir.join("k.gkey").exists());
}

#[test]
fn keygen_never_overwrites() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(
        &geode(dir, None, &["keygen", "--insecure-plaintext", "k.gkey"]),
        "first",
    );
    let before = std::fs::read(dir.join("k.gkey")).unwrap();
    let again = geode(dir, Some("pw"), &["keygen", "--cheap", "k.gkey"]);
    assert_eq!(again.status.code(), Some(1), "{}", stderr(&again));
    assert_eq!(std::fs::read(dir.join("k.gkey")).unwrap(), before);
}

/// A raw key in the layout v1.2.1 `geode keygen` wrote: `GKEY`, version 1,
/// kind 0, ISK[32], BLAKE3(ISK)[..16].
#[test]
fn v1_2_1_raw_key_still_loads() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let isk = [0x42u8; 32];
    let mut raw = b"GKEY\x01\x00".to_vec();
    raw.extend_from_slice(&isk);
    raw.extend_from_slice(&blake3::hash(&isk).as_bytes()[..16]);
    let key = dir.join("v121.gkey");
    std::fs::write(&key, &raw).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let a = geode(dir, None, &["--key", "v121.gkey", "sign", "pub"]);
    assert_ok(&a, "v1.2.1 raw key loads");
    let b = geode(dir, None, &["--key", "v121.gkey", "sign", "pub"]);
    assert_eq!(a.stdout, b.stdout, "same key, same public half");
}

/// Needs a live OS keychain (macOS Keychain or Secret Service); CI hosts
/// have none. Run with `cargo test -p geode-cli --test keygen_cli -- --ignored`.
#[test]
#[ignore = "needs an OS keychain"]
fn keychain_unlocks_without_prompt() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let o = geode(dir, None, &["keygen", "--keychain", "kc.gkey"]);
    assert_ok(&o, "keygen --keychain");
    let key = dir.join("kc.gkey");
    assert_eq!(kind(&key), 1, "keychain keys stay wrapped on disk");
    #[cfg(unix)]
    assert_0600(&key);
    let index = std::fs::read_to_string(dir.join("config/hedronite/geode/keyring.json")).unwrap();
    let doc: serde_json::Value = serde_json::from_str(&index).unwrap();
    assert_eq!(doc["keys"][0]["label"], "kc", "{index}");
    let id = doc["keys"][0]["id"].as_str().unwrap().to_owned();
    let pubk = geode(dir, None, &["--key", "kc.gkey", "sign", "pub"]);
    let _ = geode_grotto::keyring::delete_secret_os(&id);
    assert_ok(&pubk, "keychain unlock");
}
