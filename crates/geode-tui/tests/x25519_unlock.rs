//! TUI unlock for an X25519 identity added with `vault add-recipient`.
//!
//! The fixture is built with the `geode` CLI (subprocess, dummy keys,
//! HOME/XDG isolated); the assertions drive `geode_tui::vault::open`
//! in-process, as the TUI does.

#![cfg(feature = "tui")]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn geode_bin() -> PathBuf {
    for key in ["CARGO_BIN_EXE_GEO_DE", "CARGO_BIN_EXE_geode"] {
        if let Ok(p) = std::env::var(key) {
            let pb = PathBuf::from(p);
            if pb.is_file() {
                return pb;
            }
        }
    }
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let pb = PathBuf::from(td).join("debug/geode");
        if pb.is_file() {
            return pb;
        }
    }
    let target_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let pb = target_root.join("debug/geode");
    if pb.is_file() {
        return pb;
    }
    if let Ok(entries) = std::fs::read_dir(&target_root) {
        for entry in entries.flatten() {
            let pb = entry.path().join("debug/geode");
            if pb.is_file() {
                return pb;
            }
        }
    }
    panic!("geode binary not found (build geode-cli first)");
}

fn geode(dir: &Path, args: &[&str]) -> Output {
    let home = dir.join("home");
    let xdg = dir.join("xdg");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&xdg).unwrap();
    let out = Command::new(geode_bin())
        .args(args)
        .current_dir(dir)
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_DATA_HOME", &xdg)
        .env("XDG_CACHE_HOME", &xdg)
        .env("XDG_STATE_HOME", &xdg)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_PASSPHRASE")
        .output()
        .expect("spawn geode");
    assert!(
        out.status.success(),
        "geode {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn key_id(dir: &Path, gpub: &str) -> String {
    let v: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(dir.join(gpub)).unwrap()).unwrap();
    v["key_id"].as_str().unwrap().to_string()
}

/// Vault owned by `owner.gkey` holding `src/hello.txt`, plus `added.gkey`
/// as an X25519 recipient.
fn fixture(dir: &Path) {
    geode(dir, &["keygen", "--insecure-plaintext", "owner.gkey"]);
    geode(dir, &["keygen", "--insecure-plaintext", "added.gkey"]);
    geode(dir, &["--key", "owner.gkey", "vault", "init", "v.geode"]);
    std::fs::create_dir_all(dir.join("src")).unwrap();
    std::fs::write(dir.join("src/hello.txt"), b"hello world\n").unwrap();
    geode(dir, &["--key", "owner.gkey", "seal", "src", "v.geode"]);
    geode(
        dir,
        &[
            "--key",
            "owner.gkey",
            "vault",
            "add-recipient",
            "--gpub",
            "added.gpub",
            "v.geode",
        ],
    );
}

fn preview_hello(dir: &Path, key: &str) -> geode_grotto::Result<Vec<u8>> {
    let ctx = geode_tui::vault::open(&dir.join("v.geode"), Some(&dir.join(key)))?;
    geode_tui::vault::verify(&ctx, true)?;
    let p = geode_tui::vault::preview(&ctx, "hello.txt", 64)?;
    Ok(p.bytes.to_vec())
}

#[test]
fn tui_unlock_x25519_recipient() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    fixture(dir);
    assert_eq!(preview_hello(dir, "added.gkey").unwrap(), b"hello world\n");
    assert_eq!(preview_hello(dir, "owner.gkey").unwrap(), b"hello world\n");
    let ctx = geode_tui::vault::open(&dir.join("v.geode"), Some(&dir.join("added.gkey"))).unwrap();
    assert_eq!(
        geode_tui::vault::hex(&ctx.key_id().0),
        key_id(dir, "added.gpub")
    );
}

#[test]
fn tui_unlock_after_owner_dropped() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    fixture(dir);
    let owner = key_id(dir, "owner.gpub");
    geode(
        dir,
        &[
            "--key",
            "owner.gkey",
            "vault",
            "rotate",
            "v.geode",
            "--yes",
            "--reseal",
            "--drop-recipient",
            &owner,
        ],
    );
    assert_eq!(preview_hello(dir, "added.gkey").unwrap(), b"hello world\n");
    assert!(matches!(
        preview_hello(dir, "owner.gkey"),
        Err(geode_grotto::Error::AuthFail)
    ));
}

#[test]
fn tui_unlock_stranger_is_auth_fail() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path();
    fixture(dir);
    geode(dir, &["keygen", "--insecure-plaintext", "stranger.gkey"]);
    assert!(matches!(
        preview_hello(dir, "stranger.gkey"),
        Err(geode_grotto::Error::AuthFail)
    ));
}
