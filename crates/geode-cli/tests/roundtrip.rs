//! G5b — CLI fixtures against the shipped `geode` binary.
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`) end to end:
//!
//! 1. `roundtrip_seal_verify_open` — keygen (0600) -> vault init -> seal a
//!    small tree (text, nested, binary, symlink) -> verify full/cheap/sample
//!    -> list -> cat -> open -> byte-for-byte compare with the source.
//! 2. `bit_flip_fails_closed_exit_2` — flip one ciphertext byte inside a
//!    `.gobj` and require `verify` (full AND cheap) to exit **2**
//!    (authentication/integrity family, 05-cli 3). Restore and re-verify.
//!
//! No passphrases, no key bytes, no plaintext in assertions beyond the
//! fixture's own throwaway content.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// The binary under test (cargo builds it for integration tests).
fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("spawn geode")
}

fn assert_ok(dir: &Path, args: &[&str]) -> Output {
    let out = geode(dir, args);
    assert!(
        out.status.success(),
        "geode {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn assert_exit(dir: &Path, args: &[&str], code: i32) -> Output {
    let out = geode(dir, args);
    assert_eq!(
        out.status.code(),
        Some(code),
        "geode {args:?} exit: want {code}, stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

/// Recursively collect relative paths of a tree (files and symlinks).
fn collect(root: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let ty = entry.file_type().expect("file_type");
        if ty.is_dir() {
            collect(&path, base, out);
        } else {
            out.push(path.strip_prefix(base).expect("prefix").to_path_buf());
        }
    }
}

/// Byte-compare two trees (file contents and symlink targets).
fn assert_trees_equal(a: &Path, b: &Path) {
    let mut left = Vec::new();
    collect(a, a, &mut left);
    left.sort();
    let mut right = Vec::new();
    collect(b, b, &mut right);
    right.sort();
    assert_eq!(left, right, "tree shapes differ");
    for rel in &left {
        let pa = a.join(rel);
        let pb = b.join(rel);
        let ta = std::fs::symlink_metadata(&pa).expect("meta a");
        if ta.file_type().is_symlink() {
            assert_eq!(
                std::fs::read_link(&pa).expect("link a"),
                std::fs::read_link(&pb).expect("link b"),
                "symlink target differs at {}", rel.display()
            );
        } else {
            assert_eq!(
                std::fs::read(&pa).expect("read a"),
                std::fs::read(&pb).expect("read b"),
                "content differs at {}", rel.display()
            );
        }
    }
}

/// First `.gobj` under a vault's epochs dir.
fn first_object(vault: &Path) -> PathBuf {
    let mut found = Vec::new();
    collect(&vault.join("epochs"), &vault.join("epochs"), &mut found);
    found.sort();
    let rel = found
        .iter()
        .find(|p| p.extension().is_some_and(|e| e == "gobj"))
        .expect("a .gobj in the vault");
    vault.join("epochs").join(rel)
}

#[test]
fn roundtrip_seal_verify_open() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    // G3a: keygen writes a 0600 raw GKEY.
    assert_ok(dir, &["keygen", "k.gkey"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("k.gkey"))
            .expect("key file")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "key file MUST be 0600");
    }

    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);

    // Fixture tree: text, nested, binary, symlink.
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub")).expect("mkdir");
    std::fs::write(src.join("a.txt"), b"hello geode\n").expect("write");
    std::fs::write(src.join("sub").join("b.txt"), b"nested\n").expect("write");
    std::fs::write(src.join("bin.dat"), vec![0xabu8; 3000]).expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.txt", src.join("link.txt")).expect("symlink");

    // G3b: seal -> verify (all three modes) -> list -> cat -> open.
    assert_ok(dir, &["--key", "k.gkey", "seal", "src", "v.geode"]);
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode", "--cheap"]);
    assert_ok(
        dir,
        &["--key", "k.gkey", "verify", "v.geode", "--sample", "0.5"],
    );
    let list = assert_ok(dir, &["--key", "k.gkey", "list", "v.geode"]);
    let listing = String::from_utf8_lossy(&list.stdout);
    assert!(listing.contains("a.txt"), "list shows a.txt: {listing}");
    assert!(listing.contains("sub/b.txt"), "list shows nested: {listing}");
    let cat = assert_ok(dir, &["--key", "k.gkey", "cat", "v.geode", "a.txt"]);
    assert_eq!(cat.stdout, b"hello geode\n");

    assert_ok(dir, &["--key", "k.gkey", "open", "v.geode", "out"]);
    assert_trees_equal(&src, &dir.join("out"));

    // JSON events carry the public-id envelope (no secrets).
    let ev = assert_ok(
        dir,
        &["--key", "k.gkey", "verify", "v.geode", "--output", "json"],
    );
    let doc: serde_json::Value =
        serde_json::from_slice(&ev.stdout).expect("verify event is json");
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["verb"], "verify");
    assert!(doc["vault_id"].as_str().is_some_and(|s| s.len() == 32));
    assert!(doc["key_id"].as_str().is_some_and(|s| s.len() == 32));
}

#[test]
fn bit_flip_fails_closed_exit_2() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "k.gkey"]);
    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    std::fs::write(dir.join("note.txt"), b"integrity matters\n").expect("write");
    assert_ok(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]);
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);

    // Flip one byte in the middle of the object (chunk ciphertext region).
    let obj = first_object(&dir.join("v.geode"));
    let original = std::fs::read(&obj).expect("read object");
    let mut flipped = original.clone();
    let mid = flipped.len() / 2;
    flipped[mid] ^= 0x01;
    std::fs::write(&obj, &flipped).expect("write flipped");

    // Fail closed: exit 2, not 1, in both full and cheap modes (04-vault 4).
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode"], 2);
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode", "--cheap"], 2);

    // Restore: the vault verifies again.
    std::fs::write(&obj, &original).expect("restore object");
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
}
