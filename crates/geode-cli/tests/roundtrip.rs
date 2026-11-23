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
        // Never resolve the operator's key, keyring or config.
        .env("HOME", dir.join(".iso/home"))
        .env("XDG_CONFIG_HOME", dir.join(".iso/config"))
        .env("XDG_DATA_HOME", dir.join(".iso/data"))
        .env("XDG_STATE_HOME", dir.join(".iso/state"))
        .env("XDG_CACHE_HOME", dir.join(".iso/cache"))
        .env("XDG_RUNTIME_DIR", dir.join(".iso/runtime"))
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
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
                "symlink target differs at {}",
                rel.display()
            );
        } else {
            assert_eq!(
                std::fs::read(&pa).expect("read a"),
                std::fs::read(&pb).expect("read b"),
                "content differs at {}",
                rel.display()
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
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
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
    assert!(
        listing.contains("sub/b.txt"),
        "list shows nested: {listing}"
    );
    let cat = assert_ok(dir, &["--key", "k.gkey", "cat", "v.geode", "a.txt"]);
    assert_eq!(cat.stdout, b"hello geode\n");

    assert_ok(dir, &["--key", "k.gkey", "open", "v.geode", "out"]);
    assert_trees_equal(&src, &dir.join("out"));

    // JSON events carry the public-id envelope (no secrets).
    let ev = assert_ok(
        dir,
        &["--key", "k.gkey", "verify", "v.geode", "--output", "json"],
    );
    let doc: serde_json::Value = serde_json::from_slice(&ev.stdout).expect("verify event is json");
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["verb"], "verify");
    assert!(doc["vault_id"].as_str().is_some_and(|s| s.len() == 32));
    assert!(doc["key_id"].as_str().is_some_and(|s| s.len() == 32));
}

#[test]
fn bit_flip_fails_closed_exit_2() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
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

// ---- v310 G2: verify integrity and tamper detection ----

/// Key material for a vault the shipped CLI built. Tests only: it reads the
/// throwaway fixture key the same way `geode` does.
struct VaultKeys {
    vault_id: geode_grotto::kdf::VaultId,
    epoch: geode_grotto::kdf::Epoch,
    manifest_key: [u8; 32],
    meta_key: [u8; 32],
}

fn unhex32(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0, "hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

fn vault_keys(dir: &Path) -> VaultKeys {
    let root = dir.join("v.geode");
    let raw = std::fs::read(dir.join("k.gkey")).expect("gkey");
    let isk =
        geode_grotto::kdf::IdentitySecret::from_bytes(raw[6..38].try_into().expect("isk bytes"));
    let header: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join("header.json")).expect("header")).unwrap();
    let vault_id = geode_grotto::kdf::VaultId(
        unhex32(header["vault_id"].as_str().unwrap())
            .try_into()
            .unwrap(),
    );
    let epoch = geode_grotto::kdf::Epoch(u32::try_from(header["epoch"].as_u64().unwrap()).unwrap());
    let recipients: geode_grotto::recipients::Recipients =
        serde_json::from_slice(&std::fs::read(root.join("recipients.json")).expect("recipients"))
            .unwrap();
    let ek = geode_grotto::recipients::unwrap_for_identity(&recipients, &isk, vault_id, epoch)
        .expect("unwrap epoch key");
    VaultKeys {
        vault_id,
        epoch,
        manifest_key: geode_grotto::kdf::derive_manifest_key(&ek, vault_id, epoch),
        meta_key: geode_grotto::kdf::derive_meta_key(&ek, vault_id, epoch),
    }
}

fn load_manifest(dir: &Path, keys: &VaultKeys) -> geode_grotto::manifest::Manifest {
    geode_grotto::snapshot::read_manifest_file(&dir.join("v.geode"), keys.epoch, &keys.manifest_key)
        .expect("manifest")
}

fn write_manifest(dir: &Path, keys: &VaultKeys, manifest: &geode_grotto::manifest::Manifest) {
    geode_grotto::snapshot::write_manifest_file(
        &dir.join("v.geode"),
        keys.epoch,
        manifest,
        &keys.manifest_key,
    )
    .expect("write manifest");
}

#[test]
fn trailing_bytes_fail_verify_and_cat() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    std::fs::write(dir.join("note.txt"), b"tail check\n").expect("write");
    assert_ok(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]);
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
    let obj = first_object(&dir.join("v.geode"));
    let original = std::fs::read(&obj).expect("read object");
    let mut longer = original.clone();
    longer.extend_from_slice(b"thirteen-byte");
    std::fs::write(&obj, &longer).expect("append");
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode"], 2);
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode", "--cheap"], 2);
    assert_exit(dir, &["--key", "k.gkey", "cat", "v.geode", "note.txt"], 2);
    std::fs::write(&obj, &original).expect("restore");
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
}

#[test]
fn tampered_manifest_root_fails_full_and_cheap_verify() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    std::fs::write(dir.join("note.txt"), b"root check\n").expect("write");
    assert_ok(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]);
    let keys = vault_keys(dir);
    let mut manifest = load_manifest(dir, &keys);
    manifest.root = [0xaa; 32];
    write_manifest(dir, &keys, &manifest);
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode"], 2);
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode", "--cheap"], 2);
}

#[test]
fn tampered_entry_content_root_fails_full_verify() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    std::fs::write(dir.join("note.txt"), b"entry root check\n").expect("write");
    assert_ok(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]);
    let keys = vault_keys(dir);
    let mut manifest = load_manifest(dir, &keys);
    let entry = manifest
        .entries
        .iter_mut()
        .find(|e| e.kind == geode_grotto::manifest::EntryKind::File)
        .expect("a file entry");
    entry.content_root = [0xbb; 32];
    manifest.root = geode_grotto::manifest::entries_root(&manifest.entries).expect("root");
    write_manifest(dir, &keys, &manifest);
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode"], 2);
}

#[test]
fn tampered_policy_fails_full_verify_and_clean_policy_passes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    assert_ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
    assert_ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    std::fs::write(dir.join("note.txt"), b"policy check\n").expect("write");
    assert_ok(dir, &["--key", "k.gkey", "seal", "note.txt", "v.geode"]);
    let keys = vault_keys(dir);
    // No sealed policy yet: verify stays clean.
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
    let vault_hex = keys.vault_id.0.iter().fold(String::new(), |mut s, b| {
        use std::fmt::Write as _;
        let _ = write!(s, "{b:02x}");
        s
    });
    let policy = geode_grotto::policy::default_policy(&vault_hex);
    let path = geode_grotto::policy::seal_policy(
        &dir.join("v.geode"),
        &policy,
        &keys.meta_key,
        keys.vault_id,
        keys.epoch,
    )
    .expect("seal policy");
    assert_ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
    let mut sealed = std::fs::read(&path).expect("policy bytes");
    let last = sealed.len() - 1;
    sealed[last] ^= 0x01;
    std::fs::write(&path, &sealed).expect("tamper policy");
    assert_exit(dir, &["--key", "k.gkey", "verify", "v.geode"], 2);
}
