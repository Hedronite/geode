//! v310 G4: `--seal-names` vaults survive epoch rotation.
//!
//! Seals a tree with sealed filenames, rotates twice (`--yes --reseal`), and
//! requires `list`, `cat`, `open`, and `verify` (full + cheap) to keep
//! working with the exact plaintext names and bytes after each rotation.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
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

fn ok(dir: &Path, args: &[&str]) -> Output {
    let out = geode(dir, args);
    assert!(
        out.status.success(),
        "geode {args:?} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

fn collect(root: &Path, base: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).expect("read_dir") {
        let entry = entry.expect("entry");
        let path = entry.path();
        let ty = entry.file_type().expect("file_type");
        if ty.is_dir() {
            collect(&path, base, out);
        } else {
            out.push(path.strip_prefix(base).expect("prefix").to_path_buf());
        }
    }
}

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
        let meta = std::fs::symlink_metadata(&pa).expect("meta");
        if meta.file_type().is_symlink() {
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

fn assert_plaintext_surface(dir: &Path, src: &Path, out_name: &str) {
    let listing = String::from_utf8_lossy(&ok(dir, &["--key", "k.gkey", "list", "v.geode"]).stdout)
        .into_owned();
    for want in ["one.txt", "sub/two.txt", "sub/deep/three.bin", "link.txt"] {
        assert!(
            listing.contains(want),
            "list after rotate is missing {want}: {listing}"
        );
    }
    let one = ok(dir, &["--key", "k.gkey", "cat", "v.geode", "one.txt"]);
    assert_eq!(one.stdout, std::fs::read(src.join("one.txt")).unwrap());
    let deep = ok(
        dir,
        &["--key", "k.gkey", "cat", "v.geode", "sub/deep/three.bin"],
    );
    assert_eq!(
        deep.stdout,
        std::fs::read(src.join("sub/deep/three.bin")).unwrap()
    );
    let out = dir.join(out_name);
    let _ = std::fs::remove_dir_all(&out);
    ok(dir, &["--key", "k.gkey", "open", "v.geode", out_name]);
    assert_trees_equal(src, &out);
    ok(dir, &["--key", "k.gkey", "verify", "v.geode"]);
    ok(dir, &["--key", "k.gkey", "verify", "v.geode", "--cheap"]);
}

#[test]
fn sealed_names_survive_two_rotations() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    ok(dir, &["keygen", "--insecure-plaintext", "k.gkey"]);
    ok(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);

    let src = dir.join("src");
    std::fs::create_dir_all(src.join("sub/deep")).expect("mkdir");
    std::fs::write(src.join("one.txt"), b"sealed one\n").expect("write");
    std::fs::write(src.join("sub/two.txt"), b"sealed two\n").expect("write");
    std::fs::write(src.join("sub/deep/three.bin"), vec![0x5au8; 4096]).expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink("one.txt", src.join("link.txt")).expect("symlink");

    ok(
        dir,
        &["--key", "k.gkey", "seal", "src", "v.geode", "--seal-names"],
    );
    assert_plaintext_surface(dir, &src, "out-before");

    ok(
        dir,
        &[
            "--key", "k.gkey", "vault", "rotate", "v.geode", "--yes", "--reseal",
        ],
    );
    assert_plaintext_surface(dir, &src, "out-epoch2");

    ok(
        dir,
        &[
            "--key", "k.gkey", "vault", "rotate", "v.geode", "--yes", "--reseal",
        ],
    );
    assert_plaintext_surface(dir, &src, "out-epoch3");
}
