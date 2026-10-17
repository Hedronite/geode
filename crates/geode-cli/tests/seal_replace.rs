//! `geode seal` warns when it replaces a stored path, then still exits 0.
//!
//! The warning path is the stored path: the `--as` string, the directory
//! relative path, or the sealed name when `--seal-names` is set.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .expect("spawn geode")
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn setup() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().expect("tempdir");
    let dir = std::fs::canonicalize(t.path()).expect("canonicalize");
    assert!(
        geode(&dir, &["keygen", "k.gkey"]).status.success(),
        "keygen"
    );
    let init = geode(&dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    assert!(init.status.success(), "vault init: {}", err(&init));
    (t, dir)
}

fn seal(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["--key", "k.gkey", "seal"];
    args.extend_from_slice(extra);
    geode(dir, &args)
}

fn warning_paths(stderr: &str) -> Vec<String> {
    let prefix = "warning: replacing existing vault path ";
    stderr
        .lines()
        .filter_map(|line| line.strip_prefix(prefix).map(str::to_owned))
        .collect()
}

fn assert_silent(stderr: &str) {
    assert!(
        !stderr.contains("replacing existing vault path"),
        "new path warned: {stderr}"
    );
}

fn cat(dir: &Path, path: &str) -> Vec<u8> {
    let o = geode(dir, &["--key", "k.gkey", "cat", "v.geode", path]);
    assert!(o.status.success(), "cat {path}: {}", err(&o));
    assert!(o.status.code() == Some(0));
    o.stdout
}

fn list_paths(dir: &Path) -> Vec<String> {
    let o = geode(
        dir,
        &["--key", "k.gkey", "--output", "json", "list", "v.geode"],
    );
    assert!(o.status.success(), "list: {}", err(&o));
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if let Some(path) = v["path"].as_str() {
            out.push(path.to_owned());
        }
    }
    out
}

#[test]
fn second_seal_warns_exits_0_and_cat_returns_new_bytes() {
    let (_t, dir) = setup();
    std::fs::write(dir.join("note.txt"), b"old-bytes").unwrap();
    let first = seal(&dir, &["note.txt", "v.geode"]);
    assert!(first.status.success(), "{}", err(&first));
    assert_silent(&err(&first));
    assert_eq!(cat(&dir, "note.txt"), b"old-bytes");

    std::fs::write(dir.join("note.txt"), b"new-bytes").unwrap();
    let second = seal(&dir, &["note.txt", "v.geode"]);
    assert_eq!(second.status.code(), Some(0), "{}", err(&second));
    assert_eq!(
        warning_paths(&err(&second)),
        ["note.txt".to_string()],
        "{}",
        err(&second)
    );
    assert_eq!(cat(&dir, "note.txt"), b"new-bytes");

    // Identical bytes still warn and still replace.
    let third = seal(&dir, &["note.txt", "v.geode"]);
    assert_eq!(third.status.code(), Some(0), "{}", err(&third));
    assert_eq!(warning_paths(&err(&third)), ["note.txt".to_string()]);
    assert_eq!(cat(&dir, "note.txt"), b"new-bytes");
}

#[test]
fn directory_reseal_warns_once_per_existing_file() {
    let (_t, dir) = setup();
    std::fs::create_dir_all(dir.join("tree/keep")).unwrap();
    std::fs::write(dir.join("tree/keep/a.txt"), b"a").unwrap();
    std::fs::write(dir.join("tree/keep/b.txt"), b"b").unwrap();
    let first = seal(&dir, &["tree", "v.geode"]);
    assert!(first.status.success(), "{}", err(&first));
    assert_silent(&err(&first));

    let second = seal(&dir, &["tree", "v.geode"]);
    assert_eq!(second.status.code(), Some(0), "{}", err(&second));
    let mut warned = warning_paths(&err(&second));
    warned.sort();
    assert_eq!(warned, ["keep/a.txt".to_string(), "keep/b.txt".to_string()]);
    assert_eq!(cat(&dir, "keep/a.txt"), b"a");
    assert_eq!(cat(&dir, "keep/b.txt"), b"b");
}

#[test]
fn second_as_warns_with_that_path() {
    let (_t, dir) = setup();
    std::fs::create_dir_all(dir.join("stage/api")).unwrap();
    std::fs::write(dir.join("stage/api/svc-a.txt"), b"one").unwrap();
    let first = seal(
        &dir,
        &["stage/api/svc-a.txt", "v.geode", "--as", "api/svc-a.txt"],
    );
    assert!(first.status.success(), "{}", err(&first));
    assert_silent(&err(&first));

    std::fs::write(dir.join("stage/api/svc-a.txt"), b"two").unwrap();
    let second = seal(
        &dir,
        &["stage/api/svc-a.txt", "v.geode", "--as", "api/svc-a.txt"],
    );
    assert_eq!(second.status.code(), Some(0), "{}", err(&second));
    assert_eq!(warning_paths(&err(&second)), ["api/svc-a.txt".to_string()]);
    assert_eq!(cat(&dir, "api/svc-a.txt"), b"two");
}

#[test]
fn seal_names_warns_with_the_stored_path() {
    let (_t, dir) = setup();
    std::fs::write(dir.join("plain.txt"), b"named").unwrap();
    let first = seal(&dir, &["plain.txt", "v.geode", "--seal-names"]);
    assert!(first.status.success(), "{}", err(&first));
    assert_silent(&err(&first));
    assert_eq!(list_paths(&dir), ["plain.txt"]);

    let second = seal(&dir, &["plain.txt", "v.geode", "--seal-names"]);
    assert_eq!(second.status.code(), Some(0), "{}", err(&second));
    let warned = warning_paths(&err(&second));
    assert_eq!(warned.len(), 1, "{}", err(&second));
    let stored = &warned[0];
    assert_ne!(stored, "plain.txt");
    assert!(!stored.contains("plain.txt"), "{stored}");
    assert!(
        stored
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b)),
        "stored path is not the sealed name: {stored}"
    );
    assert_eq!(list_paths(&dir), ["plain.txt"]);
    assert_eq!(cat(&dir, "plain.txt"), b"named");

    let third = seal(&dir, &["plain.txt", "v.geode", "--seal-names"]);
    assert_eq!(warning_paths(&err(&third)), warned);
}
