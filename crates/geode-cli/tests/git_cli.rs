//! G1 (v0.2.8) — `geode git` fixtures against the shipped binary
//! (09-git; SPEC-v028 G1a–G1c).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `git_init_creates_vault_and_readme` — `--key` creates `.geode/vault`
//!    + README. Missing `--key` is exit 1.
//! 2. `git_add_gitignores_and_status` — `git add` seals, gitignores
//!    plaintext, leaves ciphertext under `.geode/`; `status` lists sealed
//!    vs unlocked.
//! 3. `git_token_cannot_init_or_add` — `--token` is unexpected on git
//!    verbs and must not create `.geode` or seal; `GEODE_TOKEN` never
//!    substitutes for `--key`.
//! 4. `git_unlock_then_lock` — unlock writes a working copy; lock unlinks
//!    it without deleting ciphertext.
//! 5. `git_help_names_github_visibility` — `git` / verb `--help` names
//!    GitHub-visible metadata (G2a). No ISK.
//! 6. `tui_token_still_unexpected` — `geode tui --token x` is unexpected
//!    (G2b). TUI src is not edited this pack.
//!
//! No passphrases, no key bytes, no ISK in any captured output.

use std::path::Path;
use std::process::{Command, Output};

fn geode(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_KEY_FILE")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .output()
        .expect("spawn geode")
}

fn geode_with_token_env(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(args)
        .current_dir(dir)
        .env("GEODE_TOKEN", "deadbeef")
        .env_remove("GEODE_KEY_FILE")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
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
    }
    assert!(!text.contains("ISK"), "{what} leaked ISK marker: {text}");
}

fn setup_key(dir: &Path) {
    assert_ok(&geode(dir, &["keygen", "k.gkey"]), "keygen");
}

fn has_gobj(root: &Path) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|e| e == "gobj") {
                return true;
            }
        }
    }
    false
}

fn gitignore_has(dir: &Path, rel: &str) -> bool {
    let path = dir.join(".gitignore");
    path.is_file()
        && std::fs::read_to_string(path)
            .expect("gitignore")
            .lines()
            .any(|l| {
                let t = l.trim();
                t == rel || t == format!("/{rel}")
            })
}

/// `--token` is not a git-sidecar flag (agent plane only). Clap must
/// reject it as unexpected and the verb must not have run.
fn assert_token_unexpected(dir: &Path, args: &[&str], what: &str) {
    let out = geode(dir, args);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "{what}: {text}");
    assert!(
        text.to_ascii_lowercase().contains("unexpected"),
        "{what} must be unexpected --token, got: {text}"
    );
    assert_no_isk(&out, dir, &["k.gkey"], what);
}

#[test]
fn git_init_creates_vault_and_readme() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_key(dir);

    let no_key = geode(dir, &["git", "init"]);
    assert_eq!(
        no_key.status.code(),
        Some(1),
        "git init without --key: {}",
        combined(&no_key)
    );
    assert!(
        !dir.join(".geode").exists(),
        "missing --key must not create .geode"
    );

    let out = geode(dir, &["--key", "k.gkey", "git", "init"]);
    assert_ok(&out, "git init");
    assert_no_isk(&out, dir, &["k.gkey"], "git init");
    assert!(dir.join(".geode/vault").is_dir(), ".geode/vault created");
    assert!(dir.join(".geode/vault/GEODE").is_file(), "vault sentinel");
    let readme = std::fs::read_to_string(dir.join(".geode/README")).expect("readme");
    assert!(
        readme.contains("sealed by Geode; do not hand-edit"),
        "README sentence: {readme}"
    );
    assert!(dir.join(".geode/vault/header.json").is_file());
    assert!(dir.join(".geode/vault/recipients.json").is_file());
    assert!(dir.join(".geode/vault/sidecar-index.json").is_file());
}

#[test]
fn git_add_gitignores_and_status() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_key(dir);
    assert_ok(&geode(dir, &["--key", "k.gkey", "git", "init"]), "git init");
    std::fs::write(dir.join("NOTES.md"), b"secret notes\n").expect("write");

    let add = geode(dir, &["--key", "k.gkey", "git", "add", "NOTES.md"]);
    assert_ok(&add, "git add");
    assert_no_isk(&add, dir, &["k.gkey"], "git add");
    assert!(
        dir.join("NOTES.md").is_file(),
        "plaintext working copy remains until lock"
    );
    assert!(
        gitignore_has(dir, "NOTES.md"),
        "plaintext gitignored: {}",
        std::fs::read_to_string(dir.join(".gitignore")).unwrap_or_default()
    );
    let gi = std::fs::read_to_string(dir.join(".gitignore")).expect("gitignore");
    assert!(
        !gi.lines()
            .any(|l| l.trim() == ".geode/" || l.trim() == ".geode"),
        ".geode/ must not be gitignored: {gi}"
    );
    assert!(has_gobj(&dir.join(".geode")), "ciphertext under .geode/");

    let st = geode(dir, &["--key", "k.gkey", "git", "status"]);
    assert_ok(&st, "git status");
    let text = combined(&st);
    assert!(
        text.contains("unlocked") && text.contains("NOTES.md"),
        "status lists unlocked sealed path: {text}"
    );
}

#[test]
fn git_token_cannot_init_or_add() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_key(dir);

    assert_token_unexpected(
        dir,
        &["--token", "deadbeef", "git", "init"],
        "--token before git init",
    );
    assert_token_unexpected(
        dir,
        &["--key", "k.gkey", "git", "init", "--token", "deadbeef"],
        "--token after git init",
    );
    assert!(
        !dir.join(".geode").exists(),
        "--token git init must not create .geode"
    );

    let env_init = geode_with_token_env(dir, &["git", "init"]);
    assert_eq!(
        env_init.status.code(),
        Some(1),
        "GEODE_TOKEN without --key on git init: {}",
        combined(&env_init)
    );
    assert_no_isk(&env_init, dir, &["k.gkey"], "GEODE_TOKEN git init");
    assert!(
        !dir.join(".geode").exists(),
        "GEODE_TOKEN must not substitute for --key on git init"
    );

    assert_ok(&geode(dir, &["--key", "k.gkey", "git", "init"]), "git init");
    std::fs::write(dir.join("NOTES.md"), b"working copy\n").expect("write");

    assert_token_unexpected(
        dir,
        &["--token", "deadbeef", "git", "add", "NOTES.md"],
        "--token before git add",
    );
    assert_token_unexpected(
        dir,
        &[
            "--key",
            "k.gkey",
            "git",
            "add",
            "NOTES.md",
            "--token",
            "deadbeef",
        ],
        "--token after git add",
    );
    assert!(
        !gitignore_has(dir, "NOTES.md"),
        "--token git add must not gitignore plaintext"
    );
    assert!(
        !has_gobj(&dir.join(".geode")),
        "--token git add must not write ciphertext"
    );

    let env_add = geode_with_token_env(dir, &["git", "add", "NOTES.md"]);
    assert_eq!(
        env_add.status.code(),
        Some(1),
        "GEODE_TOKEN without --key on git add: {}",
        combined(&env_add)
    );
    assert_no_isk(&env_add, dir, &["k.gkey"], "GEODE_TOKEN git add");
    assert!(
        !has_gobj(&dir.join(".geode")),
        "GEODE_TOKEN must not substitute for --key on git add"
    );
}

#[test]
fn git_unlock_then_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_key(dir);
    assert_ok(&geode(dir, &["--key", "k.gkey", "git", "init"]), "git init");
    std::fs::write(dir.join("NOTES.md"), b"working copy\n").expect("write");
    let add = geode(dir, &["--key", "k.gkey", "git", "add", "NOTES.md"]);
    assert_ok(&add, "git add");
    assert_no_isk(&add, dir, &["k.gkey"], "git add");

    let locked = geode(dir, &["--key", "k.gkey", "git", "lock"]);
    assert_ok(&locked, "git lock");
    assert_no_isk(&locked, dir, &["k.gkey"], "git lock");
    assert!(!dir.join("NOTES.md").exists(), "lock unlinks working copy");
    assert!(
        has_gobj(&dir.join(".geode")),
        "lock does not delete ciphertext"
    );

    let st = geode(dir, &["--key", "k.gkey", "git", "status"]);
    assert_ok(&st, "status after lock");
    let text = combined(&st);
    assert!(
        text.contains("NOTES.md"),
        "status still lists sealed path: {text}"
    );
    assert!(
        !text.contains("unlocked NOTES.md"),
        "not unlocked after lock: {text}"
    );

    let unlocked = geode(dir, &["--key", "k.gkey", "git", "unlock", "NOTES.md"]);
    assert_ok(&unlocked, "git unlock");
    assert_no_isk(&unlocked, dir, &["k.gkey"], "git unlock");
    assert_eq!(
        std::fs::read(dir.join("NOTES.md")).expect("read unlocked"),
        b"working copy\n"
    );
}

fn assert_github_visibility(text: &str, what: &str) {
    let lower = text.to_ascii_lowercase();
    for needle in ["counts", "sizes", "tree", "times", "recipient key"] {
        assert!(
            lower.contains(needle),
            "{what} missing {needle:?}: {text}"
        );
    }
    assert!(
        lower.contains("not plaintext"),
        "{what} must say not plaintext: {text}"
    );
    assert!(!text.contains("ISK"), "{what} leaked ISK: {text}");
}

#[test]
fn git_help_names_github_visibility() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let cases: &[&[&str]] = &[
        &["git", "--help"],
        &["git", "init", "--help"],
        &["git", "add", "--help"],
        &["git", "status", "--help"],
        &["git", "unlock", "--help"],
        &["git", "lock", "--help"],
    ];
    for args in cases {
        let out = geode(dir, args);
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}: {}",
            args.join(" "),
            combined(&out)
        );
        assert_github_visibility(&combined(&out), &args.join(" "));
    }
    let parent = combined(&geode(dir, &["git", "--help"]));
    for verb in ["init", "add", "status", "unlock", "lock"] {
        assert!(
            parent.contains(verb),
            "git --help must list {verb}: {parent}"
        );
    }
    assert!(
        parent.to_ascii_lowercase().contains("local"),
        "git --help must say hooks are local: {parent}"
    );
}

#[test]
fn tui_token_still_unexpected() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let out = geode(tmp.path(), &["tui", "--token", "x"]);
    let text = combined(&out);
    assert_eq!(out.status.code(), Some(1), "tui --token: {text}");
    assert!(
        text.to_ascii_lowercase().contains("unexpected"),
        "tui --token must be unexpected, got: {text}"
    );
    assert!(!text.contains("ISK"), "tui --token leaked ISK: {text}");
}
