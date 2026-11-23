//! G3 (v311): refuse `vault init` anywhere inside an existing vault, before
//! creating any directory or file. The check canonicalizes the deepest
//! existing ancestor so symlinked and relative paths are covered too.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

struct Env {
    _t: tempfile::TempDir,
    dir: PathBuf,
}

impl Env {
    fn new() -> Self {
        let t = tempfile::tempdir().expect("tempdir");
        let dir = std::fs::canonicalize(t.path()).expect("canonicalize");
        std::fs::create_dir_all(dir.join("home")).unwrap();
        std::fs::create_dir_all(dir.join("cfg")).unwrap();
        Self { _t: t, dir }
    }

    fn geode_in(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_geode"))
            .args(args)
            .current_dir(cwd)
            .env("HOME", self.dir.join("home"))
            .env("XDG_CONFIG_HOME", self.dir.join("cfg"))
            .env_remove("GEODE_KEY_FILE")
            .env_remove("GEODE_PASSPHRASE")
            .env_remove("GEODE_TOKEN")
            .stdin(Stdio::null())
            .output()
            .expect("spawn geode")
    }

    fn geode(&self, args: &[&str]) -> Output {
        self.geode_in(&self.dir, args)
    }

    fn key(&self) -> String {
        self.dir.join("k.gkey").display().to_string()
    }
}

fn combined(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(o: Output, what: &str) -> Output {
    assert_eq!(o.status.code(), Some(0), "{what}: {}", combined(&o));
    o
}

fn init_vault(e: &Env) -> PathBuf {
    ok(
        e.geode(&["keygen", "--insecure-plaintext", "k.gkey"]),
        "keygen",
    );
    ok(
        e.geode(&["--key", "k.gkey", "vault", "init", "v.geode"]),
        "vault init",
    );
    e.dir.join("v.geode")
}

fn verify(e: &Env, vault: &Path) {
    let path = vault.display().to_string();
    ok(
        e.geode(&["--key", &e.key(), "verify", &path]),
        "vault verify",
    );
}

fn refused(o: &Output) {
    assert_eq!(o.status.code(), Some(1), "{}", combined(o));
    assert!(
        combined(o).contains("refusing to initialize a vault inside existing vault"),
        "{}",
        combined(o)
    );
}

#[test]
fn direct_subdir_is_refused_and_creates_nothing() {
    let e = Env::new();
    let root = init_vault(&e);
    let o = e.geode(&["--key", "k.gkey", "vault", "init", "v.geode/sub"]);
    refused(&o);
    assert!(!root.join("sub").exists());
    verify(&e, &root);
}

#[test]
fn deep_nonexistent_subdir_creates_no_intermediate_dirs() {
    let e = Env::new();
    let root = init_vault(&e);
    let o = e.geode(&[
        "--key",
        "k.gkey",
        "vault",
        "init",
        "v.geode/a/b/inner.geode",
    ]);
    refused(&o);
    assert!(!root.join("a").exists());
    verify(&e, &root);
}

#[cfg(unix)]
#[test]
fn symlinks_into_a_vault_are_refused() {
    let e = Env::new();
    let root = init_vault(&e);

    std::os::unix::fs::symlink("v.geode", e.dir.join("link_to_vault")).unwrap();
    let o = e.geode(&[
        "--key",
        "k.gkey",
        "vault",
        "init",
        "link_to_vault/inner.geode",
    ]);
    refused(&o);
    assert!(!root.join("inner.geode").exists());

    std::fs::create_dir_all(root.join("subdir")).unwrap();
    std::os::unix::fs::symlink("v.geode/subdir", e.dir.join("link_to_subdir")).unwrap();
    let o = e.geode(&[
        "--key",
        "k.gkey",
        "vault",
        "init",
        "link_to_subdir/inner.geode",
    ]);
    refused(&o);
    assert!(!root.join("subdir/inner.geode").exists());
    verify(&e, &root);
}

#[test]
fn relative_paths_from_inside_a_vault_are_refused() {
    let e = Env::new();
    let root = init_vault(&e);

    let o = e.geode_in(&root, &["--key", &e.key(), "vault", "init", "child.geode"]);
    refused(&o);
    assert!(!root.join("child.geode").exists());

    let before: Vec<Vec<u8>> = ["GEODE", "header.json", "recipients.json"]
        .iter()
        .map(|f| std::fs::read(root.join(f)).unwrap())
        .collect();
    let o = e.geode_in(&root, &["--key", &e.key(), "vault", "init", "."]);
    refused(&o);
    for (f, bytes) in ["GEODE", "header.json", "recipients.json"]
        .iter()
        .zip(before)
    {
        assert_eq!(std::fs::read(root.join(f)).unwrap(), bytes, "{f} changed");
    }
    verify(&e, &root);
}

#[test]
fn reinitializing_an_existing_vault_is_refused_without_modification() {
    let e = Env::new();
    let root = init_vault(&e);
    let before: Vec<(PathBuf, Vec<u8>)> = walkdir::WalkDir::new(&root)
        .into_iter()
        .filter_map(std::result::Result::ok)
        .filter(|x| x.file_type().is_file())
        .map(|x| {
            let rel = x.path().strip_prefix(&root).unwrap().to_path_buf();
            (rel, std::fs::read(x.path()).unwrap())
        })
        .collect();

    let o = e.geode(&["--key", "k.gkey", "vault", "init", "v.geode"]);
    assert_eq!(o.status.code(), Some(1), "{}", combined(&o));

    for (rel, bytes) in before {
        assert_eq!(std::fs::read(root.join(&rel)).unwrap(), bytes, "{rel:?}");
    }
    verify(&e, &root);
}

#[test]
fn nested_refusal_happens_before_a_key_is_required() {
    let e = Env::new();
    let root = init_vault(&e);
    std::fs::remove_file(e.dir.join("k.gkey")).unwrap();
    let o = e.geode(&["vault", "init", "v.geode/sub"]);
    refused(&o);
    assert!(!root.join("sub").exists());
}

#[test]
fn sibling_vault_succeeds() {
    let e = Env::new();
    let root = init_vault(&e);
    let sibling = e.dir.join("sibling.geode");
    ok(
        e.geode(&["--key", "k.gkey", "vault", "init", "sibling.geode"]),
        "sibling vault init",
    );
    verify(&e, &sibling);
    verify(&e, &root);
}
