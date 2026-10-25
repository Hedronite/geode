//! `geode seal --as PATH` against the shipped binary.
//!
//! G0a: one file with `--as api/svc-a.txt` lists that path; without `--as`
//!      it lists the basename; a directory with `--as` exits 1 and writes
//!      nothing.
//! G0b: bad `--as` paths exit 1 and leave the vault byte-for-byte unchanged
//!      (NUL cannot travel in argv; the unit test in `cmd::seal` covers it).
//! G0c: a token issued with `--allow-prefix api/` lists the `--as` entry and
//!      does not treat a basename-only `svc-a.txt` as inside `api/`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

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
        .env_remove("GEODE_TOKEN")
        .stdin(Stdio::null())
        .output()
        .expect("spawn geode")
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

/// Temp dir with a key, an empty vault, and `stage/api/svc-a.txt`.
fn setup() -> (tempfile::TempDir, PathBuf) {
    let t = tempfile::tempdir().expect("tempdir");
    let dir = std::fs::canonicalize(t.path()).expect("canonicalize");
    assert!(
        geode(&dir, &["keygen", "--insecure-plaintext", "k.gkey"])
            .status
            .success(),
        "keygen"
    );
    let init = geode(&dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    assert!(init.status.success(), "vault init: {}", err(&init));
    std::fs::create_dir_all(dir.join("stage/api")).expect("stage");
    std::fs::write(dir.join("stage/api/svc-a.txt"), b"svc-a body\n").expect("svc-a");
    (t, dir)
}

fn seal(dir: &Path, extra: &[&str]) -> Output {
    let mut args = vec!["--key", "k.gkey", "seal"];
    args.extend_from_slice(extra);
    geode(dir, &args)
}

/// Paths from a list verb's JSON: `list` prints one line per entry with
/// `path`; `agent list` prints one event with an `entries` array.
fn paths(o: &Output) -> Vec<String> {
    let mut out = Vec::new();
    for v in String::from_utf8_lossy(&o.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
    {
        let rows = v["entries"].as_array().cloned().unwrap_or_else(|| vec![v]);
        out.extend(
            rows.iter()
                .filter_map(|r| r["path"].as_str().map(str::to_owned)),
        );
    }
    out
}

fn list(dir: &Path) -> Vec<String> {
    let o = geode(
        dir,
        &["--key", "k.gkey", "--output", "json", "list", "v.geode"],
    );
    assert!(o.status.success(), "list: {}", err(&o));
    paths(&o)
}

/// Every file under the vault and its bytes.
fn snapshot(vault: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    walkdir::WalkDir::new(vault)
        .into_iter()
        .map(|e| e.expect("walk"))
        .filter(|e| e.file_type().is_file())
        .map(|e| {
            (
                e.path().to_path_buf(),
                std::fs::read(e.path()).expect("read"),
            )
        })
        .collect()
}

#[test]
fn without_as_lists_the_basename() {
    let (_t, dir) = setup();
    let o = seal(&dir, &["stage/api/svc-a.txt", "v.geode"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(list(&dir), ["svc-a.txt"]);
}

#[test]
fn as_stores_the_given_path() {
    let (_t, dir) = setup();
    let o = seal(
        &dir,
        &["stage/api/svc-a.txt", "v.geode", "--as", "api/svc-a.txt"],
    );
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(list(&dir), ["api/svc-a.txt"]);

    // An explicit basename is accepted too.
    let o = seal(
        &dir,
        &["stage/api/svc-a.txt", "v.geode", "--as", "svc-a.txt"],
    );
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(list(&dir), ["api/svc-a.txt", "svc-a.txt"]);

    // The body is the file, whatever the stored path.
    let o = geode(&dir, &["--key", "k.gkey", "open", "v.geode", "out"]);
    assert!(o.status.success(), "open: {}", err(&o));
    assert_eq!(
        std::fs::read(dir.join("out/api/svc-a.txt")).unwrap(),
        b"svc-a body\n"
    );
}

#[cfg(unix)]
#[test]
fn as_on_a_symlink_keeps_the_target_as_the_body() {
    let (_t, dir) = setup();
    std::os::unix::fs::symlink("api/svc-a.txt", dir.join("stage/link")).expect("symlink");
    let o = seal(&dir, &["stage/link", "v.geode", "--as", "api/link"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(list(&dir), ["api/link"]);
    let o = geode(&dir, &["--key", "k.gkey", "open", "v.geode", "out"]);
    assert!(o.status.success(), "open: {}", err(&o));
    let target = std::fs::read_link(dir.join("out/api/link")).expect("restored link");
    assert_eq!(target, Path::new("api/svc-a.txt"));
}

#[test]
fn directory_with_as_exits_1_and_writes_nothing() {
    let (_t, dir) = setup();
    let vault = dir.join("v.geode");
    let before = snapshot(&vault);
    let o = seal(&dir, &["stage", "v.geode", "--as", "api/svc-a.txt"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("--as is for one file"), "{}", err(&o));
    assert_eq!(snapshot(&vault), before, "vault changed");
    assert!(list(&dir).is_empty());

    // Without --as the directory still seals relative to itself.
    let o = seal(&dir, &["stage", "v.geode"]);
    assert!(o.status.success(), "{}", err(&o));
    assert_eq!(list(&dir), ["api/svc-a.txt"]);
}

#[test]
fn bad_as_paths_exit_1_and_write_nothing() {
    let (_t, dir) = setup();
    let vault = dir.join("v.geode");
    let before = snapshot(&vault);
    for bad in ["", ".", "/tmp/x", "../x", "api/../x", "api\\x", "api/"] {
        let o = seal(&dir, &["stage/api/svc-a.txt", "v.geode", "--as", bad]);
        assert_eq!(o.status.code(), Some(1), "{bad:?}: {}", err(&o));
        assert!(err(&o).contains("--as"), "{bad:?}: {}", err(&o));
        assert_eq!(snapshot(&vault), before, "{bad:?} changed the vault");
    }
    assert!(list(&dir).is_empty());
}

#[test]
fn help_has_one_operator_sentence() {
    let (_t, dir) = setup();
    let o = geode(&dir, &["seal", "--help"]);
    assert_eq!(o.status.code(), Some(0));
    let h = String::from_utf8_lossy(&o.stdout);
    let line = h
        .lines()
        .find(|l| l.trim_start().starts_with("--as <PATH>"))
        .expect("--as in help");
    assert!(line.contains("instead of its basename"), "{line}");
    for cite in ["SPEC", "G0", "w15", "fullstack", "§"] {
        assert!(!line.contains(cite), "{line}");
    }
}

#[test]
fn api_prefix_token_lists_the_as_entry_only() {
    let (_t, dir) = setup();
    for extra in [&["--as", "api/svc-a.txt"][..], &[][..]] {
        let mut args = vec!["stage/api/svc-a.txt", "v.geode"];
        args.extend_from_slice(extra);
        let o = seal(&dir, &args);
        assert!(o.status.success(), "{}", err(&o));
    }
    assert_eq!(list(&dir), ["api/svc-a.txt", "svc-a.txt"]);

    let show = geode(
        &dir,
        &[
            "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
        ],
    );
    assert!(show.status.success(), "policy show: {}", err(&show));
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).expect("show json");
    let vid = doc["policy"]["vault_id"].as_str().expect("vault_id");
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"agent:api","ops":["list","read"],"prefixes":["api/"]}}]}}"#
    );
    std::fs::write(dir.join("policy.json"), policy).expect("policy.json");
    let set = geode(
        &dir,
        &[
            "--key",
            "k.gkey",
            "policy",
            "set",
            "v.geode",
            "--file",
            "policy.json",
        ],
    );
    assert!(set.status.success(), "policy set: {}", err(&set));

    let issue = geode(
        &dir,
        &[
            "--key",
            "k.gkey",
            "--output",
            "json",
            "agent",
            "token",
            "issue",
            "--vault",
            "v.geode",
            "--principal",
            "agent:api",
            "--ops",
            "list,read",
            "--allow-prefix",
            "api/",
            "--ttl",
            "15m",
        ],
    );
    assert!(issue.status.success(), "token issue: {}", err(&issue));
    let doc: serde_json::Value = serde_json::from_slice(&issue.stdout).expect("issue json");
    let token = doc["token"].as_str().expect("token");

    let o = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args([
            "--key", "k.gkey", "--output", "json", "agent", "list", "v.geode",
        ])
        .current_dir(&dir)
        .env("GEODE_TOKEN", token)
        .env_remove("GEODE_KEY_FILE")
        .env_remove("GEODE_PASSPHRASE")
        .stdin(Stdio::null())
        .output()
        .expect("agent list");
    assert!(o.status.success(), "agent list: {}", err(&o));
    assert_eq!(
        paths(&o),
        ["api/svc-a.txt"],
        "{}",
        String::from_utf8_lossy(&o.stdout)
    );
}
