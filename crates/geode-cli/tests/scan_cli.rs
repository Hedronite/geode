//! `geode scan` against the shipped binary.
//!
//! Fixtures are generated at runtime from random bytes; no real-looking
//! token is committed. Every test checks its own captured output for the
//! planted values in raw, base64 and hex form, and for an unkeyed hash.
//!
//! - `--hook` exits 2 with an AWS key, a `ghp_` token and a 40-byte base64
//!   blob all listed; a clean tree exits 0.
//! - An unreadable file, a `--max-bytes` overflow and a symlink escaping the
//!   root each exit 1.
//! - Fingerprints are keyed: a different key gives a different fingerprint.
//! - `scan.key` and `default.gkey` inside a root are always findings.

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use base64ct::{Base64, Base64UrlUnpadded, Encoding as _};

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

    fn geode(&self, args: &[&str]) -> Output {
        self.geode_cfg(args, &self.dir.join("cfg"))
    }

    fn geode_cfg(&self, args: &[&str], cfg: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_geode"))
            .args(args)
            .current_dir(&self.dir)
            .env("HOME", self.dir.join("home"))
            .env("XDG_CONFIG_HOME", cfg)
            .env_remove("GEODE_KEY_FILE")
            .env_remove("GEODE_PASSPHRASE")
            .env_remove("GEODE_TOKEN")
            .stdin(Stdio::null())
            .output()
            .expect("spawn geode")
    }
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).expect("random");
    b
}

fn pick(alphabet: &[u8], n: usize) -> String {
    random(n)
        .iter()
        .map(|b| alphabet[usize::from(*b) % alphabet.len()] as char)
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Plants {
    aws: String,
    ghp: String,
    blob_raw: Vec<u8>,
    blob: String,
}

fn plant(root: &Path) -> Plants {
    let aws = format!("AKIA{}", pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16));
    let ghp = format!(
        "ghp_{}",
        pick(
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            36
        )
    );
    // Random bytes until the encoding has upper, lower and a digit (the
    // entropy rule wants three classes; a miss is ~1e-6 per draw).
    let (blob_raw, blob) = loop {
        let raw = random(40);
        let b = Base64::encode_string(&raw);
        let has = |f: fn(&u8) -> bool| b.as_bytes().iter().any(f);
        if has(u8::is_ascii_uppercase) && has(u8::is_ascii_lowercase) && has(u8::is_ascii_digit) {
            break (raw, b);
        }
    };
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(
        root.join("aws.env"),
        format!("# creds\nAWS_ACCESS_KEY_ID={aws}\n"),
    )
    .unwrap();
    std::fs::write(root.join("sub/gh.txt"), format!("token: {ghp}\n")).unwrap();
    std::fs::write(root.join("blob.conf"), format!("[x]\ndata = {blob}\n")).unwrap();
    std::fs::write(
        root.join("README"),
        "Plain prose with nothing secret in it.\n",
    )
    .unwrap();
    Plants {
        aws,
        ghp,
        blob_raw,
        blob,
    }
}

/// Every form of every planted value that must never be printed.
fn forbidden(p: &Plants) -> Vec<String> {
    let mut out = Vec::new();
    for v in [
        p.aws.as_bytes(),
        p.ghp.as_bytes(),
        p.blob.as_bytes(),
        &p.blob_raw[..],
    ] {
        out.push(Base64::encode_string(v));
        out.push(Base64UrlUnpadded::encode_string(v));
        out.push(hex(v));
        out.push(hex(v).to_uppercase());
        let unkeyed = blake3::hash(v).to_hex().to_string();
        out.push(unkeyed[..32].to_string());
        out.push(unkeyed);
    }
    out.push(p.aws.clone());
    out.push(p.ghp.clone());
    out.push(p.blob.clone());
    out
}

fn assert_no_values(o: &Output, p: &Plants) {
    let all = [&o.stdout[..], &o.stderr[..]].concat();
    let text = String::from_utf8_lossy(&all);
    for f in forbidden(p) {
        assert!(!text.contains(&f), "output carries a planted value form");
    }
    assert!(
        !all.windows(p.blob_raw.len())
            .any(|w| w == p.blob_raw.as_slice()),
        "output carries raw blob bytes"
    );
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout)
        .unwrap_or_else(|e| panic!("not json ({e}): {}", String::from_utf8_lossy(&o.stdout)))
}

fn rules(doc: &serde_json::Value) -> Vec<(String, String)> {
    let mut v: Vec<(String, String)> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["path"].as_str().unwrap().to_owned(),
                f["rule"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    v.sort();
    v
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn hook_blocks_all_three_plants_without_printing_them() {
    let e = Env::new();
    let p = plant(&e.dir.join("tree"));

    let o = e.geode(&["scan", "--hook", "--json", "tree"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_no_values(&o, &p);
    let doc = json(&o);
    assert_eq!(doc["version"], 1);
    assert_eq!(doc["clean"], false);
    assert_eq!(doc["suppressed"], 0);
    assert_eq!(
        rules(&doc),
        [
            ("tree/aws.env".into(), "aws-access-key".into()),
            ("tree/blob.conf".into(), "entropy-base64".into()),
            ("tree/sub/gh.txt".into(), "github-token".into()),
        ]
    );
    for f in doc["findings"].as_array().unwrap() {
        let mut keys: Vec<&String> = f.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(keys, ["col", "fingerprint", "line", "path", "rule"]);
        assert_eq!(f["fingerprint"].as_str().unwrap().len(), 32);
    }
    let aws = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["rule"] == "aws-access-key")
        .unwrap();
    assert_eq!(
        (aws["line"].as_u64(), aws["col"].as_u64()),
        (Some(2), Some(19))
    );

    // Text mode: same exit, same silence, and the suppressed count line.
    let o = e.geode(&["scan", "--hook", "tree"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_no_values(&o, &p);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("tree/aws.env:2:19: aws-access-key "), "{out}");
    assert!(out.contains("0 suppressed by allowlist"), "{out}");

    // Without --hook the report is the same and the exit is 0.
    let o = e.geode(&["scan", "--json", "tree"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    assert_eq!(json(&o)["findings"].as_array().unwrap().len(), 3);
}

#[test]
fn clean_tree_exits_0() {
    let e = Env::new();
    let root = e.dir.join("clean");
    std::fs::create_dir_all(root.join("a/b")).unwrap();
    std::fs::write(
        root.join("a/notes.md"),
        "# Notes\n\nNothing to see here.\nport = 8080\n",
    )
    .unwrap();
    std::fs::write(
        root.join("a/b/data.bin"),
        [0u8, 1, 2, 3, 255, 254, b'\n', 7],
    )
    .unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("../notes.md", root.join("a/b/inside-link")).unwrap();
    let o = e.geode(&["scan", "--hook", "clean"]);
    assert_eq!(
        o.status.code(),
        Some(0),
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        err(&o)
    );
    assert!(String::from_utf8_lossy(&o.stdout).contains("0 suppressed by allowlist"));
    let o = e.geode(&["scan", "--hook", "--json", "clean"]);
    assert_eq!(o.status.code(), Some(0));
    assert_eq!(json(&o)["clean"], true);
}

#[test]
fn binary_files_are_scanned() {
    let e = Env::new();
    let aws = format!("AKIA{}", pick(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", 16));
    let mut bin = vec![0u8, 0xff, 0x00, 0x13, b'\n'];
    bin.extend_from_slice(aws.as_bytes());
    bin.extend_from_slice(&[0u8, 0xfe]);
    std::fs::create_dir_all(e.dir.join("bin")).unwrap();
    std::fs::write(e.dir.join("bin/blob.dat"), &bin).unwrap();
    let o = e.geode(&["scan", "--hook", "--json", "bin"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    assert_eq!(
        rules(&json(&o)),
        [("bin/blob.dat".into(), "aws-access-key".into())]
    );
    assert!(!String::from_utf8_lossy(&[&o.stdout[..], &o.stderr[..]].concat()).contains(&aws));
}

#[test]
fn allowlist_suppresses_by_fingerprint_only() {
    let e = Env::new();
    let p = plant(&e.dir.join("tree"));
    let doc = json(&e.geode(&["scan", "--json", "tree"]));
    let fps: Vec<(String, String)> = doc["findings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["rule"].as_str().unwrap().to_owned(),
                f["fingerprint"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    let aws_fp = &fps.iter().find(|(r, _)| r == "aws-access-key").unwrap().1;

    std::fs::write(e.dir.join("one.allow"), format!("# reviewed\n{aws_fp}\n\n")).unwrap();
    let o = e.geode(&["scan", "--hook", "--allow", "one.allow", "tree"]);
    assert_eq!(o.status.code(), Some(2));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("1 suppressed by allowlist"), "{out}");
    assert!(!out.contains("aws-access-key"), "{out}");

    // The default allowlist is .geode/scan-allow in the working directory.
    std::fs::create_dir_all(e.dir.join(".geode")).unwrap();
    let all: String = fps.iter().map(|(_, f)| format!("{f}\n")).collect();
    std::fs::write(e.dir.join(".geode/scan-allow"), all).unwrap();
    let o = e.geode(&["scan", "--hook", "--json", "tree"]);
    assert_eq!(o.status.code(), Some(0), "{}", err(&o));
    let d = json(&o);
    assert_eq!(
        (d["clean"].as_bool(), d["suppressed"].as_u64()),
        (Some(true), Some(3))
    );

    // A value pasted into the allowlist is an error, and is not echoed.
    std::fs::write(e.dir.join("bad.allow"), format!("{}\n", p.aws)).unwrap();
    let o = e.geode(&["scan", "--hook", "--allow", "bad.allow", "tree"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(err(&o).contains("line 1: not a fingerprint"), "{}", err(&o));
    assert_no_values(&o, &p);
}

#[test]
fn errors_exit_1_and_are_never_skipped() {
    let e = Env::new();
    let p = plant(&e.dir.join("tree"));

    // --max-bytes overflow.
    let o = e.geode(&["scan", "--hook", "--max-bytes", "16", "tree"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("larger than --max-bytes 16"),
        "{}",
        err(&o)
    );
    assert_no_values(&o, &p);

    // A symlink escaping the root, to a file holding a planted value.
    let outside = e.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("secret.env"), format!("K={}\n", p.aws)).unwrap();
    let esc = e.dir.join("esc");
    std::fs::create_dir_all(&esc).unwrap();
    std::fs::write(esc.join("ok.txt"), "fine\n").unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("../outside/secret.env", esc.join("link")).unwrap();
        let o = e.geode(&["scan", "--hook", "esc"]);
        assert_eq!(o.status.code(), Some(1), "{}", err(&o));
        assert!(
            err(&o).contains("resolves outside the scan root"),
            "{}",
            err(&o)
        );
        assert_no_values(&o, &p);
    }

    // An unreadable file. Root reads through mode 000, so only assert
    // when the mode actually bites.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let locked = e.dir.join("locked");
        std::fs::create_dir_all(&locked).unwrap();
        let f = locked.join("no-read.txt");
        std::fs::write(&f, "x\n").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read(&f).is_err() {
            let o = e.geode(&["scan", "--hook", "locked"]);
            assert_eq!(o.status.code(), Some(1), "{}", err(&o));
            assert!(err(&o).contains("cannot read"), "{}", err(&o));
        } else {
            eprintln!(
                "GAP: running as root; mode 000 is readable, unreadable-file case not exercised"
            );
        }
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    // A missing root.
    let o = e.geode(&["scan", "--hook", "nope"]);
    assert_eq!(o.status.code(), Some(1), "{}", err(&o));
}

#[test]
fn fingerprints_are_keyed() {
    let e = Env::new();
    let p = plant(&e.dir.join("tree"));
    let fp = |o: &Output| -> Vec<String> {
        let mut v: Vec<String> = json(o)["findings"]
            .as_array()
            .unwrap()
            .iter()
            .map(|f| f["fingerprint"].as_str().unwrap().to_owned())
            .collect();
        v.sort();
        v
    };
    // Per-user scan.key: created once, mode 0600, stable across runs.
    let a1 = e.geode(&["scan", "--json", "tree"]);
    let a2 = e.geode(&["scan", "--json", "tree"]);
    assert_eq!(fp(&a1), fp(&a2));
    let key = e.dir.join("cfg/hedronite/geode/scan.key");
    assert_eq!(std::fs::read(&key).unwrap().len(), 32);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    // Another user's scan.key gives other fingerprints.
    let other = e.dir.join("cfg2");
    let b = e.geode_cfg(&["scan", "--json", "tree"], &other);
    assert!(
        fp(&a1).iter().all(|f| !fp(&b).contains(f)),
        "fingerprints matched across keys"
    );

    // An identity key (--key) derives its own scan key.
    assert!(e.geode(&["keygen", "id.gkey"]).status.success());
    let c = e.geode(&["--key", "id.gkey", "scan", "--json", "tree"]);
    assert_eq!(c.status.code(), Some(0), "{}", err(&c));
    assert!(fp(&a1).iter().all(|f| !fp(&c).contains(f)));
    assert_eq!(
        fp(&c),
        fp(&e.geode(&["--key", "id.gkey", "scan", "--json", "tree"]))
    );

    for o in [&a1, &b, &c] {
        assert_no_values(o, &p);
    }

    // A scan.key readable by others is refused.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        let o = e.geode(&["scan", "--hook", "tree"]);
        assert_eq!(o.status.code(), Some(1), "{}", err(&o));
        assert!(err(&o).contains("must be mode 0600"), "{}", err(&o));
    }
}

#[test]
fn key_files_inside_a_root_are_always_findings() {
    let e = Env::new();
    // Put the config dir inside the scan root, so scan.key lands there.
    let root = e.dir.join("dot");
    let cfg = root.join("config");
    std::fs::create_dir_all(&cfg).unwrap();
    std::fs::write(root.join("plain.txt"), "nothing\n").unwrap();
    let o = e.geode_cfg(&["scan", "--hook", "--json", "dot"], &cfg);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    let doc = json(&o);
    assert_eq!(
        rules(&doc),
        [(
            "dot/config/hedronite/geode/scan.key".into(),
            "geode-key-file".into()
        )]
    );

    // Allowlisting its fingerprint does not suppress it.
    let fp = doc["findings"][0]["fingerprint"]
        .as_str()
        .unwrap()
        .to_owned();
    std::fs::write(e.dir.join("k.allow"), format!("{fp}\n")).unwrap();
    let o = e.geode_cfg(
        &["scan", "--hook", "--json", "--allow", "k.allow", "dot"],
        &cfg,
    );
    assert_eq!(o.status.code(), Some(2));
    assert_eq!(json(&o)["suppressed"], 0);

    // An identity key named default.gkey anywhere in a root.
    let keys = e.dir.join("keys");
    std::fs::create_dir_all(&keys).unwrap();
    let kg = e.geode(&["keygen", "keys/default.gkey"]);
    assert!(kg.status.success(), "{}", err(&kg));
    let o = e.geode(&["scan", "--hook", "--json", "keys"]);
    assert_eq!(o.status.code(), Some(2), "{}", err(&o));
    // keygen also writes default.gpub; only the .gkey is a key-file finding.
    let found = rules(&json(&o));
    let gkey: Vec<_> = found
        .iter()
        .filter(|(p, _)| p == "keys/default.gkey")
        .collect();
    assert_eq!(
        gkey,
        [&("keys/default.gkey".to_owned(), "geode-key-file".to_owned())],
        "{found:?}"
    );
}

#[test]
fn scan_writes_no_audit_rows() {
    let e = Env::new();
    let _p = plant(&e.dir.join("tree"));
    let state = e.dir.join("state");
    let o = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["scan", "--hook", "tree"])
        .current_dir(&e.dir)
        .env("HOME", e.dir.join("home"))
        .env("XDG_CONFIG_HOME", e.dir.join("cfg"))
        .env("XDG_STATE_HOME", &state)
        .env_remove("GEODE_KEY_FILE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(2));
    assert!(!state.exists(), "scan touched the state dir (audit)");
}

#[test]
fn help_names_no_values() {
    let e = Env::new();
    let o = e.geode(&["scan", "--help"]);
    assert_eq!(o.status.code(), Some(0));
    let h = String::from_utf8_lossy(&o.stdout);
    for flag in ["--json", "--hook", "--allow", "--max-bytes"] {
        assert!(h.contains(flag), "{flag}: {h}");
    }
}
