//! Metadata skill (`.agents/skills/geode`) against the shipped `geode` CLI.
//!
//! The Nushell body may spawn only the metadata allowlist. Fixture bytes
//! and the generated identity key must not appear in wrapped output.
//! `cat` is called once, directly, to show those bytes are in the vault.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MARKER: &str = "marker-do-not-print";
const SECOND: &str = "second-marker";
const ALLOWED: &[&str] = &[
    "list",
    "verify",
    "vault recipients",
    "snapshot ls",
    "policy show",
    "policy check",
    "audit verify",
    "custody status",
    "keyring list",
];

struct Fx {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    vault: String,
    isk_hex: String,
}

struct Skill {
    nu: PathBuf,
    script: PathBuf,
    dir: PathBuf,
    log: PathBuf,
}

fn repo_root() -> PathBuf {
    fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap()
}

fn geode_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_geode"))
}

fn apply_env(cmd: &mut Command, dir: &Path) {
    cmd.current_dir(dir)
        .env("HOME", dir.join("home"))
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("GEODE_KEY_FILE", dir.join("k.gkey"))
        .env_remove("GEODE_TOKEN")
        .env_remove("GEODE_PASSPHRASE")
        .env_remove("GEODE_VAULT")
        .env_remove("GEODE_FACET_EVENTS");
}

fn identity_hex(path: &Path) -> String {
    let raw = fs::read(path).unwrap();
    assert_eq!(raw.len(), 54, "raw GKEY length");
    assert_eq!(raw[5], 0, "test key must be the raw form");
    raw[6..38].iter().map(|b| format!("{b:02x}")).collect()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn json_slice(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_else(|e| panic!("json: {e}: {}", text(bytes)))
}

fn json_lines(bytes: &[u8]) -> Vec<serde_json::Value> {
    text(bytes)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap_or_else(|e| panic!("json: {e}: {line}")))
        .collect()
}

impl Fx {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = fs::canonicalize(tmp.path()).expect("canon");
        fs::create_dir_all(dir.join("home")).unwrap();
        fs::create_dir_all(dir.join("xdg")).unwrap();
        fs::create_dir_all(dir.join("state")).unwrap();
        let mut fx = Self {
            _tmp: tmp,
            vault: dir.join("v.geode").display().to_string(),
            isk_hex: String::new(),
            dir,
        };
        fx.ok(&["keygen", "--insecure-plaintext", "k.gkey"]);
        fx.isk_hex = identity_hex(&fx.dir.join("k.gkey"));
        fx.populate();
        fx
    }

    fn populate(&self) {
        self.ok(&["vault", "init", "v.geode"]);
        fs::write(self.dir.join("note.txt"), MARKER).unwrap();
        fs::write(self.dir.join("other.txt"), SECOND).unwrap();
        self.ok(&["seal", "note.txt", "v.geode"]);
        self.ok(&["seal", "other.txt", "v.geode"]);
        self.ok(&["snapshot", "create", "v.geode", "--name", "demo"]);
        geode_grotto::audit::open(&self.dir.join("state/hedronite/geode/audit.db")).unwrap();
    }

    fn geode(&self, args: &[&str]) -> Output {
        let mut cmd = Command::new(geode_bin());
        cmd.args(args);
        apply_env(&mut cmd, &self.dir);
        cmd.output().expect("spawn geode")
    }

    fn ok(&self, args: &[&str]) -> Output {
        let out = self.geode(args);
        assert!(out.status.success(), "{args:?}: {}", text(&out.stderr));
        if !self.isk_hex.is_empty() {
            self.clean_output("setup", &out);
        }
        out
    }

    fn clean(&self, label: &str, bytes: &[u8]) {
        let body = text(bytes);
        assert!(!body.contains(MARKER), "{label} printed vault contents");
        assert!(!body.contains(SECOND), "{label} printed vault contents");
        assert!(
            !body.contains(&self.isk_hex),
            "{label} printed identity key material"
        );
    }

    fn clean_output(&self, label: &str, out: &Output) {
        self.clean(label, &out.stdout);
        self.clean(label, &out.stderr);
    }
}

fn require_nu() -> Option<PathBuf> {
    if let Some(raw) = std::env::var_os("GEODE_NU") {
        let path = PathBuf::from(raw);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("nu");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if std::env::var_os("GEODE_REQUIRE_NU").is_some() {
        panic!("GEODE_REQUIRE_NU is set but nu was not found");
    }
    eprintln!("skipping skill script test: nu not on PATH");
    None
}

fn parse_allowed(src: &str) -> Vec<String> {
    let mut groups = Vec::new();
    let mut inside = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("const ALLOWED") {
            inside = true;
            continue;
        }
        if inside && trimmed == "]" {
            break;
        }
        if inside && trimmed.starts_with('[') && trimmed.ends_with(']') {
            let inner = trimmed.trim_start_matches('[').trim_end_matches(']');
            groups.push(inner.trim().to_string());
        }
    }
    groups
}

fn invocations(log: &Path) -> Vec<Vec<String>> {
    let raw = fs::read_to_string(log).unwrap_or_default();
    let mut lines = raw.lines();
    let mut out = Vec::new();
    while let Some(count) = lines.next() {
        if count.is_empty() {
            continue;
        }
        let n: usize = count.parse().expect("argc");
        let mut args = Vec::with_capacity(n);
        for _ in 0..n {
            args.push(lines.next().expect("argv").to_string());
        }
        out.push(args);
    }
    out
}

fn install_wrapper(dir: &Path) {
    let path = dir.join("bin/geode");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        "#!/bin/sh\nprintf '%s\\n' \"$#\" >> \"$GEODE_ARGV_LOG\"\n\
         for arg in \"$@\"; do\n  printf '%s\\n' \"$arg\" >> \"$GEODE_ARGV_LOG\"\n\
         done\nexec \"$GEODE_REAL\" \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

impl Skill {
    fn bind(fx: &Fx, nu: &Path) -> Self {
        install_wrapper(&fx.dir);
        Self {
            nu: nu.to_path_buf(),
            script: repo_root().join(".agents/skills/geode/geode.nu"),
            dir: fx.dir.clone(),
            log: fx.dir.join("argv.log"),
        }
    }

    fn call(&self, args: &[&str]) -> (Output, Vec<Vec<String>>) {
        self.call_vault(args, None)
    }

    fn call_vault(&self, args: &[&str], vault: Option<&str>) -> (Output, Vec<Vec<String>>) {
        let _ = fs::write(&self.log, "");
        let mut cmd = Command::new(&self.nu);
        cmd.arg(&self.script).args(args);
        apply_env(&mut cmd, &self.dir);
        cmd.env("PATH", self.dir.join("bin"))
            .env("GEODE_REAL", geode_bin())
            .env("GEODE_ARGV_LOG", &self.log);
        if let Some(vault) = vault {
            cmd.env("GEODE_VAULT", vault);
        }
        let out = cmd.output().expect("spawn nu");
        (out, invocations(&self.log))
    }
}

fn skill_ok(out: &Output) -> serde_json::Value {
    assert!(out.status.success(), "nu: {}", text(&out.stderr));
    json_slice(&out.stdout)
}

fn one(inv: &[Vec<String>]) -> &[String] {
    assert_eq!(inv.len(), 1, "invocations: {inv:?}");
    &inv[0]
}

fn assert_argv(got: &[String], expect: &[&str]) {
    let owned: Vec<String> = expect.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(got, owned.as_slice());
}

fn success_event(fx: &Fx, label: &str, out: &Output) -> serde_json::Value {
    assert!(out.status.success(), "{label}: {}", text(&out.stderr));
    fx.clean_output(label, out);
    json_slice(&out.stdout)
}

#[test]
fn skill_allowlist_is_the_metadata_set() {
    let src = fs::read_to_string(repo_root().join(".agents/skills/geode/geode.nu")).unwrap();
    assert_eq!(parse_allowed(&src), ALLOWED);
    assert_eq!(src.matches("^geode").count(), 1);
    assert!(src.contains("--output json"));
    assert!(src.contains("--cheap"));
    assert!(src.contains("--principal="));
    assert!(src.contains("not on the allowlist"));
    assert!(src.contains("not a metadata command"));
}

#[test]
fn skill_frontmatter_is_name_and_description_only() {
    let doc = fs::read_to_string(repo_root().join(".agents/skills/geode/SKILL.md")).unwrap();
    let mut lines = doc.lines();
    assert_eq!(lines.next(), Some("---"));
    let mut keys = Vec::new();
    for line in lines {
        if line == "---" {
            break;
        }
        if line.is_empty() || line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        let key = line.split_once(':').expect("frontmatter key").0;
        keys.push(key);
    }
    assert_eq!(keys, ["name", "description"]);
}

#[test]
fn skill_doc_warns_that_entry_names_can_be_sensitive() {
    let doc = fs::read_to_string(repo_root().join(".agents/skills/geode/SKILL.md")).unwrap();
    let lower = doc.to_lowercase();
    assert!(lower.contains("entry names"));
    assert!(lower.contains("sensitive"));
    for name in ["`cat`", "`open`", "`mount`", "`run`", "`agent`", "`keygen`"] {
        assert!(doc.contains(name), "{name}");
    }
    for name in [
        "`seal`",
        "`sign`",
        "add-recipient",
        "policy set",
        "keyring add",
        "`gc`",
    ] {
        assert!(doc.contains(name), "{name}");
    }
    assert!(doc.contains("unlock"));
    assert!(doc.contains("lock"));
}

#[test]
fn skill_harness_copies_match_canonical_bytes() {
    let root = repo_root();
    let canonical = root.join(".agents/skills");
    let canon_files = regular_rel_files(&canonical);
    assert!(canon_files.iter().any(|p| p == Path::new("geode/SKILL.md")));
    assert!(canon_files.iter().any(|p| p == Path::new("geode/geode.nu")));
    for dest in [".claude/skills", ".grok/skills", ".cursor/skills"] {
        let copy = root.join(dest);
        let copy_files = regular_rel_files(&copy);
        assert_eq!(canon_files, copy_files, "{dest}");
        for rel in &canon_files {
            let left = fs::read(canonical.join(rel)).unwrap();
            let right = fs::read(copy.join(rel)).unwrap();
            assert_eq!(left, right, "{dest}/{}", rel.display());
        }
    }
    assert!(!root.join("skills/geode").exists());
    assert!(!root.join(".omp/skills").exists());
    assert!(!root.join(".codex/skills").exists());
}

fn regular_rel_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let meta = fs::symlink_metadata(root).unwrap_or_else(|_| panic!("missing {}", root.display()));
    assert!(meta.is_dir(), "{}", root.display());
    assert!(!meta.file_type().is_symlink(), "symlink {}", root.display());
    walk_regular(root, root, &mut files);
    files.sort();
    files
}

fn walk_regular(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) {
    let mut ents: Vec<_> = fs::read_dir(dir).unwrap().map(|ent| ent.unwrap()).collect();
    ents.sort_by_key(|ent| ent.file_name());
    for ent in ents {
        let path = ent.path();
        let meta = fs::symlink_metadata(&path).unwrap();
        let kind = meta.file_type();
        assert!(!kind.is_symlink(), "symlink {}", path.display());
        if kind.is_dir() {
            walk_regular(root, &path, files);
        } else if kind.is_file() {
            files.push(path.strip_prefix(root).unwrap().to_path_buf());
        } else {
            panic!("not a regular file: {}", path.display());
        }
    }
}

#[test]
fn readme_recommends_skill_and_keeps_mcp() {
    let doc = fs::read_to_string(repo_root().join("README.md")).unwrap();
    assert!(doc.contains("skills/geode/"));
    assert!(doc.contains("geode agent serve"));
    assert!(doc.contains("skills + CLI"));
    assert!(doc.contains("works the same as before"));
}

#[test]
fn wrapped_argv_is_accepted_by_the_cli() {
    let fx = Fx::new();
    cli_list(&fx);
    cli_verify(&fx);
    cli_recipients_and_snapshots(&fx);
    cli_policy(&fx);
    cli_audit_keyring_custody(&fx);
    cli_cat_prints_the_fixture(&fx);
}

fn cli_list(fx: &Fx) {
    let out = fx.geode(&["--output", "json", "list", "--", &fx.vault]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    fx.clean_output("list", &out);
    let rows = json_lines(&out.stdout);
    assert!(rows.iter().any(|row| row["path"] == "note.txt"));
    assert!(rows.iter().any(|row| row["path"] == "other.txt"));
    let prefixed = fx.geode(&["--output", "json", "list", "--", &fx.vault, "note.txt"]);
    assert!(prefixed.status.success(), "{}", text(&prefixed.stderr));
    fx.clean_output("list prefix", &prefixed);
    let rows = json_lines(&prefixed.stdout);
    assert!(rows.iter().any(|row| row["path"] == "note.txt"));
    assert!(rows.iter().all(|row| row["path"] != "other.txt"));
}

fn cli_verify(fx: &Fx) {
    let cheap = fx.geode(&["--output", "json", "verify", "--cheap", "--", &fx.vault]);
    let sample = fx.geode(&[
        "--output",
        "json",
        "verify",
        "--sample=0.05",
        "--",
        &fx.vault,
    ]);
    for (label, out) in [("cheap", &cheap), ("sample", &sample)] {
        let doc = success_event(fx, label, out);
        assert_eq!(doc["verb"], "verify");
        assert_eq!(doc["files"], 2);
    }
}

fn cli_recipients_and_snapshots(fx: &Fx) {
    let recipients = fx.geode(&["--output", "json", "vault", "recipients", "--", &fx.vault]);
    let doc = success_event(fx, "recipients", &recipients);
    assert_eq!(doc["verb"], "vault_recipients");
    assert_eq!(doc["recipients"][0]["type"], "symmetric");
    assert!(doc["recipients"][0].get("wrap").is_none());
    let snaps = fx.geode(&["--output", "json", "snapshot", "ls", "--", &fx.vault]);
    let doc = success_event(fx, "snapshots", &snaps);
    assert_eq!(doc["verb"], "snapshot_ls");
    assert_eq!(doc["snapshots"][0]["name"], "demo");
}

fn cli_policy(fx: &Fx) {
    let show = fx.geode(&["--output", "json", "policy", "show", "--", &fx.vault]);
    let doc = success_event(fx, "policy show", &show);
    assert_eq!(doc["verb"], "policy_show");
    assert_eq!(doc["source"], "default");
    cli_policy_check(fx);
}

fn cli_policy_check(fx: &Fx) {
    let allow = fx.geode(&[
        "--output",
        "json",
        "policy",
        "check",
        "--principal=human:local",
        "--op=list",
        "--path=note.txt",
        "--",
        &fx.vault,
    ]);
    let doc = success_event(fx, "policy allow", &allow);
    assert_eq!(doc["verdict"], "allow");
    let deny = fx.geode(&[
        "--output",
        "json",
        "policy",
        "check",
        "--principal=agent:skill",
        "--op=read",
        "--path=note.txt",
        "--",
        &fx.vault,
    ]);
    assert_eq!(deny.status.code(), Some(3));
    fx.clean_output("policy deny", &deny);
    assert_eq!(json_slice(&deny.stdout)["error"]["code"], "policy_deny");
    cli_policy_positional_is_usage(fx);
}

fn cli_policy_positional_is_usage(fx: &Fx) {
    let positional = fx.geode(&[
        "--output",
        "json",
        "policy",
        "check",
        &fx.vault,
        "human:local",
        "list",
        "note.txt",
    ]);
    assert!(!positional.status.success());
    assert!(text(&positional.stderr).contains("unexpected"));
}

fn cli_audit_keyring_custody(fx: &Fx) {
    let audit = fx.geode(&["--output", "json", "audit", "verify"]);
    let doc = success_event(fx, "audit", &audit);
    assert_eq!(doc["verb"], "audit_verify");
    assert_eq!(doc["intact"], true);
    let keys = fx.geode(&["--output", "json", "keyring", "list"]);
    let doc = success_event(fx, "keyring", &keys);
    assert_eq!(doc["files"], 0);
    let status = fx.geode(&["--output", "json", "custody", "status"]);
    let doc = json_slice(&status.stdout);
    let verb = doc["verb"].as_str().unwrap();
    assert!(verb == "custody" || verb == "custody_status", "{verb}");
    fx.clean_output("custody", &status);
}

fn cli_cat_prints_the_fixture(fx: &Fx) {
    let out = fx.geode(&["--output", "json", "cat", "--", &fx.vault, "note.txt"]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(text(&out.stdout).contains(MARKER));
}

#[test]
fn skill_script_matches_cli_and_refuses_the_rest() {
    let Some(nu) = require_nu() else {
        return;
    };
    let fx = Fx::new();
    let skill = Skill::bind(&fx, &nu);
    skill_list(&fx, &skill);
    skill_verify(&fx, &skill);
    skill_views(&fx, &skill);
    skill_policy(&fx, &skill);
    skill_status(&fx, &skill);
    skill_vault_env(&fx, &skill);
    skill_refuses(&skill, &fx.vault);
}

fn skill_list(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["list", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill list", &out);
    assert_eq!(doc["command"], "list");
    assert_eq!(doc["ok"], true);
    let rows = doc["data"].as_array().expect("list ndjson");
    assert!(rows.iter().any(|row| row["path"] == "note.txt"));
    assert!(rows.iter().any(|row| row["path"] == "other.txt"));
    assert_argv(one(&inv), &["--output", "json", "list", "--", &fx.vault]);
    let (out, inv) = skill.call(&["list", &fx.vault, "note.txt"]);
    let _ = skill_ok(&out);
    fx.clean_output("skill prefix", &out);
    let body = text(&out.stdout);
    assert!(body.contains("note.txt"));
    assert!(!body.contains("other.txt"));
    assert_argv(
        one(&inv),
        &["--output", "json", "list", "--", &fx.vault, "note.txt"],
    );
}

fn skill_verify(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["verify", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill cheap", &out);
    assert_eq!(doc["data"]["verb"], "verify");
    assert_eq!(doc["data"]["files"], 2);
    assert_argv(
        one(&inv),
        &["--output", "json", "verify", "--cheap", "--", &fx.vault],
    );
    let (out, inv) = skill.call(&["verify", &fx.vault, "--sample", "0.05"]);
    let doc = skill_ok(&out);
    fx.clean_output("skill sample", &out);
    assert_eq!(doc["data"]["verb"], "verify");
    assert_argv(
        one(&inv),
        &[
            "--output",
            "json",
            "verify",
            "--sample=0.05",
            "--",
            &fx.vault,
        ],
    );
}

fn skill_views(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["recipients", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill recipients", &out);
    assert_eq!(doc["data"]["verb"], "vault_recipients");
    assert_eq!(doc["data"]["recipients"][0]["type"], "symmetric");
    assert!(doc["data"]["recipients"][0].get("wrap").is_none());
    assert_argv(
        one(&inv),
        &["--output", "json", "vault", "recipients", "--", &fx.vault],
    );
    let (out, inv) = skill.call(&["snapshots", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill snapshots", &out);
    assert_eq!(doc["data"]["snapshots"][0]["name"], "demo");
    assert_argv(
        one(&inv),
        &["--output", "json", "snapshot", "ls", "--", &fx.vault],
    );
}

fn skill_policy(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["policy", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill policy", &out);
    assert_eq!(doc["data"]["source"], "default");
    assert_argv(
        one(&inv),
        &["--output", "json", "policy", "show", "--", &fx.vault],
    );
    let (out, inv) = skill.call(&["can", "human:local", "list", "note.txt", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill allow", &out);
    assert_eq!(doc["exit"], 0);
    assert_eq!(doc["data"]["verdict"], "allow");
    assert_argv(
        one(&inv),
        &[
            "--output",
            "json",
            "policy",
            "check",
            "--principal=human:local",
            "--op=list",
            "--path=note.txt",
            "--",
            &fx.vault,
        ],
    );
    skill_can_deny(fx, skill);
}

fn skill_can_deny(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["can", "agent:skill", "read", "note.txt", &fx.vault]);
    let doc = skill_ok(&out);
    fx.clean_output("skill deny", &out);
    assert_eq!(doc["exit"], 3);
    assert_eq!(doc["ok"], true);
    assert_eq!(doc["data"]["error"]["code"], "policy_deny");
    assert_argv(
        one(&inv),
        &[
            "--output",
            "json",
            "policy",
            "check",
            "--principal=agent:skill",
            "--op=read",
            "--path=note.txt",
            "--",
            &fx.vault,
        ],
    );
}

fn skill_status(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call(&["audit"]);
    let doc = skill_ok(&out);
    fx.clean_output("skill audit", &out);
    assert_eq!(doc["data"]["intact"], true);
    assert_argv(one(&inv), &["--output", "json", "audit", "verify"]);
    let (out, inv) = skill.call(&["keyring"]);
    let doc = skill_ok(&out);
    fx.clean_output("skill keyring", &out);
    assert_eq!(doc["data"]["files"], 0);
    assert_argv(one(&inv), &["--output", "json", "keyring", "list"]);
    let (out, inv) = skill.call(&["custody"]);
    let doc = skill_ok(&out);
    fx.clean_output("skill custody", &out);
    assert_eq!(doc["command"], "custody");
    assert_argv(one(&inv), &["--output", "json", "custody", "status"]);
}

fn skill_vault_env(fx: &Fx, skill: &Skill) {
    let (out, inv) = skill.call_vault(&["list"], Some(&fx.vault));
    let doc = skill_ok(&out);
    fx.clean_output("skill env", &out);
    assert!(doc["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["path"] == "note.txt"));
    assert_argv(one(&inv), &["--output", "json", "list", "--", &fx.vault]);
    let (out, inv) = skill.call(&["list"]);
    assert!(!out.status.success(), "{}", text(&out.stdout));
    assert!(text(&out.stderr).contains("no vault"));
    assert!(inv.is_empty());
    let (out, inv) = skill.call(&[]);
    assert!(out.status.success(), "{}", text(&out.stderr));
    assert!(inv.is_empty());
}

fn skill_refuses(skill: &Skill, vault: &str) {
    let cases: &[&[&str]] = &[
        &["cat", vault, "note.txt"],
        &["open", vault],
        &["mount", vault, "mnt"],
        &["run"],
        &["agent"],
        &["keygen"],
        &["seal"],
        &["sign"],
        &["rotate"],
        &["gc"],
        &["add-recipient"],
        &["unlock"],
        &["lock"],
        &["vault", "init", vault],
        &["policy", "set", vault],
        &["keyring", "add"],
        &["custody", "unlock"],
        &["custody", "lock"],
        &["git", "unlock"],
        &["scan"],
        &["tui"],
        &["verify", vault, "--full"],
    ];
    for args in cases {
        refuse_one(skill, args);
    }
}

fn refuse_one(skill: &Skill, args: &[&str]) {
    let (out, inv) = skill.call(args);
    assert!(!out.status.success(), "{args:?}: {}", text(&out.stderr));
    assert!(inv.is_empty(), "{args:?} spawned geode: {inv:?}");
    let err = text(&out.stderr);
    let refused = err.contains("refusing")
        || err.contains("Extra positional")
        || err.contains("unexpected")
        || err.contains("unknown flag");
    assert!(refused, "{args:?}: {err}");
}
