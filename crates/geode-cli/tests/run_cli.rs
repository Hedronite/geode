//! SPEC-v034 G6 — local `geode run` and `geode audit verify`.
//!
//! G6a: verify exits 0 on an intact chain and 2 at the first bad seq.
//! G6b: the echo, base64, and `xxd -p` cases print `[REDACTED:KEY]`, exit 0,
//!      with a `custody: false` row. The child env has no `GEODE_TOKEN`.
//! G6c: empty `allow_cmds`, a policy deny, a short binding, a token, and a
//!      missing `--` never spawn. A needle in argv is `argv_rejected` and its
//!      row does not hash that argv. A child exit 3 is `spawned: true`, exit 3.
//!
//! Executables are canonicalized at runtime. `/bin/sh` is never assumed
//! canonical (Ubuntu resolves it to `/usr/bin/dash`). Dummy values only.
//!
//! Pin tests hash with `sha2` and exec through the existing hashed-fd path.
//! Linux execs that fd. macOS has no `fexecve`; `geode-os` re-checks the
//! inode in the child. These tests have no macOS-only branch. A successful
//! pin runs `geode-pin-helper`, a Cargo bin, not a copy of `/bin/sh`:
//! macOS launch constraints SIGKILL a relocated platform binary. The
//! success test injects a trust root under that bin (feature
//! `test-trusted-root`). That feature is also what builds the helper, so
//! the helper tests are compiled only when it is on. A root-owned install
//! is `#[ignore]` and is not part of the default run.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const DUMMY: &str = "sk-dummy-0000QA";

/// One audit row: outcome, custody, argv0, exit code, argv hash.
type Row = (String, i64, String, Option<i64>, Vec<u8>);

struct Fx {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    sh: String,
}

impl Fx {
    /// Vault with `cfg/dummy.env` (the dummy), `cfg/pin` (4 bytes), and the
    /// default policy (`human:local` holds `inject` on everything).
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = std::fs::canonicalize(tmp.path()).expect("canonical tmp");
        let fx = Self {
            _tmp: tmp,
            dir,
            sh: canonical_on_path("sh"),
        };
        fx.ok(&["keygen", "--insecure-plaintext", "k.gkey"]);
        fx.ok(&["--key", "k.gkey", "vault", "init", "v.geode"]);
        std::fs::create_dir_all(fx.dir.join("src/cfg")).unwrap();
        std::fs::write(fx.dir.join("src/cfg/dummy.env"), DUMMY).unwrap();
        std::fs::write(fx.dir.join("src/cfg/pin"), "1234").unwrap();
        fx.ok(&["--key", "k.gkey", "seal", "src", "v.geode"]);
        fx
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_geode"));
        c.args(args).current_dir(&self.dir);
        isolate_test_env(&mut c, &self.dir);
        c.env_remove("GEODE_PASSPHRASE")
            .env_remove("GEODE_FACET_EVENTS")
            .env("G6_PARENT_MARK", "parent-only");
        c
    }

    fn geode(&self, args: &[&str]) -> Output {
        self.cmd(args).output().expect("spawn geode")
    }

    fn ok(&self, args: &[&str]) -> Output {
        let out = self.geode(args);
        assert!(out.status.success(), "{args:?}: {}", err(&out));
        out
    }

    /// `geode --key k.gkey run --vault v.geode <pre> -- <cmd>`.
    ///
    /// The test-only seam skips host confinement so these cases can spawn
    /// without a network namespace. Release builds do not have the flag.
    /// Tests of the allowlist do not use this helper.
    fn run(&self, pre: &[&str], cmd: &[&str]) -> Output {
        let mut args = vec!["--key", "k.gkey", "run", "--vault", "v.geode"];
        #[cfg(feature = "test-trusted-root")]
        args.push("--test-unconfined-hosts");
        args.extend_from_slice(pre);
        args.push("--");
        args.extend_from_slice(cmd);
        self.geode(&args)
    }

    fn allow_sh(&self) -> [&str; 2] {
        ["--allow-cmd", self.sh.as_str()]
    }

    fn db(&self) -> PathBuf {
        self.dir.join("state/hedronite/geode/audit.db")
    }

    fn rows(&self) -> Vec<Row> {
        let conn = rusqlite::Connection::open(self.db()).expect("open db");
        let mut st = conn
            .prepare("SELECT outcome, custody, argv0, exit_code, argv_hash FROM audit ORDER BY seq")
            .unwrap();
        st.query_map([], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .unwrap()
        .map(Result::unwrap)
        .collect()
    }

    fn marker(&self) -> PathBuf {
        self.dir.join("spawned.marker")
    }

    /// A command that would leave a marker file if it ever ran.
    fn touch_script(&self) -> String {
        format!("echo x > '{}'", self.marker().display())
    }
}

/// Point identity and XDG lookups at `dir`, never the caller's home.
/// `XDG_STATE_HOME` stays `dir/state` so the audit DB path does not move.
fn isolate_test_env(cmd: &mut Command, dir: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let home = dir.join("home");
    let xdg = dir.join("xdg");
    for sub in [
        home.clone(),
        xdg.join("config"),
        xdg.join("data"),
        xdg.join("cache"),
        xdg.join("runtime"),
        dir.join("state"),
    ] {
        std::fs::create_dir_all(&sub).unwrap_or_else(|e| panic!("{}: {e}", sub.display()));
        std::fs::set_permissions(&sub, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    cmd.env("HOME", &home)
        .env("XDG_CONFIG_HOME", xdg.join("config"))
        .env("XDG_DATA_HOME", xdg.join("data"))
        .env("XDG_CACHE_HOME", xdg.join("cache"))
        .env("XDG_STATE_HOME", dir.join("state"))
        .env("XDG_RUNTIME_DIR", xdg.join("runtime"))
        .env("GEODE_KEY_FILE", home.join("identity.gkey"))
        .env_remove("GEODE_TOKEN");
}

/// Resolve `name` on PATH and canonicalize it, as the plan does.
fn canonical_on_path(name: &str) -> String {
    let path = std::env::var_os("PATH").expect("PATH");
    let found = std::env::split_paths(&path)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .unwrap_or_else(|| panic!("{name} not on PATH"));
    std::fs::canonicalize(found)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned()
}

fn on_path(name: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(name).is_file()))
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn code(o: &Output) -> Option<i32> {
    o.status.code()
}

fn assert_no_dummy(o: &Output, what: &str) {
    assert!(
        !out(o).contains(DUMMY),
        "{what}: dummy on stdout: {}",
        out(o)
    );
    assert!(
        !err(o).contains(DUMMY),
        "{what}: dummy on stderr: {}",
        err(o)
    );
}

#[test]
fn echo_base64_xxd_redact_and_row_is_local() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let secret = ["--secret", "KEY=cfg/dummy.env"];
    let pre = [allow[0], allow[1], secret[0], secret[1]];

    let echo = fx.run(&pre, &["sh", "-c", "echo $KEY"]);
    assert_eq!(code(&echo), Some(0), "{}", err(&echo));
    assert_eq!(out(&echo), "[REDACTED:KEY]\n");
    assert!(
        err(&echo).contains("geode: injected: KEY (values withheld)"),
        "{}",
        err(&echo)
    );
    assert!(
        err(&echo).contains("geode: warning: redacted output: KEY\u{d7}1"),
        "{}",
        err(&echo)
    );
    assert_no_dummy(&echo, "echo");

    let b64 = fx.run(&pre, &["sh", "-c", "printf %s \"$KEY\" | base64"]);
    assert_eq!(code(&b64), Some(0), "{}", err(&b64));
    assert_eq!(out(&b64).trim_end(), "[REDACTED:KEY]");
    assert_no_dummy(&b64, "base64");

    if on_path("xxd") {
        let xxd = fx.run(&pre, &["sh", "-c", "printf %s \"$KEY\" | xxd -p"]);
        assert_eq!(code(&xxd), Some(0), "{}", err(&xxd));
        assert_eq!(out(&xxd).trim_end(), "[REDACTED:KEY]");
        assert_no_dummy(&xxd, "xxd");
    } else {
        eprintln!("xxd not on PATH; skipping the xxd -p case");
    }

    let rows = fx.rows();
    assert!(!rows.is_empty());
    assert_eq!(rows.len() % 2, 0, "each run is a started + spawned pair");
    for pair in rows.chunks(2) {
        assert_eq!(pair[0].0, "started");
        assert_eq!(pair[0].3, None, "intent row has no exit code");
        assert_eq!(pair[1].0, "spawned");
        assert_eq!(pair[1].3, Some(0));
        for (_, custody, argv0, _, _) in pair {
            assert_eq!(*custody, 0, "local rows are custody: false");
            assert_eq!(argv0, &fx.sh);
        }
    }
    let db = std::fs::read(fx.db()).unwrap();
    assert!(
        !String::from_utf8_lossy(&db).contains(DUMMY),
        "dummy in audit db"
    );
}

#[test]
fn child_env_is_built_from_scratch() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    // `set` is a shell builtin; it lists exported and shell variables.
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "env"],
    );
    assert_eq!(code(&o), Some(0), "{}", err(&o));
    let env = out(&o);
    let keys: Vec<&str> = env.lines().filter_map(|l| l.split('=').next()).collect();
    for k in &keys {
        assert!(
            ["PATH", "HOME", "LANG", "TERM", "KEY", "PWD", "SHLVL", "_", "OLDPWD"].contains(k),
            "unexpected child env key {k}: {env}"
        );
    }
    assert!(keys.contains(&"KEY"));
    assert!(!env.contains("GEODE_TOKEN"));
    assert!(!env.contains("G6_PARENT_MARK"));
    assert!(!env.contains("XDG_STATE_HOME"));
}

#[test]
fn child_exit_3_is_spawned_and_passed_through() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "exit 3"],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));

    let mut args = vec![
        "--key", "k.gkey", "--output", "json", "run", "--vault", "v.geode",
    ];
    args.extend_from_slice(&[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"]);
    #[cfg(feature = "test-trusted-root")]
    args.push("--test-unconfined-hosts");
    args.push("--");
    args.extend_from_slice(&["sh", "-c", "echo $KEY >&2; exit 3"]);
    let j = fx.geode(&args);
    assert_eq!(code(&j), Some(3), "{}", err(&j));
    let doc: serde_json::Value = serde_json::from_slice(&j.stdout).expect("one json doc");
    assert_eq!(doc["spawned"], true);
    assert_eq!(doc["exit_code"], 3);
    assert_eq!(doc["timed_out"], false);
    assert_eq!(doc["stderr_redacted"], "[REDACTED:KEY]\n");
    assert_eq!(doc["redaction_hits"]["KEY"], 1);
    assert_no_dummy(&j, "json");
}

#[test]
fn timeout_terms_the_child() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let o = fx.run(
        &[
            allow[0],
            allow[1],
            "--secret",
            "KEY=cfg/dummy.env",
            "--timeout",
            "1",
        ],
        &["sh", "-c", "sleep 30"],
    );
    assert_eq!(code(&o), Some(128 + 15), "{}", err(&o));
    assert!(err(&o).contains("timed out"), "{}", err(&o));
    assert_eq!(fx.rows().last().unwrap().0, "timed_out");
}

#[test]
fn empty_allow_hosts_on_a_secret_binding_refuses() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    // Not `fx.run`: that helper sets the test-only seam.
    let o = fx.geode(&[
        "--key",
        "k.gkey",
        "run",
        "--vault",
        "v.geode",
        allow[0],
        allow[1],
        "--secret",
        "KEY=cfg/dummy.env",
        "--",
        "sh",
        "-c",
        &touch,
    ]);
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    let text = format!("{}{}", out(&o), err(&o));
    assert!(text.contains("allow_hosts"), "{text}");
    assert!(text.contains("refusing"), "{text}");
    assert!(!text.contains("injected:"), "{text}");
    assert!(!fx.marker().exists(), "empty allow_hosts spawned");
    assert_no_dummy(&o, "empty allow_hosts");
}

/// Linux can confine only with `CAP_SYS_ADMIN` (bit 21 of `CapEff`).
#[cfg(target_os = "linux")]
fn cap_sys_admin() -> bool {
    let text = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let Some(raw) = text.lines().find_map(|line| line.strip_prefix("CapEff:")) else {
        return false;
    };
    let hex = raw.trim().trim_start_matches("0x");
    let tail = hex.get(hex.len().saturating_sub(16)..).unwrap_or(hex);
    let bits = u64::from_str_radix(tail, 16).unwrap_or(0);
    bits & (1 << 21) != 0
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn last_hosts(fx: &Fx) -> String {
    let conn = rusqlite::Connection::open(fx.db()).unwrap();
    conn.query_row(
        "SELECT hosts FROM audit ORDER BY seq DESC LIMIT 1",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

/// macOS must confine. Linux confines when it holds `CAP_SYS_ADMIN` and
/// otherwise refuses. Neither path is an unconfined child.
#[test]
fn local_allow_hosts_outcome_is_per_os() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    let o = fx.geode(&[
        "--key",
        "k.gkey",
        "run",
        "--vault",
        "v.geode",
        allow[0],
        allow[1],
        "--secret",
        "KEY=cfg/dummy.env",
        "--allow-host",
        "api.example.com",
        "--",
        "sh",
        "-c",
        &touch,
    ]);
    let text = format!("{}{}", out(&o), err(&o));
    #[cfg(target_os = "macos")]
    {
        assert_eq!(code(&o), Some(0), "{text}");
        assert!(fx.marker().exists(), "confined child did not run");
        assert_eq!(last_hosts(&fx), "api.example.com");
        assert_no_dummy(&o, "confined");
    }
    #[cfg(target_os = "linux")]
    {
        if cap_sys_admin() {
            assert_eq!(code(&o), Some(0), "{text}");
            assert!(fx.marker().exists(), "confined child did not run");
            assert_eq!(last_hosts(&fx), "api.example.com");
            assert_no_dummy(&o, "confined");
        } else {
            assert_eq!(code(&o), Some(3), "{text}");
            assert!(text.contains("allow_hosts"), "{text}");
            assert!(!fx.marker().exists(), "ran without isolation");
            assert_no_dummy(&o, "refused");
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        assert_eq!(code(&o), Some(3), "{text}");
        assert!(text.contains("allow_hosts"), "{text}");
        assert!(!fx.marker().exists(), "ran without isolation");
        assert_no_dummy(&o, "refused");
    }
}

#[test]
fn refusals_do_not_spawn() {
    let fx = Fx::new();
    let touch = fx.touch_script();
    let allow = fx.allow_sh();
    let key = ["--secret", "KEY=cfg/dummy.env"];

    // Empty allow_cmds: exit 3.
    let o = fx.run(&key, &["sh", "-c", &touch]);
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("allow_cmds is empty"), "{}", err(&o));

    // argv[0] not listed: exit 3.
    let geode_exe = std::fs::canonicalize(env!("CARGO_BIN_EXE_geode")).unwrap();
    let other = geode_exe.to_str().unwrap();
    let o = fx.run(
        &["--allow-cmd", other, key[0], key[1]],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("is not in allow_cmds"), "{}", err(&o));

    // Short binding: refused, exit 3, never injected.
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "PIN=cfg/pin"],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(
        err(&o).contains("binding PIN: too short to redact safely"),
        "{}",
        err(&o)
    );
    assert!(!err(&o).contains("1234"));
    assert!(!err(&o).contains("injected:"));

    // Missing object: usage.
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/nope"],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));

    // Bad and reserved names: usage.
    for b in [
        "key=cfg/dummy.env",
        "PATH=cfg/dummy.env",
        "GEODE_X=cfg/dummy.env",
        "LD_PRELOAD=cfg/dummy.env",
        "nobinding",
    ] {
        let o = fx.run(&[allow[0], allow[1], "--secret", b], &["sh", "-c", &touch]);
        assert_eq!(code(&o), Some(1), "{b}: {}", err(&o));
    }
    // No binding at all: usage.
    let o = fx.run(&[allow[0], allow[1]], &["sh", "-c", &touch]);
    assert_eq!(code(&o), Some(1), "{}", err(&o));

    // --file is not local in this build: usage.
    let o = fx.run(
        &[allow[0], allow[1], "--file", "KEY=cfg/dummy.env"],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));

    assert!(!fx.marker().exists(), "a refused run spawned a child");
}

#[test]
fn policy_deny_is_exit_3_and_does_not_spawn() {
    let fx = Fx::new();
    // Seal a policy where human:local may inject only under other/.
    let show = fx.ok(&[
        "--key", "k.gkey", "--output", "json", "policy", "show", "v.geode",
    ]);
    let doc: serde_json::Value = serde_json::from_slice(&show.stdout).unwrap();
    let vid = doc["policy"]["vault_id"].as_str().unwrap();
    let policy = format!(
        r#"{{"version":1,"vault_id":"{vid}","default":"deny","principals":[{{"id":"human:local","ops":["list","read","write","mount","verify","admin"],"prefixes":[""]}},{{"id":"human:local","ops":["inject"],"prefixes":["other/"]}}]}}"#
    );
    std::fs::write(fx.dir.join("policy.json"), policy).unwrap();
    fx.ok(&[
        "--key",
        "k.gkey",
        "policy",
        "set",
        "v.geode",
        "--file",
        "policy.json",
    ]);

    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("policy denies inject"), "{}", err(&o));
    assert!(!fx.marker().exists());
    let rows = fx.rows();
    let (outcome, custody, argv0, exit_code, _) = rows.last().unwrap();
    assert_eq!(outcome, "policy_deny");
    assert_eq!((*custody, argv0.as_str(), *exit_code), (0, "", None));
}

#[test]
fn needle_in_argv_is_argv_rejected_without_hashing_argv() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    let script = format!("{touch}; echo {DUMMY}");
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", &script],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("argv rejected"), "{}", err(&o));
    assert_no_dummy(&o, "argv_rejected");
    assert!(!fx.marker().exists());

    let rows = fx.rows();
    let (outcome, custody, argv0, _, argv_hash) = rows.last().unwrap();
    assert_eq!(outcome, "argv_rejected");
    assert_eq!(*custody, 0);
    let rejected = geode_grotto::audit::hash_rejected_argv(&fx.sh);
    assert_eq!(
        argv_hash.as_slice(),
        rejected.as_slice(),
        "row hashes only the exe"
    );
    let clean = geode_grotto::audit::hash_clean_argv(&fx.sh, &["-c", &script]);
    assert_ne!(argv_hash.as_slice(), clean.as_slice());
    assert_eq!(argv0, &fx.sh);
    let db = std::fs::read(fx.db()).unwrap();
    assert!(!String::from_utf8_lossy(&db).contains(DUMMY));
}

#[test]
fn token_and_dashdash_rules() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let key = ["--secret", "KEY=cfg/dummy.env"];
    let touch = fx.touch_script();

    // Any token on local run: exit 4.
    let o = fx
        .cmd(&[
            "--key", "k.gkey", "run", "--vault", "v.geode", allow[0], allow[1], key[0], key[1],
            "--", "sh", "-c", &touch,
        ])
        .env("GEODE_TOKEN", "deadbeef")
        .output()
        .unwrap();
    assert_eq!(code(&o), Some(4), "{}", err(&o));
    std::fs::write(fx.dir.join("t"), "deadbeef").unwrap();
    let o = fx.run(
        &[allow[0], allow[1], key[0], key[1], "--token-file", "t"],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(4), "{}", err(&o));

    // Raw --token: exit 1, value not echoed.
    let o = fx.run(
        &[
            allow[0],
            allow[1],
            key[0],
            key[1],
            "--token",
            "deadbeefcafe",
        ],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(!err(&o).contains("deadbeefcafe"));

    // Missing `--`: exit 1, named.
    let o = fx.geode(&[
        "--key", "k.gkey", "run", "--vault", "v.geode", allow[0], allow[1], key[0], key[1], "sh",
        "-c", &touch,
    ]);
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("no command after --"), "{}", err(&o));

    // `--` with nothing after it: exit 1, named.
    let o = fx.geode(&[
        "--key", "k.gkey", "run", "--vault", "v.geode", allow[0], allow[1], key[0], key[1], "--",
    ]);
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(
        err(&o).contains("geode: error: no command after --"),
        "{}",
        err(&o)
    );

    assert!(!fx.marker().exists());
}

#[test]
fn allow_cmd_must_be_canonical() {
    let fx = Fx::new();
    let link = fx.dir.join("sh-link");
    std::os::unix::fs::symlink(&fx.sh, &link).unwrap();
    let link = link.to_str().unwrap();
    let o = fx.run(
        &["--allow-cmd", link, "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "true"],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("is not canonical"), "{}", err(&o));
    // Where /bin/sh is a symlink (Ubuntu), it is refused, not resolved.
    if std::fs::canonicalize("/bin/sh").unwrap() != Path::new("/bin/sh") {
        let o = fx.run(
            &["--allow-cmd", "/bin/sh", "--secret", "KEY=cfg/dummy.env"],
            &["sh", "-c", "true"],
        );
        assert_eq!(code(&o), Some(1), "{}", err(&o));
        assert!(err(&o).contains("is not canonical"), "{}", err(&o));
    }
}

#[test]
fn audit_verify_good_then_tampered() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    for script in ["true", "exit 3", "true"] {
        let _ = fx.run(
            &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
            &["sh", "-c", script],
        );
    }
    assert_eq!(fx.rows().len(), 6, "started + close row per run");
    let db = fx.db();
    let db = db.to_str().unwrap();

    let good = fx.geode(&["audit", "verify", "--db", db]);
    assert_eq!(code(&good), Some(0), "{}", err(&good));
    // Default path is the caller's local DB.
    let default = fx.geode(&["audit", "verify"]);
    assert_eq!(code(&default), Some(0), "{}", err(&default));

    // Tamper with seq 4 (the exit-3 close row): an attacker can drop the trigger; verify cannot be fooled.
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "DROP TRIGGER audit_no_update; UPDATE audit SET exit_code = 0 WHERE seq = 4;",
    )
    .unwrap();
    drop(conn);
    let bad = fx.geode(&["audit", "verify", "--db", db]);
    assert_eq!(code(&bad), Some(2), "{}", err(&bad));
    assert!(err(&bad).contains("seq 4"), "{}", err(&bad));

    let missing = fx.geode(&["audit", "verify", "--db", "nope.db"]);
    assert_eq!(code(&missing), Some(1), "{}", err(&missing));
}

// Fix 3: a failed audit append stops the run (fail closed). Faults are
// injected with a SQLite trigger in the test's own audit DB, so the binary
// carries no test hook. `audit::open` only runs `CREATE ... IF NOT EXISTS`,
// so the trigger survives the open and fires on the insert.

impl Fx {
    /// Make every audit insert matching `when` (SQL on `NEW`) fail.
    fn fail_audit_when(&self, when: &str) {
        let _ = self.run(&["--allow-cmd", self.sh.as_str()], &["sh", "-c", "true"]);
        let conn = rusqlite::Connection::open(self.db()).expect("open db");
        conn.execute_batch(&format!(
            "CREATE TRIGGER fix3_fault BEFORE INSERT ON audit WHEN {when} \
             BEGIN SELECT RAISE(ABORT, 'fix3 injected fault'); END;"
        ))
        .unwrap();
    }
}

#[test]
fn fix3_audit_failure_before_spawn_releases_nothing() {
    let fx = Fx::new();
    fx.fail_audit_when("1");
    let before = fx.rows().len();
    let allow = fx.allow_sh();
    // The child would write its env (with the value) to the marker.
    let script = format!("env > '{}'", fx.marker().display());
    for json in [false, true] {
        let mut args = vec!["--key", "k.gkey"];
        if json {
            args.extend_from_slice(&["--output", "json"]);
        }
        args.extend_from_slice(&["run", "--vault", "v.geode", allow[0], allow[1]]);
        args.extend_from_slice(&["--secret", "KEY=cfg/dummy.env", "--", "sh", "-c", &script]);
        let o = fx.geode(&args);
        assert_eq!(code(&o), Some(1), "{}", err(&o));
        let text = format!("{}{}", out(&o), err(&o));
        assert!(text.contains("audit append failed"), "{text}");
        assert!(text.contains("refusing to run"), "{text}");
        if json {
            assert!(text.contains("audit_failed"), "{text}");
        }
        assert_no_dummy(&o, "audit_failed");
        assert!(!fx.marker().exists(), "child spawned without an audit row");
    }
    assert_eq!(fx.rows().len(), before, "no row was written");
}

#[test]
fn fix3_success_writes_one_intent_row_without_the_value() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "echo $KEY"],
    );
    assert_eq!(code(&o), Some(0), "{}", err(&o));
    let rows = fx.rows();
    let started = rows.iter().filter(|r| r.0 == "started").count();
    assert_eq!(started, 1, "exactly one pre-release row: {rows:?}");
    assert_eq!(rows.len(), 2, "started + spawned: {rows:?}");
    assert_eq!(rows[0].0, "started");
    assert_eq!(rows[1].0, "spawned");
    let db = std::fs::read(fx.db()).unwrap();
    assert!(
        !String::from_utf8_lossy(&db).contains(DUMMY),
        "value in audit db"
    );
    let v = fx.geode(&["audit", "verify"]);
    assert_eq!(code(&v), Some(0), "{}", err(&v));
}

#[test]
fn fix3_close_row_failure_is_non_zero_but_output_still_redacted() {
    let fx = Fx::new();
    fx.fail_audit_when("NEW.outcome <> 'started'");
    let allow = fx.allow_sh();
    let o = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "echo $KEY"],
    );
    assert_eq!(code(&o), Some(1), "child exited 0 but the close row failed");
    assert!(err(&o).contains("audit append failed"), "{}", err(&o));
    assert_eq!(out(&o), "[REDACTED:KEY]\n");
    assert_no_dummy(&o, "close row");
    assert_eq!(fx.rows().last().unwrap().0, "started", "intent row stays");
}

#[test]
fn fix3_deny_path_writes_row_or_fails_closed() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    let script = format!("{touch}; echo {DUMMY}");
    let pre = [allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"];

    // Writable chain: the refusal leaves an argv_rejected row.
    let o = fx.run(&pre, &["sh", "-c", &script]);
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert_eq!(fx.rows().last().unwrap().0, "argv_rejected");

    // Broken chain: the refusal becomes audit_failed and still spawns nothing.
    fx.fail_audit_when("1");
    let o = fx.run(&pre, &["sh", "-c", &script]);
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("audit append failed"), "{}", err(&o));
    assert_no_dummy(&o, "deny + audit_failed");
    assert!(!fx.marker().exists());
}

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(std::fs::read(path).expect("read pin target"))
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Copy `src` to `dir/bin/name` as a 0755 file. The pin path is this absolute
/// path. A `#!` file cannot be pinned on Linux.
fn copy_exec(dir: &Path, name: &str, src: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let bin = dir.join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    let dest = bin.join(name);
    std::fs::copy(src, &dest).unwrap();
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    let head = std::fs::read(&dest).unwrap();
    assert!(
        head.len() >= 2 && !head.starts_with(b"#!"),
        "pin fixture must be a binary: {}",
        dest.display()
    );
    dest
}

fn write_pins(dir: &Path, rules: &serde_json::Value) {
    std::fs::write(dir.join("pins.json"), serde_json::to_vec(rules).unwrap()).unwrap();
}

#[test]
fn run_help_documents_pinning() {
    let o = Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["run", "--help"])
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", err(&o));
    let text = out(&o);
    assert!(text.contains("sha256"), "{text}");
    assert!(text.contains("args_prefix"), "{text}");
    assert!(text.contains("allow-cmds-file"), "{text}");
    assert!(text.contains("require-pin"), "{text}");
    assert!(text.contains("require_pin"), "{text}");
    assert!(text.contains("owned by root"), "{text}");
}

/// Cargo fixture. Not a copy of a platform shell.
///
/// Stable Cargo exports `CARGO_BIN_EXE_<bin>` with the hyphen kept.
/// Older Cargo rewrote hyphens to underscores. Accept either.
/// The bin's `required-features` is `test-trusted-root`, so these tests
/// are absent unless that feature is enabled.
#[cfg(feature = "test-trusted-root")]
fn pin_helper() -> PathBuf {
    let raw = option_env!("CARGO_BIN_EXE_geode-pin-helper")
        .or(option_env!("CARGO_BIN_EXE_geode_pin_helper"))
        .expect("CARGO_BIN_EXE for geode-pin-helper");
    std::fs::canonicalize(raw).unwrap()
}

/// Root-owned copy of `geode-pin-helper` for the ignored sudo test only.
/// Default tests do not call this. A missing anchor fails the test.
#[cfg(feature = "test-trusted-root")]
struct InstalledPin {
    dir: PathBuf,
    bin: PathBuf,
}

#[cfg(feature = "test-trusted-root")]
impl InstalledPin {
    fn place() -> Self {
        let src = pin_helper();
        let mut errors = Vec::new();
        for anchor in [Path::new("/usr/local"), Path::new("/opt")] {
            if !component_is_trusted(anchor) {
                errors.push(format!("{} is not a trusted anchor", anchor.display()));
                continue;
            }
            let dir = anchor.join(format!("geode-pin-fixture-{}", std::process::id()));
            let bin = dir.join("geode-pin-helper");
            match install_pin(&src, &dir, &bin) {
                Ok(()) => return Self { dir, bin },
                Err(e) => {
                    remove_pin(&dir, &bin);
                    errors.push(e);
                }
            }
        }
        panic!(
            "could not install geode-pin-helper on a trusted path (need passwordless sudo):\n{}",
            errors.join("\n")
        );
    }
}

#[cfg(feature = "test-trusted-root")]
impl Drop for InstalledPin {
    fn drop(&mut self) {
        remove_pin(&self.dir, &self.bin);
    }
}

#[cfg(feature = "test-trusted-root")]
fn component_is_trusted(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0
}

#[cfg(feature = "test-trusted-root")]
fn tree_is_trusted(bin: &Path) -> Result<(), String> {
    let canon = std::fs::canonicalize(bin).map_err(|e| e.to_string())?;
    let mut cur = PathBuf::new();
    for c in canon.components() {
        match c {
            std::path::Component::RootDir => cur.push("/"),
            std::path::Component::Normal(seg) => cur.push(seg),
            _ => return Err(format!("{} is not absolute", canon.display())),
        }
        if !component_is_trusted(&cur) {
            return Err(format!("{} is not trusted", cur.display()));
        }
    }
    Ok(())
}

#[cfg(feature = "test-trusted-root")]
fn euid_is_root() -> bool {
    let out = Command::new("id")
        .arg("-u")
        .stdin(std::process::Stdio::null())
        .output()
        .expect("spawn id -u");
    assert!(
        out.status.success(),
        "id -u failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let uid = String::from_utf8(out.stdout).expect("uid");
    match uid.trim() {
        "0" => true,
        other if other.chars().all(|c| c.is_ascii_digit()) && !other.is_empty() => false,
        other => panic!("bad uid {other}"),
    }
}

#[cfg(feature = "test-trusted-root")]
fn run_as_root(args: &[&str]) -> Result<(), String> {
    let (program, rest) = args.split_first().expect("argv");
    let mut cmd = if euid_is_root() {
        Command::new(program)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(program);
        c
    };
    let out = cmd
        .args(rest)
        .stdin(std::process::Stdio::null())
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    Err(format!(
        "{} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&out.stderr).trim()
    ))
}

#[cfg(feature = "test-trusted-root")]
fn install_pin(src: &Path, dir: &Path, bin: &Path) -> Result<(), String> {
    let src_s = src.to_str().expect("utf8 pin helper");
    let dir_s = dir.to_str().expect("utf8 fixture dir");
    let bin_s = bin.to_str().expect("utf8 fixture bin");
    run_as_root(&["install", "-d", "-m", "755", dir_s])?;
    run_as_root(&["install", "-m", "755", src_s, bin_s])?;
    // A copy keeps an ad-hoc signature. Re-sign on macOS so AMFI accepts
    // the installed image. This is not a platform signature, so launch
    // constraints do not apply. The pin hashes the bytes after this.
    if cfg!(target_os = "macos") {
        run_as_root(&["codesign", "--force", "--sign", "-", bin_s])?;
    }
    tree_is_trusted(bin)
}

#[cfg(feature = "test-trusted-root")]
fn pin_paths_ok(dir: &Path, bin: &Path) -> bool {
    let Some(name) = dir.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    if !name.starts_with("geode-pin-fixture-") {
        return false;
    }
    let Some(parent) = dir.parent() else {
        return false;
    };
    if parent != Path::new("/usr/local") && parent != Path::new("/opt") {
        return false;
    }
    bin.parent() == Some(dir) && bin.file_name().is_some_and(|n| n == "geode-pin-helper")
}

#[cfg(feature = "test-trusted-root")]
fn remove_pin(dir: &Path, bin: &Path) {
    if !pin_paths_ok(dir, bin) {
        return;
    }
    let bin_s = bin.to_str().unwrap();
    let dir_s = dir.to_str().unwrap();
    let _ = run_as_root(&["rm", "-f", bin_s]);
    let _ = run_as_root(&["rmdir", dir_s]);
}

/// Canonical `/tmp`. macOS resolves the symlink to `/private/tmp`.
/// Fails if `/tmp` cannot be resolved, is some other directory, or
/// cannot be written.
#[cfg(feature = "test-trusted-root")]
fn canonical_sticky_tmp() -> PathBuf {
    let canon =
        std::fs::canonicalize("/tmp").unwrap_or_else(|e| panic!("cannot canonicalize /tmp: {e}"));
    assert!(
        canon == Path::new("/tmp") || canon == Path::new("/private/tmp"),
        "/tmp canonicalized to {}, not /tmp or /private/tmp",
        canon.display()
    );
    let probe = canon.join(format!(".geode-tmp-probe-{}", std::process::id()));
    std::fs::write(&probe, b"x").unwrap_or_else(|e| panic!("cannot write /tmp: {e}"));
    std::fs::remove_file(&probe).unwrap_or_else(|e| panic!("cannot remove /tmp probe: {e}"));
    canon
}

#[cfg(feature = "test-trusted-root")]
fn assert_pinned_ok(fx: &Fx, output: &Output, tool: &str, what: &str) {
    assert_eq!(code(output), Some(0), "{}", err(output));
    assert_eq!(out(output), "ok");
    assert_no_dummy(output, what);
    let (outcome, _, argv0, exit_code, _) = fx.rows().last().unwrap().clone();
    assert_eq!(outcome, "spawned");
    assert_eq!(argv0, tool);
    assert_eq!(exit_code, Some(0));
}

/// Copy the Cargo helper into a 0755 directory owned by this uid.
#[cfg(feature = "test-trusted-root")]
fn stage_helper(dir: &Path) -> (PathBuf, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let root = dir.join("pin-root");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dest = root.join("geode-pin-helper");
    std::fs::copy(pin_helper(), &dest).expect("copy pin helper");
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755)).unwrap();
    if cfg!(target_os = "macos") {
        let status = Command::new("codesign")
            .args(["--force", "--sign", "-"])
            .arg(&dest)
            .status()
            .expect("codesign");
        assert!(status.success(), "ad-hoc sign of the staged helper failed");
    }
    (
        std::fs::canonicalize(&root).unwrap(),
        std::fs::canonicalize(&dest).unwrap(),
    )
}

#[cfg(feature = "test-trusted-root")]
fn current_uid() -> String {
    let out = Command::new("id").arg("-u").output().expect("spawn id -u");
    assert!(
        out.status.success(),
        "id -u failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let uid = String::from_utf8(out.stdout)
        .expect("uid")
        .trim()
        .to_owned();
    assert!(
        !uid.is_empty() && uid.chars().all(|c| c.is_ascii_digit()),
        "bad uid {uid}"
    );
    uid
}

#[cfg(feature = "test-trusted-root")]
#[test]
fn pinned_matching_command_runs() {
    let fx = Fx::new();
    // geode-pin-helper, not a relocated /bin/sh. Apple's launch constraints
    // SIGKILL a copied platform binary (CODESIGNING, com.apple.sh,
    // platform identifier 26). The Cargo target path is not root-owned, so
    // the same bytes are staged under a directory this test names as the
    // trust root, with this process's uid. No sudo.
    let (root, tool) = stage_helper(&fx.dir);
    let uid = current_uid();
    let root_s = root.to_str().unwrap().to_owned();
    let tool_s = tool.to_str().unwrap().to_owned();
    let sum = sha256_hex(&tool);
    let spec = serde_json::json!({
        "path": tool_s,
        "sha256": sum.to_uppercase(),
        "args_prefix": ["-c", "printf ok"],
    })
    .to_string();
    let inline = fx.run(
        &[
            "--test-trusted-root",
            &root_s,
            "--test-trusted-uid",
            &uid,
            "--allow-cmd",
            &spec,
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", "printf ok"],
    );
    assert_pinned_ok(&fx, &inline, &tool_s, "pinned inline");

    write_pins(
        &fx.dir,
        &serde_json::json!([{
            "path": tool_s,
            "sha256": sum,
            "args_prefix": ["-c", "printf ok"],
        }]),
    );
    let from_file = fx.run(
        &[
            "--test-trusted-root",
            &root_s,
            "--test-trusted-uid",
            &uid,
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", "printf ok"],
    );
    assert_pinned_ok(&fx, &from_file, &tool_s, "pinned file");
}

/// Real root-owned install. Not part of `cargo test` or nextest.
/// `pin-macos` runs it with `--ignored` and this name. Missing `sudo -n`
/// fails the test.
#[cfg(feature = "test-trusted-root")]
#[test]
#[ignore = "passwordless sudo; pin-macos runs it with --ignored"]
fn pinned_sudo_trusted_path_runs() {
    let sudo = Command::new("sudo").args(["-n", "true"]).status();
    assert!(
        sudo.as_ref().ok().is_some_and(|s| s.success()),
        "sudo -n is unavailable: {sudo:?}"
    );
    let fx = Fx::new();
    let installed = InstalledPin::place();
    let tool = std::fs::canonicalize(&installed.bin).unwrap();
    let tool_s = tool.to_str().unwrap().to_owned();
    let sum = sha256_hex(&tool);
    let spec = serde_json::json!({
        "path": tool_s,
        "sha256": sum,
        "args_prefix": ["-c", "printf ok"],
    })
    .to_string();
    let o = fx.run(
        &["--allow-cmd", &spec, "--secret", "KEY=cfg/dummy.env"],
        &[&tool_s, "-c", "printf ok"],
    );
    assert_pinned_ok(&fx, &o, &tool_s, "sudo pin");
}

#[cfg(feature = "test-trusted-root")]
#[test]
fn pinned_cargo_target_is_refused() {
    let fx = Fx::new();
    let tool = pin_helper();
    let tool_s = tool.to_str().unwrap().to_owned();
    let spec = serde_json::json!({
        "path": tool_s,
        "sha256": sha256_hex(&tool),
        "args_prefix": ["-c", "printf ok"],
    })
    .to_string();
    let o = fx.run(
        &["--allow-cmd", &spec, "--secret", "KEY=cfg/dummy.env"],
        &[&tool_s, "-c", "printf ok"],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("trusted path"), "{}", err(&o));
    assert!(out(&o).is_empty(), "{}", out(&o));
    assert_eq!(fx.rows().last().unwrap().0, "policy_deny");
}

#[cfg(feature = "test-trusted-root")]
fn assert_real_pin_refused(tool: &Path) {
    let fx = Fx::new();
    let tool_s = tool.to_str().expect("utf8").to_owned();
    let spec = serde_json::json!({
        "path": tool_s,
        "sha256": sha256_hex(tool),
        "args_prefix": ["-c", "printf ok"],
    })
    .to_string();
    let o = fx.run(
        &["--allow-cmd", &spec, "--secret", "KEY=cfg/dummy.env"],
        &[&tool_s, "-c", "printf ok"],
    );
    assert_ne!(code(&o), Some(0), "untrusted pin ran: {}", err(&o));
    assert_ne!(out(&o), "ok");
    assert!(
        err(&o).contains("trusted path")
            || err(&o).contains("symlink")
            || err(&o).contains("canonical"),
        "{}",
        err(&o)
    );
    assert!(!fx.marker().exists(), "untrusted pin spawned");
}

#[cfg(feature = "test-trusted-root")]
#[test]
fn pinned_user_tmp_writable_and_symlink_are_refused() {
    use std::os::unix::fs::PermissionsExt;
    // `$TMPDIR` on a macOS runner is `/var/folders/.../T`, not `/tmp`.
    let canon_tmp = canonical_sticky_tmp();
    let base = canon_tmp.join(format!("geode-pin-neg-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();

    let user = base.join("user");
    std::fs::create_dir(&user).unwrap();
    std::fs::set_permissions(&user, std::fs::Permissions::from_mode(0o755)).unwrap();
    let user_bin = user.join("geode-pin-helper");
    std::fs::copy(pin_helper(), &user_bin).unwrap();
    std::fs::set_permissions(&user_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_real_pin_refused(&std::fs::canonicalize(&user_bin).unwrap());

    let in_tmp = canon_tmp.join(format!("geode-pin-tmp-{}", std::process::id()));
    std::fs::copy(pin_helper(), &in_tmp).unwrap();
    std::fs::set_permissions(&in_tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_real_pin_refused(&std::fs::canonicalize(&in_tmp).unwrap());
    std::fs::remove_file(&in_tmp).unwrap();

    for mode in [0o775_u32, 0o777] {
        let anc = base.join(format!("m{mode:o}"));
        std::fs::create_dir(&anc).unwrap();
        std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(mode)).unwrap();
        let bin = anc.join("geode-pin-helper");
        std::fs::copy(pin_helper(), &bin).unwrap();
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_real_pin_refused(&std::fs::canonicalize(&bin).unwrap());
    }

    let real = base.join("real");
    std::fs::create_dir(&real).unwrap();
    let real_bin = real.join("geode-pin-helper");
    std::fs::copy(pin_helper(), &real_bin).unwrap();
    std::fs::set_permissions(&real_bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    let link = base.join("via");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_real_pin_refused(&link.join("geode-pin-helper"));
    let _ = std::fs::remove_dir_all(&base);
}

#[test]
fn pinned_wrong_digest_refused() {
    let fx = Fx::new();
    // The real shell, not a copy: the path is trusted, so the refusal is
    // the digest and the child never starts.
    let tool_s = fx.sh.clone();
    let touch = fx.touch_script();
    write_pins(
        &fx.dir,
        &serde_json::json!([{
            "path": tool_s,
            "sha256": "00".repeat(32),
            "args_prefix": ["-c", touch],
        }]),
    );
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("sha256"), "{}", err(&o));
    assert_no_dummy(&o, "wrong digest");
    assert!(out(&o).is_empty(), "{}", out(&o));
    assert!(!fx.marker().exists(), "wrong digest spawned");
    assert_eq!(fx.rows().last().unwrap().0, "policy_deny");
}

#[test]
fn unpinned_path_refused() {
    let fx = Fx::new();
    let tool = copy_exec(&fx.dir, "tool", Path::new(&fx.sh));
    let tool_s = tool.to_str().unwrap().to_owned();
    write_pins(
        &fx.dir,
        &serde_json::json!([{
            "path": tool_s,
            "sha256": sha256_hex(&tool),
        }]),
    );
    let touch = fx.touch_script();
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("is not pinned"), "{}", err(&o));
    assert_no_dummy(&o, "unpinned path");
    assert!(out(&o).is_empty(), "{}", out(&o));
    assert!(!fx.marker().exists(), "unpinned path spawned");
    assert_eq!(fx.rows().last().unwrap().0, "policy_deny");
}

#[test]
fn args_prefix_mismatch_refused() {
    let fx = Fx::new();
    let tool = copy_exec(&fx.dir, "tool", Path::new(&fx.sh));
    let tool_s = tool.to_str().unwrap().to_owned();
    let touch = fx.touch_script();
    write_pins(
        &fx.dir,
        &serde_json::json!([{
            "path": tool_s,
            "sha256": sha256_hex(&tool),
            "args_prefix": ["-c", "true"],
        }]),
    );
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", &touch],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("args_prefix"), "{}", err(&o));
    assert!(!err(&o).contains("spawned.marker"), "{}", err(&o));
    assert_no_dummy(&o, "args_prefix");
    assert!(out(&o).is_empty(), "{}", out(&o));
    assert!(!fx.marker().exists(), "args_prefix mismatch spawned");
}

#[test]
fn relative_pin_refused() {
    let fx = Fx::new();
    let tool = copy_exec(&fx.dir, "tool", Path::new(&fx.sh));
    let tool_s = tool.to_str().unwrap().to_owned();
    let sum = sha256_hex(&tool);
    write_pins(
        &fx.dir,
        &serde_json::json!([{"path": "bin/tool", "sha256": sum}]),
    );
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", "true"],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("not an absolute path"), "{}", err(&o));
    assert_no_dummy(&o, "relative pin");

    let inline = serde_json::json!({"path": "bin/tool", "sha256": sum}).to_string();
    let o = fx.run(
        &["--allow-cmd", &inline, "--secret", "KEY=cfg/dummy.env"],
        &[&tool_s, "-c", "true"],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("not an absolute path"), "{}", err(&o));

    write_pins(&fx.dir, &serde_json::json!([{"path": tool_s}]));
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s, "-c", "true"],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("sha256 is required"), "{}", err(&o));
    assert_no_dummy(&o, "missing sha256");

    write_pins(
        &fx.dir,
        &serde_json::json!([{"path": tool_s, "sha256": sum}]),
    );
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &["./bin/tool", "-c", "true"],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("not an absolute path"), "{}", err(&o));
    assert!(!fx.marker().exists());
}

#[test]
fn symlink_swap_refused() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fx::new();
    let tool = copy_exec(&fx.dir, "tool", Path::new(&fx.sh));
    let tool_s = tool.to_str().unwrap().to_owned();
    let sum = sha256_hex(&tool);
    let marker = fx.marker();

    let link = fx.dir.join("bin/via-link");
    let evil = fx.dir.join("bin/evil.sh");
    std::fs::write(&evil, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
    std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::symlink(&evil, &link).unwrap();

    // A symlink that resolves to a different file is not the pinned binary.
    write_pins(
        &fx.dir,
        &serde_json::json!([{"path": tool_s, "sha256": sum}]),
    );
    let via = link.to_str().unwrap();
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[via],
    );
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    assert!(err(&o).contains("symlink"), "{}", err(&o));
    assert!(err(&o).contains("not pinned"), "{}", err(&o));
    assert!(!err(&o).contains("touch"), "{}", err(&o));
    assert_no_dummy(&o, "symlink argv");
    assert!(!marker.exists(), "symlink argv spawned");

    // The pinned path itself is replaced with a symlink before the run.
    std::fs::remove_file(&tool).unwrap();
    std::os::unix::fs::symlink(&evil, &tool).unwrap();
    let o = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &[&tool_s],
    );
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(err(&o).contains("not canonical"), "{}", err(&o));
    assert!(!err(&o).contains("touch"), "{}", err(&o));
    assert_no_dummy(&o, "symlink swap");
    assert!(!marker.exists(), "symlink swap spawned");
}

#[test]
fn require_pin_refuses_unpinned_rules_and_off_allows_them() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();

    let denied = fx.run(
        &[
            "--require-pin",
            allow[0],
            allow[1],
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&denied), Some(1), "{}", err(&denied));
    assert!(err(&denied).contains("require-pin"), "{}", err(&denied));
    assert!(err(&denied).contains("sha256"), "{}", err(&denied));
    assert!(err(&denied).contains(&fx.sh), "{}", err(&denied));
    assert_no_dummy(&denied, "require-pin flag");
    assert!(!fx.marker().exists(), "require-pin spawned");
    assert!(!fx.db().exists(), "require-pin reached the audit db");

    // The file setting turns the same check on without the flag.
    std::fs::write(
        fx.dir.join("pins.json"),
        br#"{"require_pin":true,"cmds":[]}"#,
    )
    .unwrap();
    let from_file = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            allow[0],
            allow[1],
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&from_file), Some(1), "{}", err(&from_file));
    assert!(
        err(&from_file).contains("require-pin"),
        "{}",
        err(&from_file)
    );
    assert!(!fx.marker().exists(), "require_pin in the file spawned");

    // Off: a bare path still runs.
    let allowed = fx.run(
        &[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env"],
        &["sh", "-c", "true"],
    );
    assert_eq!(code(&allowed), Some(0), "{}", err(&allowed));

    std::fs::write(
        fx.dir.join("pins.json"),
        br#"{"require_pin":false,"cmds":[]}"#,
    )
    .unwrap();
    let file_off = fx.run(
        &[
            "--allow-cmds-file",
            "pins.json",
            allow[0],
            allow[1],
            "--secret",
            "KEY=cfg/dummy.env",
        ],
        &["sh", "-c", "true"],
    );
    assert_eq!(code(&file_off), Some(0), "{}", err(&file_off));
}

#[test]
fn missing_or_unreadable_allow_cmds_file_does_not_spawn() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fx::new();
    let touch = fx.touch_script();
    let secret = ["--secret", "KEY=cfg/dummy.env"];

    let missing = fx.run(
        &[
            "--allow-cmds-file",
            "no-such-pins.json",
            secret[0],
            secret[1],
        ],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&missing), Some(1), "{}", err(&missing));
    let missing_err = err(&missing);
    assert!(missing_err.contains("allow-cmds-file"), "{missing_err}");
    assert!(missing_err.contains("no-such-pins.json"), "{missing_err}");
    assert_no_dummy(&missing, "missing allow-cmds-file");
    assert!(!fx.marker().exists(), "missing allow-cmds-file spawned");
    assert!(!fx.db().exists(), "missing file opened the audit db");

    // A directory cannot be read as the file. Fails closed for every uid.
    std::fs::create_dir(fx.dir.join("pins-dir")).unwrap();
    let dir = fx.run(
        &["--allow-cmds-file", "pins-dir", secret[0], secret[1]],
        &["sh", "-c", &touch],
    );
    assert_eq!(code(&dir), Some(1), "{}", err(&dir));
    assert!(err(&dir).contains("allow-cmds-file"), "{}", err(&dir));
    assert_no_dummy(&dir, "directory allow-cmds-file");
    assert!(!fx.marker().exists(), "unreadable allow-cmds-file spawned");

    let mode000 = fx.dir.join("pins-000.json");
    std::fs::write(&mode000, b"[]").unwrap();
    std::fs::set_permissions(&mode000, std::fs::Permissions::from_mode(0o000)).unwrap();
    let unreadable = fx.run(
        &["--allow-cmds-file", "pins-000.json", secret[0], secret[1]],
        &["sh", "-c", &touch],
    );
    std::fs::set_permissions(&mode000, std::fs::Permissions::from_mode(0o644)).unwrap();
    if std::fs::read(&mode000).is_ok() && unreadable.status.success() {
        // Root ignores mode 000. The directory case above already failed closed.
        return;
    }
    assert_eq!(code(&unreadable), Some(1), "{}", err(&unreadable));
    assert!(
        err(&unreadable).contains("allow-cmds-file"),
        "{}",
        err(&unreadable)
    );
    assert_no_dummy(&unreadable, "mode 000 allow-cmds-file");
    assert!(!fx.marker().exists(), "mode 000 allow-cmds-file spawned");
}

/// `--home` does not loosen the host gate: a secret run with no
/// `--allow-host` is refused before spawn on every OS, Linux included.
#[test]
fn home_with_secret_and_no_allow_host_refuses_on_every_os() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let touch = fx.touch_script();
    let home = fx.dir.join("child-home");
    std::fs::create_dir_all(&home).unwrap();
    let home = home.to_str().unwrap().to_owned();
    // Not `fx.run`: that helper sets the test-only seam.
    let o = fx.geode(&[
        "--key",
        "k.gkey",
        "run",
        "--vault",
        "v.geode",
        allow[0],
        allow[1],
        "--home",
        &home,
        "--secret",
        "KEY=cfg/dummy.env",
        "--",
        "sh",
        "-c",
        &touch,
    ]);
    assert_eq!(code(&o), Some(3), "{}", err(&o));
    let text = format!("{}{}", out(&o), err(&o));
    assert!(text.contains("allow_hosts"), "{text}");
    assert!(!text.contains("injected:"), "{text}");
    assert!(!fx.marker().exists(), "secret run with no hosts spawned");
    assert_no_dummy(&o, "home + empty hosts");
    assert_eq!(fx.rows().last().unwrap().0, "policy_deny");
}

/// The pre-#106 spelling is gone; only `--allow-host` parses.
#[test]
fn allow_hosts_plural_is_a_usage_error() {
    let fx = Fx::new();
    let allow = fx.allow_sh();
    let o = fx.geode(&[
        "--key",
        "k.gkey",
        "run",
        "--vault",
        "v.geode",
        allow[0],
        allow[1],
        "--allow-hosts",
        "api.example.com",
        "--secret",
        "KEY=cfg/dummy.env",
        "--",
        "sh",
        "-c",
        "true",
    ]);
    assert_eq!(code(&o), Some(1), "{}", err(&o));
    assert!(!fx.marker().exists());
    assert_no_dummy(&o, "--allow-hosts");
}
