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
        fx.ok(&["keygen", "k.gkey"]);
        fx.ok(&["--key", "k.gkey", "vault", "init", "v.geode"]);
        std::fs::create_dir_all(fx.dir.join("src/cfg")).unwrap();
        std::fs::write(fx.dir.join("src/cfg/dummy.env"), DUMMY).unwrap();
        std::fs::write(fx.dir.join("src/cfg/pin"), "1234").unwrap();
        fx.ok(&["--key", "k.gkey", "seal", "src", "v.geode"]);
        fx
    }

    fn cmd(&self, args: &[&str]) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_geode"));
        c.args(args)
            .current_dir(&self.dir)
            .env_remove("GEODE_TOKEN")
            .env_remove("GEODE_KEY_FILE")
            .env_remove("GEODE_PASSPHRASE")
            .env_remove("GEODE_FACET_EVENTS")
            .env("XDG_STATE_HOME", self.dir.join("state"))
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
    fn run(&self, pre: &[&str], cmd: &[&str]) -> Output {
        let mut args = vec!["--key", "k.gkey", "run", "--vault", "v.geode"];
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
    for (outcome, custody, argv0, exit_code, _) in &rows {
        assert_eq!(outcome, "spawned");
        assert_eq!(*custody, 0, "local rows are custody: false");
        assert_eq!(argv0, &fx.sh);
        assert_eq!(*exit_code, Some(0));
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
    args.extend_from_slice(&[allow[0], allow[1], "--secret", "KEY=cfg/dummy.env", "--"]);
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
    assert_eq!(fx.rows().len(), 3);
    let db = fx.db();
    let db = db.to_str().unwrap();

    let good = fx.geode(&["audit", "verify", "--db", db]);
    assert_eq!(code(&good), Some(0), "{}", err(&good));
    // Default path is the caller's local DB.
    let default = fx.geode(&["audit", "verify"]);
    assert_eq!(code(&default), Some(0), "{}", err(&default));

    // Tamper with seq 2: an attacker can drop the trigger; verify cannot be fooled.
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.execute_batch(
        "DROP TRIGGER audit_no_update; UPDATE audit SET exit_code = 0 WHERE seq = 2;",
    )
    .unwrap();
    drop(conn);
    let bad = fx.geode(&["audit", "verify", "--db", db]);
    assert_eq!(code(&bad), Some(2), "{}", err(&bad));
    assert!(err(&bad).contains("seq 2"), "{}", err(&bad));

    let missing = fx.geode(&["audit", "verify", "--db", "nope.db"]);
    assert_eq!(code(&missing), Some(1), "{}", err(&missing));
}
