//! Mount CLI fixtures against the shipped `geode` binary (08-mount).
//!
//! G0 (v0.2.9): on Darwin, a missing FUSE-T or macFUSE driver exits 1 and
//! the error names both. `--token` stays unexpected. The UID-bypass warning
//! is still the first stderr line. Linux unmount still calls `fusermount3`
//! with `-u` (source check; this host does not run that helper).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `mount_without_read_only_is_read_write` — `geode mount VAULT MP`
//!    with `--key` and without `--read-only` is accepted read-write.
//!    Without feature `fuse` (the default) live FUSE still exits 1
//!    (Darwin: unsupported). The UID-bypass warning is the first stderr
//!    line. These fixtures never open `/dev/fuse`.
//! 2. `mount_read_only_stays_read_only` — `--read-only` is accepted
//!    read-only, still exit 1, warning still printed.
//! 3. `mount_requires_key` — missing `--key` exits 1 after the warning.
//!    `GEODE_TOKEN` does not substitute.
//! 4. `mount_token_cannot_mount` — `--token` is unexpected, with or
//!    without `--key`.
//! 5. `unmount_is_documented_exit_1` — `geode unmount MOUNTPOINT` exits 1
//!    until the FUSE session lands; no UID-bypass warning.
//!
//! The MCP toolset invariant (no `geode_mount` in tools/list) is covered
//! by `agent_plane.rs::serve_stdio_mcp`, which asserts the exact
//! three-tool list.
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
        .env_remove("GEODE_PASSPHRASE")
        .env_remove("GEODE_MOUNT_DAEMON_CHILD")
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
        .env_remove("GEODE_PASSPHRASE")
        .env("HOME", dir)
        .env("XDG_CONFIG_HOME", dir.join("xdg"))
        .output()
        .expect("spawn geode")
}

const WARNING: &str = "a mount is a policy bypass for any process of that UID";

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn combined(out: &Output) -> String {
    let mut s = stdout(out);
    s.push_str(&stderr(out));
    s
}

fn assert_warning(out: &Output, what: &str) {
    let err = stderr(out);
    assert!(err.contains(WARNING), "{what} warning on stderr: {err}");
    let first = err.lines().next().unwrap_or("");
    assert!(
        first.contains(WARNING),
        "{what} warning is the first stderr line: {err}"
    );
    assert!(
        !stdout(out).contains(WARNING),
        "{what} warning never on stdout: {}",
        stdout(out)
    );
}

#[allow(dead_code)]
fn assert_live_exit_1(out: &Output, what: &str) {
    let err = stderr(out);
    assert_eq!(out.status.code(), Some(1), "{what}: {err}");
    #[cfg(target_os = "macos")]
    assert!(
        err.contains("FUSE-T") && err.contains("macFUSE"),
        "{what} names FUSE-T or macFUSE: {err}"
    );
    #[cfg(not(target_os = "macos"))]
    assert!(
        err.contains("not in this build"),
        "{what} live FUSE is not in this build: {err}"
    );
}

fn isk_hex(dir: &Path, gkey: &str) -> String {
    let raw = std::fs::read(dir.join(gkey)).expect("read gkey");
    raw[6..38].iter().fold(String::new(), |mut acc, b| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{b:02x}");
        acc
    })
}

fn assert_no_isk(out: &Output, dir: &Path, what: &str) {
    let text = combined(out);
    let hex = isk_hex(dir, "k.gkey");
    assert!(!text.contains(&hex), "{what} leaked ISK hex: {text}");
    assert!(!text.contains("ISK"), "{what} leaked ISK marker: {text}");
}

fn mountpoint(dir: &Path) -> std::path::PathBuf {
    let mp = dir.join("mp");
    std::fs::create_dir_all(&mp).expect("mountpoint");
    mp
}

fn setup_key(dir: &Path) {
    let out = geode(dir, &["keygen", "k.gkey"]);
    assert!(out.status.success(), "keygen: {}", combined(&out));
}

#[allow(dead_code)]
fn setup_vault(dir: &Path) {
    setup_key(dir);
    let out = geode(dir, &["--key", "k.gkey", "vault", "init", "v.geode"]);
    assert!(out.status.success(), "vault init: {}", combined(&out));
}

/// Valid-key mounts block when feature `fuse` is on and the target is
/// Linux. Default `cargo test` leaves `fuse` off, so this stays kernel-free.
#[cfg(not(feature = "fuse"))]
#[test]
fn mount_without_read_only_is_read_write() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);

    let bare = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "mount",
            "v.geode",
            mountpoint(dir).to_str().unwrap(),
        ],
    );
    assert_live_exit_1(&bare, "bare mount");
    assert_warning(&bare, "bare mount");
    let err = stderr(&bare);
    assert!(
        err.contains("accepted read-write"),
        "omitting --read-only is read-write: {err}"
    );
    assert!(
        !err.contains("accepted read-only"),
        "bare mount must not be read-only: {err}"
    );
    assert!(
        !err.contains("only --read-only mounts are supported"),
        "bare mount must not refuse for missing --read-only: {err}"
    );
    #[cfg(target_os = "macos")]
    {
        assert!(
            err.contains("FUSE-T") && err.contains("macFUSE"),
            "missing driver names FUSE-T or macFUSE: {err}"
        );
    }
    assert_no_isk(&bare, dir, "bare mount");
}

#[cfg(not(feature = "fuse"))]
#[test]
fn mount_read_only_stays_read_only() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);

    let ro = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "mount",
            "v.geode",
            mountpoint(dir).to_str().unwrap(),
            "--read-only",
        ],
    );
    assert_live_exit_1(&ro, "read-only mount");
    assert_warning(&ro, "read-only mount");
    let err = stderr(&ro);
    assert!(
        err.contains("accepted read-only"),
        "--read-only stays read-only: {err}"
    );
    assert!(
        !err.contains("accepted read-write"),
        "--read-only must not be read-write: {err}"
    );
    assert_no_isk(&ro, dir, "read-only mount");
}

#[cfg(not(feature = "fuse"))]
#[test]
fn mount_daemon_without_fuse_feature_exits_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_vault(dir);
    let out = geode(
        dir,
        &[
            "--key",
            "k.gkey",
            "mount",
            "v.geode",
            mountpoint(dir).to_str().unwrap(),
            "--daemon",
        ],
    );
    assert_live_exit_1(&out, "daemon mount");
    assert_warning(&out, "daemon mount");
    let err = stderr(&out);
    assert!(
        err.contains("accepted read-write"),
        "daemon without the fuse feature is still a refused RW mount: {err}"
    );
    assert_no_isk(&out, dir, "daemon mount");
}

#[test]
fn mount_requires_key() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    let no_key = geode(
        dir,
        &["mount", "v.geode", mountpoint(dir).to_str().unwrap()],
    );
    assert_eq!(
        no_key.status.code(),
        Some(1),
        "missing --key: {}",
        stderr(&no_key)
    );
    assert_warning(&no_key, "missing --key");
    let err = stderr(&no_key);
    assert!(err.contains("missing --key"), "mount requires --key: {err}");
    assert!(
        !err.contains("accepted read-write"),
        "missing --key is not an accepted mount: {err}"
    );

    // GEODE_TOKEN never substitutes for --key.
    let token_env = geode_with_token_env(
        dir,
        &["mount", "v.geode", mountpoint(dir).to_str().unwrap()],
    );
    assert_eq!(
        token_env.status.code(),
        Some(1),
        "GEODE_TOKEN: {}",
        stderr(&token_env)
    );
    assert_warning(&token_env, "GEODE_TOKEN");
    let err = stderr(&token_env);
    assert!(
        err.contains("missing --key"),
        "GEODE_TOKEN must not satisfy --key: {err}"
    );
    assert!(
        !err.contains("deadbeef"),
        "token bytes must not be echoed: {err}"
    );
    assert!(
        !err.contains("accepted read-write"),
        "GEODE_TOKEN must not mount: {err}"
    );
}

#[test]
fn mount_token_cannot_mount() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    setup_key(dir);

    for (args, what) in [
        (
            &[
                "mount",
                "v.geode",
                mountpoint(dir).to_str().unwrap(),
                "--token",
                "x",
            ][..],
            "mount --token",
        ),
        (
            &[
                "--key",
                "k.gkey",
                "mount",
                "v.geode",
                mountpoint(dir).to_str().unwrap(),
                "--token",
                "x",
            ][..],
            "mount --key --token",
        ),
    ] {
        let out = geode(dir, args);
        let text = combined(&out);
        assert_eq!(out.status.code(), Some(1), "{what}: {text}");
        assert!(
            text.to_ascii_lowercase().contains("unexpected"),
            "{what} must be unexpected --token, got: {text}"
        );
        assert!(
            !text.contains("accepted read-write") && !text.contains("accepted read-only"),
            "{what} must not accept a mount: {text}"
        );
        assert_no_isk(&out, dir, what);
    }
}

#[test]
fn unmount_is_documented_exit_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let out = geode(dir, &["unmount", "mp"]);
    assert_eq!(out.status.code(), Some(1), "unmount: {}", stderr(&out));
    assert!(
        !stderr(&out).contains(WARNING),
        "unmount does not print the mount warning"
    );
    #[cfg(target_os = "macos")]
    {
        let err = stderr(&out);
        assert!(
            !err.contains("fusermount3"),
            "Darwin unmount must not report fusermount3: {err}"
        );
    }
}

/// 08-mount 6: behavioural unmount oracle (G-P11).
#[cfg(all(target_os = "linux", feature = "fuse"))]
#[test]
fn linux_unmount_execs_fusermount3_dash_u() {
    use std::os::unix::fs::PermissionsExt;
    let stub = tempfile::tempdir().expect("stubdir");
    let bin = stub.path().join("fusermount3");
    let log = stub.path().join("argv.txt");
    std::fs::write(
        &bin,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" > {}\nexit 0\n",
            log.display()
        ),
    )
    .expect("write stub");
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).expect("chmod stub");
    let mnt = tempfile::tempdir().expect("mnt");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_geode"))
        .args(["unmount", mnt.path().to_str().expect("utf8")])
        .env(
            "PATH",
            format!(
                "{}:{}",
                stub.path().display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .output()
        .expect("spawn geode unmount");
    assert!(
        out.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let argv = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(argv.contains("-u"), "argv={argv}");
}

#[test]
fn mount_verbs_in_help() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let help = geode(dir, &["--help"]);
    assert!(help.status.success());
    let text = stdout(&help);
    assert!(text.contains("mount"), "help lists mount: {text}");
    assert!(text.contains("unmount"), "help lists unmount: {text}");
}
