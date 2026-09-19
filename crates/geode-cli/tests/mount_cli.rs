//! G1 (v0.2.5) — mount CLI fixtures against the shipped `geode` binary
//! (08-mount).
//!
//! Drives `target/debug/geode` (via `CARGO_BIN_EXE_geode`):
//!
//! 1. `mount_warns_then_refuses` — every mount attempt prints the
//!    UID-bypass warning BEFORE giving up: without `--read-only` (usage,
//!    exit 1) and with it (unsupported on this build, exit 1). The
//!    warning is on stderr in both cases.
//! 2. `unmount_is_documented_exit_1` — `geode unmount MOUNTPOINT` exists
//!    and exits 1 (usage) until the FUSE session lands; no UID-bypass
//!    warning (unmount removes the bypass).
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
        .output()
        .expect("spawn geode")
}

const WARNING: &str = "a mount is a policy bypass for any process of that UID";

#[test]
fn mount_warns_then_refuses() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();

    // Without --read-only: usage error, exit 1, warning printed first.
    let bare = geode(dir, &["mount", "v.geode", "mp"]);
    assert_eq!(
        bare.status.code(),
        Some(1),
        "bare mount: {}",
        String::from_utf8_lossy(&bare.stderr)
    );
    let stderr = String::from_utf8_lossy(&bare.stderr);
    assert!(stderr.contains(WARNING), "warning on stderr: {stderr}");
    assert!(
        !String::from_utf8_lossy(&bare.stdout).contains(WARNING),
        "warning never on stdout"
    );

    // With --read-only: still exit 1 (no FUSE session in this build;
    // Darwin is unsupported), but the warning is still printed.
    let ro = geode(dir, &["mount", "v.geode", "mp", "--read-only"]);
    assert_eq!(
        ro.status.code(),
        Some(1),
        "read-only mount: {}",
        String::from_utf8_lossy(&ro.stderr)
    );
    let stderr = String::from_utf8_lossy(&ro.stderr);
    assert!(stderr.contains(WARNING), "warning on stderr: {stderr}");
    #[cfg(target_os = "macos")]
    assert!(
        stderr.contains("unsupported on Darwin"),
        "Darwin names the unsupported platform: {stderr}"
    );
}

#[test]
fn unmount_is_documented_exit_1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let out = geode(dir, &["unmount", "mp"]);
    assert_eq!(
        out.status.code(),
        Some(1),
        "unmount: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !String::from_utf8_lossy(&out.stderr).contains(WARNING),
        "unmount does not print the mount warning"
    );
}

#[test]
fn mount_verbs_in_help() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let dir = tmp.path();
    let help = geode(dir, &["--help"]);
    assert!(help.status.success());
    let text = String::from_utf8_lossy(&help.stdout);
    assert!(text.contains("mount"), "help lists mount: {text}");
    assert!(text.contains("unmount"), "help lists unmount: {text}");
}
