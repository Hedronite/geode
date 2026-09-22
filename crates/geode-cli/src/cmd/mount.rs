//! `geode mount` / `geode unmount` — mount surface (08-mount). Thin CLI
//! adapter: the clap shape lives in `main.rs`; help prose chrome is
//! frontend's G2.
//!
//! G1 (v0.2.8): on Linux, feature `fuse` runs a foreground FUSE session.
//! Omitting `--read-only` is read-write. `--read-only` stays read-only.
//! `--daemon` forks (re-exec) and writes `$XDG_RUNTIME_DIR/geode/mount-<id>.pid`.
//! `geode unmount` calls `fusermount3 -u`. `--key` is required. `--token`
//! is not a flag on this verb and `GEODE_TOKEN` never substitutes for `--key`.
//!
//! - Every mount attempt prints the UID-bypass warning BEFORE giving up
//!   (08-mount 7: "A mount is a policy bypass for any process of that
//!   UID" — printed every time, including on Darwin).
//! - Darwin: the live session is unsupported and mount exits 1. Feature
//!   `fuse` is not the default, so `cargo test` never needs `/dev/fuse`.
//! - The agent toolset has no `geode_mount` (06-agent-plane 3); nothing
//!   here changes the MCP surface.

#[cfg(all(feature = "fuse", target_os = "linux"))]
use std::os::unix::process::CommandExt;
use std::path::Path;
#[cfg(all(feature = "fuse", target_os = "linux"))]
use std::path::PathBuf;
#[cfg(all(feature = "fuse", target_os = "linux"))]
use std::process::{Command, Stdio};

use geode_grotto::{Error, Result};

use crate::{GlobalArgs, OutMode};

#[cfg(all(feature = "fuse", target_os = "linux"))]
#[path = "../fuse_linux.rs"]
mod fuse_linux;

/// 08-mount 7, printed on EVERY mount attempt (before giving up).
const UID_BYPASS_WARNING: &str =
    "warning: a mount is a policy bypass for any process of that UID (08-mount 5)";

/// Set on the re-exec'd daemon child so it mounts instead of spawning again.
#[cfg(all(feature = "fuse", target_os = "linux"))]
const DAEMON_CHILD: &str = "GEODE_MOUNT_DAEMON_CHILD";

/// `geode mount VAULT MOUNTPOINT` (08-mount).
///
/// Omitting `--read-only` accepts a read-write mount. `--read-only` accepts
/// a read-only mount. On Linux with feature `fuse`, foreground is the
/// default and blocks until unmount. `--daemon` re-execs and writes a pid
/// file. Darwin stays unsupported (exit 1).
pub fn mount(
    vault: &Path,
    mountpoint: &Path,
    read_only: bool,
    daemon: bool,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let _ = out;
    // The warning is unconditional and first: even a refused attempt must
    // leave the operator in no doubt about what a mount would mean.
    eprintln!("{UID_BYPASS_WARNING}");
    let key = super::require_key(global)?;
    // A path is not a key. Parse and drop it so `--key` is a real identity
    // file; the bytes never enter the error text. The FUSE child loads it
    // again when the session starts.
    drop(super::load_isk(&key)?);

    #[cfg(all(feature = "fuse", target_os = "linux"))]
    {
        if daemon && std::env::var_os(DAEMON_CHILD).is_none() {
            return spawn_daemon(vault);
        }
        fuse_linux::mount_foreground(vault, mountpoint, read_only, &key)
    }
    #[cfg(not(all(feature = "fuse", target_os = "linux")))]
    {
        let _ = (vault, mountpoint, daemon, key);
        Err(Error::Format(format!(
            "{}; {}",
            unsupported_message(),
            accepted_mode(read_only)
        )))
    }
}

/// `geode unmount MOUNTPOINT` (08-mount 6: fusermount3 / umount).
pub fn unmount(mountpoint: &Path, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let _ = (global, out);
    #[cfg(all(feature = "fuse", target_os = "linux"))]
    {
        fuse_linux::unmount_mountpoint(mountpoint)
    }
    #[cfg(not(all(feature = "fuse", target_os = "linux")))]
    {
        let _ = mountpoint;
        Err(Error::Format(
            "unmount lands with the vfs FUSE session (not in this build)".into(),
        ))
    }
}

/// Re-exec this binary with the same argv. The parent writes the child's
/// pid and returns; the child (see [`DAEMON_CHILD`]) runs the session.
#[cfg(all(feature = "fuse", target_os = "linux"))]
fn spawn_daemon(vault: &Path) -> Result<()> {
    let exe = std::env::current_exe().map_err(Error::Io)?;
    let mut cmd = Command::new(exe);
    cmd.args(std::env::args_os().skip(1));
    cmd.env(DAEMON_CHILD, "1");
    cmd.stdin(Stdio::null());
    // New process group so the shell does not deliver the parent's signals.
    cmd.process_group(0);
    let child = cmd.spawn().map_err(Error::Io)?;
    write_pid_file(vault, child.id())?;
    Ok(())
}

/// `$XDG_RUNTIME_DIR/geode/mount-<id>.pid` (08-mount 6). `<id>` is the first
/// 16 hex chars of blake3(canonical vault path). When `XDG_RUNTIME_DIR` is
/// unset, the file lands in the temp dir so a daemon still has a pid.
#[cfg(all(feature = "fuse", target_os = "linux"))]
fn write_pid_file(vault: &Path, pid: u32) -> Result<()> {
    let path = pid_path(vault);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    std::fs::write(&path, format!("{pid}\n")).map_err(Error::Io)?;
    Ok(())
}

#[cfg(all(feature = "fuse", target_os = "linux"))]
fn pid_path(vault: &Path) -> PathBuf {
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|v| !v.is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from);
    base.join("geode")
        .join(format!("mount-{}.pid", mount_id(vault)))
}

#[cfg(all(feature = "fuse", target_os = "linux"))]
fn mount_id(vault: &Path) -> String {
    let name = vault.canonicalize().unwrap_or_else(|_| vault.to_path_buf());
    let hex = format!("{}", blake3::hash(name.to_string_lossy().as_bytes()));
    hex.chars().take(16).collect()
}

/// Mode clause after the platform refusal. Observable without a kernel:
/// omitting `--read-only` is read-write; the flag stays read-only.
#[cfg_attr(all(feature = "fuse", target_os = "linux"), allow(dead_code))]
fn accepted_mode(read_only: bool) -> &'static str {
    if read_only {
        "accepted read-only"
    } else {
        "accepted read-write"
    }
}

/// The platform-specific refusal line for a mount attempt. Kept as a
/// helper so the error text is testable without a kernel.
#[cfg_attr(all(feature = "fuse", target_os = "linux"), allow(dead_code))]
#[must_use]
pub fn unsupported_message() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "mount is unsupported on Darwin in this build (08-mount: macOS is SHOULD)"
    }
    #[cfg(not(target_os = "macos"))]
    {
        "mount lands with the vfs FUSE session (not in this build)"
    }
}
