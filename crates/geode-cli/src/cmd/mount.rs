//! `geode mount` / `geode unmount` — mount surface (08-mount). Thin CLI
//! adapter: the clap shape lives in `main.rs`; help prose chrome is
//! frontend's G2.
//!
//! G1 (v0.2.9): omitting `--read-only` is read-write. `--read-only` stays
//! read-only. `--key` is required. `--token` is not a flag on this verb
//! and `GEODE_TOKEN` never substitutes for `--key`.
//!
//! - Every mount attempt prints the UID-bypass warning BEFORE giving up
//!   (08-mount 5: "A mount is a policy bypass for any process of that
//!   UID" — printed every time, including on Darwin).
//! - Darwin (and any target in this build): the live FUSE session is
//!   unsupported and mount exits 1 AFTER the mode is accepted. Kernel-free
//!   tests assert that accepted mode; they do not require `/dev/fuse`.
//! - `geode unmount MOUNTPOINT` exists and exits 1 (usage) until the FUSE
//!   session lands. No warning — unmount removes the bypass, it does not
//!   create one.
//! - The agent toolset has no `geode_mount` (06-agent-plane 3); nothing
//!   here changes the MCP surface.

use std::path::Path;

use geode_grotto::{Error, Result};

use crate::{GlobalArgs, OutMode};

/// 08-mount 5, printed on EVERY mount attempt (before giving up).
const UID_BYPASS_WARNING: &str =
    "warning: a mount is a policy bypass for any process of that UID (08-mount 5)";

/// `geode mount VAULT MOUNTPOINT` (08-mount).
///
/// Omitting `--read-only` accepts a read-write mount. `--read-only` accepts
/// a read-only mount. Neither mode starts a kernel session in this build:
/// Darwin stays unsupported (exit 1), and there is no `/dev/fuse` adapter
/// yet. Foreground is the default (`--daemon` is parsed but not honored).
pub fn mount(
    vault: &Path,
    mountpoint: &Path,
    read_only: bool,
    daemon: bool,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let _ = (vault, mountpoint, daemon, out);
    // The warning is unconditional and first: even a refused attempt must
    // leave the operator in no doubt about what a mount would mean.
    eprintln!("{UID_BYPASS_WARNING}");
    let key = super::require_key(global)?;
    // A path is not a key. Parse and drop it so `--key` is a real identity
    // file; the bytes never enter the error text.
    drop(super::load_isk(&key)?);
    Err(Error::Format(format!(
        "{}; {}",
        unsupported_message(),
        accepted_mode(read_only)
    )))
}

/// `geode unmount MOUNTPOINT` (08-mount 3: fusermount3 / umount). No
/// mounts exist yet, so this is a documented exit 1 (usage).
pub fn unmount(mountpoint: &Path, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let _ = (mountpoint, global, out);
    Err(Error::Format(
        "unmount lands with the vfs FUSE session (not in this build)".into(),
    ))
}

/// Mode clause after the platform refusal. Observable without a kernel:
/// omitting `--read-only` is read-write; the flag stays read-only.
fn accepted_mode(read_only: bool) -> &'static str {
    if read_only {
        "accepted read-only"
    } else {
        "accepted read-write"
    }
}

/// The platform-specific refusal line for a mount attempt. Kept as a
/// helper so the error text is testable without a kernel.
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
