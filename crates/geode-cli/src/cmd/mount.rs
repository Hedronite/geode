//! `geode mount` / `geode unmount` — mount surface (08-mount). Thin CLI
//! adapter: the clap shape lives in `main.rs` (`MountArgs`); help prose
//! chrome is frontend's G2.
//!
//! G1 (v0.2.5): the kernel mount is not in this pack — core `vfs` is the
//! kernel-free read path (chunk decrypt slice). What ships here is the
//! surface contract:
//!
//! - Every mount attempt prints the UID-bypass warning BEFORE giving up
//!   (08-mount 5: "A mount is a policy bypass for any process of that
//!   UID" — printed every time, including on Darwin).
//! - Darwin (and any non-Linux target): mount exits 1, unsupported.
//! - Linux: the FUSE session lands with the vfs mount work; until then
//!   mount exits 1 (usage), after the warning.
//! - `geode unmount MOUNTPOINT` exists and is documented; it exits 1
//!   (usage) until the mount lands. No warning — unmount removes the
//!   bypass, it does not create one.
//! - The agent toolset has no `geode_mount` (06-agent-plane 3); nothing
//!   here changes the MCP surface.

use std::path::Path;

use geode_grotto::{Error, Result};

use crate::{GlobalArgs, OutMode};

/// 08-mount 5, printed on EVERY mount attempt (before giving up).
const UID_BYPASS_WARNING: &str =
    "warning: a mount is a policy bypass for any process of that UID (08-mount 5)";

/// `geode mount VAULT MOUNTPOINT` (08-mount). `--read-only` is the only
/// mode this pack; foreground is the default (`--daemon` is parsed but
/// not honored until the FUSE session lands).
pub fn mount(
    vault: &Path,
    mountpoint: &Path,
    read_only: bool,
    daemon: bool,
    global: &GlobalArgs,
    out: OutMode,
) -> Result<()> {
    let _ = (vault, mountpoint, daemon, global, out);
    // The warning is unconditional and first: even a refused attempt must
    // leave the operator in no doubt about what a mount would mean.
    eprintln!("{UID_BYPASS_WARNING}");
    if !read_only {
        return Err(Error::Format(
            "only --read-only mounts are supported in this build (08-mount)".into(),
        ));
    }
    Err(Error::Format(unsupported_message().to_owned()))
}

/// `geode unmount MOUNTPOINT` (08-mount 3: fusermount3 / umount). No
/// mounts exist yet, so this is a documented exit 1 (usage).
pub fn unmount(mountpoint: &Path, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let _ = (mountpoint, global, out);
    Err(Error::Format(
        "unmount lands with the vfs FUSE session (not in this build)".into(),
    ))
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
