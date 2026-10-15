//! Process-level OS calls for Geode.
//!
//! `deny_core_dumps` sets `RLIMIT_CORE` to 0. Linux also sets
//! `PR_SET_DUMPABLE` to 0. macOS also calls `ptrace(PT_DENY_ATTACH)`.
//!
//! `spawn` (SPEC-v034 G6) is the only place Geode starts a user child for
//! `geode run`. `spawn_as` and `ident` (G7) add the custody child identity,
//! peer credentials, and the user and group lookups. It takes an already-authorized plan: an absolute program, an
//! env built from scratch, and a timeout. It never reads a vault or a key.

use std::io;

pub mod ident;
mod spawn;
pub use ident::ChildIdentity;
pub use spawn::{spawn, spawn_as, ChildOutcome, SpawnSpec, Stream};

/// Append one line to the FIFO at `path` without blocking (SPEC-v034 G6
/// audit mirror). A FIFO with no reader is an error, not a wait. A path
/// that is not a FIFO is refused, so the mirror never lands in a regular
/// file or on process stdout.
///
/// # Errors
///
/// Returns the OS error, or `InvalidInput` when `path` is not a FIFO.
pub fn write_fifo_line(path: &std::path::Path, line: &[u8]) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)?;
    if !f.metadata()?.file_type().is_fifo() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a FIFO"));
    }
    let mut buf = line.to_vec();
    buf.push(b'\n');
    f.write_all(&buf)
}

/// Apply the core-dump refusal for the calling process.
///
/// # Errors
///
/// Returns the OS error if `setrlimit`, `prctl`, or `ptrace` fails.
pub fn deny_core_dumps() -> io::Result<()> {
    // SAFETY: setrlimit, prctl, and ptrace here take constant arguments and
    // affect only the calling process. No pointer is dereferenced and no
    // child is spawned.
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "linux")]
        {
            if libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
        #[cfg(target_os = "macos")]
        {
            if libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) != 0 {
                return Err(io::Error::last_os_error());
            }
        }
    }
    Ok(())
}
