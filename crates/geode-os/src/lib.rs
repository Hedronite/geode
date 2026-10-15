//! Refuse core dumps for this process.
//!
//! Sets `RLIMIT_CORE` to 0. Linux also sets `PR_SET_DUMPABLE` to 0.
//! macOS also calls `ptrace(PT_DENY_ATTACH)`. This crate does not spawn
//! a user child.

use std::io;

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
