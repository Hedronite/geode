//! Per-child network namespace (Linux; SPEC-v034 G8).
//!
//! [`enter_new_netns`] moves the calling thread (only that thread) into a
//! fresh network namespace and brings its loopback up. A child forked from
//! that thread inherits the namespace: loopback only, no routes out. Needs
//! `CAP_SYS_ADMIN`; without it this returns `EPERM` and the caller refuses
//! the run.

use std::io;

/// Unshare the calling thread's network namespace and raise `lo`.
///
/// # Errors
///
/// The OS error from `unshare` or the loopback `ioctl`.
pub fn enter_new_netns() -> io::Result<()> {
    // SAFETY: unshare takes a flag and affects only the calling thread.
    if unsafe { libc::unshare(libc::CLONE_NEWNET) } != 0 {
        return Err(io::Error::last_os_error());
    }
    loopback_up()
}

fn loopback_up() -> io::Result<()> {
    // SAFETY: a plain datagram socket used only for interface ioctls; it is
    // closed on every path. `ifr` is a zeroed ifreq with a NUL-terminated
    // name, valid for both ioctls.
    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        let result = if libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut ifr) < 0 {
            Err(io::Error::last_os_error())
        } else {
            #[allow(clippy::cast_possible_truncation)]
            {
                ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            }
            if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &ifr) < 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        };
        libc::close(fd);
        result
    }
}
