//! Custody identity (SPEC-v034 G7; design §1).
//!
//! OS lookups (peer credentials, users, groups, the console user) and the
//! pure decisions built on them. Every decision takes ids as arguments so a
//! test can drive euid 0, the console user, the child uid, and group
//! membership without root or real accounts.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::AsRawFd;
use std::path::Path;

/// Daemon user on this OS.
#[cfg(target_os = "macos")]
pub const DAEMON_USER: &str = "_geode";
/// Daemon user on this OS.
#[cfg(not(target_os = "macos"))]
pub const DAEMON_USER: &str = "geode";
/// Linux child user for custody runs.
pub const RUN_USER: &str = "geode-run";
/// Group whose members may connect but may not unlock or lock.
pub const AGENTS_GROUP: &str = "geode-agents";

/// Credentials of the process on the other end of a Unix socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCred {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}

/// Effective uid of this process.
#[must_use]
pub fn euid() -> u32 {
    // SAFETY: geteuid takes no arguments and cannot fail.
    unsafe { libc::geteuid() }
}

/// Peer credentials of a connected Unix stream (`SO_PEERCRED` on Linux,
/// `getpeereid` plus `LOCAL_PEERPID` on macOS).
///
/// # Errors
///
/// Returns the OS error from the credential call.
pub fn peer_cred(sock: &impl AsRawFd) -> io::Result<PeerCred> {
    let fd = sock.as_raw_fd();
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::ucred>()).unwrap_or(0);
        // SAFETY: `cred` and `len` are valid for writes and sized for ucred.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                std::ptr::addr_of_mut!(cred).cast(),
                &mut len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(PeerCred {
            uid: cred.uid,
            gid: cred.gid,
            pid: Some(cred.pid),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let (mut uid, mut gid) = (0, 0);
        // SAFETY: `uid` and `gid` are valid for writes.
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        #[cfg(target_os = "macos")]
        let pid = {
            let mut pid: libc::pid_t = 0;
            let mut len =
                libc::socklen_t::try_from(std::mem::size_of::<libc::pid_t>()).unwrap_or(0);
            // SAFETY: `pid` and `len` are valid for writes and sized for pid_t.
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_LOCAL,
                    libc::LOCAL_PEERPID,
                    std::ptr::addr_of_mut!(pid).cast(),
                    &mut len,
                )
            };
            (rc == 0).then_some(pid)
        };
        #[cfg(not(target_os = "macos"))]
        let pid = None;
        Ok(PeerCred { uid, gid, pid })
    }
}

/// A user's uid and primary gid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserIds {
    pub uid: u32,
    pub gid: u32,
}

const LOOKUP_BUF: usize = 16 * 1024;

/// Look up a user by name. `Ok(None)` when it does not exist.
///
/// # Errors
///
/// Returns the OS error from `getpwnam_r`.
pub fn lookup_user(name: &str) -> io::Result<Option<UserIds>> {
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: zeroed passwd is a valid out-parameter for getpwnam_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; LOOKUP_BUF];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid; `buf` outlives the call and `pw`.
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pw,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok((!out.is_null()).then_some(UserIds {
        uid: pw.pw_uid,
        gid: pw.pw_gid,
    }))
}

/// Look up a group's gid by name. `Ok(None)` when it does not exist.
///
/// # Errors
///
/// Returns the OS error from `getgrnam_r`.
pub fn lookup_group(name: &str) -> io::Result<Option<u32>> {
    let cname = CString::new(name).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: zeroed group is a valid out-parameter for getgrnam_r.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; LOOKUP_BUF];
    let mut out: *mut libc::group = std::ptr::null_mut();
    // SAFETY: all pointers are valid; `buf` outlives the call and `gr`.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut gr,
            buf.as_mut_ptr(),
            buf.len(),
            &mut out,
        )
    };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    Ok((!out.is_null()).then_some(gr.gr_gid))
}

/// Every gid `uid` belongs to: its primary gid plus supplementary groups.
///
/// # Errors
///
/// Returns the OS error from the lookup. An unknown uid is an error.
pub fn user_gids(uid: u32) -> io::Result<Vec<u32>> {
    // SAFETY: zeroed passwd is a valid out-parameter for getpwuid_r.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; LOOKUP_BUF];
    let mut out: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: all pointers are valid; `buf` outlives the call and `pw`.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut out) };
    if rc != 0 {
        return Err(io::Error::from_raw_os_error(rc));
    }
    if out.is_null() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "unknown uid"));
    }
    // SAFETY: pw_name points into `buf`, NUL-terminated by getpwuid_r.
    let name = unsafe { CStr::from_ptr(pw.pw_name) }.to_owned();
    let primary = pw.pw_gid;
    let mut n: libc::c_int = 64;
    loop {
        let mut groups = vec![0; usize::try_from(n).unwrap_or(64)];
        let mut count = n;
        // SAFETY: `groups` holds `count` entries; `name` is NUL-terminated.
        #[cfg(target_os = "macos")]
        let rc = unsafe {
            libc::getgrouplist(
                name.as_ptr(),
                libc::c_int::try_from(primary).unwrap_or(-1),
                groups.as_mut_ptr(),
                &mut count,
            )
        };
        // SAFETY: as above.
        #[cfg(not(target_os = "macos"))]
        let rc =
            unsafe { libc::getgrouplist(name.as_ptr(), primary, groups.as_mut_ptr(), &mut count) };
        if rc >= 0 {
            groups.truncate(usize::try_from(count).unwrap_or(0));
            // macOS fills c_int gids; Linux fills gid_t (already u32).
            #[cfg(target_os = "macos")]
            let mut gids: Vec<u32> = groups
                .into_iter()
                .filter_map(|g| u32::try_from(g).ok())
                .collect();
            #[cfg(not(target_os = "macos"))]
            let mut gids: Vec<u32> = groups;
            if !gids.contains(&primary) {
                gids.push(primary);
            }
            return Ok(gids);
        }
        if n >= 65_536 {
            return Err(io::Error::other("group list too long"));
        }
        n = count.max(n * 2);
    }
}

/// The uid that owns `/dev/console`, when that is not root. On macOS this
/// is the logged-in GUI user.
#[must_use]
pub fn console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/dev/console")
        .ok()
        .map(|m| m.uid())
        .filter(|&u| u != 0)
}

/// Daemon start check: never euid 0, never the console user, and only the
/// dedicated daemon user (`daemon_uid` from [`lookup_user`] of
/// [`DAEMON_USER`]).
///
/// # Errors
///
/// A one-line reason. The caller exits 1.
pub fn check_daemon_identity(
    euid: u32,
    console_uid: Option<u32>,
    daemon_uid: Option<u32>,
) -> Result<(), String> {
    if euid == 0 {
        return Err("custody refuses to run as euid 0".into());
    }
    if console_uid == Some(euid) {
        return Err("custody refuses to run as the console user".into());
    }
    match daemon_uid {
        Some(d) if d == euid => Ok(()),
        Some(_) => Err(format!("custody runs only as user {DAEMON_USER}")),
        None => Err(format!("user {DAEMON_USER} does not exist")),
    }
}

/// Client check after the handshake: a custody peer must not share the
/// caller's uid.
///
/// # Errors
///
/// `custody peer shares caller uid`. The caller exits 1.
pub fn check_custody_peer(server_uid: u32, caller_uid: u32) -> Result<(), String> {
    if server_uid == caller_uid {
        Err("custody peer shares caller uid".into())
    } else {
        Ok(())
    }
}

/// `unlock` and `lock` are refused for a member of [`AGENTS_GROUP`].
#[must_use]
pub fn may_control(peer_gids: &[u32], agents_gid: Option<u32>) -> bool {
    agents_gid.is_none_or(|g| !peer_gids.contains(&g))
}

/// Who a custody child runs as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChildIdentity {
    /// Same process identity. Local `geode run` only, never custody.
    Inherit,
    /// Linux: switch to this uid/gid, drop groups, no new privileges.
    User { uid: u32, gid: u32 },
    /// macOS: stay the daemon user under a seatbelt that denies `deny`.
    Seatbelt { deny: Vec<std::path::PathBuf> },
}

/// Which OS rules apply. Passed in so both branches are testable anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Os {
    Linux,
    Macos,
}

impl Os {
    /// This build's OS.
    #[must_use]
    pub fn current() -> Self {
        if cfg!(target_os = "macos") {
            Self::Macos
        } else {
            Self::Linux
        }
    }
}

/// Pick the custody child identity. Linux: `geode-run`, never the daemon
/// and never the agent. macOS: the daemon user under a seatbelt, never the
/// agent. There is no `run_as_peer`.
///
/// # Errors
///
/// When the required identity cannot be taken. The caller does not spawn,
/// and never falls back to the caller's own identity.
pub fn child_identity(
    os: Os,
    daemon_uid: u32,
    peer_uid: u32,
    run_user: Option<UserIds>,
    seatbelt_deny: &[&Path],
) -> Result<ChildIdentity, String> {
    match os {
        Os::Linux => {
            let run = run_user.ok_or_else(|| format!("user {RUN_USER} does not exist"))?;
            if run.uid == 0 || run.uid == daemon_uid || run.uid == peer_uid {
                return Err(format!(
                    "user {RUN_USER} must differ from root, the daemon, and the agent"
                ));
            }
            Ok(ChildIdentity::User {
                uid: run.uid,
                gid: run.gid,
            })
        }
        Os::Macos => {
            if daemon_uid == peer_uid {
                return Err("custody child would share the agent uid".into());
            }
            if seatbelt_deny.is_empty() {
                return Err("seatbelt needs the key, audit DB, and socket paths".into());
            }
            Ok(ChildIdentity::Seatbelt {
                deny: seatbelt_deny.iter().map(|p| p.to_path_buf()).collect(),
            })
        }
    }
}

/// Seatbelt profile that allows everything except reading or writing the
/// denied paths (and an audit DB's `-wal`/`-shm` siblings) and connecting
/// to a denied socket.
///
/// # Errors
///
/// When a path cannot be quoted safely.
pub fn seatbelt_profile(deny: &[std::path::PathBuf]) -> Result<String, String> {
    let mut lits = String::new();
    for p in deny {
        let s = p.to_str().ok_or("seatbelt path is not UTF-8")?;
        if s.contains(['"', '\\', '\n']) || !p.is_absolute() {
            return Err(format!("seatbelt cannot quote {s}"));
        }
        for suffix in ["", "-wal", "-shm", "-journal"] {
            lits.push_str(&format!(" (literal \"{s}{suffix}\")"));
        }
    }
    let mut sock = String::new();
    for p in deny {
        let s = p.to_str().unwrap_or_default();
        sock.push_str(&format!(" (remote unix-socket (path-literal \"{s}\"))"));
    }
    Ok(format!(
        "(version 1)\n(allow default)\n(deny file-read* file-write*{lits})\n(deny network-outbound{sock})\n"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_identity_refusals() {
        assert!(check_daemon_identity(0, None, Some(0))
            .unwrap_err()
            .contains("euid 0"));
        assert!(check_daemon_identity(501, Some(501), Some(501))
            .unwrap_err()
            .contains("console user"));
        assert!(check_daemon_identity(502, Some(501), Some(600))
            .unwrap_err()
            .contains("runs only as"));
        assert!(check_daemon_identity(502, Some(501), None)
            .unwrap_err()
            .contains("does not exist"));
        assert!(check_daemon_identity(600, Some(501), Some(600)).is_ok());
        assert!(check_daemon_identity(600, None, Some(600)).is_ok());
    }

    #[test]
    fn same_uid_peer_is_refused() {
        assert_eq!(
            check_custody_peer(600, 600).unwrap_err(),
            "custody peer shares caller uid"
        );
        assert!(check_custody_peer(600, 1000).is_ok());
    }

    #[test]
    fn agents_cannot_control() {
        assert!(!may_control(&[20, 700], Some(700)));
        assert!(may_control(&[20], Some(700)));
        assert!(may_control(&[20], None));
    }

    #[test]
    fn linux_child_is_geode_run_never_agent_or_daemon() {
        let run = Some(UserIds { uid: 990, gid: 990 });
        assert_eq!(
            child_identity(Os::Linux, 980, 1000, run, &[]).unwrap(),
            ChildIdentity::User { uid: 990, gid: 990 }
        );
        assert!(child_identity(Os::Linux, 980, 1000, None, &[]).is_err());
        for bad in [0, 980, 1000] {
            let r = child_identity(
                Os::Linux,
                980,
                1000,
                Some(UserIds { uid: bad, gid: 1 }),
                &[],
            );
            assert!(r.is_err(), "uid {bad} accepted");
        }
    }

    #[test]
    fn macos_child_is_seatbelted_daemon_never_agent() {
        let key = Path::new("/var/geode/default.gkey");
        let r = child_identity(Os::Macos, 260, 501, None, &[key]).unwrap();
        assert_eq!(
            r,
            ChildIdentity::Seatbelt {
                deny: vec![key.to_path_buf()]
            }
        );
        assert!(child_identity(Os::Macos, 501, 501, None, &[key]).is_err());
        assert!(child_identity(Os::Macos, 260, 501, None, &[]).is_err());
    }

    #[test]
    fn seatbelt_profile_names_each_path() {
        let p = seatbelt_profile(&[
            "/a/k.gkey".into(),
            "/b/audit.db".into(),
            "/c/custody.sock".into(),
        ])
        .unwrap();
        for want in [
            "(literal \"/a/k.gkey\")",
            "(literal \"/b/audit.db-wal\")",
            "(path-literal \"/c/custody.sock\")",
        ] {
            assert!(p.contains(want), "{p}");
        }
        assert!(seatbelt_profile(&["rel".into()]).is_err());
        assert!(seatbelt_profile(&["/a\"b".into()]).is_err());
    }

    #[test]
    fn peer_cred_of_a_socketpair_is_us() {
        let (a, _b) = std::os::unix::net::UnixStream::pair().unwrap();
        let c = peer_cred(&a).unwrap();
        assert_eq!(c.uid, euid());
    }

    #[test]
    fn lookups_do_not_require_custody_accounts() {
        assert!(lookup_user("geode-no-such-user-0000").unwrap().is_none());
        assert!(lookup_group("geode-no-such-group-0000").unwrap().is_none());
        assert!(!user_gids(euid()).unwrap().is_empty());
    }
}
