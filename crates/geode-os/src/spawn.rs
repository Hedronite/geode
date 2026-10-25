//! Spawn one `geode run` child (SPEC-v034 G6, harmonized spec §3 steps 6–10).
//!
//! The child gets exactly the env in [`SpawnSpec::env`] (the parent env is
//! cleared), stdin `/dev/null` unless asked, and its own process group so a
//! timeout reaches grandchildren. Output arrives in chunks through a
//! callback; redaction is the caller's job. On timeout: SIGTERM to the
//! group, 2 seconds, then SIGKILL.
//!
//! A pinned program ([`spawn_with_pin`]) runs from the fd that was
//! hashed. Linux execs that fd. macOS has no `fexecve`, so it execs the
//! path after checking, in the child just before exec, that the path and
//! the fd are still the hashed file.

use std::ffi::OsString;
use std::fs::Metadata;
use std::io::{self, Read};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use crate::ident::ChildIdentity;

/// Grace between SIGTERM and SIGKILL on timeout.
const KILL_GRACE: Duration = Duration::from_secs(2);
const POLL: Duration = Duration::from_millis(20);

/// Which child stream a chunk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stream {
    Stdout,
    Stderr,
}

/// An authorized child. `program` is the canonical absolute path that
/// matched `allow_cmds`. `env` is the whole child env.
pub struct SpawnSpec {
    pub program: PathBuf,
    pub args: Vec<OsString>,
    pub env: Vec<(OsString, OsString)>,
    pub cwd: Option<PathBuf>,
    pub inherit_stdin: bool,
    pub timeout: Duration,
}

/// The `O_CLOEXEC` fd of [`SpawnSpec::program`] whose bytes matched the
/// pin, and its `fstat` from before the hash.
#[derive(Debug)]
pub struct PinnedExe {
    pub fd: OwnedFd,
    pub meta: Metadata,
}

/// `Debug` names the program and env keys only, never env values or args.
impl std::fmt::Debug for SpawnSpec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<&OsString> = self.env.iter().map(|(k, _)| k).collect();
        f.debug_struct("SpawnSpec")
            .field("program", &self.program)
            .field("env_keys", &keys)
            .field("timeout", &self.timeout)
            .finish_non_exhaustive()
    }
}

/// How the child ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildOutcome {
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub timed_out: bool,
}

impl ChildOutcome {
    /// The process exit Geode should use: the child's code, or `128+N`.
    #[must_use]
    pub fn process_exit(&self) -> i32 {
        match (self.exit_code, self.signal) {
            (Some(code), _) => code,
            (None, Some(sig)) => 128 + sig,
            (None, None) => 1,
        }
    }
}

/// Spawn `spec` and feed each output chunk to `on_chunk` on the calling
/// thread. Returns after the child exits and both pipes are drained.
///
/// # Errors
///
/// Returns the OS error when the child cannot be started. Nothing ran.
pub fn spawn(spec: SpawnSpec, on_chunk: impl FnMut(Stream, &[u8])) -> io::Result<ChildOutcome> {
    spawn_as(spec, &ChildIdentity::Inherit, on_chunk)
}

/// [`spawn`] under a custody child identity (SPEC-v034 G7). `User` switches
/// uid/gid in the child before exec (Linux only); `Seatbelt` wraps the
/// program in `sandbox-exec` (macOS only). If the identity cannot be taken
/// the child never execs and this returns the error: there is no fallback
/// to the caller's identity.
///
/// # Errors
///
/// The OS error from start-up or the identity switch, or `Unsupported`
/// for an identity this OS cannot take.
pub fn spawn_as(
    spec: SpawnSpec,
    identity: &ChildIdentity,
    on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    spawn_with(spec, identity, &[], on_chunk)
}

/// Env names the child gets pointing at the egress proxy.
#[cfg(target_os = "linux")]
const PROXY_VARS: [&str; 6] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

/// [`spawn_as`] with `allow_hosts` (SPEC-v034 G8). Empty: unrestricted, no
/// namespace. Non-empty, Linux: the child runs in its own network namespace
/// with only loopback, where a userspace proxy admits listed hosts; the
/// proxy env vars point at it. Non-empty elsewhere: `Unsupported`, nothing
/// runs. If the namespace cannot be made, nothing runs.
///
/// # Errors
///
/// As [`spawn_as`], plus the namespace error.
pub fn spawn_with(
    spec: SpawnSpec,
    identity: &ChildIdentity,
    allow_hosts: &[String],
    on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    spawn_with_pin(spec, None, identity, allow_hosts, on_chunk)
}

/// [`spawn_with`] for a rule that pins `sha256` (Fix 4). `pin` is the fd of
/// `spec.program` whose bytes matched. Linux execs that fd; macOS execs
/// `spec.program` after the child re-checks it against `pin`. `None` is
/// exactly [`spawn_with`].
///
/// # Errors
///
/// As [`spawn_with`]. A pin that no longer matches, or on macOS a program
/// writable by group or other, is an error and nothing runs.
pub fn spawn_with_pin(
    spec: SpawnSpec,
    pin: Option<PinnedExe>,
    identity: &ChildIdentity,
    allow_hosts: &[String],
    on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    let cmd = prepared(&spec, identity)?;
    let pin = pin.map(|p| (p, spec.program.clone()));
    #[cfg(test)]
    tests::before_exec();
    if allow_hosts.is_empty() {
        let child = launch(cmd, pin)?;
        return supervise(child, spec.timeout, on_chunk);
    }
    isolated(cmd, pin, allow_hosts, spec.timeout, on_chunk)
}

/// Spawn `cmd`. With a pin, the last pre-exec hook checks the pin and, on
/// Linux, execs its fd. `cmd` is dropped before return, which closes the
/// parent's copy of the fd.
fn launch(mut cmd: Command, pin: Option<(PinnedExe, PathBuf)>) -> io::Result<Child> {
    if let Some((pin, program)) = pin {
        arm_pin(&mut cmd, pin, &program)?;
    }
    cmd.spawn()
}

/// What the pin recorded: identity, size, and mtime of the hashed file.
#[derive(Clone, Copy, PartialEq, Eq)]
struct FileStamp {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
}

impl FileStamp {
    fn of(m: &Metadata) -> Self {
        use std::os::unix::fs::MetadataExt;
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_nsec: m.mtime_nsec(),
        }
    }

    // The `stat` field types differ between Linux and macOS.
    #[allow(clippy::unnecessary_cast)]
    fn of_stat(st: &libc::stat) -> Self {
        Self {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            size: st.st_size as u64,
            mtime: st.st_mtime as i64,
            mtime_nsec: st.st_mtime_nsec as i64,
        }
    }

    /// `fstat(fd)` still matches. Async-signal-safe: no allocation.
    fn matches_fd(self, fd: i32) -> bool {
        // SAFETY: fstat writes only into `st`, a local of the right type.
        unsafe {
            let mut st: libc::stat = std::mem::zeroed();
            libc::fstat(fd, &mut st) == 0 && Self::of_stat(&st) == self
        }
    }
}

/// A NULL-terminated `char *[]`, built before fork for `fexecve`.
#[cfg(target_os = "linux")]
struct CArray {
    _owned: Vec<std::ffi::CString>,
    ptrs: Vec<*const libc::c_char>,
}

// SAFETY: `ptrs` point into the heap buffers of `_owned`, which are never
// moved or written after construction. The array is only read.
#[cfg(target_os = "linux")]
unsafe impl Send for CArray {}
#[cfg(target_os = "linux")]
unsafe impl Sync for CArray {}

#[cfg(target_os = "linux")]
impl CArray {
    fn new(items: impl Iterator<Item = Vec<u8>>) -> io::Result<Self> {
        let owned = items
            .map(std::ffi::CString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in argv or env"))?;
        let mut ptrs: Vec<*const libc::c_char> = owned.iter().map(|s| s.as_ptr()).collect();
        ptrs.push(std::ptr::null());
        Ok(Self {
            _owned: owned,
            ptrs,
        })
    }

    // A method, not a field access, so a closure captures the whole
    // `CArray` (Send + Sync) rather than the bare pointer `Vec`.
    fn as_ptr(&self) -> *const *const libc::c_char {
        self.ptrs.as_ptr()
    }
}

/// Linux: exec the hashed fd itself, so a file swapped in at `program`
/// after the hash never runs. The plan has already refused a pin that is
/// not on a trusted path (root-owned, not group- or other-writable, no
/// symlink from the file up to `/`). argv and envp are copied from `cmd`
/// now, so call this after the env is final. Registered after the identity
/// hook.
#[cfg(target_os = "linux")]
fn arm_pin(cmd: &mut Command, pin: PinnedExe, _program: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let argv = CArray::new(
        std::iter::once(cmd.get_program())
            .chain(cmd.get_args())
            .map(|a| a.as_bytes().to_vec()),
    )?;
    let envp = CArray::new(cmd.get_envs().filter_map(|(k, v)| {
        let mut kv = k.as_bytes().to_vec();
        kv.push(b'=');
        kv.extend_from_slice(v?.as_bytes());
        Some(kv)
    }))?;
    let stamp = FileStamp::of(&pin.meta);
    // SAFETY: the hook runs in the forked child after std's own setup and
    // the identity hook. It only calls fstat and fexecve, both
    // async-signal-safe, on an fd and arrays built before the fork. The fd
    // is O_CLOEXEC, so the new image does not inherit it. On success
    // fexecve does not return; on failure the errno aborts the spawn.
    unsafe {
        cmd.pre_exec(move || {
            let fd = pin.fd.as_raw_fd();
            if !stamp.matches_fd(fd) {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
            libc::fexecve(fd, argv.as_ptr(), envp.as_ptr());
            Err(io::Error::last_os_error())
        });
    }
    Ok(())
}

/// No `fexecve` here: the child execs `program` by path. The plan has
/// already required a root-owned, non-writable, non-symlink path from the
/// binary up to `/`. That is the main defense on macOS. Residual: between
/// this inode check and the kernel's open of `program` at exec, a root
/// writer can still swap the file. A program writable by group or other is
/// refused outright.
#[cfg(not(target_os = "linux"))]
fn arm_pin(cmd: &mut Command, pin: PinnedExe, program: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    if pin.meta.permissions().mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "pinned program is writable by group or other",
        ));
    }
    let path = std::ffi::CString::new(program.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in program"))?;
    let stamp = FileStamp::of(&pin.meta);
    // SAFETY: the hook runs in the forked child just before exec. It only
    // calls fstat and lstat, both async-signal-safe, on an fd and a path
    // built before the fork. The fd is O_CLOEXEC.
    unsafe {
        cmd.pre_exec(move || {
            let mut st: libc::stat = std::mem::zeroed();
            let path_ok =
                libc::lstat(path.as_ptr(), &mut st) == 0 && FileStamp::of_stat(&st) == stamp;
            if path_ok && stamp.matches_fd(pin.fd.as_raw_fd()) {
                Ok(())
            } else {
                Err(io::Error::from_raw_os_error(libc::EACCES))
            }
        });
    }
    Ok(())
}

/// The command with its identity, a cleared env plus `spec.env`, piped
/// output, stdin, cwd, and its own process group.
fn prepared(spec: &SpawnSpec, identity: &ChildIdentity) -> io::Result<Command> {
    let mut cmd = build_command(spec, identity)?;
    cmd.env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(if spec.inherit_stdin {
            Stdio::inherit()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    if let Some(dir) = &spec.cwd {
        cmd.current_dir(dir);
    }
    Ok(cmd)
}

#[cfg(target_os = "linux")]
fn isolated(
    cmd: Command,
    pin: Option<(PinnedExe, PathBuf)>,
    allow_hosts: &[String],
    timeout: Duration,
    on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let allow = crate::egress::AllowList::parse(allow_hosts);
    if allow.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "allow_hosts has no usable entry",
        ));
    }
    // Workers are spawned from this host-namespace thread, so they dial out
    // from the daemon's namespace.
    let (conn_tx, conn_rx) = mpsc::channel::<TcpStream>();
    let dispatcher = thread::spawn(move || {
        for s in conn_rx {
            let a = allow.clone();
            thread::spawn(move || {
                let _ = crate::egress::handle_client(s, &a);
            });
        }
    });
    let stop = Arc::new(AtomicBool::new(false));
    let stop_bridge = Arc::clone(&stop);
    let (child_tx, child_rx) = mpsc::channel::<io::Result<Child>>();
    // Only this thread enters the child's namespace. It binds the proxy
    // there, forks the child from there, then accepts for the proxy.
    let bridge = thread::spawn(move || {
        let listener =
            match crate::netns::enter_new_netns().and_then(|()| TcpListener::bind("127.0.0.1:0")) {
                Ok(l) => l,
                Err(e) => {
                    let _ = child_tx.send(Err(e));
                    return;
                }
            };
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
        let url = format!("http://127.0.0.1:{port}");
        let mut cmd = cmd;
        for k in PROXY_VARS {
            cmd.env(k, &url);
        }
        let spawned = launch(cmd, pin);
        let ok = spawned.is_ok();
        let _ = child_tx.send(spawned);
        if !ok || listener.set_nonblocking(true).is_err() {
            return;
        }
        while !stop_bridge.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((s, _)) => {
                    if s.set_nonblocking(false).is_ok() && conn_tx.send(s).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => thread::sleep(POLL),
                Err(_) => break,
            }
        }
    });
    let child = child_rx
        .recv()
        .map_err(|_| io::Error::other("network namespace thread failed"))?;
    let outcome = child.and_then(|c| supervise(c, timeout, on_chunk));
    stop.store(true, Ordering::Relaxed);
    let _ = bridge.join();
    let _ = dispatcher.join();
    outcome
}

#[cfg(not(target_os = "linux"))]
fn isolated(
    _cmd: Command,
    _pin: Option<(PinnedExe, PathBuf)>,
    _allow_hosts: &[String],
    _timeout: Duration,
    _on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "allow_hosts: unsupported on this host",
    ))
}

/// Read both pipes, enforce the timeout, and reap the group.
fn supervise(
    mut child: Child,
    timeout: Duration,
    mut on_chunk: impl FnMut(Stream, &[u8]),
) -> io::Result<ChildOutcome> {
    let pgid = i32::try_from(child.id()).unwrap_or(0);

    let (tx, rx) = mpsc::channel::<(Stream, Vec<u8>)>();
    let mut readers = Vec::new();
    if let Some(out) = child.stdout.take() {
        readers.push(pipe_reader(out, Stream::Stdout, tx.clone()));
    }
    if let Some(err) = child.stderr.take() {
        readers.push(pipe_reader(err, Stream::Stderr, tx.clone()));
    }
    drop(tx);

    let deadline = Instant::now() + timeout;
    let mut term_at: Option<Instant> = None;
    let mut timed_out = false;
    let status = loop {
        // Drain for at most one poll slice so a chatty child cannot starve
        // the deadline check.
        let slice_end = Instant::now() + POLL;
        loop {
            let left = slice_end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match rx.recv_timeout(left) {
                Ok((stream, chunk)) => on_chunk(stream, &chunk),
                Err(mpsc::RecvTimeoutError::Timeout) => break,
                // Both pipes closed; the child may still run.
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    thread::sleep(POLL);
                    break;
                }
            }
        }
        if let Some(status) = child.try_wait()? {
            break status;
        }
        let now = Instant::now();
        match term_at {
            None if now >= deadline => {
                timed_out = true;
                signal_group(pgid, libc::SIGTERM);
                term_at = Some(now);
            }
            Some(t) if now >= t + KILL_GRACE => {
                signal_group(pgid, libc::SIGKILL);
            }
            _ => {}
        }
    };
    // Anything the child left behind in its group would hold the pipes
    // open; it does not outlive the run.
    signal_group(pgid, libc::SIGKILL);
    for (stream, chunk) in rx {
        on_chunk(stream, &chunk);
    }
    for r in readers {
        let _ = r.join();
    }
    Ok(ChildOutcome {
        exit_code: status.code(),
        signal: status.signal(),
        timed_out,
    })
}

/// The program, args, and identity hook for one child.
fn build_command(spec: &SpawnSpec, identity: &ChildIdentity) -> io::Result<Command> {
    match identity {
        ChildIdentity::Inherit => {
            let mut cmd = Command::new(&spec.program);
            cmd.args(&spec.args);
            Ok(cmd)
        }
        ChildIdentity::User { uid, gid } => user_command(spec, *uid, *gid),
        ChildIdentity::Seatbelt { deny } => seatbelt_command(spec, deny),
    }
}

#[cfg(target_os = "linux")]
fn user_command(spec: &SpawnSpec, uid: u32, gid: u32) -> io::Result<Command> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args);
    // SAFETY: the hook runs in the forked child before exec and only makes
    // async-signal-safe syscalls on plain integers. Any failure aborts the
    // exec, so the child never runs as the caller.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setgroups(0, std::ptr::null()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(io::Error::last_os_error());
            }
            if libc::getuid() != uid || libc::geteuid() != uid || libc::getgid() != gid {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(cmd)
}

#[cfg(not(target_os = "linux"))]
fn user_command(_spec: &SpawnSpec, _uid: u32, _gid: u32) -> io::Result<Command> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "custody uid switch is Linux only",
    ))
}

/// `sandbox-exec` ships with macOS at this fixed path.
#[cfg(target_os = "macos")]
const SANDBOX_EXEC: &str = "/usr/bin/sandbox-exec";

#[cfg(target_os = "macos")]
fn seatbelt_command(spec: &SpawnSpec, deny: &[PathBuf]) -> io::Result<Command> {
    let profile = crate::ident::seatbelt_profile(deny)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mut cmd = Command::new(SANDBOX_EXEC);
    cmd.arg("-p")
        .arg(profile)
        .arg(&spec.program)
        .args(&spec.args);
    Ok(cmd)
}

#[cfg(not(target_os = "macos"))]
fn seatbelt_command(_spec: &SpawnSpec, _deny: &[PathBuf]) -> io::Result<Command> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "seatbelt is macOS only",
    ))
}

fn pipe_reader(
    mut pipe: impl Read + Send + 'static,
    stream: Stream,
    tx: mpsc::Sender<(Stream, Vec<u8>)>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buf = vec![0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.send((stream, buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
            }
        }
    })
}

fn signal_group(pgid: i32, sig: i32) {
    if pgid <= 0 {
        return;
    }
    // SAFETY: kill(2) with a negative pid signals the child's own process
    // group, created by `process_group(0)` at spawn. No memory is touched.
    unsafe {
        libc::kill(-pgid, sig);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_EXEC: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    /// Runs the hook a test set on this thread: after the pin is verified
    /// and taken, before exec.
    pub(super) fn before_exec() {
        if let Some(f) = BEFORE_EXEC.with(|h| h.borrow_mut().take()) {
            f();
        }
    }

    fn set_before_exec(f: impl FnOnce() + 'static) {
        BEFORE_EXEC.with(|h| *h.borrow_mut() = Some(Box::new(f)));
    }

    fn sh() -> PathBuf {
        std::fs::canonicalize("/bin/sh").expect("sh")
    }

    fn spec(script: &str, timeout: Duration) -> SpawnSpec {
        SpawnSpec {
            program: sh(),
            args: vec!["-c".into(), script.into()],
            env: vec![("ONLY".into(), "one".into())],
            cwd: None,
            inherit_stdin: false,
            timeout,
        }
    }

    /// Open `p` as `inject::match_cmd` does for a pinned rule. The hash
    /// itself is geode-core's; here only the fd and its stamp matter.
    fn pin(p: &Path) -> PinnedExe {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(p)
            .unwrap();
        let meta = f.metadata().unwrap();
        PinnedExe { fd: f.into(), meta }
    }

    /// A temp dir with a copy of `src` at `prog` (mode 0755). Returns the
    /// canonical `prog`.
    fn copy_exe(dir: &Path, src: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::fs::canonicalize(dir).unwrap();
        let prog = dir.join("prog");
        std::fs::copy(std::fs::canonicalize(src).unwrap(), &prog).unwrap();
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o755)).unwrap();
        prog
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("geode-os-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Spec running `prog -c 'echo swapped'` with `prog` (a copy of echo)
    /// pinned, and a hook that renames a copy of `/bin/sh` over `prog`
    /// before exec.
    fn swapped_spec(dir: &Path) -> (SpawnSpec, PinnedExe) {
        let prog = copy_exe(dir, "/bin/echo");
        let pinned = pin(&prog);
        let evil = dir.join("evil");
        std::fs::copy(sh(), &evil).unwrap();
        let target = prog.clone();
        set_before_exec(move || std::fs::rename(&evil, &target).unwrap());
        let spec = SpawnSpec {
            program: prog,
            args: vec!["-c".into(), "echo swapped".into()],
            env: Vec::new(),
            cwd: None,
            inherit_stdin: false,
            timeout: Duration::from_secs(10),
        };
        (spec, pinned)
    }

    fn run(spec: SpawnSpec, pin: PinnedExe) -> io::Result<(ChildOutcome, String)> {
        let mut out = Vec::new();
        let o = spawn_with_pin(spec, Some(pin), &ChildIdentity::Inherit, &[], |s, c| {
            if s == Stream::Stdout {
                out.extend_from_slice(c);
            }
        })?;
        Ok((o, String::from_utf8_lossy(&out).into_owned()))
    }

    #[test]
    fn pinned_non_platform_helper_runs() {
        // A rustc binary, not a copy of /bin/sh. macOS launch constraints
        // SIGKILL a relocated platform image; this one is ad-hoc signed.
        let dir = tmpdir("pin-helper");
        let src = dir.join("helper.rs");
        std::fs::write(&src, "fn main() { print!(\"ok\"); }\n").unwrap();
        let prog = dir.join("helper");
        let built = std::process::Command::new("rustc")
            .arg(&src)
            .arg("-o")
            .arg(&prog)
            .status()
            .expect("rustc");
        assert!(built.success(), "rustc helper");
        let pinned = pin(&prog);
        let mut s = spec("", Duration::from_secs(10));
        s.program = prog;
        s.args.clear();
        let (o, out) = run(s, pinned).unwrap();
        assert_eq!((o.exit_code, out.as_str()), (Some(0), "ok"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pinned_program_runs_from_its_fd() {
        // Not a copy: macOS kills a relocated copy of a platform binary.
        let prog = std::fs::canonicalize("/bin/echo").unwrap();
        let pinned = pin(&prog);
        let mut s = spec("", Duration::from_secs(10));
        s.program = prog;
        s.args = vec!["pinned-ok".into()];
        let (o, out) = run(s, pinned).unwrap();
        assert_eq!((o.exit_code, out.as_str()), (Some(0), "pinned-ok\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn swap_after_verify_still_runs_the_hashed_file() {
        let dir = tmpdir("pin-swap");
        let (s, pinned) = swapped_spec(&dir);
        let (o, out) = run(s, pinned).unwrap();
        // echo prints its args; the swapped-in sh would print "swapped".
        assert_eq!(o.exit_code, Some(0));
        assert_eq!(out, "-c echo swapped\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    // TODO(macOS CI): un-ignore once a macOS runner lands. Passes on a
    // local macOS host with `cargo test -p geode-os -- --ignored`.
    #[cfg(not(target_os = "linux"))]
    #[ignore = "macOS inode re-check; needs a macOS CI runner"]
    #[test]
    fn swap_after_verify_is_refused_by_the_inode_recheck() {
        let dir = tmpdir("pin-swap");
        let (s, pinned) = swapped_spec(&dir);
        let r = run(s, pinned);
        assert!(r.is_err(), "swapped program ran: {r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_in_place_after_verify_is_refused() {
        use std::io::Write as _;
        let dir = tmpdir("pin-write");
        let prog = copy_exe(&dir, "/bin/echo");
        let pinned = pin(&prog);
        let mut s = spec("", Duration::from_secs(10));
        s.program = prog.clone();
        s.args = vec!["ran".into()];
        set_before_exec(move || {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&prog)
                .unwrap();
            f.write_all(b"\0").unwrap();
        });
        let r = run(s, pinned);
        assert!(r.is_err(), "modified program ran: {r:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn child_does_not_inherit_the_pin_fd() {
        let canon = sh();
        let pinned = pin(&canon);
        let raw = pinned.fd.as_raw_fd();
        let mut s = spec(
            &format!("[ -e /proc/self/fd/{raw} ] && echo leaked; ls -l /proc/$$/fd"),
            Duration::from_secs(10),
        );
        s.env.push(("PATH".into(), "/usr/bin:/bin".into()));
        let (o, out) = run(s, pinned).unwrap();
        assert_eq!(o.exit_code, Some(0), "{out}");
        assert!(
            !out.contains("leaked"),
            "pin fd {raw} reached the child: {out}"
        );
        assert!(
            !out.contains(canon.to_str().unwrap()),
            "the child holds an fd on its own program: {out}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn group_writable_pin_is_refused_on_macos() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmpdir("pin-mode");
        let prog = copy_exe(&dir, "/bin/echo");
        std::fs::set_permissions(&prog, std::fs::Permissions::from_mode(0o775)).unwrap();
        let pinned = pin(&prog);
        let mut s = spec("", Duration::from_secs(10));
        s.program = prog;
        let e = run(s, pinned).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn collect(spec: SpawnSpec) -> (ChildOutcome, Vec<u8>, Vec<u8>) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let o = spawn(spec, |s, c| match s {
            Stream::Stdout => out.extend_from_slice(c),
            Stream::Stderr => err.extend_from_slice(c),
        })
        .expect("spawn");
        (o, out, err)
    }

    #[test]
    fn env_is_exactly_the_spec() {
        // `set` is a builtin, so it works with no PATH.
        let (o, out, _) = collect(spec(
            "echo \"$ONLY:${HOME-unset}\"",
            Duration::from_secs(10),
        ));
        assert_eq!(o.exit_code, Some(0));
        assert_eq!(out, b"one:unset\n");
    }

    #[test]
    fn exit_code_and_streams() {
        let (o, out, err) = collect(spec(
            "echo out; echo err >&2; exit 3",
            Duration::from_secs(10),
        ));
        assert_eq!(
            (o.exit_code, o.timed_out, o.process_exit()),
            (Some(3), false, 3)
        );
        assert_eq!(out, b"out\n");
        assert_eq!(err, b"err\n");
    }

    #[test]
    fn timeout_terms_the_group() {
        let start = Instant::now();
        let (o, _, _) = collect(spec("while :; do :; done", Duration::from_millis(300)));
        assert!(o.timed_out);
        assert_eq!(o.signal, Some(libc::SIGTERM));
        assert_eq!(o.process_exit(), 128 + libc::SIGTERM);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn user_identity_never_falls_back_to_the_caller() {
        let tmp = std::env::temp_dir().join(format!("geode-os-ident-{}", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut s = spec(
            &format!("id -u > '{}'", tmp.display()),
            Duration::from_secs(10),
        );
        s.env.push(("PATH".into(), "/usr/bin:/bin".into()));
        let nobody = ChildIdentity::User {
            uid: 65534,
            gid: 65534,
        };
        let r = spawn_as(s, &nobody, |_, _| {});
        let me = crate::ident::euid();
        if cfg!(target_os = "linux") && me == 0 {
            // Root can switch: the child is really 65534.
            assert_eq!(r.unwrap().exit_code, Some(0));
            assert_eq!(std::fs::read_to_string(&tmp).unwrap().trim(), "65534");
        } else {
            // Not root (or not Linux): no child runs, as the caller or anyone.
            assert!(r.is_err(), "spawned without the identity: {r:?}");
            assert!(!tmp.exists(), "a child ran");
        }
        let _ = std::fs::remove_file(&tmp);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn seatbelt_denies_listed_paths_only() {
        let dir = std::env::temp_dir().join(format!("geode-os-sb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dir = std::fs::canonicalize(&dir).unwrap();
        let key = dir.join("default.gkey");
        let other = dir.join("other.txt");
        std::fs::write(&key, "sk-dummy-0000QA").unwrap();
        std::fs::write(&other, "public").unwrap();
        let script = format!("cat '{}'; echo; cat '{}'", other.display(), key.display());
        let mut s = spec(&script, Duration::from_secs(10));
        s.env.push(("PATH".into(), "/usr/bin:/bin".into()));
        let id = ChildIdentity::Seatbelt {
            deny: vec![key.clone()],
        };
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let o = spawn_as(s, &id, |st, c| match st {
            Stream::Stdout => out.extend_from_slice(c),
            Stream::Stderr => err.extend_from_slice(c),
        })
        .unwrap();
        let out = String::from_utf8_lossy(&out);
        assert!(out.contains("public"), "{out}");
        assert!(
            !out.contains("sk-dummy"),
            "seatbelt let the key through: {out}"
        );
        assert_ne!(o.exit_code, Some(0));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn seatbelt_is_refused_off_macos() {
        let id = ChildIdentity::Seatbelt {
            deny: vec!["/x".into()],
        };
        assert!(spawn_as(spec("true", Duration::from_secs(1)), &id, |_, _| {}).is_err());
    }

    /// One-shot HTTP upstream on 127.0.0.1 in this (host) namespace that
    /// reports each connection.
    fn http_upstream() -> (u16, mpsc::Receiver<()>) {
        use std::io::Write as _;
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            for mut s in l.incoming().flatten() {
                let _ = tx.send(());
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nhello-upstream\n");
            }
        });
        (port, rx)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn allow_hosts_blocks_unlisted_hosts_in_a_netns() {
        let curl = ["/usr/bin/curl", "/bin/curl"]
            .into_iter()
            .find(|p| std::path::Path::new(p).exists());
        let Some(curl) = curl else {
            eprintln!("GAP: no curl on this host; netns end-to-end not run");
            return;
        };
        let (ok_port, ok_seen) = http_upstream();
        let (bad_port, bad_seen) = http_upstream();
        let script = format!(
            "{curl} -s -p --max-time 5 http://127.0.0.1:{ok_port}/; echo rc1=$?; \
             {curl} -s -p --max-time 5 http://127.0.0.1:{bad_port}/; echo rc2=$?; \
             {curl} -s --noproxy '*' --max-time 3 http://127.0.0.1:{ok_port}/; echo rc3=$?"
        );
        let mut sp = spec(&script, Duration::from_secs(30));
        sp.env.push(("PATH".into(), "/usr/bin:/bin".into()));
        let mut out = Vec::new();
        let r = spawn_with(
            sp,
            &ChildIdentity::Inherit,
            &[format!("127.0.0.1:{ok_port}")],
            |st, c| {
                if st == Stream::Stdout {
                    out.extend_from_slice(c);
                }
            },
        );
        match r {
            Err(e) if e.raw_os_error() == Some(libc::EPERM) => {
                // GitHub runners lack CAP_SYS_ADMIN: the run is refused, not
                // run unconfined. The proxy itself is tested in `egress`.
                eprintln!(
                    "GAP: cannot create a network namespace here ({e}); refused, nothing ran"
                );
                assert!(ok_seen.try_recv().is_err() && bad_seen.try_recv().is_err());
            }
            Err(e) => panic!("unexpected: {e}"),
            Ok(o) => {
                let out = String::from_utf8_lossy(&out);
                assert_eq!(o.exit_code, Some(0), "{out}");
                assert!(
                    out.contains("hello-upstream") && out.contains("rc1=0"),
                    "allowed host: {out}"
                );
                assert!(!out.contains("rc2=0"), "unlisted host got through: {out}");
                assert!(!out.contains("rc3=0"), "direct connect got through: {out}");
                assert!(ok_seen.try_recv().is_ok());
                assert!(bad_seen.try_recv().is_err(), "unlisted upstream was dialed");
            }
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn allow_hosts_refuses_before_spawn_off_linux() {
        let marker = std::env::temp_dir().join(format!("geode-os-hosts-{}", std::process::id()));
        let sp = spec(
            &format!("echo x > '{}'", marker.display()),
            Duration::from_secs(5),
        );
        let r = spawn_with(
            sp,
            &ChildIdentity::Inherit,
            &["api.example.com".into()],
            |_, _| {},
        );
        assert_eq!(r.unwrap_err().kind(), io::ErrorKind::Unsupported);
        assert!(!marker.exists());
    }

    #[test]
    fn empty_allow_hosts_is_unrestricted() {
        let (port, seen) = http_upstream();
        let mut sp = spec(
            &format!("exec 3<>/dev/tcp/127.0.0.1/{port} 2>/dev/null || true"),
            Duration::from_secs(5),
        );
        sp.program = std::fs::canonicalize("/bin/bash").unwrap_or_else(|_| sh());
        let o = spawn_with(sp, &ChildIdentity::Inherit, &[], |_, _| {}).unwrap();
        assert_eq!(o.exit_code, Some(0));
        if std::path::Path::new("/bin/bash").exists() {
            assert!(
                seen.recv_timeout(Duration::from_secs(2)).is_ok(),
                "empty list must not deny"
            );
        }
    }

    #[test]
    fn debug_has_no_values() {
        let d = format!("{:?}", spec("echo secret-arg", Duration::from_secs(1)));
        assert!(!d.contains("secret-arg") && !d.contains("one"), "{d}");
    }
}
