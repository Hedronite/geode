//! Spawn one `geode run` child (SPEC-v034 G6, harmonized spec §3 steps 6–10).
//!
//! The child gets exactly the env in [`SpawnSpec::env`] (the parent env is
//! cleared), stdin `/dev/null` unless asked, and its own process group so a
//! timeout reaches grandchildren. Output arrives in chunks through a
//! callback; redaction is the caller's job. On timeout: SIGTERM to the
//! group, 2 seconds, then SIGKILL.

use std::ffi::OsString;
use std::io::{self, Read};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

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
pub fn spawn(spec: SpawnSpec, mut on_chunk: impl FnMut(Stream, &[u8])) -> io::Result<ChildOutcome> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .env_clear()
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
    let mut child = cmd.spawn()?;
    drop(cmd);
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

    let deadline = Instant::now() + spec.timeout;
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
    fn debug_has_no_values() {
        let d = format!("{:?}", spec("echo secret-arg", Duration::from_secs(1)));
        assert!(!d.contains("secret-arg") && !d.contains("one"), "{d}");
    }
}
