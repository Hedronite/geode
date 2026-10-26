//! Inject plan (SPEC-v034 G6; harmonized spec §3 "one pipeline, two
//! transports").
//!
//! [`plan`] is the only authorize / decrypt / `allow_cmds` path for
//! `geode run`. Local mode (`human:local`, key in hand) calls it in-process;
//! the custody daemon (G7) will call the same function. It does not spawn:
//! `geode-os` does. [`Collector`] is the shared redact-and-cap step the
//! transport feeds child output through.
//!
//! Order: binding names, `allow_hosts`, authorize every binding, resolve and
//! match `argv[0]` (a pin also has to sit on a trusted path), `--no-redact`
//! gate, decrypt, value checks, argv needle check. All pass or nothing is
//! spawned. Errors name binding NAMEs and the canonical `argv[0]` only —
//! never a value or the full argv.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use geode_redact::{NamedRedactor, NamedStream, Placeholder};
use secrecy::{ExposeSecret, SecretBox};

use crate::kdf::{Epoch, EpochKey};
use crate::manifest::Manifest;
use crate::object::{self, HEADER_SIZE};
use crate::policy::{evaluate, prefix_covers, Op, Policy, PrincipalId, Verdict};
use crate::token::{CmdRule, RedactLevel, Token};
use crate::vault as corevault;

/// Output cap per stream (harmonized spec §3).
pub const OUTPUT_CAP: usize = 1024 * 1024;
/// Marker appended once a stream passes [`OUTPUT_CAP`].
pub const TRUNCATED_MARK: &[u8] = b"[TRUNCATED]";
/// Names the child env always gets from the base; bindings may not use them.
pub const BASE_ENV: [&str; 4] = ["PATH", "HOME", "LANG", "TERM"];
const RESERVED_PREFIXES: [&str; 3] = ["GEODE_", "LD_", "DYLD_"];
const MAX_NAME: usize = 64;

/// Why a plan refused. The transport maps each kind to the shipped exit
/// codes: `Usage` 1, `Auth` 2, `Deny` and `ArgvRejected` 3.
#[derive(Debug)]
pub enum PlanError {
    /// Malformed request (names, empty command, missing object).
    Usage(String),
    /// Vault or object authentication failed.
    Auth,
    /// Policy, `allow_cmds`, `allow_hosts`, or a value the redactor cannot
    /// guard. `exe` is the canonical `argv[0]` when it was resolved.
    Deny { reason: String, exe: Option<String> },
    /// An argument carried a bound value. Only the canonical exe is kept.
    ArgvRejected { exe: String },
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Usage(m) => f.write_str(m),
            Self::Auth => f.write_str("authentication / integrity failure"),
            Self::Deny { reason, .. } => f.write_str(reason),
            Self::ArgvRejected { exe } => {
                write!(
                    f,
                    "argv rejected: an argument to {exe} carries a bound value"
                )
            }
        }
    }
}

impl std::error::Error for PlanError {}

/// The audit `hosts` value: `unrestricted` for an empty list, else the
/// list itself.
#[must_use]
pub fn hosts_label(allow_hosts: &[String]) -> String {
    if allow_hosts.is_empty() {
        "unrestricted".to_owned()
    } else {
        allow_hosts.join(",")
    }
}

/// Who is asking, and what it may run. Local mode passes the policy
/// principal and no token; the daemon passes the verified token too.
pub struct Caller<'a> {
    pub principal: &'a PrincipalId,
    pub policy: &'a Policy,
    pub token: Option<&'a Token>,
    pub allow_cmds: &'a [CmdRule],
    pub allow_hosts: &'a [String],
    pub redact: RedactLevel,
    /// The transport can enforce a non-empty `allow_hosts` (the custody
    /// proxy on Linux, and the same proxy behind a seatbelt on macOS).
    /// When false, a non-empty list is refused before spawn. An empty list
    /// is not allow-all for a secret binding: `geode run` and custody refuse
    /// it before they call [`plan`]. Spawn still treats an empty list as no
    /// confinement, which those transports do not use for a secret.
    pub enforce_hosts: bool,
}

impl std::fmt::Debug for Caller<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Caller")
            .field("principal", &self.principal.0)
            .field("token", &self.token.is_some())
            .field("allow_cmds", &self.allow_cmds.len())
            .field("allow_hosts", &self.allow_hosts.len())
            .field("redact", &self.redact)
            .field("enforce_hosts", &self.enforce_hosts)
            .finish()
    }
}

/// The vault the bindings come from, already unlocked by the transport.
pub struct VaultView<'a> {
    pub root: &'a Path,
    pub ek: &'a EpochKey,
    pub epoch: Epoch,
    pub manifest: &'a Manifest,
}

impl std::fmt::Debug for VaultView<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultView")
            .field("root", &self.root)
            .field("epoch", &self.epoch.0)
            .finish_non_exhaustive()
    }
}

/// One `--secret NAME=PATH`.
#[derive(Clone, Debug)]
pub struct BindingSpec {
    pub name: String,
    pub path: String,
}

/// The request as parsed by the transport.
pub struct PlanRequest<'a> {
    pub bindings: &'a [BindingSpec],
    pub argv: &'a [String],
    /// `PATH` from before any binding is applied. `argv[0]` without a `/`
    /// is resolved against it.
    pub base_path: Option<&'a OsStr>,
    pub no_redact: bool,
}

/// `Debug` names the bindings and the command name only, never the args.
impl std::fmt::Debug for PlanRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlanRequest")
            .field("bindings", &self.bindings)
            .field("argv0", &self.argv.first())
            .field("no_redact", &self.no_redact)
            .finish_non_exhaustive()
    }
}

/// `argv[0]` after it matched `allow_cmds`.
pub(crate) struct VerifiedExe {
    /// Canonical absolute path.
    canon: String,
    /// Pinned rules only: the fd whose bytes matched `sha256`, and its
    /// `fstat` from before the hash. `None` for an unpinned rule.
    fd: Option<(OwnedFd, Metadata)>,
}

/// An authorized run. Values are `SecretBox`; nothing here prints them.
pub struct Plan {
    /// Canonical `argv[0]` that matched `allow_cmds`.
    pub exe: String,
    /// `argv[1..]`.
    pub args: Vec<String>,
    /// Binding names in command-line order, with their values.
    pub env: Vec<(String, SecretBox<[u8]>)>,
    /// Vault paths in command-line order (audit `paths`).
    pub paths: Vec<String>,
    /// `None` only for an admitted `--no-redact`.
    pub redactor: Option<NamedRedactor>,
    /// See [`Plan::take_pin`].
    pin: Option<(OwnedFd, Metadata)>,
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("Plan")
            .field("exe", &self.exe)
            .field("pinned", &self.pin.is_some())
            .field("names", &names)
            .finish_non_exhaustive()
    }
}

impl Plan {
    /// Binding names in command-line order.
    #[must_use]
    pub fn names(&self) -> Vec<&str> {
        self.env.iter().map(|(n, _)| n.as_str()).collect()
    }

    /// Pinned rules only: the `O_CLOEXEC` fd of [`Plan::exe`] whose bytes
    /// matched `sha256`, and its `fstat` from before the hash. Spawn must
    /// exec this fd, not the path. The first call takes it; later calls and
    /// unpinned rules return `None`.
    pub fn take_pin(&mut self) -> Option<(OwnedFd, Metadata)> {
        self.pin.take()
    }
}

/// Authorize, resolve, decrypt, and check one run. Nothing is spawned here.
///
/// A sha256 pin is trusted only when every component from the canonical
/// path up to `/` is owned by uid 0. There is no argument that moves that
/// root.
///
/// # Errors
///
/// See [`PlanError`]. On any error no value has left this function.
pub fn plan(
    caller: &Caller<'_>,
    vault: &VaultView<'_>,
    req: &PlanRequest<'_>,
) -> Result<Plan, PlanError> {
    plan_anchored(caller, vault, req, Path::new("/"), 0)
}

// Two compile refusals keep `test-trusted-root` out of an optimized build:
// this one (`not(debug_assertions)`: `cargo build --release`, `cargo
// install`), and `build.rs`, which also refuses any `opt-level` other than
// 0, so a custom profile with debug assertions on cannot ship it. A plain
// dev or test build can still enable the feature.
#[cfg(all(feature = "test-trusted-root", not(debug_assertions)))]
compile_error!(
    "feature `test-trusted-root` is test-only and insecure (it moves the pin trust root); \
     release builds, including `cargo install`, cannot enable it"
);

/// Same as [`plan`], but the trust walk stops at `root` and expects `uid`.
///
/// Test-only and insecure. Compiled for unit tests and for the
/// `test-trusted-root` feature, which lets a caller move the pin trust
/// root. The feature fails to compile when debug assertions are off
/// (`cargo build --release`, `cargo install`) or at any opt-level other
/// than 0 (`build.rs`). A plain dev build can still enable it. A release `geode` does not call this and does not contain it.
#[cfg(any(test, feature = "test-trusted-root"))]
pub fn plan_with_test_root(
    caller: &Caller<'_>,
    vault: &VaultView<'_>,
    req: &PlanRequest<'_>,
    root: &Path,
    uid: u32,
) -> Result<Plan, PlanError> {
    if !root.is_absolute() {
        return Err(PlanError::Usage("test trusted root is not absolute".into()));
    }
    plan_anchored(caller, vault, req, root, uid)
}

fn plan_anchored(
    caller: &Caller<'_>,
    vault: &VaultView<'_>,
    req: &PlanRequest<'_>,
    root: &Path,
    uid: u32,
) -> Result<Plan, PlanError> {
    check_names(req.bindings)?;
    if req.argv.is_empty() {
        return Err(PlanError::Usage("no command after --".into()));
    }
    if !caller.allow_hosts.is_empty() && !caller.enforce_hosts {
        return Err(deny("allow_hosts: unsupported on this host", None));
    }
    for b in req.bindings {
        authorize(caller, &b.path)
            .map_err(|reason| deny(&format!("binding {}: {reason}", b.name), None))?;
    }
    let VerifiedExe {
        canon: exe,
        fd: pin,
    } = match_cmd_trusted(
        caller.allow_cmds,
        &req.argv[0],
        &req.argv[1..],
        req.base_path,
        TrustAnchor { root, uid },
    )?;
    if req.no_redact && !may_skip_redaction(caller, req.bindings) {
        return Err(deny(
            "--no-redact needs a human:* principal with admin",
            Some(exe),
        ));
    }
    let mut env = Vec::with_capacity(req.bindings.len());
    for b in req.bindings {
        let value = decrypt(vault, b)?;
        let v = value.expose_secret();
        if v.contains(&0) || std::str::from_utf8(v).is_err() {
            return Err(deny(
                &format!("binding {}: not env-safe", b.name),
                Some(exe),
            ));
        }
        if v.len() < 8 {
            return Err(deny(
                &format!("binding {}: too short to redact safely", b.name),
                Some(exe),
            ));
        }
        env.push((b.name.clone(), value));
    }
    let placeholder = match caller.redact {
        RedactLevel::Strict => Placeholder::Named,
        RedactLevel::Hidden => Placeholder::Hidden,
    };
    let pairs: Vec<(&str, &[u8])> = env
        .iter()
        .map(|(n, v)| (n.as_str(), v.expose_secret()))
        .collect();
    let redactor = NamedRedactor::try_new(&pairs, placeholder)
        .map_err(|e| deny(&e.to_string(), Some(exe.clone())))?;
    drop(pairs);
    if req.argv[1..]
        .iter()
        .any(|a| redactor.contains_binding(a.as_bytes()))
    {
        return Err(PlanError::ArgvRejected { exe });
    }
    Ok(Plan {
        exe,
        args: req.argv[1..].to_vec(),
        env,
        paths: req.bindings.iter().map(|b| b.path.clone()).collect(),
        redactor: if req.no_redact { None } else { Some(redactor) },
        pin,
    })
}

fn deny(reason: &str, exe: Option<String>) -> PlanError {
    PlanError::Deny {
        reason: reason.to_owned(),
        exe,
    }
}

/// NAME matches `[A-Z_][A-Z0-9_]{0,63}`, is not reserved, appears once, and
/// at least one binding exists.
fn check_names(bindings: &[BindingSpec]) -> Result<(), PlanError> {
    if bindings.is_empty() {
        return Err(PlanError::Usage(
            "at least one --secret NAME=PATH is required".into(),
        ));
    }
    let mut seen: Vec<&str> = Vec::new();
    for b in bindings {
        let n = b.name.as_str();
        let mut chars = n.bytes();
        let first_ok = chars
            .next()
            .is_some_and(|c| c.is_ascii_uppercase() || c == b'_');
        let rest_ok = chars.all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_');
        if !first_ok || !rest_ok || n.len() > MAX_NAME {
            return Err(PlanError::Usage(format!(
                "binding name '{n}' must match [A-Z_][A-Z0-9_]{{0,63}}"
            )));
        }
        if BASE_ENV.contains(&n) || RESERVED_PREFIXES.iter().any(|p| n.starts_with(p)) {
            return Err(PlanError::Usage(format!("binding name '{n}' is reserved")));
        }
        if seen.contains(&n) {
            return Err(PlanError::Usage(format!(
                "binding name '{n}' appears twice"
            )));
        }
        if b.path.is_empty() {
            return Err(PlanError::Usage(format!("binding {n}: empty vault path")));
        }
        seen.push(n);
    }
    Ok(())
}

/// `Inject` on the path for the principal, and, with a token, `Inject` in
/// its ops, a covering prefix, and the token still a narrowing of policy.
fn authorize(caller: &Caller<'_>, path: &str) -> Result<(), String> {
    let norm = crate::policy::normalize_path(path).map_err(|_| "bad vault path".to_owned())?;
    let allowed = evaluate(caller.policy, caller.principal, Op::Inject, &norm)
        .map_err(|_| "bad vault path".to_owned())?;
    if allowed != Verdict::Allow {
        return Err("policy denies inject".into());
    }
    if let Some(t) = caller.token {
        let covered = t.allow_prefix.iter().any(|p| prefix_covers(p, &norm));
        if &t.principal_id != caller.principal
            || !t.allow_ops.contains(&Op::Inject)
            || !covered
            || crate::policy::token_narrows_policy(t, caller.policy).is_err()
        {
            return Err("token denies inject".into());
        }
    }
    Ok(())
}

/// `--no-redact` is for a `human:*` principal with `admin` on every bound
/// path, and never for a token.
fn may_skip_redaction(caller: &Caller<'_>, bindings: &[BindingSpec]) -> bool {
    caller.token.is_none()
        && caller.principal.0.starts_with("human:")
        && bindings.iter().all(|b| {
            matches!(
                evaluate(caller.policy, caller.principal, Op::Admin, &b.path),
                Ok(Verdict::Allow)
            )
        })
}

/// Resolve `argv[0]` against the base `PATH`, canonicalize, and match one
/// `allow_cmds` entry exactly (path, then `sha256` and `args_prefix` when
/// the entry sets them). Shells get no special case. No globs.
///
/// A pinned entry opens `canon` once and hashes that fd; the fd travels in
/// the result so spawn execs the bytes that were hashed (Fix 4). When any
/// rule for that path carries `sha256`, an unpinned rule for the same path
/// is ignored.
///
/// Before that open, the canonical path and every ancestor up to `/` must
/// be owned by uid 0, not group- or other-writable, and not a symlink. The
/// refusal names the first failing component from `/` down. The check runs
/// on Linux and macOS. On macOS there is no `fexecve`, so this is what
/// stops a non-root writer from winning the inode-check window.
/// The production caller stops at `/` and uid 0. A test build can pass
/// another directory and uid; a release build has no such caller.
/// Where a pin's trust walk stops, and the uid that must own that subtree.
/// Production is `/` and uid 0. Tests may pass another absolute directory.
struct TrustAnchor<'a> {
    root: &'a Path,
    uid: u32,
}

#[cfg(test)]
fn match_cmd(
    allow: &[CmdRule],
    argv0: &str,
    args: &[String],
    base_path: Option<&OsStr>,
) -> Result<VerifiedExe, PlanError> {
    match_cmd_trusted(
        allow,
        argv0,
        args,
        base_path,
        TrustAnchor {
            root: Path::new("/"),
            uid: 0,
        },
    )
}

fn match_cmd_trusted(
    allow: &[CmdRule],
    argv0: &str,
    args: &[String],
    base_path: Option<&OsStr>,
    anchor: TrustAnchor<'_>,
) -> Result<VerifiedExe, PlanError> {
    if allow.is_empty() {
        return Err(deny("allow_cmds is empty: nothing may run", None));
    }
    let (found, followed_symlink) = resolve_for_match(argv0, base_path)?;
    let canon = std::fs::canonicalize(&found)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .ok_or_else(|| deny(&format!("argv[0] '{argv0}' cannot be resolved"), None))?;
    let rule = select_rule(allow, &canon, args, argv0, followed_symlink)?;
    let Some(want) = &rule.sha256 else {
        return Ok(VerifiedExe { canon, fd: None });
    };
    ensure_trusted_pin(&canon, anchor.root, anchor.uid)?;
    let pinned =
        open_pinned(Path::new(&canon), want).map_err(|e| pin_mismatch(&canon, e, allow))?;
    Ok(VerifiedExe {
        canon,
        fd: Some(pinned),
    })
}

/// Refuse a relative `argv[0]`. A bare name is resolved on `PATH` later.
fn resolve_for_match(argv0: &str, base_path: Option<&OsStr>) -> Result<(PathBuf, bool), PlanError> {
    if argv0.contains('/') && !Path::new(argv0).is_absolute() {
        return Err(deny(
            &format!("argv[0] '{argv0}' is not an absolute path"),
            None,
        ));
    }
    let found = resolve_argv0(argv0, base_path).ok_or_else(|| {
        deny(
            &format!("argv[0] '{argv0}' is not an executable on PATH"),
            None,
        )
    })?;
    let followed_symlink =
        std::fs::symlink_metadata(&found).is_ok_and(|m| m.file_type().is_symlink());
    Ok((found, followed_symlink))
}

/// Pick the rule that authorizes `canon`. A digest on the path wins over an
/// unpinned rule, so the pin cannot be skipped.
fn select_rule<'a>(
    allow: &'a [CmdRule],
    canon: &str,
    args: &[String],
    argv0: &str,
    followed_symlink: bool,
) -> Result<&'a CmdRule, PlanError> {
    let mut matched: Vec<&CmdRule> = allow.iter().filter(|r| r.path == canon).collect();
    if matched.is_empty() {
        // A bare name may land on a symlink (`/bin/sh` -> dash). That is
        // PATH resolution, reported as not listed. A path the operator
        // named that is itself a symlink, and does not canonicalize to a
        // pin, is the swap.
        if followed_symlink && argv0.contains('/') {
            return Err(deny(
                &format!(
                    "argv[0] '{argv0}' resolves through a symlink to {canon}, which is not pinned"
                ),
                None,
            ));
        }
        return Err(unlisted(allow, canon));
    }
    if matched.iter().any(|r| r.sha256.is_some()) {
        matched.retain(|r| r.sha256.is_some());
    }
    matched
        .into_iter()
        .find(|r| args_match(&r.args_prefix, args))
        .ok_or_else(|| {
            deny(
                &format!("argv[0] {canon} does not match its allow_cmds args_prefix"),
                Some(canon.to_owned()),
            )
        })
}

fn unlisted(allow: &[CmdRule], canon: &str) -> PlanError {
    if allow.iter().all(|r| r.sha256.is_some()) {
        deny(&format!("argv[0] {canon} is not pinned"), None)
    } else {
        deny(&format!("argv[0] {canon} is not in allow_cmds"), None)
    }
}

fn pin_mismatch(canon: &str, err: PinError, allow: &[CmdRule]) -> PlanError {
    match err {
        PinError::Mismatch => deny(
            &format!("argv[0] {canon} does not match its allow_cmds sha256"),
            Some(canon.to_owned()),
        ),
        PinError::Script => deny(
            &format!("argv[0] {canon} is a #! script; a sha256 pin needs a binary"),
            Some(canon.to_owned()),
        ),
        PinError::Unusable
            if std::fs::symlink_metadata(Path::new(canon))
                .is_ok_and(|m| m.file_type().is_symlink()) =>
        {
            deny(
                &format!("argv[0] {canon} is a symlink; a sha256 pin opens the pinned file only"),
                Some(canon.to_owned()),
            )
        }
        PinError::Unusable => unlisted(allow, canon),
    }
}

/// One `lstat` of a path component. `mode` is the permission bits only
/// (`st_mode & 0o777`). Symlinks are reported here and are not followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ComponentStat {
    uid: u32,
    mode: u32,
    is_symlink: bool,
}

/// Ownership source for the trusted-path check. Production uses `lstat`.
/// Tests supply a map so they do not need a root-owned tree.
trait PathStat {
    fn stat_nofollow(&self, path: &Path) -> std::io::Result<ComponentStat>;
}

/// `lstat` via `symlink_metadata`: a symlink is visible, not followed.
struct FsStat;

impl PathStat for FsStat {
    fn stat_nofollow(&self, path: &Path) -> std::io::Result<ComponentStat> {
        use std::os::unix::fs::MetadataExt;
        let meta = std::fs::symlink_metadata(path)?;
        Ok(ComponentStat {
            uid: meta.uid(),
            mode: meta.mode() & 0o777,
            is_symlink: meta.file_type().is_symlink(),
        })
    }
}

/// Why a pinned path is not trusted. The path is the failing component.
#[derive(Debug, PartialEq, Eq)]
enum TrustError {
    NotAbsolute(PathBuf),
    Unreadable { path: PathBuf, detail: String },
    Symlink(PathBuf),
    NotRoot(PathBuf),
    NotUid { path: PathBuf, uid: u32 },
    GroupWritable(PathBuf),
    OtherWritable(PathBuf),
    Outside { canon: PathBuf, root: PathBuf },
}

impl TrustError {
    /// One line. Names the component and the reason. No file bytes.
    fn reason(&self) -> String {
        match self {
            Self::NotAbsolute(p) => format!("trusted path: {} is not absolute", p.display()),
            Self::Unreadable { path, detail } => {
                format!(
                    "trusted path: {} cannot be checked: {detail}",
                    path.display()
                )
            }
            Self::Symlink(p) => format!("trusted path: {} is a symlink", p.display()),
            Self::NotRoot(p) => format!("trusted path: {} is not owned by root", p.display()),
            Self::NotUid { path, uid } => {
                format!("trusted path: {} is not owned by uid {uid}", path.display())
            }
            Self::GroupWritable(p) => format!("trusted path: {} is group-writable", p.display()),
            Self::OtherWritable(p) => format!("trusted path: {} is other-writable", p.display()),
            Self::Outside { canon, root } => format!(
                "trusted path: {} is outside {}",
                canon.display(),
                root.display()
            ),
        }
    }
}

/// `/`, then each ancestor, then `canon` itself.
fn trusted_components(canon: &Path) -> Result<Vec<PathBuf>, TrustError> {
    if !canon.is_absolute() {
        return Err(TrustError::NotAbsolute(canon.to_path_buf()));
    }
    let mut out = Vec::new();
    let mut cur = PathBuf::new();
    for c in canon.components() {
        match c {
            std::path::Component::RootDir => cur.push(std::path::MAIN_SEPARATOR_STR),
            std::path::Component::Normal(seg) => cur.push(seg),
            std::path::Component::Prefix(_)
            | std::path::Component::CurDir
            | std::path::Component::ParentDir => {
                return Err(TrustError::NotAbsolute(canon.to_path_buf()));
            }
        }
        out.push(cur.clone());
    }
    if out.is_empty() {
        return Err(TrustError::NotAbsolute(canon.to_path_buf()));
    }
    Ok(out)
}

/// Production walk: uid 0, every component from `canon` up to `/`.
#[cfg(test)]
fn check_trusted_path(canon: &Path, stat: &impl PathStat) -> Result<(), TrustError> {
    check_anchored(canon, stat, Path::new("/"), 0)
}

/// `root` and `uid` are the production pair (`/`, 0) or a test injection.
/// Components strictly above `root` are not checked. The first failure from
/// `root` down is the one reported.
fn check_anchored(
    canon: &Path,
    stat: &impl PathStat,
    root: &Path,
    uid: u32,
) -> Result<(), TrustError> {
    if !root.is_absolute() {
        return Err(TrustError::NotAbsolute(root.to_path_buf()));
    }
    let mut saw_root = false;
    for component in trusted_components(canon)? {
        if !component.starts_with(root) {
            continue;
        }
        saw_root = true;
        let st = stat
            .stat_nofollow(&component)
            .map_err(|e| TrustError::Unreadable {
                path: component.clone(),
                detail: e.to_string(),
            })?;
        reject_component(component, &st, uid)?;
    }
    if !saw_root {
        return Err(TrustError::Outside {
            canon: canon.to_path_buf(),
            root: root.to_path_buf(),
        });
    }
    Ok(())
}

fn reject_component(path: PathBuf, st: &ComponentStat, uid: u32) -> Result<(), TrustError> {
    if st.is_symlink {
        return Err(TrustError::Symlink(path));
    }
    if st.uid != uid {
        return Err(if uid == 0 {
            TrustError::NotRoot(path)
        } else {
            TrustError::NotUid { path, uid }
        });
    }
    let mode = st.mode & 0o777;
    if mode & 0o020 != 0 {
        return Err(TrustError::GroupWritable(path));
    }
    if mode & 0o002 != 0 {
        return Err(TrustError::OtherWritable(path));
    }
    Ok(())
}

fn ensure_trusted_pin(canon: &str, root: &Path, uid: u32) -> Result<(), PlanError> {
    check_anchored(Path::new(canon), &FsStat, root, uid).map_err(|e| {
        deny(
            &format!("argv[0] {canon}: {}", e.reason()),
            Some(canon.to_owned()),
        )
    })
}

/// Why a pinned `argv[0]` failed its check.
#[derive(Debug, PartialEq, Eq)]
enum PinError {
    /// Cannot be opened without following a symlink, or is not a regular
    /// file with an exec bit.
    Unusable,
    Mismatch,
    /// Linux only: `fexecve` on an `O_CLOEXEC` fd cannot start a `#!`
    /// script, and an inheritable fd would leak into the child.
    Script,
}

/// Open `canon` once, check the fd is a regular executable file, and hash
/// it from that fd. `O_NOFOLLOW` refuses a symlink swapped in at the final
/// component after canonicalize. `O_CLOEXEC` keeps the fd out of the child.
fn open_pinned(canon: &Path, want: &str) -> Result<(OwnedFd, Metadata), PinError> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(canon)
        .map_err(|_| PinError::Unusable)?;
    let meta = file.metadata().map_err(|_| PinError::Unusable)?;
    if !meta.is_file() || meta.permissions().mode() & 0o111 == 0 {
        return Err(PinError::Unusable);
    }
    let (digest, head) = hash_fd(&mut file).map_err(|_| PinError::Unusable)?;
    if !digest.eq_ignore_ascii_case(want) {
        return Err(PinError::Mismatch);
    }
    if cfg!(target_os = "linux") && head.starts_with(b"#!") {
        return Err(PinError::Script);
    }
    Ok((file.into(), meta))
}

/// SHA-256 hex of everything read from `file`, streamed, and its first two
/// bytes.
fn hash_fd(file: &mut File) -> std::io::Result<(String, Vec<u8>)> {
    use sha2::{Digest, Sha256};
    use std::io::Read as _;
    let mut hasher = Sha256::new();
    let mut head = Vec::with_capacity(2);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        let take = (2 - head.len()).min(n);
        head.extend_from_slice(&buf[..take]);
        hasher.update(&buf[..n]);
    }
    Ok((to_hex(&hasher.finalize()), head))
}

fn args_match(prefix: &[String], args: &[String]) -> bool {
    args.len() >= prefix.len() && prefix.iter().zip(args).all(|(p, a)| p == a)
}

fn resolve_argv0(argv0: &str, base_path: Option<&OsStr>) -> Option<PathBuf> {
    if argv0.is_empty() {
        return None;
    }
    if argv0.contains('/') {
        let p = PathBuf::from(argv0);
        return (p.is_absolute() && is_exec(&p)).then_some(p);
    }
    let path = base_path?;
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(argv0))
        .find(|p| is_exec(p))
}

fn is_exec(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

fn to_hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decrypt one binding's object straight into a `SecretBox`.
fn decrypt(vault: &VaultView<'_>, b: &BindingSpec) -> Result<SecretBox<[u8]>, PlanError> {
    let norm = crate::policy::normalize_path(&b.path)
        .map_err(|_| PlanError::Usage(format!("binding {}: bad vault path", b.name)))?;
    let entry = vault
        .manifest
        .entries
        .iter()
        .find(|e| e.path == norm)
        .ok_or_else(|| {
            PlanError::Usage(format!("binding {}: {norm} is not in the vault", b.name))
        })?;
    let raw =
        corevault::read_object(vault.root, vault.epoch, &entry.object_id).map_err(|e| match e {
            crate::Error::AuthFail => PlanError::Auth,
            _ => PlanError::Usage(format!("binding {}: cannot read {norm}", b.name)),
        })?;
    if raw.len() < HEADER_SIZE {
        return Err(PlanError::Auth);
    }
    let bind: &[u8] = if entry.bind {
        entry.path.as_bytes()
    } else {
        b""
    };
    let (_, plain) = object::open_object(vault.ek, &raw[..HEADER_SIZE], &raw[HEADER_SIZE..], bind)
        .map_err(|_| PlanError::Auth)?;
    Ok(SecretBox::new(plain.into_boxed_slice()))
}

/// One redacted, capped output stream.
struct Capped<'a> {
    stream: Option<NamedStream<'a>>,
    emitted: usize,
    truncated: bool,
}

impl Capped<'_> {
    fn cap(&mut self, bytes: Vec<u8>) -> Vec<u8> {
        if self.truncated {
            return Vec::new();
        }
        let room = OUTPUT_CAP - self.emitted;
        if bytes.len() <= room {
            self.emitted += bytes.len();
            return bytes;
        }
        self.truncated = true;
        self.emitted = OUTPUT_CAP;
        let mut out = bytes[..room].to_vec();
        out.extend_from_slice(TRUNCATED_MARK);
        out
    }
}

/// Redacts and caps child output for one run. Feed it every chunk, then
/// call [`Collector::finish`]. The transport decides where bytes go.
pub struct Collector<'a> {
    out: Capped<'a>,
    err: Capped<'a>,
}

impl std::fmt::Debug for Collector<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Collector")
            .field("truncated", &self.truncated())
            .finish_non_exhaustive()
    }
}

/// Which stream a chunk belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    Stdout,
    Stderr,
}

impl<'a> Collector<'a> {
    #[must_use]
    pub fn new(plan: &'a Plan) -> Self {
        let mk = || Capped {
            stream: plan.redactor.as_ref().map(NamedRedactor::stream),
            emitted: 0,
            truncated: false,
        };
        Self {
            out: mk(),
            err: mk(),
        }
    }

    fn side(&mut self, ch: Channel) -> &mut Capped<'a> {
        match ch {
            Channel::Stdout => &mut self.out,
            Channel::Stderr => &mut self.err,
        }
    }

    /// Redact `chunk` and return the bytes that are safe to emit now.
    #[must_use]
    pub fn push(&mut self, ch: Channel, chunk: &[u8]) -> Vec<u8> {
        let side = self.side(ch);
        let bytes = match side.stream.as_mut() {
            Some(s) => s.push(chunk),
            None => chunk.to_vec(),
        };
        side.cap(bytes)
    }

    /// Flush the redactor tail of `ch`.
    #[must_use]
    pub fn finish(&mut self, ch: Channel) -> Vec<u8> {
        let side = self.side(ch);
        let bytes = side
            .stream
            .as_mut()
            .map(NamedStream::finish)
            .unwrap_or_default();
        side.cap(bytes)
    }

    /// Whether either stream passed the cap.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.out.truncated || self.err.truncated
    }

    /// Hits per binding name across both streams.
    #[must_use]
    pub fn hits(&self) -> BTreeMap<String, u64> {
        let mut all = BTreeMap::new();
        for s in [&self.out, &self.err] {
            if let Some(stream) = &s.stream {
                for (k, v) in stream.hits() {
                    *all.entry(k).or_insert(0) += v;
                }
            }
        }
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{default_policy, DefaultVerdict, PrincipalGrant};

    fn human() -> PrincipalId {
        PrincipalId("human:local".into())
    }

    fn bindings(pairs: &[(&str, &str)]) -> Vec<BindingSpec> {
        pairs
            .iter()
            .map(|(n, p)| BindingSpec {
                name: (*n).into(),
                path: (*p).into(),
            })
            .collect()
    }

    fn sh_rule() -> (CmdRule, String) {
        let canon = std::fs::canonicalize("/bin/sh").unwrap();
        let canon = canon.to_str().unwrap().to_owned();
        (
            CmdRule {
                path: canon.clone(),
                sha256: None,
                args_prefix: Vec::new(),
            },
            canon,
        )
    }

    // Name and hosts checks come before any vault access, so an empty
    // manifest and a zero key are enough.
    fn try_plan(
        policy: &Policy,
        cmds: &[CmdRule],
        hosts: &[String],
        b: &[BindingSpec],
        argv: &[&str],
    ) -> Result<Plan, PlanError> {
        let root = std::env::temp_dir();
        let ek = EpochKey::from_bytes([0u8; 32]);
        let manifest = Manifest {
            vault_id: crate::kdf::VaultId([0x01; 16]),
            epoch: Epoch(1),
            suite: crate::SUITE_0X01,
            flags: 0,
            generated_at: 0,
            generator: "test".into(),
            root: [0u8; 32],
            entry_count: 0,
            total_plain_bytes: 0,
            total_cipher_bytes: 0,
            entries: Vec::new(),
        };
        let principal = human();
        let caller = Caller {
            principal: &principal,
            policy,
            token: None,
            allow_cmds: cmds,
            allow_hosts: hosts,
            redact: RedactLevel::Strict,
            enforce_hosts: false,
        };
        let vault = VaultView {
            root: &root,
            ek: &ek,
            epoch: Epoch(1),
            manifest: &manifest,
        };
        let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        let path = std::env::var_os("PATH");
        plan(
            &caller,
            &vault,
            &PlanRequest {
                bindings: b,
                argv: &argv,
                base_path: path.as_deref(),
                no_redact: false,
            },
        )
    }

    #[test]
    fn names_are_checked_first() {
        let p = default_policy("v");
        let (rule, _) = sh_rule();
        for (name, why) in [
            ("lower", "charset"),
            ("1ABC", "leading digit"),
            ("PATH", "reserved"),
            ("GEODE_X", "reserved prefix"),
            ("LD_PRELOAD", "reserved prefix"),
            ("DYLD_X", "reserved prefix"),
        ] {
            let r = try_plan(
                &p,
                std::slice::from_ref(&rule),
                &[],
                &bindings(&[(name, "cfg/x")]),
                &["sh"],
            );
            assert!(matches!(r, Err(PlanError::Usage(_))), "{why}: {r:?}");
        }
        let dup = bindings(&[("KEY", "cfg/a"), ("KEY", "cfg/b")]);
        assert!(matches!(
            try_plan(&p, std::slice::from_ref(&rule), &[], &dup, &["sh"]),
            Err(PlanError::Usage(_))
        ));
        assert!(matches!(
            try_plan(&p, &[rule], &[], &[], &["sh"]),
            Err(PlanError::Usage(_))
        ));
    }

    #[test]
    fn empty_argv_is_usage() {
        let (rule, _) = sh_rule();
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &[],
        );
        assert!(
            matches!(r, Err(PlanError::Usage(ref m)) if m == "no command after --"),
            "{r:?}"
        );
    }

    #[test]
    fn hosts_label_empty_is_unrestricted() {
        assert_eq!(hosts_label(&[]), "unrestricted");
        assert_eq!(
            hosts_label(&["a.example".into(), "b.example:443".into()]),
            "a.example,b.example:443"
        );
    }

    #[test]
    fn allow_hosts_refuses() {
        let (rule, _) = sh_rule();
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &["api.example.com".into()],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh"],
        );
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, .. }) if reason.contains("allow_hosts")),
            "{r:?}"
        );
    }

    #[test]
    fn policy_deny_before_cmd_match() {
        let policy = Policy {
            version: 1,
            vault_id: "v".into(),
            default: DefaultVerdict::Deny,
            principals: vec![PrincipalGrant {
                id: human(),
                ops: vec![Op::List, Op::Read],
                prefixes: vec![String::new()],
                max_bytes: None,
                max_calls_per_10s: None,
            }],
        };
        let (rule, _) = sh_rule();
        let r = try_plan(
            &policy,
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh"],
        );
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, .. }) if reason.contains("policy denies inject")),
            "{r:?}"
        );
    }

    #[test]
    fn empty_or_unlisted_allow_cmds_deny() {
        let p = default_policy("v");
        let b = bindings(&[("KEY", "cfg/x")]);
        let r = try_plan(&p, &[], &[], &b, &["sh"]);
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, .. }) if reason.contains("allow_cmds is empty")),
            "{r:?}"
        );
        let other = CmdRule {
            path: "/nonexistent/geode".into(),
            sha256: None,
            args_prefix: Vec::new(),
        };
        let r = try_plan(&p, &[other], &[], &b, &["sh"]);
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, .. }) if reason.contains("not in allow_cmds")),
            "{r:?}"
        );
    }

    #[test]
    fn matched_cmd_reaches_decrypt() {
        let (rule, _) = sh_rule();
        // The empty manifest has no cfg/x: authorization and the cmd match
        // passed, so the miss is a usage error naming the binding.
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh"],
        );
        assert!(
            matches!(r, Err(PlanError::Usage(ref m)) if m.contains("binding KEY")),
            "{r:?}"
        );
    }

    #[test]
    fn args_prefix_must_match() {
        let (mut rule, _) = sh_rule();
        rule.args_prefix = vec!["-c".into(), "true".into()];
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh", "-c", "false"],
        );
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, .. }) if reason.contains("args_prefix")),
            "{r:?}"
        );
    }

    #[test]
    fn relative_argv0_is_refused() {
        let (rule, _) = sh_rule();
        let r = match_cmd(&[rule], "./sh", &[], Some(OsStr::new("/bin")));
        let Err(PlanError::Deny { reason, .. }) = r else {
            panic!("relative argv0 was allowed");
        };
        assert!(reason.contains("not an absolute path"), "{reason}");
    }

    #[test]
    fn pinned_list_refuses_a_different_path() {
        let (mut rule, _) = sh_rule();
        rule.path = "/nonexistent/geode-pin".into();
        rule.sha256 = Some("ab".repeat(32));
        let r = match_cmd(
            std::slice::from_ref(&rule),
            "sh",
            &[],
            Some(OsStr::new("/bin")),
        );
        let Err(PlanError::Deny { reason, .. }) = r else {
            panic!("an unpinned path was allowed");
        };
        assert!(reason.contains("is not pinned"), "{reason}");
    }

    #[test]
    fn unpinned_rule_does_not_bypass_a_pin() {
        let (unpinned, _) = sh_rule();
        let mut pinned = unpinned.clone();
        pinned.sha256 = Some("00".repeat(32));
        let r = match_cmd(&[unpinned, pinned], "sh", &[], Some(OsStr::new("/bin")));
        let Err(PlanError::Deny { reason, .. }) = r else {
            panic!("an unpinned rule bypassed the pin");
        };
        assert!(reason.contains("sha256"), "{reason}");
    }

    #[test]
    fn symlink_to_a_different_file_is_not_pinned() {
        let (_real_dir, real) = file_in("real", b"\x7fELF-real", 0o755);
        let (_other_dir, other) = file_in("other", b"\x7fELF-other", 0o755);
        let link = other.with_file_name("via-link");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        let rule = CmdRule {
            path: real.to_str().unwrap().to_owned(),
            sha256: Some(sha_of(&real)),
            args_prefix: Vec::new(),
        };
        let r = match_cmd(
            std::slice::from_ref(&rule),
            link.to_str().unwrap(),
            &[],
            None,
        );
        let Err(PlanError::Deny { reason, .. }) = r else {
            panic!("a symlink to a different file was allowed");
        };
        assert!(reason.contains("symlink"), "{reason}");
        assert!(reason.contains("not pinned"), "{reason}");
        assert!(!reason.contains("ELF"), "{reason}");
    }

    fn sha_of(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        to_hex(&Sha256::digest(std::fs::read(path).unwrap()))
    }

    /// A temp dir holding `name` with `body` at `mode`.
    fn file_in(name: &str, body: &[u8], mode: u32) -> (tempfile::TempDir, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let dir = std::fs::canonicalize(tmp.path()).unwrap();
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(mode)).unwrap();
        (tmp, p)
    }

    #[test]
    fn pinned_cmd_with_the_right_hash_carries_its_fd() {
        let (mut rule, canon) = sh_rule();
        rule.sha256 = Some(sha_of(Path::new(&canon)).to_ascii_uppercase());
        let v = match_cmd(
            std::slice::from_ref(&rule),
            "sh",
            &[],
            Some(OsStr::new("/bin")),
        )
        .unwrap();
        assert_eq!(v.canon, canon);
        assert!(
            v.fd.is_some(),
            "a pinned rule must hand spawn the hashed fd"
        );
        // The rest of the plan runs as before.
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh"],
        );
        assert!(
            matches!(r, Err(PlanError::Usage(ref m)) if m.contains("binding KEY")),
            "{r:?}"
        );
    }

    #[test]
    fn pinned_cmd_with_the_wrong_hash_denies() {
        let (mut rule, canon) = sh_rule();
        rule.sha256 = Some("00".repeat(32));
        let r = try_plan(
            &default_policy("v"),
            &[rule],
            &[],
            &bindings(&[("KEY", "cfg/x")]),
            &["sh"],
        );
        assert!(
            matches!(r, Err(PlanError::Deny { ref reason, exe: Some(ref e) })
                if reason.contains("sha256") && *e == canon),
            "{r:?}"
        );
    }

    #[test]
    fn take_pin_hands_the_fd_out_once() {
        let canon = std::fs::canonicalize("/bin/sh").unwrap();
        let mut p = Plan {
            exe: canon.to_str().unwrap().to_owned(),
            args: Vec::new(),
            env: Vec::new(),
            paths: Vec::new(),
            redactor: None,
            pin: Some(open_pinned(&canon, &sha_of(&canon)).unwrap()),
        };
        assert!(p.take_pin().is_some());
        assert!(p.take_pin().is_none());
    }

    #[test]
    fn unpinned_cmd_execs_by_path() {
        let (rule, canon) = sh_rule();
        let v = match_cmd(&[rule], "sh", &[], Some(OsStr::new("/bin"))).unwrap();
        assert_eq!(v.canon, canon);
        assert!(v.fd.is_none());
    }

    #[test]
    fn symlink_swapped_in_at_the_final_component_is_refused() {
        let canon = std::fs::canonicalize("/bin/sh").unwrap();
        let want = sha_of(&canon);
        let (_tmp, real) = file_in("real", &std::fs::read(&canon).unwrap(), 0o755);
        assert!(open_pinned(&real, &want).is_ok());
        // What canonicalize returned is now a symlink to a file with the
        // same bytes. O_NOFOLLOW refuses it anyway.
        let link = real.with_file_name("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(open_pinned(&link, &want).unwrap_err(), PinError::Unusable);
    }

    #[test]
    fn hash_is_streamed_from_the_fd() {
        // Larger than the read buffer, so the hash spans several reads.
        let body: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (_tmp, p) = file_in("big", &body, 0o755);
        let want = sha_of(&p);
        let mut f = File::open(&p).unwrap();
        // With the path gone and replaced, only the fd can give the bytes.
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, b"other").unwrap();
        let (got, head) = hash_fd(&mut f).unwrap();
        assert_eq!(got, want);
        assert_eq!(head, body[..2]);
    }

    #[test]
    fn pinned_non_executable_is_refused() {
        let (_tmp, p) = file_in("plain", b"\x7fELF", 0o644);
        assert_eq!(
            open_pinned(&p, &sha_of(&p)).unwrap_err(),
            PinError::Unusable
        );
    }

    #[test]
    fn pinned_script_is_refused_on_linux() {
        let (_tmp, p) = file_in("s.sh", b"#!/bin/sh\necho hi\n", 0o755);
        let r = open_pinned(&p, &sha_of(&p));
        if cfg!(target_os = "linux") {
            assert_eq!(r.unwrap_err(), PinError::Script);
        } else {
            assert!(r.is_ok(), "{r:?}");
        }
    }

    /// Map stand-in for [`PathStat`]. Missing paths fail closed.
    struct FakeStat(BTreeMap<PathBuf, ComponentStat>);

    impl PathStat for FakeStat {
        fn stat_nofollow(&self, path: &Path) -> std::io::Result<ComponentStat> {
            self.0.get(path).copied().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "no stat for component")
            })
        }
    }

    /// A fully root-owned tree, then one component overwritten.
    fn trust_tree(leaf: &str) -> FakeStat {
        let comps = trusted_components(Path::new(leaf)).unwrap();
        let map = comps
            .into_iter()
            .map(|p| {
                (
                    p,
                    ComponentStat {
                        uid: 0,
                        mode: 0o755,
                        is_symlink: false,
                    },
                )
            })
            .collect();
        FakeStat(map)
    }

    fn trust_reason(leaf: &str, stat: &FakeStat) -> String {
        check_trusted_path(Path::new(leaf), stat)
            .unwrap_err()
            .reason()
    }

    #[test]
    fn trusted_path_rejects_group_writable_ancestor() {
        let leaf = "/usr/local/bin/tool";
        let mut stat = trust_tree(leaf);
        stat.0.insert(
            PathBuf::from("/usr/local"),
            ComponentStat {
                uid: 0,
                mode: 0o775,
                is_symlink: false,
            },
        );
        let reason = trust_reason(leaf, &stat);
        assert!(reason.contains("/usr/local"), "{reason}");
        assert!(reason.contains("group-writable"), "{reason}");
        assert!(!reason.contains("/usr/local/bin"), "{reason}");
    }

    #[test]
    fn trusted_path_rejects_other_writable_binary() {
        let leaf = "/usr/local/bin/tool";
        let mut stat = trust_tree(leaf);
        stat.0.insert(
            PathBuf::from(leaf),
            ComponentStat {
                uid: 0,
                mode: 0o757,
                is_symlink: false,
            },
        );
        let reason = trust_reason(leaf, &stat);
        assert!(reason.contains(leaf), "{reason}");
        assert!(reason.contains("other-writable"), "{reason}");
    }

    #[test]
    fn trusted_path_rejects_non_root_owner() {
        let leaf = "/usr/local/bin/tool";
        let mut stat = trust_tree(leaf);
        stat.0.insert(
            PathBuf::from(leaf),
            ComponentStat {
                uid: 1000,
                mode: 0o755,
                is_symlink: false,
            },
        );
        let reason = trust_reason(leaf, &stat);
        assert!(reason.contains(leaf), "{reason}");
        assert!(reason.contains("not owned by root"), "{reason}");
    }

    #[test]
    fn trusted_path_rejects_symlinked_ancestor() {
        let leaf = "/usr/local/bin/tool";
        let mut stat = trust_tree(leaf);
        // A symlink's mode is often 0777. The symlink itself is the failure,
        // not the write bits.
        stat.0.insert(
            PathBuf::from("/usr/local"),
            ComponentStat {
                uid: 0,
                mode: 0o777,
                is_symlink: true,
            },
        );
        let reason = trust_reason(leaf, &stat);
        assert!(reason.contains("/usr/local"), "{reason}");
        assert!(reason.contains("is a symlink"), "{reason}");
        assert!(!reason.contains("writable"), "{reason}");
    }

    #[test]
    fn trusted_path_accepts_root_owned_path() {
        let leaf = "/usr/bin/tool";
        let stat = trust_tree(leaf);
        assert!(check_trusted_path(Path::new(leaf), &stat).is_ok());
    }

    #[test]
    fn trusted_path_real_system_shell_is_accepted() {
        let canon = std::fs::canonicalize("/bin/sh").unwrap();
        check_trusted_path(&canon, &FsStat).unwrap_or_else(|e| panic!("{}", e.reason()));
    }

    #[test]
    fn trusted_path_real_user_tree_is_rejected() {
        let (_tmp, p) = file_in("tool", b"\x7fELF", 0o755);
        let reason = check_trusted_path(&p, &FsStat).unwrap_err().reason();
        assert!(reason.contains("trusted path"), "{reason}");
        assert!(
            reason.contains("other-writable")
                || reason.contains("group-writable")
                || reason.contains("not owned by root")
                || reason.contains("is a symlink"),
            "{reason}"
        );
    }

    #[test]
    fn trusted_path_user_owned_pin_is_refused_before_exec() {
        let (_tmp, p) = file_in("tool", b"\x7fELF", 0o755);
        let canon = p.to_str().unwrap().to_owned();
        let rule = CmdRule {
            path: canon.clone(),
            sha256: Some(sha_of(&p)),
            args_prefix: Vec::new(),
        };
        let err = match match_cmd(std::slice::from_ref(&rule), &canon, &[], None) {
            Err(e) => e,
            Ok(_) => panic!("user-owned pin was allowed"),
        };
        match err {
            PlanError::Deny { reason, exe } => {
                assert!(reason.contains("trusted path"), "{reason}");
                assert_eq!(exe.as_deref(), Some(canon.as_str()));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn trusted_path_injected_root_accepts_user_tree() {
        let leaf = "/tmp/pin-root/bin/tool";
        let mut stat = trust_tree(leaf);
        for path in ["/tmp/pin-root", "/tmp/pin-root/bin", leaf] {
            stat.0.insert(
                PathBuf::from(path),
                ComponentStat {
                    uid: 1000,
                    mode: 0o755,
                    is_symlink: false,
                },
            );
        }
        let root = Path::new("/tmp/pin-root");
        assert!(check_anchored(Path::new(leaf), &stat, root, 1000).is_ok());
        stat.0.insert(
            PathBuf::from("/tmp/pin-root/bin"),
            ComponentStat {
                uid: 1000,
                mode: 0o775,
                is_symlink: false,
            },
        );
        let reason = check_anchored(Path::new(leaf), &stat, root, 1000)
            .unwrap_err()
            .reason();
        assert!(reason.contains("/tmp/pin-root/bin"), "{reason}");
        assert!(reason.contains("group-writable"), "{reason}");
    }

    #[test]
    fn trusted_path_real_untrusted_trees_are_refused() {
        use std::os::unix::fs::PermissionsExt;
        // `$TMPDIR` on a macOS runner is `/var/folders/.../T`, not the
        // sticky world-writable `/tmp` this case has to refuse. `/tmp` is
        // a symlink to `/private/tmp` there. A missing or unexpected `/tmp`
        // fails the test.
        let canon_tmp = canonical_sticky_tmp();
        let base = canon_tmp.join(format!("geode-trust-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let file = base.join("tool");
        std::fs::write(&file, b"\x7fELF").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o755)).unwrap();
        let user = check_trusted_path(&file, &FsStat).unwrap_err().reason();
        assert!(user.contains("trusted path"), "{user}");

        let in_tmp = canon_tmp.join(format!("geode-trust-file-{}", std::process::id()));
        std::fs::write(&in_tmp, b"\x7fELF").unwrap();
        let tmp_reason = check_trusted_path(&in_tmp, &FsStat).unwrap_err().reason();
        assert!(tmp_reason.contains("trusted path"), "{tmp_reason}");
        let _ = std::fs::remove_file(&in_tmp);

        for mode in [0o775_u32, 0o777] {
            let anc = base.join(format!("m{mode:o}"));
            std::fs::create_dir(&anc).unwrap();
            std::fs::set_permissions(&anc, std::fs::Permissions::from_mode(mode)).unwrap();
            let nested = anc.join("tool");
            std::fs::write(&nested, b"\x7fELF").unwrap();
            let reason = check_trusted_path(&nested, &FsStat).unwrap_err().reason();
            assert!(reason.contains("trusted path"), "{mode:o} {reason}");
        }

        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let tool = real.join("tool");
        std::fs::write(&tool, b"\x7fELF").unwrap();
        let link = base.join("via");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let via = link.join("tool");
        let reason = check_trusted_path(&via, &FsStat).unwrap_err().reason();
        assert!(reason.contains("trusted path"), "{reason}");
        let _ = std::fs::remove_dir_all(&base);
    }

    /// Canonical `/tmp`. macOS resolves the symlink to `/private/tmp`.
    /// Fails if `/tmp` cannot be resolved, is some other directory, or
    /// cannot be written.
    fn canonical_sticky_tmp() -> PathBuf {
        let canon = std::fs::canonicalize("/tmp")
            .unwrap_or_else(|e| panic!("cannot canonicalize /tmp: {e}"));
        assert!(
            canon == Path::new("/tmp") || canon == Path::new("/private/tmp"),
            "/tmp canonicalized to {}, not /tmp or /private/tmp",
            canon.display()
        );
        let probe = canon.join(format!(".geode-tmp-probe-{}", std::process::id()));
        std::fs::write(&probe, b"x").unwrap_or_else(|e| panic!("cannot write /tmp: {e}"));
        std::fs::remove_file(&probe).unwrap_or_else(|e| panic!("cannot remove /tmp probe: {e}"));
        canon
    }
}
