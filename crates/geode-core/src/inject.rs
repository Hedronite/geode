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
//! match `argv[0]`, `--no-redact` gate, decrypt, value checks, argv needle
//! check. All pass or nothing is spawned. Errors name binding NAMEs and the
//! canonical `argv[0]` only — never a value or the full argv.

use std::collections::BTreeMap;
use std::ffi::OsStr;
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
    /// The transport can enforce a non-empty `allow_hosts` (Linux custody,
    /// per-child netns and egress proxy). When false, a non-empty list is
    /// refused before spawn. An empty list is unrestricted either way.
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
}

impl std::fmt::Debug for Plan {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let names: Vec<&str> = self.env.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("Plan")
            .field("exe", &self.exe)
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
}

/// Authorize, resolve, decrypt, and check one run. Nothing is spawned here.
///
/// # Errors
///
/// See [`PlanError`]. On any error no value has left this function.
pub fn plan(
    caller: &Caller<'_>,
    vault: &VaultView<'_>,
    req: &PlanRequest<'_>,
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
    let exe = match_cmd(
        caller.allow_cmds,
        &req.argv[0],
        &req.argv[1..],
        req.base_path,
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
fn match_cmd(
    allow: &[CmdRule],
    argv0: &str,
    args: &[String],
    base_path: Option<&OsStr>,
) -> Result<String, PlanError> {
    if allow.is_empty() {
        return Err(deny("allow_cmds is empty: nothing may run", None));
    }
    let found = resolve_argv0(argv0, base_path).ok_or_else(|| {
        deny(
            &format!("argv[0] '{argv0}' is not an executable on PATH"),
            None,
        )
    })?;
    let canon = std::fs::canonicalize(&found)
        .ok()
        .and_then(|p| p.to_str().map(str::to_owned))
        .ok_or_else(|| deny(&format!("argv[0] '{argv0}' cannot be resolved"), None))?;
    let not_listed = || deny(&format!("argv[0] {canon} is not in allow_cmds"), None);
    let rule = allow
        .iter()
        .find(|r| r.path == canon && args_match(&r.args_prefix, args))
        .ok_or_else(not_listed)?;
    if let Some(want) = &rule.sha256 {
        let bytes = std::fs::read(&canon).map_err(|_| not_listed())?;
        if !sha256_hex(&bytes).eq_ignore_ascii_case(want) {
            return Err(deny(
                &format!("argv[0] {canon} does not match its allow_cmds sha256"),
                Some(canon.clone()),
            ));
        }
    }
    Ok(canon)
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

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    let digest = Sha256::digest(data);
    let mut s = String::with_capacity(64);
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
        assert!(matches!(r, Err(PlanError::Deny { .. })), "{r:?}");
    }
}
