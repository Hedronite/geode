//! Human-facing CLI output — text and error chrome for `geode`.
//!
//! Owner: frontend-geode (G0c, G4, G5c). `geode-cli` calls these helpers.
//! This module NEVER prints secret material (ISK/FEK/passphrase/token/wrap
//! bytes). It prints only public identifiers (`vault_id`, `key_id`, `epoch`,
//! manifest hash, `object_id` prefix, paths, counts, sizes) and human error
//! text. The JSON event path (`--output json`) lives in `cmd` (G3); this
//! module owns the *human* text surface and the exit-code family (05-cli §3).
//!
//! G4 ships: exit-code table, `tui` stub (G0c), `GEODE_PASSPHRASE` warning,
//! no-echo passphrase prompt, and the human error formatter that names the
//! exit family (2 vs 1).
//!
//! v0.2.0 G0 chrome: the keygen default-path warning (05-cli §2.1) is now
//! frontend-owned copy in `output.rs`, naming the recommended path
//! `~/.config/hedronite/geode/default.gkey`. `cmd/key.rs` keeps its inline
//! `eprintln!` until fullstack wires the helper; the text matches.

use std::io::Write;

use geode_grotto::Error;

/// Exit codes — 05-cli §3. Scripts MUST distinguish 2 from 1.
/// `LOCKED` (5) has no mapping in v0.1.0 (no mount/lock path) and is
/// `#[allow(dead_code)]` until a verb produces it.
#[allow(dead_code)]
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 1;
    pub const AUTH: i32 = 2;
    pub const POLICY: i32 = 3;
    pub const TOKEN: i32 = 4;
    pub const LOCKED: i32 = 5;
}

/// `geode tui` on a build without the `tui` feature (05-cli §2.9, 14-tui §2.3).
/// Prints to stderr and exits 1 — not 2, because 2 is the auth/integrity
/// family and this is a "this build has no TUI" usage condition.
#[cfg(not(feature = "tui"))]
pub fn tui_unavailable() -> ! {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "geode: `tui` is not available in this build (profile `core`). \
         See `geode --help` for the verbs this build ships."
    );
    std::process::exit(exit::USAGE);
}

/// `GEODE_PASSPHRASE` warning (SPEC §5.5, 05-cli §1). Printed to stderr once
/// when the env var is set. The env var is a CI/script escape hatch, not the
/// happy path — it may be visible in process listings.
pub fn warn_passphrase_env() {
    if std::env::var_os("GEODE_PASSPHRASE").is_some() {
        let mut err = std::io::stderr().lock();
        let _ = writeln!(
            err,
            "geode: warning: GEODE_PASSPHRASE is set. Passphrase-from-env is a \
             CI/script escape hatch and may be visible in process listings; \
             prefer `--passphrase-fd` or the no-echo prompt."
        );
    }
}

/// Read a passphrase from the terminal with no echo (G4b, 05-cli §1).
///
/// Uses `rpassword` so we avoid `unsafe` (forbidden workspace-wide). The
/// returned buffer is `Zeroizing` so it is wiped on drop. On a TTY-less
/// host (CI) this returns an error; callers SHOULD then fall back to
/// `--passphrase-fd` or surface the failure — they MUST NOT echo the
/// passphrase. The prompt label is printed to stderr first.
pub fn prompt_passphrase(label: &str) -> std::io::Result<zeroize::Zeroizing<String>> {
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "{label}");
    let _ = err.flush();
    let pass = rpassword::read_password()
        .map(zeroize::Zeroizing::new)
        .map_err(std::io::Error::other)?;
    let _ = writeln!(err);
    Ok(pass)
}

/// The keygen default-path warning (05-cli §2.1). Frontend owns the copy.
///
/// When `geode keygen` is called without an explicit PATH, it writes
/// `./secret.gkey` and warns the operator to move it to the recommended
/// location `~/.config/hedronite/geode/default.gkey`. The warning text
/// MUST name that path so a new operator knows where the key belongs. It
/// never includes key bytes — it is a path recommendation only.
#[must_use]
pub fn keygen_default_path_warning() -> String {
    "warning: writing ./secret.gkey — move it to ~/.config/hedronite/geode/default.gkey".into()
}

/// Print the keygen default-path warning to stderr (05-cli §2.1).
///
/// `cmd/key.rs` keeps an inline `eprintln!` with the same text until fullstack
/// wires this helper; the copy is frontend-owned here either way.
#[allow(dead_code)]
pub fn print_keygen_default_path_warning() {
    eprintln!("{}", keygen_default_path_warning());
}

/// Human error text for a failed verb (G4c, 05-cli §3). Names the exit
/// family so an operator can tell "you typed it wrong" (1) from "the vault
/// is compromised" (2). Never includes key bytes — `Error` variants carry
/// only public context (paths, messages, io errors), never ISK/FEK.
#[must_use]
pub fn human_error(verb: &str, err: &Error) -> String {
    let (family, code) = exit_family(err);
    format!("geode {verb}: {err} (exit {code} — {family})")
}

/// Map a `geode-core::Error` to its exit family label + code (05-cli §3).
/// Mirrors `cmd::map_error` but returns the human label too.
#[must_use]
pub fn exit_family(err: &Error) -> (&'static str, i32) {
    match err {
        Error::AuthFail => ("authentication/integrity failure", exit::AUTH),
        Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => ("not found", exit::USAGE),
        Error::Io(_) => ("io/usage", exit::USAGE),
        Error::Format(m) if m.contains("unknown cipher suite") => {
            ("unsupported suite", exit::AUTH)
        }
        Error::Format(m) if m.contains("unknown magic") => ("authentication/integrity failure", exit::AUTH),
        Error::Format(_) | Error::Crypto(_) | Error::NotImplemented => ("usage", exit::USAGE),
        Error::PolicyDeny => ("policy deny", exit::POLICY),
        Error::TokenInvalid => ("token invalid", exit::TOKEN),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_spec() {
        assert_eq!(exit::OK, 0);
        assert_eq!(exit::USAGE, 1);
        assert_eq!(exit::AUTH, 2);
        assert_eq!(exit::POLICY, 3);
        assert_eq!(exit::TOKEN, 4);
        assert_eq!(exit::LOCKED, 5);
    }

    #[test]
    fn auth_fail_is_exit_2() {
        let (label, code) = exit_family(&Error::AuthFail);
        assert_eq!(code, 2);
        assert!(label.contains("authentication"));
    }

    #[test]
    fn format_usage_is_exit_1() {
        let (label, code) = exit_family(&Error::Format("bad hex".into()));
        assert_eq!(code, 1);
        assert_eq!(label, "usage");
    }

    #[test]
    fn policy_deny_is_exit_3() {
        let (_, code) = exit_family(&Error::PolicyDeny);
        assert_eq!(code, 3);
    }

    #[test]
    fn human_error_names_family() {
        let s = human_error("verify", &Error::AuthFail);
        assert!(s.contains("exit 2"));
        assert!(s.contains("authentication"));
        assert!(!s.contains("ISK"));
    }

    #[test]
    fn keygen_warning_names_recommended_path() {
        let w = keygen_default_path_warning();
        assert!(
            w.contains("~/.config/hedronite/geode/default.gkey"),
            "warning must name the recommended path: {w}",
        );
        assert!(!w.contains("ISK") && !w.contains("FEK"));
    }
}
