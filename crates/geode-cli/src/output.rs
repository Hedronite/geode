//! Human-facing CLI output — text and error chrome for `geode`.
//!
//! Owner: frontend-geode (G0c, G4). `geode-cli` calls these helpers; they
//! never print secret material (ISK/FEK/passphrase/token/wrap bytes). The
//! JSON event path (`--output json`) lands in G3 with the verb modules; this
//! module owns the *human* text surface and the exit-code family (05-cli §3).
//!
//! G0c ships the exit-code table and the `tui` stub. The usage/auth error
//! printers, footer line, and `GEODE_PASSPHRASE` warning land in G4 with the
//! passphrase and error chrome, wired from the G3 verb modules — kept out
//! here until they have callers so `clippy -D warnings` stays green.

use std::io::Write;

/// Exit codes — 05-cli §3. Scripts MUST distinguish 2 from 1.
/// `USAGE` is live in G0c (the `tui` stub); the rest are used by G3/G4 verb
/// modules and are `#[allow(dead_code)]` until those land.
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
pub fn tui_unavailable() -> ! {
    let mut err = std::io::stderr().lock();
    let _ = writeln!(
        err,
        "geode: `tui` is not available in this build (profile `core`). \
         See `geode --help` for the verbs this build ships."
    );
    std::process::exit(exit::USAGE);
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
}
