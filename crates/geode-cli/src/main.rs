//! `geode` — Hedronite custody plane CLI.
//!
//! G0 scaffold stub: clap shell only. Verbs land in G3 (fullstack,
//! `cmd/*.rs`); help/error chrome and `output.rs` are frontend (G0c/G4).
//! Bare `geode` prints help. `geode tui` is a stub that exits 1 on a
//! `core`-profile build (no `tui` feature) per 05-cli §2.9 / 14-tui §2.3.
//!
//! Exit-code discipline (05-cli §3): clap's default error exit is 2, which
//! collides with the auth/integrity family. We intercept clap errors and
//! force usage/IO/config errors to exit **1** so scripts can distinguish
//! "you typed it wrong" (1) from "the vault is compromised" (2).
//! `--help` and `--version` are successful displays (exit 0), not errors.

mod output;

use clap::error::ErrorKind;
use clap::{ArgAction, Command};

fn cli() -> Command {
    Command::new("geode")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Geode — Hedronite file custody (GDE1, suite 0x01)")
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(ArgAction::Count)
                .global(true)
                .help("Debug output; still redacts secrets"),
        )
        // G0c: `tui` is a stub on a `core`-profile build. The Ratatui
        // surface is Phase 2 (14-tui); this build has no `tui` feature, so
        // the verb prints "not available" and exits 1 (05-cli §2.9).
        .subcommand(
            Command::new("tui")
                .about("Ratatui operator surface (not in this build — profile `core`)"),
        )
    // G3 (fullstack): subcommands keygen, vault, seal, open, verify, list, cat.
}

fn main() {
    // clap's default Error::exit() uses code 2, which is the auth/integrity
    // family in Geode (05-cli §3). Intercept: --help/--version are successful
    // displays (exit 0); all other clap errors are usage conditions (exit 1).
    let matches = match cli().try_get_matches() {
        Ok(matches) => matches,
        Err(error) => {
            error.print().expect("error writes to stderr");
            let code = match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => output::exit::OK,
                _ => output::exit::USAGE,
            };
            std::process::exit(code);
        }
    };

    match matches.subcommand() {
        // `geode tui` on a build without the `tui` feature: exit 1, not 2.
        Some(("tui", _)) => output::tui_unavailable(),
        // No verb: print help. Bare `geode` stays CLI help (05-cli §2.9).
        None => {
            cli().print_help().expect("help writes to stdout");
            println!();
        }
        // G3: dispatch to cmd modules. Unknown subcommands are caught by
        // clap above (now exit 1, not 2, per 05-cli §3).
        Some(_) => {}
    }
}
