//! `geode` — Hedronite custody plane CLI.
//!
//! G0 scaffold stub: clap shell only. Verbs land in G3 (fullstack,
//! `cmd/*.rs`); help/error chrome and `output.rs` are frontend (G0c/G4).
//! Bare `geode` prints help. `geode tui` is not a verb in v0.1.0.

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
    // G0c/G3: subcommands keygen, vault, seal, open, verify, list, cat.
}

fn main() {
    let matches = cli().get_matches();
    // No verbs wired yet. Bare `geode` (or flags only) prints help.
    if matches.subcommand().is_none() {
        cli().print_help().expect("help writes to stdout");
        println!();
    }
}
