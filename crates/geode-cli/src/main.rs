//! `geode` — Hedronite custody plane CLI.
//!
//! G3: data verbs wired (keygen, vault init, seal, open, verify, list, cat)
//! as thin adapters over `geode-core`. `output.rs` and the human error/help
//! chrome stay frontend-owned (G0c/G4). `geode tui` is a stub that exits 1
//! on a `core`-profile build (no `tui` feature) per 05-cli 2.9 / 14-tui 2.3.
//!
//! v0.2.0 G1c: `keyring` subcommand is registered (clap help chrome,
//! frontend-owned) so `--help` lists it. The dispatch stubs to
//! `Error::NotImplemented` (exit 1 usage) until fullstack G1b wires the
//! real `cmd::keyring` module.
//!
//! Exit-code discipline (05-cli 3): clap's default error exit is 2, which
//! collides with the auth/integrity family. We intercept clap errors and
//! force usage/IO/config errors to exit **1** so scripts can distinguish
//! "you typed it wrong" (1) from "the vault is compromised" (2).
//! `--help` and `--version` are successful displays (exit 0), not errors.

mod cmd;
mod output;

use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(
    name = "geode",
    version = concat!(env!("CARGO_PKG_VERSION"), " (GDE1 suite 0x01)"),
    about = "Geode — Hedronite file custody (GDE1, suite 0x01)"
)]
struct Cli {
    #[command(flatten)]
    global: GlobalArgs,
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Args, Clone, Debug)]
pub struct GlobalArgs {
    /// Identity key file.
    #[arg(long, global = true, env = "GEODE_KEY_FILE", value_name = "PATH")]
    pub key: Option<PathBuf>,
    /// Output format.
    #[arg(long, global = true, value_enum, default_value = "text")]
    pub output: OutMode,
    /// Debug output; still redacts secrets.
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum OutMode {
    Text,
    Json,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate an identity key file (GKEY, raw form, 0600).
    Keygen(cmd::key::KeygenArgs),
    /// Vault lifecycle (init).
    Vault(cmd::vault::VaultArgs),
    /// Seal a file or tree into a vault.
    Seal(cmd::seal::SealArgs),
    /// Open a vault out to a directory.
    Open(cmd::open::OpenArgs),
    /// Verify a vault (full / --cheap / --sample P).
    Verify(cmd::verify::VerifyArgs),
    /// List vault entries.
    List(cmd::list::ListArgs),
    /// Print one object to stdout.
    Cat(cmd::list::CatArgs),
    /// Manage the keyring (OS keyring / file 0600 fallback). Not wired in this build.
    Keyring(KeyringArgs),
    /// Ratatui operator surface (not in this build — profile `core`).
    Tui,
}

impl Commands {
    fn verb(&self) -> &'static str {
        match self {
            Self::Keygen(_) => "keygen",
            Self::Vault(_) => "vault_init",
            Self::Seal(_) => "seal",
            Self::Open(_) => "open",
            Self::Verify(_) => "verify",
            Self::List(_) => "list",
            Self::Cat(_) => "cat",
            Self::Keyring(_) => "keyring",
            Self::Tui => "tui",
        }
    }
}

/// `geode keyring` — keyring management (05-cli 2.1). Frontend registers the
/// subcommand shape so `--help` lists it; fullstack G1b wires the real
/// `cmd::keyring` module. Until then the dispatch stubs to
/// `Error::NotImplemented` (exit 1 usage).
#[derive(Args, Debug)]
pub struct KeyringArgs {
    #[command(subcommand)]
    pub cmd: KeyringCmd,
}

#[derive(Subcommand, Debug)]
pub enum KeyringCmd {
    /// List registered identity keys.
    List,
    /// Add a key file to the keyring with a label.
    Add {
        /// Path to the key file.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Label for the key.
        #[arg(long, value_name = "NAME")]
        label: String,
    },
}

fn main() {
    // G4b: warn if GEODE_PASSPHRASE is set (SPEC 5.5, 05-cli 1) - once per
    // invocation, before any passphrase prompt or verb dispatch.
    crate::output::warn_passphrase_env();

    // clap's default Error::exit() uses code 2, which is the auth/integrity
    // family in Geode (05-cli 3). Intercept: --help/--version are successful
    // displays (exit 0); all other clap errors are usage conditions (exit 1).
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            error.print().expect("error writes to stderr");
            let code = match error.kind() {
                ErrorKind::DisplayHelp
                | ErrorKind::DisplayVersion
                | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => output::exit::OK,
                _ => output::exit::USAGE,
            };
            std::process::exit(code);
        }
    };

    let out = cli.global.output;
    let Some(command) = &cli.command else {
        // Bare `geode` prints help (no TUI in v0.1.0).
        use clap::CommandFactory;
        Cli::command().print_help().expect("help writes to stdout");
        println!();
        return;
    };

    let result = match command {
        Commands::Keygen(a) => cmd::key::run(a, out),
        Commands::Vault(a) => cmd::vault::run(a, &cli.global, out),
        Commands::Seal(a) => cmd::seal::run(a, &cli.global, out),
        Commands::Open(a) => cmd::open::run(a, &cli.global, out),
        Commands::Verify(a) => cmd::verify::run(a, &cli.global, out),
        Commands::List(a) => cmd::list::run(a, &cli.global, out),
        Commands::Cat(a) => cmd::list::cat(a, &cli.global, out),
        // G1c stub: keyring verbs are not wired until fullstack G1b lands.
        // `Error::NotImplemented` -> exit 1 (usage) via `cmd::fail`.
        Commands::Keyring(_) => Err(geode_core::Error::NotImplemented),
        // `geode tui` on a build without the `tui` feature: exit 1, not 2.
        Commands::Tui => output::tui_unavailable(),
    };

    if let Err(err) = result {
        cmd::fail(out, command.verb(), &err);
    }
}
