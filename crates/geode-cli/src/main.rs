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
//! v0.2.2 G2c: `agent` subcommand help chrome is frontend-owned (clap
//! shapes in this file) so `geode agent --help` documents the agent plane
//! verbs (06-agent-plane: serve, token issue/inspect, read/write/list).
//! Fullstack G1 (PR #20) wired `cmd::agent::run` for serve/read/write/list;
//! the chrome here MUST stay in sync with the shipped verbs. `--token`/
//! `GEODE_TOKEN` is scoped to the token-gated agent verbs, NOT a global clap
//! flag, so `geode tui` cannot gain a `--token` unlock path (14-tui §1.4:
//! the TUI is a human surface). `geode agent scope` is token-free (shadow
//! Jev remainder only) and the TUI stays Jev-free.
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
    about = "Geode — Hedronite file custody (GDE1, suite 0x01)",
    long_about = concat!(
        "Geode — Hedronite file custody (GDE1, suite 0x01).\n",
        "\n",
        "Agent plane (geode agent serve --stdio) is driven from a Facet ",
        "collection; see examples/facet-geode.yaml for a worked example ",
        "with secret-hydrated vars. No key bytes in this help."
    )
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

/// Built-in TUI palette selector for `geode tui --appearance` (14-tui §11).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum AppearanceArg {
    /// Graphite Honey — dark (default).
    Graphite,
    /// Porcelain Honey — light.
    Porcelain,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate an identity key file (GKEY, raw form, 0600).
    Keygen(cmd::key::KeygenArgs),
    /// Vault lifecycle (init, recipients, add-recipient, rotate).
    Vault(cmd::vault::VaultArgs),
    /// Git sidecar (init, add, status, unlock, lock).
    ///
    /// GitHub still sees counts, sizes, tree, times, and recipient key ids.
    /// That is not plaintext. Optional hooks are local only.
    Git(cmd::git::GitArgs),
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
    /// Named manifest snapshots (create/ls, 04-vault 7).
    Snapshot(cmd::snapshot::SnapshotArgs),
    /// Delete objects unreferenced by the manifest and all snapshots.
    Gc(cmd::snapshot::GcArgs),
    /// Manage the keyring (named identity keys, 05-cli 2.1).
    Keyring(KeyringArgs),
    /// Policy document (10-policy): show the effective policy, seal a new
    /// one, or dry-run an op against it.
    Policy(PolicyArgs),
    /// Mount a vault at MOUNTPOINT (08-mount). On Linux with feature
    /// `fuse`, this runs a real FUSE session: foreground is the default
    /// and blocks until unmount; `--daemon` forks and writes a pid file
    /// (08-mount 3, 6). Default is READ-WRITE: omitting `--read-only`
    /// accepts a read-write mount (copy-on-write chunk writes, manifest
    /// mutations, fsync per 08-mount 3). Pass `--read-only` for a
    /// read-only mount — the recommended default for agent-adjacent
    /// mounts (08-mount 7). Darwin is unsupported (exit 1); macOS live
    /// FUSE is a later slice. Windows / WinFsp is not offered. Every
    /// attempt prints the UID-bypass warning FIRST, before any refusal:
    ///
    ///   warning: a mount is a policy bypass for any process of that UID
    ///   (08-mount 7)
    ///
    /// Unmount before leaving agents unsupervised. No key bytes in this help.
    Mount {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Mountpoint directory.
        #[arg(value_name = "MOUNTPOINT")]
        mountpoint: PathBuf,
        /// Mount read-only. Omitting this flag mounts READ-WRITE;
        /// `--read-only` is the recommended default for agent-adjacent
        /// mounts (08-mount 7).
        #[arg(long)]
        read_only: bool,
        /// Fork to background and write a pid file (08-mount 6; Linux
        /// feature `fuse` only).
        #[arg(long)]
        daemon: bool,
    },
    /// Unmount a mounted vault (fusermount3 / umount, 08-mount 3).
    Unmount {
        /// Mountpoint directory.
        #[arg(value_name = "MOUNTPOINT")]
        mountpoint: PathBuf,
    },
    /// Agent plane (06-agent-plane): serve MCP over stdio/socket, issue and
    /// inspect scoped tokens, and run the read/write/list tool verbs under a
    /// token. Help chrome is frontend-owned (G2c); dispatch is wired by
    /// fullstack G1 (PR #20) to `cmd::agent::run`.
    Agent(AgentArgs),
    /// Ratatui operator surface (14-tui). With the `tui` feature off
    /// (core-profile build) this prints "not available" and exits 1.
    ///
    /// Invariant (14-tui §1.4, §10): the TUI is a **human** surface. It
    /// unlocks in-process via `--key` + passphrase, never via `--token`.
    /// `--token` is deliberately NOT a global clap arg here (it would leak
    /// into the TUI subcommand); it lives on the agent verbs only. The TUI
    /// MUST NOT gain a `--token` unlock path or any agent-verb surface.
    Tui {
        /// Vault to open; omit for the vault picker.
        #[arg(value_name = "VAULT")]
        vault: Option<PathBuf>,
        /// Built-in palette (14-tui §11). Default: graphite.
        #[arg(
            long,
            value_name = "NAME",
            env = "GEODE_APPEARANCE",
            default_value = "graphite"
        )]
        appearance: AppearanceArg,
        /// Skip the opening splash (14-tui polish; env: `GEODE_TUI_NO_SPLASH=true`).
        #[arg(long, env = "GEODE_TUI_NO_SPLASH")]
        no_splash: bool,
    },
}

impl Commands {
    fn verb(&self) -> &'static str {
        match self {
            Self::Keygen(_) => "keygen",
            Self::Vault(a) => match &a.cmd {
                cmd::vault::VaultCmd::Init(_) => "vault_init",
                cmd::vault::VaultCmd::Recipients(_) => "vault_recipients",
                cmd::vault::VaultCmd::AddRecipient(_) => "vault_add_recipient",
                cmd::vault::VaultCmd::Rotate(_) => "vault_rotate",
            },
            Self::Git(a) => match &a.cmd {
                cmd::git::GitCmd::Init(_) => "git_init",
                cmd::git::GitCmd::Add(_) => "git_add",
                cmd::git::GitCmd::Status(_) => "git_status",
                cmd::git::GitCmd::Unlock(_) => "git_unlock",
                cmd::git::GitCmd::Lock(_) => "git_lock",
            },
            Self::Seal(_) => "seal",
            Self::Open(_) => "open",
            Self::Verify(_) => "verify",
            Self::List(_) => "list",
            Self::Cat(_) => "cat",
            Self::Snapshot(_) => "snapshot",
            Self::Gc(_) => "gc",
            Self::Keyring(_) => "keyring",
            Self::Policy(_) => "policy",
            Self::Mount { .. } => "mount",
            Self::Unmount { .. } => "unmount",
            Self::Agent(_) => "agent",
            Self::Tui { .. } => "tui",
        }
    }
}

/// `geode policy` — policy document verbs (10-policy). Frontend registers
/// the subcommand shape (G2) so `geode policy --help` and `show|set|check
/// --help` list the shipped verbs; fullstack G1 (v0.2.3) wired the real
/// `cmd::policy` module. Help prose chrome is frontend-owned. No key
/// bytes are printed — see `output.rs` (public ids only).
///
/// Break-glass (10-policy 4): rewriting a sealed policy requires
/// `--yes --break-glass` and is printed **loudly** to stderr (never
/// silent); there is no break-glass for tokens. `policy check` deny is
/// `Error::PolicyDeny` → JSON `code: policy_deny`, exit 3.
#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub cmd: PolicyCmd,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCmd {
    /// Print the effective policy (the default when none is sealed).
    Show {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
    },
    /// Seal a JSON policy file into the vault. Rewriting an existing
    /// sealed policy requires `--yes --break-glass` (10-policy 4).
    Set {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Policy JSON file to seal.
        #[arg(long, value_name = "PATH")]
        file: PathBuf,
        /// Confirm the rewrite.
        #[arg(long)]
        yes: bool,
        /// Human override flag (10-policy 4); never applies to tokens.
        #[arg(long)]
        break_glass: bool,
    },
    /// Dry-run: would PRINCIPAL be allowed OP on PATH? Deny exits 3.
    Check {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Principal id (`human:...`, `agent:...`, `h3s:...`, `ci:...`).
        #[arg(long, value_name = "ID")]
        principal: String,
        /// Operation (`list|read|write|mount|verify|admin`).
        #[arg(long, value_name = "OP")]
        op: String,
        /// Vault-relative path.
        #[arg(long, value_name = "PATH")]
        path: String,
    },
}

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

/// `geode agent` — agent plane verbs (05-cli 2.6, 06-agent-plane). Frontend
/// owns the clap help chrome (G2c) so `geode agent --help` documents the
/// verbs; fullstack G1 (PR #20) wired `cmd::agent::run` for serve/read/
/// write/list. No key bytes are printed by this chrome — see `output.rs`
/// (public ids only).
///
/// `--token`/`GEODE_TOKEN` is the agent identity path (05-cli 1). It is
/// scoped to the agent verbs below, NOT a global clap flag, so it cannot
/// reach `geode tui` (14-tui §1.4: the TUI is a human surface).
#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub cmd: AgentCmd,
}

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    /// Serve the MCP tool server (06 §3). Default transport is a Unix socket;
    /// `--stdio` speaks MCP over stdin/stdout for Facet/agent hosts.
    Serve {
        /// Speak MCP over stdin/stdout (no socket).
        #[arg(long)]
        stdio: bool,
        /// Unix socket path (default transport when `--stdio` is absent).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Sealed agent token (hex armor or GTOK); else `$GEODE_TOKEN`.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
    /// Token lifecycle: issue a scoped token, or inspect one.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Read one object (06 §4). Agents SHOULD prefer this over `geode cat`.
    Read {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Object path inside the vault.
        #[arg(value_name = "PATH")]
        path: String,
        /// Sealed agent token (hex armor or GTOK); else `$GEODE_TOKEN`.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
    /// Write stdin as a new object at PATH under an allow prefix (06 §4).
    Write {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Object path inside the vault.
        #[arg(value_name = "PATH")]
        path: String,
        /// Sealed agent token (hex armor or GTOK); else `$GEODE_TOKEN`.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
    /// List entries under a prefix.
    List {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Prefix to list under (optional).
        #[arg(value_name = "PREFIX")]
        prefix: Option<String>,
        /// Sealed agent token (hex armor or GTOK); else `$GEODE_TOKEN`.
        #[arg(long, value_name = "TOKEN")]
        token: Option<String>,
    },
    /// Classify non-prefix remainder (shadow Jev). Code owns prefix / `../`
    /// / TTL / MAC. No `--token` — this verb does not seal, open, or verify.
    /// The TUI stays Jev-free.
    Scope {
        /// Vault-relative path already under an allow prefix.
        #[arg(long, value_name = "PATH")]
        path: String,
        /// Operation (`list|read|write`). Never seal/open/verify.
        #[arg(long, value_name = "OP")]
        op: String,
        /// Path prefix the grant already allows (repeatable). Code-checked.
        #[arg(long, value_name = "PREFIX")]
        allow_prefix: Vec<String>,
        /// Principal id (public). Default `agent:remainder`.
        #[arg(long, value_name = "ID", default_value = "agent:remainder")]
        principal: String,
        /// Declared non-prefix intent (public text; never a token).
        #[arg(long, value_name = "TEXT")]
        intent: Option<String>,
        /// BLAKE3 hex of a write body (not the body).
        #[arg(long, value_name = "HEX")]
        body_digest: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    /// Issue a sealed token (`GTOK…`) for a principal (06 §2). Stdout is the
    /// token or a path; Facet MUST store it `secret: true`.
    Issue {
        /// Vault the token is scoped to.
        #[arg(long, value_name = "DIR")]
        vault: PathBuf,
        /// Principal id (`agent:…`, `h3s:…`, `ci:…`).
        #[arg(long, value_name = "ID")]
        principal: String,
        /// Token lifetime (e.g. `15m`; default 15m, max 12h).
        #[arg(long, value_name = "DURATION", default_value = "15m")]
        ttl: String,
        /// Allowed operation set (comma list: `list,read,write,…`).
        #[arg(long, value_name = "OPS")]
        ops: String,
        /// Path prefix the token allows (repeatable).
        #[arg(long, value_name = "PREFIX")]
        allow_prefix: Vec<String>,
        /// Per-token byte cap for reads/writes (default applies when omitted).
        #[arg(long, value_name = "BYTES")]
        max_bytes: Option<u64>,
    },
    /// Inspect a sealed token: principal, ops, prefixes, ttl, expiry.
    /// Read-only — the TUI mirrors this view (14-tui §6.10); issuance is
    /// CLI-only. Token source: PATH, else `$GEODE_TOKEN`, else stdin.
    Inspect {
        /// Sealed token file to inspect.
        #[arg(value_name = "TOKEN")]
        token: Option<PathBuf>,
        /// Vault the token was issued for (needed to verify the MAC).
        #[arg(long, value_name = "DIR")]
        vault: PathBuf,
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
        Commands::Git(a) => cmd::git::run(a, &cli.global, out),
        Commands::Seal(a) => cmd::seal::run(a, &cli.global, out),
        Commands::Open(a) => cmd::open::run(a, &cli.global, out),
        Commands::Verify(a) => cmd::verify::run(a, &cli.global, out),
        Commands::List(a) => cmd::list::run(a, &cli.global, out),
        Commands::Cat(a) => cmd::list::cat(a, &cli.global, out),
        Commands::Snapshot(a) => cmd::snapshot::run(a, &cli.global, out),
        Commands::Gc(a) => cmd::snapshot::gc(a, &cli.global, out),
        Commands::Keyring(a) => cmd::keyring::run(a, out),
        Commands::Policy(a) => cmd::policy::run(a, &cli.global, out),
        Commands::Mount {
            vault,
            mountpoint,
            read_only,
            daemon,
        } => cmd::mount::mount(vault, mountpoint, *read_only, *daemon, &cli.global, out),
        Commands::Unmount { mountpoint } => cmd::mount::unmount(mountpoint, &cli.global, out),
        Commands::Agent(a) => cmd::agent::run(a, &cli.global, out),
        // Feature on: the TUI starts (14-tui 2), wired with the vault path
        // and the global `--key` / `GEODE_KEY_FILE` identity path (G5). The
        // TUI unlocks in-process via `geode-grotto` (14-tui 3); the CLI stays
        // a thin adapter. Feature off (core-profile build): exit 1, not 2 —
        // 2 is the auth/integrity family.
        #[cfg(feature = "tui")]
        Commands::Tui {
            vault,
            appearance,
            no_splash,
        } => {
            let options = geode_tui::RunOptions {
                appearance: match appearance {
                    AppearanceArg::Graphite => geode_tui::theme::Appearance::Graphite,
                    AppearanceArg::Porcelain => geode_tui::theme::Appearance::Porcelain,
                },
                splash: !no_splash,
            };
            geode_tui::run(vault.as_deref(), cli.global.key.as_deref(), options)
        }
        #[cfg(not(feature = "tui"))]
        Commands::Tui { .. } => output::tui_unavailable(),
    };

    if let Err(err) = result {
        cmd::fail(out, command.verb(), &err);
    }
}
