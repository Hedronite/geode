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
    /// Sign a file with the vault identity (Ed25519).
    ///
    /// `pub` writes the public key as PEM. `blob` signs the raw file
    /// bytes. Check with `cosign verify-blob --key pub.pem --signature sig`.
    Sign(cmd::sign::SignArgs),
    /// Open a vault out to a directory.
    Open(cmd::open::OpenArgs),
    /// Verify a vault (full / --cheap / --sample P).
    Verify(cmd::verify::VerifyArgs),
    /// List vault entries.
    List(cmd::list::ListArgs),
    /// Print one object to stdout.
    Cat(cmd::list::CatArgs),
    /// Name the current manifest, or list those names.
    Snapshot(cmd::snapshot::SnapshotArgs),
    /// Delete objects unreferenced by the manifest and all snapshots.
    Gc(cmd::snapshot::GcArgs),
    /// List identity keys, or add one under a label.
    Keyring(KeyringArgs),
    /// Show, seal, or dry-run the vault policy.
    Policy(PolicyArgs),
    /// Mount a vault at a directory.
    ///
    /// On macOS this needs FUSE-T or macFUSE. The default is foreground,
    /// and it blocks until you unmount. `--daemon` forks and writes a pid
    /// file. If neither driver is loaded, mount exits 1 and names the one
    /// it looked for. A build with FUSE support does the same on Linux,
    /// and `fusermount3` unmounts it.
    ///
    /// The default is read-write. Pass `--read-only` when a process other
    /// than you will see the mount. Windows is not offered.
    ///
    /// Every attempt prints this warning before any refusal:
    ///
    ///   warning: a mount is a policy bypass for any process of that UID
    ///
    /// Unmount before leaving other programs unsupervised.
    Mount {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Mountpoint directory.
        #[arg(value_name = "MOUNTPOINT")]
        mountpoint: PathBuf,
        /// Mount read-only. Omit this to mount read-write.
        #[arg(long)]
        read_only: bool,
        /// Fork to the background and write a pid file. Needs a FUSE build.
        #[arg(long)]
        daemon: bool,
    },
    /// Unmount a vault (`fusermount3` on Linux, `umount` on macOS).
    Unmount {
        /// Mountpoint directory.
        #[arg(value_name = "MOUNTPOINT")]
        mountpoint: PathBuf,
    },
    /// Issue a token, or call the vault tools with one.
    ///
    /// `serve` speaks MCP on stdio or a Unix socket. `read`, `write`, and
    /// `list` require a token. `geode tui` does not accept one.
    Agent(AgentArgs),
    /// Run a command with vault secrets in its environment.
    ///
    /// Needs your key, and refuses a token. Put the command after `--`.
    /// Output is redacted. Redaction does not stop a hostile command.
    Run(cmd::run::RunArgs),
    /// Audit log: verify the append-only hash chain.
    Audit(cmd::audit::AuditArgs),
    /// Find secret-looking values in files.
    ///
    /// Prints the path, line, rule and a keyed fingerprint for each finding,
    /// never the value. --hook exits 2 on any finding, 0 when clean, and 1
    /// on any error. Low-entropy secrets such as short passwords are missed.
    Scan(cmd::scan::ScanArgs),
    /// Unlock, lock, or check the custody daemon.
    Custody(cmd::custody::CustodyArgs),
    /// Open the terminal UI.
    ///
    /// A build without the `tui` feature prints "not available" and exits 1.
    /// The UI unlocks with `--key` and a passphrase. It does not take a token.
    Tui {
        /// Vault to open; omit for the vault picker.
        #[arg(value_name = "VAULT")]
        vault: Option<PathBuf>,
        /// Color palette. Default: graphite.
        #[arg(
            long,
            value_name = "NAME",
            env = "GEODE_APPEARANCE",
            default_value = "graphite"
        )]
        appearance: AppearanceArg,
        /// Skip the opening splash.
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
            Self::Sign(a) => match &a.cmd {
                cmd::sign::SignCmd::Pub { .. } => "sign_pub",
                cmd::sign::SignCmd::Blob { .. } => "sign_blob",
            },
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
            Self::Run(_) => "run",
            Self::Audit(_) => "audit_verify",
            Self::Scan(_) => "scan",
            Self::Custody(_) => "custody",
            Self::Tui { .. } => "tui",
        }
    }
}

/// Show the vault policy, seal a new one, or dry-run an operation.
///
/// Rewriting a sealed policy requires `--yes --break-glass` and is
/// printed to stderr. Tokens cannot use that override. A denied check
/// exits 3.
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
    /// Seal a JSON policy file. Rewriting one requires `--yes --break-glass`.
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
        /// Confirm a human rewrite of a sealed policy. Does not apply to tokens.
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

/// Issue a scoped token, or use the vault tools with one.
///
/// Token flags belong to `serve`, `read`, `write`, and `list`. They are
/// not global, so `geode tui` does not accept a token.
#[derive(Args, Debug)]
pub struct AgentArgs {
    #[command(subcommand)]
    pub cmd: AgentCmd,
}

/// Where a token-gated verb reads the token and the passphrase.
///
/// Used by `serve`, `read`, `write`, and `list`. Pass one of `--token-file`,
/// `--token-fd`, or `--token`. With none of them, `$GEODE_TOKEN` is used.
#[derive(Args, Debug)]
pub struct TokenSource {
    /// Sealed agent token (hex armor or GTOK) on argv. Deprecated: argv is
    /// visible in ps/history. Prefer `--token-file`; else `$GEODE_TOKEN`.
    #[arg(long, value_name = "TOKEN", conflicts_with_all = ["token_file", "token_fd"])]
    pub token: Option<String>,
    /// Read the sealed token from PATH. The file must be mode 0600 and
    /// owned by the caller.
    #[arg(long, value_name = "PATH", conflicts_with = "token_fd")]
    pub token_file: Option<PathBuf>,
    /// Read the sealed token from open file descriptor N.
    #[arg(long, value_name = "N")]
    pub token_fd: Option<u32>,
    /// Read the passphrase for a wrapped `--key` from open file
    /// descriptor N (first line). Wins over `$GEODE_PASSPHRASE`.
    #[arg(long, value_name = "N")]
    pub passphrase_fd: Option<u32>,
}

#[derive(Subcommand, Debug)]
pub enum AgentCmd {
    /// Serve the vault tools over MCP.
    ///
    /// One transport per run. `--socket PATH` listens on a mode-0600 Unix
    /// socket. The parent directory must already exist, and stdout is not
    /// the MCP stream in that mode. `--stdio` uses stdin and stdout.
    /// Combining the two exits 1, and so does passing neither.
    /// A token is required.
    Serve {
        /// Speak MCP over stdin and stdout.
        /// Mutually exclusive with `--socket PATH`; combining them exits 1.
        #[arg(long)]
        stdio: bool,
        /// Serve MCP on a mode-0600 Unix socket at PATH — the same
        /// newline-delimited JSON frames as `--stdio`. Mutually exclusive
        /// with `--stdio`; one of the two is required (neither exits 1).
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
        /// Run the custody daemon (user `geode` / `_geode` only). Listens on
        /// the fixed custody socket, mode 0660, group `geode-agents`; takes a
        /// token per connection. Not with `--stdio` or `--socket`.
        #[arg(long)]
        custody: bool,
        /// Vault the custody daemon is bound to. Requires `--custody`.
        #[arg(long, value_name = "DIR")]
        vault: Option<PathBuf>,
        #[command(flatten)]
        token: TokenSource,
    },
    /// Token lifecycle: issue a scoped token, or inspect one.
    Token {
        #[command(subcommand)]
        cmd: TokenCmd,
    },
    /// Read one object. Prefer this over `geode cat` when you hold a token.
    Read {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Object path inside the vault.
        #[arg(value_name = "PATH")]
        path: String,
        /// Rendering mode. Default follows the token: `text` with `read`,
        /// `hash` with `inject` and no `read`. `text`/`hex` need `read`.
        #[arg(long, value_enum, value_name = "MODE")]
        mode: Option<ReadModeArg>,
        #[command(flatten)]
        token: TokenSource,
    },
    /// Seal stdin as a new object at PATH, under an allow prefix.
    Write {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Object path inside the vault.
        #[arg(value_name = "PATH")]
        path: String,
        #[command(flatten)]
        token: TokenSource,
    },
    /// List entries under a prefix.
    List {
        /// Vault directory.
        #[arg(value_name = "VAULT")]
        vault: PathBuf,
        /// Prefix to list under (optional).
        #[arg(value_name = "PREFIX")]
        prefix: Option<String>,
        #[command(flatten)]
        token: TokenSource,
    },
    /// Check that a path under an allow prefix is still in scope.
    ///
    /// Does not seal, open, or verify, and takes no token.
    Scope {
        /// Vault-relative path already under an allow prefix.
        #[arg(long, value_name = "PATH")]
        path: String,
        /// Operation (`list|read|write`). Never seal/open/verify.
        #[arg(long, value_name = "OP")]
        op: String,
        /// Path prefix the token already allows (repeatable).
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

/// How `token issue` labels a redacted value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum RedactArg {
    /// `[REDACTED:NAME]` (default).
    Strict,
    /// `[REDACTED]`, no binding name.
    Hidden,
}

/// How `geode agent read` renders an object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ReadModeArg {
    /// Plaintext bytes.
    Text,
    /// Lowercase hex of the bytes.
    Hex,
    /// sha256 only, no body.
    Hash,
}

#[derive(Subcommand, Debug)]
pub enum TokenCmd {
    /// Issue a sealed token (`GTOK…`) for a principal.
    ///
    /// Stdout is the token. Treat it as a secret.
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
        /// Allowed operation set (comma list of `list`, `read`, `write`,
        /// `verify`, `inject`). Required. `--ops list,inject` lets a token
        /// use secrets without reading plaintext. A token with no
        /// `--allow-cmd` cannot run anything, even with `inject`.
        #[arg(long, value_name = "OPS")]
        ops: String,
        /// Path prefix the token allows (repeatable).
        #[arg(long, value_name = "PREFIX")]
        allow_prefix: Vec<String>,
        /// Per-token byte cap for reads/writes (default applies when omitted).
        #[arg(long, value_name = "BYTES")]
        max_bytes: Option<u64>,
        /// Absolute canonical executable an `inject` run may start
        /// (repeatable). One rule per flag: the path only, no digest, no
        /// argument prefix.
        #[arg(long = "allow-cmd", value_name = "PATH")]
        allow_cmd: Vec<PathBuf>,
        /// JSON list of command rules: `[{"path": "/abs/exe", "sha256":
        /// "<hex>", "args_prefix": ["…"]}]`. `sha256` and `args_prefix`
        /// are optional. Combined with `--allow-cmd`.
        #[arg(long, value_name = "FILE")]
        allow_cmds_file: Option<PathBuf>,
        /// Host an `inject` run may reach (repeatable). Recorded intent.
        #[arg(long = "allow-host", value_name = "HOST")]
        allow_host: Vec<String>,
        /// Bind the token to one socket peer uid.
        #[arg(long, value_name = "N")]
        peer_uid: Option<u32>,
        /// How redaction names a hit: `strict` shows the binding name,
        /// `hidden` does not.
        #[arg(long, value_enum, default_value = "strict")]
        redact: RedactArg,
    },
    /// Show a token's principal, operations, prefixes, and expiry.
    ///
    /// Does not print the token's secrets. Pass a token file, or
    /// `$GEODE_TOKEN`, or stdin.
    Inspect {
        /// Sealed token file to inspect.
        #[arg(value_name = "TOKEN")]
        token: Option<PathBuf>,
        /// Vault the token was issued for (needed to verify the MAC).
        #[arg(long, value_name = "DIR")]
        vault: PathBuf,
    },
}

/// True when argv names the `run` verb and has no `--` separator.
fn run_without_dashdash() -> bool {
    let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
    args.iter().any(|a| a == "run") && !args.iter().any(|a| a == "--")
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
            // SPEC-v034 G6: `geode run` requires `--`; without it clap sees
            // the command as an unexpected argument.
            if error.kind() == ErrorKind::UnknownArgument && run_without_dashdash() {
                eprintln!("geode: error: no command after --");
            }
            // SPEC-v034 G4: `--ops` stays required; the usage error names the
            // inject-only shape so an operator does not reach for `read`.
            if error.kind() == ErrorKind::MissingRequiredArgument
                && error.to_string().contains("--ops <OPS>")
            {
                eprintln!(
                    "tip: --ops list,inject grants list and inject without plaintext \
                     read; add --allow-cmd PATH or the token cannot run anything"
                );
            }
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
        Commands::Sign(a) => cmd::sign::run(a, &cli.global, out),
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
        Commands::Run(a) => cmd::run::run(a, &cli.global, out),
        Commands::Audit(a) => cmd::audit::run(a, out),
        Commands::Scan(a) => cmd::scan::run(a, &cli.global, out),
        Commands::Custody(a) => cmd::custody::run(a, &cli.global, out),
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
