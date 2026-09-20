//! `geode vault` — vault lifecycle verbs (G3: init).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use geode_grotto::kdf::{self, Epoch};
use geode_grotto::recipients::{self, Recipient, Recipients};
use geode_grotto::{Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct VaultArgs {
    #[command(subcommand)]
    pub cmd: VaultCmd,
}

#[derive(Subcommand, Debug)]
pub enum VaultCmd {
    /// Create a new vault (epoch 1, empty manifest, this key as recipient).
    Init(InitArgs),
    /// List the recipient set (types + `key_id`s; public data, no key needed).
    ///
    /// `recipients.json` is public and cannot open the vault alone; any one
    /// recipient (symmetric or X25519) unwraps the epoch key. Recipient
    /// possession bypasses policy if the holder runs other software.
    Recipients(RecipientsArgs),
    /// Wrap the current EK for a new X25519 recipient from their `.gpub`.
    ///
    /// Appends an X25519 recipient wrap of the current epoch key to
    /// `recipients.json`. Requires `--key`; the ISK is dropped after unwrap
    /// and never printed. `--token` MUST NOT add or drop recipients — tokens
    /// narrow reads/writes, they never mint recipients. Recipient possession
    /// bypasses policy if the holder runs other software.
    AddRecipient(AddRecipientArgs),
}

#[derive(Args, Debug)]
pub struct RecipientsArgs {
    /// Vault directory.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
}

#[derive(Args, Debug)]
pub struct AddRecipientArgs {
    /// Vault directory.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
    /// Recipient's `.gpub` file (from their `geode keygen`).
    #[arg(long, value_name = "PATH")]
    pub gpub: PathBuf,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Vault directory to create.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
    /// Human label stored in `header.json`.
    #[arg(long)]
    pub label: Option<String>,
}

pub fn run(args: &VaultArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        VaultCmd::Init(a) => init(a, global, out),
        VaultCmd::Recipients(a) => list_recipients(a, out),
        VaultCmd::AddRecipient(a) => add_recipient(a, global, out),
    }
}

/// `geode vault recipients DIR` (05-cli 2.2). `recipients.json` is public
/// (03-format 6: it cannot open the vault alone), so no key is required.
/// Prints types + `key_id`s (+ x25519 publics); wrap blobs are never shown.
fn list_recipients(args: &RecipientsArgs, out: OutMode) -> Result<()> {
    let text = std::fs::read_to_string(args.dir.join("recipients.json")).map_err(Error::Io)?;
    let recs: Recipients =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("recipients.json: {e}")))?;
    let rows: Vec<serde_json::Value> = recs
        .recipients
        .iter()
        .map(|r| match r {
            Recipient::Symmetric { key_id, .. } => serde_json::json!({
                "type": "symmetric",
                "key_id": cmd::hex(&key_id.0),
            }),
            Recipient::X25519 { key_id, public, .. } => serde_json::json!({
                "type": "x25519",
                "key_id": cmd::hex(&key_id.0),
                "public": public,
            }),
            Recipient::Hybrid { key_id, .. } => serde_json::json!({
                "type": "hybrid",
                "key_id": cmd::hex(&key_id.0),
            }),
        })
        .collect();
    let text_rows: Vec<String> = recs
        .recipients
        .iter()
        .map(|r| match r {
            Recipient::Symmetric { key_id, .. } => {
                format!("symmetric {}", cmd::hex(&key_id.0))
            }
            Recipient::X25519 { key_id, public, .. } => {
                format!("x25519 {} public {}", cmd::hex(&key_id.0), public)
            }
            Recipient::Hybrid { key_id, .. } => format!("hybrid {}", cmd::hex(&key_id.0)),
        })
        .collect();
    cmd::emit(
        out,
        "vault_recipients",
        serde_json::json!({
            "vault": args.dir.display().to_string(),
            "vault_id": recs.vault_id,
            "epoch": recs.epoch,
            "recipients": rows,
        }),
        &format!(
            "{} (epoch {}):\n{}",
            args.dir.display(),
            recs.epoch,
            text_rows.join("\n")
        ),
    );
    Ok(())
}

/// `geode vault add-recipient DIR --gpub PATH` (02-cryptography 7.2): wrap
/// the CURRENT epoch's EK for the recipient's X25519 public and append to
/// `recipients.json`. Requires `--key` (the operator's ISK unwraps the
/// symmetric recipient to obtain EK). There is no `--token` path: tokens
/// narrow reads/writes, they never mint recipients (10-policy).
///
/// No reseal, no epoch rotation, no recipient drop this pack.
fn add_recipient(args: &AddRecipientArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let (key_id, public) = cmd::key::read_gpub(&args.gpub)?;
    // Authenticate the vault for the current EK. The ISK is dropped
    // immediately after; nothing secret is ever printed.
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&args.dir, &isk)?;
    drop(isk);

    let rec_path = args.dir.join("recipients.json");
    let text = std::fs::read_to_string(&rec_path).map_err(Error::Io)?;
    let mut recs: Recipients =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("recipients.json: {e}")))?;
    let already = recs.recipients.iter().any(|r| match r {
        Recipient::Symmetric { key_id: k, .. }
        | Recipient::X25519 { key_id: k, .. }
        | Recipient::Hybrid { key_id: k, .. } => *k == key_id,
    });
    if already {
        return Err(Error::Format(format!(
            "key_id {} is already a recipient",
            cmd::hex(&key_id.0)
        )));
    }
    let recipient = recipients::wrap_x25519(&ctx.ek, &public, ctx.vault_id, ctx.epoch, key_id)?;
    recs.recipients.push(recipient);
    let recs_text = serde_json::to_string_pretty(&recs)
        .map_err(|e| Error::Format(format!("recipients serialize: {e}")))?;
    geode_grotto::vault::write_atomic(&rec_path, recs_text.as_bytes())?;

    cmd::emit(
        out,
        "vault_add_recipient",
        serde_json::json!({
            "vault": args.dir.display().to_string(),
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": ctx.epoch.0,
            "added": {"type": "x25519", "key_id": cmd::hex(&key_id.0)},
            "recipients": recs.recipients.len(),
        }),
        &format!(
            "added x25519 recipient {} to {} (epoch {}, {} recipients)",
            cmd::hex(&key_id.0),
            args.dir.display(),
            ctx.epoch.0,
            recs.recipients.len(),
        ),
    );
    Ok(())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn init(args: &InitArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    if args.dir.exists() && args.dir.read_dir().map_err(Error::Io)?.next().is_some() {
        return Err(Error::Format(format!(
            "{} exists and is not empty",
            args.dir.display()
        )));
    }
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;

    let vault_id = geode_grotto::vault::new_vault_id()?;
    let epoch = Epoch(1);
    let key_id = kdf::derive_key_id(&isk)?;
    let ek = kdf::derive_epoch_key(&isk, vault_id, epoch, "")?;

    geode_grotto::vault::init_vault_dir(&args.dir, vault_id, epoch)?;

    // recipients.json: symmetric wrap of EK for this identity (02 7.1).
    let recipient = recipients::wrap_symmetric(&ek, &isk, vault_id, epoch, key_id)?;
    let recs = Recipients {
        vault_id: cmd::hex(&vault_id.0),
        epoch: epoch.0,
        recipients: vec![recipient],
    };
    let recs_text = serde_json::to_string_pretty(&recs)
        .map_err(|e| Error::Format(format!("recipients serialize: {e}")))?;
    geode_grotto::vault::write_atomic(&args.dir.join("recipients.json"), recs_text.as_bytes())?;

    // header.json: JSON twin of the VaultHeader fields (03-format 3), MAC'd.
    let mk = kdf::derive_manifest_key(&ek, vault_id, epoch);
    let mut header = serde_json::json!({
        "version": 1,
        "suite": geode_grotto::SUITE_0X01,
        "flags": 0,
        "vault_id": cmd::hex(&vault_id.0),
        "epoch": epoch.0,
        "chunk_size_default": geode_grotto::chunk::DEFAULT_CHUNK_SIZE,
        "creator_key_id": cmd::hex(&key_id.0),
        "created_unix_ms": now_ms(),
    });
    if let Some(label) = &args.label {
        header["label"] = serde_json::Value::String(label.clone());
    }
    cmd::write_header(&args.dir, header, &mk)?;

    // Empty manifest with a valid MAC (04-vault 1).
    let manifest = geode_grotto::manifest::Manifest {
        vault_id,
        epoch,
        suite: geode_grotto::SUITE_0X01,
        flags: 0,
        generated_at: now_ms() / 1000,
        generator: format!("geode {}", env!("CARGO_PKG_VERSION")),
        root: geode_grotto::manifest::entries_root(&[]),
        entry_count: 0,
        total_plain_bytes: 0,
        total_cipher_bytes: 0,
        entries: vec![],
    };
    let ctx = cmd::VaultCtx {
        root: args.dir.clone(),
        vault_id,
        epoch,
        key_id,
        ek,
        manifest,
    };
    cmd::write_manifest(&ctx)?;

    cmd::emit(
        out,
        "vault_init",
        serde_json::json!({
            "vault_id": cmd::hex(&vault_id.0),
            "epoch": epoch.0,
            "key_id": cmd::hex(&key_id.0),
            "path": args.dir.display().to_string(),
        }),
        &format!(
            "vault {} epoch 1 (key {}) at {}",
            cmd::hex(&vault_id.0),
            cmd::hex(&key_id.0),
            args.dir.display()
        ),
    );
    Ok(())
}
