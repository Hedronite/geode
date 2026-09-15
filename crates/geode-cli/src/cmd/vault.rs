//! `geode vault` — vault lifecycle verbs (G3: init).

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use geode_grotto::kdf::{self, Epoch};
use geode_grotto::recipients::{self, Recipients};
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
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

fn init(args: &InitArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    if args.dir.exists()
        && args.dir.read_dir().map_err(Error::Io)?.next().is_some()
    {
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
