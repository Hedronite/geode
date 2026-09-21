//! `geode vault` — vault lifecycle verbs (init, recipients, add-recipient, rotate).

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64ct::{Base64, Encoding};
use clap::{Args, Subcommand};
use geode_grotto::kdf::{self, Epoch, EpochKey};
use geode_grotto::recipients::{self, Recipient, Recipients};
use geode_grotto::rotate::{self, RotatePlan};
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
    /// Rotate the vault epoch (04-vault 6). Requires `--key`. `--token` is
    /// not a flag here and `GEODE_TOKEN` never substitutes for `--key`.
    ///
    /// `epoch += 1`; remaining recipients wrap the new EK.
    /// `--drop-recipient` + `--reseal` is the complete revocation path.
    /// Without `--reseal`, a drop is incomplete revocation (old objects stay
    /// under the old EK).
    Rotate(RotateArgs),
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

#[derive(Args, Debug)]
pub struct RotateArgs {
    /// Vault directory.
    #[arg(value_name = "DIR")]
    pub dir: PathBuf,
    /// Rewrite objects under the new EK (complete path with `--drop-recipient`).
    #[arg(long)]
    pub reseal: bool,
    /// Drop a recipient by `key_id` (hex). Incomplete without `--reseal`.
    #[arg(long, value_name = "ID")]
    pub drop_recipient: Vec<String>,
    /// Wrap the new EK for an X25519 recipient `.gpub`.
    #[arg(long, value_name = "PUB")]
    pub add_recipient: Vec<PathBuf>,
    /// Skip confirmation.
    #[arg(long)]
    pub yes: bool,
}

pub fn run(args: &VaultArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        VaultCmd::Init(a) => init(a, global, out),
        VaultCmd::Recipients(a) => list_recipients(a, out),
        VaultCmd::AddRecipient(a) => add_recipient(a, global, out),
        VaultCmd::Rotate(a) => rotate(a, global, out),
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

fn recipient_id_hex(r: &Recipient) -> String {
    match r {
        Recipient::Symmetric { key_id, .. }
        | Recipient::X25519 { key_id, .. }
        | Recipient::Hybrid { key_id, .. } => cmd::hex(&key_id.0),
    }
}

fn already_has(keep: &[Recipient], key_id: geode_grotto::kdf::KeyId) -> bool {
    keep.iter().any(|r| match r {
        Recipient::Symmetric { key_id: k, .. }
        | Recipient::X25519 { key_id: k, .. }
        | Recipient::Hybrid { key_id: k, .. } => *k == key_id,
    })
}

/// Filter `--drop-recipient` (full hex or unique prefix) then append
/// `--add-recipient` `.gpub` stubs. Core `rotate_epoch` rewraps `keep`.
fn select_keep(recs: Vec<Recipient>, drops: &[String], adds: &[PathBuf]) -> Result<Vec<Recipient>> {
    let mut keep = recs;
    for raw in drops {
        let needle = raw.trim().trim_end_matches('.').to_ascii_lowercase();
        if needle.is_empty() {
            return Err(Error::Format("empty --drop-recipient".into()));
        }
        let hits: Vec<usize> = keep
            .iter()
            .enumerate()
            .filter(|(_, r)| {
                let id = recipient_id_hex(r);
                id == needle || id.starts_with(&needle)
            })
            .map(|(i, _)| i)
            .collect();
        match hits.as_slice() {
            [i] => {
                keep.remove(*i);
            }
            [] => {
                return Err(Error::Format(format!(
                    "no recipient matching {needle}"
                )));
            }
            _ => {
                return Err(Error::Format(format!(
                    "--drop-recipient {needle} matches multiple recipients"
                )));
            }
        }
    }
    for gpub in adds {
        let (key_id, public) = cmd::key::read_gpub(gpub)?;
        if already_has(&keep, key_id) {
            return Err(Error::Format(format!(
                "key_id {} is already a recipient",
                cmd::hex(&key_id.0)
            )));
        }
        keep.push(Recipient::X25519 {
            key_id,
            public: Base64::encode_string(&public),
            wrap: String::new(),
        });
    }
    if keep.is_empty() {
        return Err(Error::Format(
            "rotate would leave no recipients".into(),
        ));
    }
    Ok(keep)
}

/// Preserve the old epoch's wraps on disk so remaining (and dropped)
/// recipients can still unwrap the old EK without reseal (04 6).
fn snapshot_old_recipients(root: &Path, epoch: Epoch, rec_text: &str) -> Result<()> {
    let path = rotate::epoch_recipients_path(root, epoch);
    if path.exists() {
        return Ok(());
    }
    geode_grotto::vault::write_atomic(&path, rec_text.as_bytes())
}

fn bump_header_epoch(
    root: &Path,
    new_epoch: Epoch,
    new_ek: &EpochKey,
    vault_id: geode_grotto::kdf::VaultId,
) -> Result<()> {
    let path = root.join("header.json");
    let text = std::fs::read_to_string(&path).map_err(Error::Io)?;
    let mut header: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("header.json: {e}")))?;
    if let Some(o) = header.as_object_mut() {
        o.remove("header_mac");
        o.insert("epoch".into(), serde_json::json!(new_epoch.0));
    }
    let mk = kdf::derive_manifest_key(new_ek, vault_id, new_epoch);
    cmd::write_header(root, header, &mk)
}

/// `geode vault rotate DIR` (04-vault 6; SPEC-v027 G1). `--key` required;
/// `--token` / `GEODE_TOKEN` never rotate. `--yes` skips confirmation.
fn rotate(args: &RotateArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    if !args.yes {
        return Err(Error::Format(
            "rotate requires --yes (skips confirmation; drop without --reseal is incomplete revocation)"
                .into(),
        ));
    }
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&args.dir, &isk)?;

    let rec_path = args.dir.join("recipients.json");
    let rec_text = std::fs::read_to_string(&rec_path).map_err(Error::Io)?;
    let recs: Recipients = serde_json::from_str(&rec_text)
        .map_err(|e| Error::Format(format!("recipients.json: {e}")))?;
    let keep = select_keep(recs.recipients, &args.drop_recipient, &args.add_recipient)?;
    snapshot_old_recipients(&args.dir, ctx.epoch, &rec_text)?;

    let generator = format!("geode {}", env!("CARGO_PKG_VERSION"));
    let generated_at = now_ms() / 1000;
    let plan = RotatePlan {
        vault_id: ctx.vault_id,
        old_epoch: ctx.epoch,
        context_label: "",
        keep,
    };
    let outcome = rotate::rotate_epoch(&isk, &args.dir, &plan, &generator, generated_at)?;
    let mut objects = 0u64;
    if args.reseal {
        objects = rotate::reseal(
            &args.dir,
            ctx.vault_id,
            ctx.epoch,
            &outcome.old_ek,
            outcome.new_epoch,
            &outcome.new_ek,
            &generator,
            generated_at,
        )?;
    }
    let policy_resealed = rotate::reseal_policy(
        &args.dir,
        ctx.vault_id,
        ctx.epoch,
        &outcome.old_ek,
        outcome.new_epoch,
        &outcome.new_ek,
    )?;
    bump_header_epoch(&args.dir, outcome.new_epoch, &outcome.new_ek, ctx.vault_id)?;
    drop(isk);

    let dropped: Vec<String> = args
        .drop_recipient
        .iter()
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();
    let incomplete = !dropped.is_empty() && !args.reseal;
    let reseal_bit = if args.reseal {
        format!(", resealed {objects} object(s)")
    } else {
        String::new()
    };
    let incomplete_bit = if incomplete {
        "; drop without --reseal is incomplete revocation"
    } else {
        ""
    };
    let text = format!(
        "rotated {} to epoch {} (key {}){reseal_bit}{incomplete_bit}",
        cmd::hex(&ctx.vault_id.0),
        outcome.new_epoch.0,
        cmd::hex(&ctx.key_id.0),
    );
    cmd::emit(
        out,
        "vault_rotate",
        serde_json::json!({
            "vault": args.dir.display().to_string(),
            "vault_id": cmd::hex(&ctx.vault_id.0),
            "epoch": outcome.new_epoch.0,
            "key_id": cmd::hex(&ctx.key_id.0),
            "reseal": args.reseal,
            "objects": objects,
            "policy_resealed": policy_resealed,
            "dropped": dropped,
            "recipients": outcome.new_recipients.recipients.len(),
            "incomplete_revocation": incomplete,
        }),
        &text,
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
