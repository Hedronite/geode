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
    /// Start a new vault epoch. Requires `--key`. A token cannot do this,
    /// and `GEODE_TOKEN` is not a substitute.
    ///
    /// `epoch += 1`; remaining recipients wrap the new EK.
    /// `--add-recipient PUB` wraps the new EK for an extra X25519 `.gpub`.
    /// `--drop-recipient ID` + `--reseal` is the complete revocation path.
    /// A vault that holds entries requires `--reseal` (objects are sealed per
    /// epoch; a new epoch without them would hide every entry). On an empty
    /// vault a drop without `--reseal` is incomplete revocation: the former
    /// recipient keeps its old-epoch wrap. Do not fix incomplete revocation
    /// in policy — recipient possession bypasses policy if the holder runs
    /// other software.
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
    /// Rewrite objects under the new EK. Required when the vault holds
    /// entries. Paired with `--drop-recipient`, this is the complete
    /// revocation path.
    #[arg(long)]
    pub reseal: bool,
    /// Drop a recipient by `key_id` (hex). A vault that holds entries
    /// requires `--reseal`, which completes the revocation. Only on an empty
    /// vault is a drop without `--reseal` allowed; the former recipient then
    /// keeps its old-epoch wrap (incomplete revocation, nothing to read).
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
                return Err(Error::Format(format!("no recipient matching {needle}")));
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
        return Err(Error::Format("rotate would leave no recipients".into()));
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
            "rotate requires --yes (skips confirmation; a vault that holds entries also requires --reseal)"
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
    let own_public = cmd::key::x25519_public(isk.as_bytes());
    // Refuse before anything touches disk: a kept recipient this operator
    // cannot re-wrap correctly, or a kept set nobody could open.
    check_keep_reachable(&keep, ctx.key_id)?;
    // Entries live in epoch-scoped objects sealed under that epoch's key, and
    // a manifest names objects of its own epoch only. A rotate that does not
    // reseal would publish an empty new-epoch manifest and hide every entry,
    // so it is refused while the vault holds anything.
    if !args.reseal && !ctx.manifest.entries.is_empty() {
        return Err(Error::Format(format!(
            "rotate without --reseal would hide the vault's {} entr{} (objects are sealed per epoch); \
             re-run with --reseal",
            ctx.manifest.entries.len(),
            if ctx.manifest.entries.len() == 1 { "y" } else { "ies" }
        )));
    }

    let generator = format!("geode {}", env!("CARGO_PKG_VERSION"));
    let generated_at = now_ms() / 1000;
    let plan = RotatePlan {
        vault_id: ctx.vault_id,
        old_epoch: ctx.epoch,
        context_label: "",
        keep,
    };
    let outcome = rotate::plan_rotation(&isk, &plan)?;
    // Every kept wrap must carry the new EK before anything is written.
    verify_new_wraps(&outcome, &isk, ctx.vault_id, &own_public)?;
    // The old EK is the one this operator actually unwrapped (`ctx.ek`).
    // `outcome.old_ek` is re-derived from the operator's ISK, which only
    // matches for the vault's original symmetric identity.
    let keys = rotate::EpochKeys {
        old_epoch: ctx.epoch,
        old_ek: &ctx.ek,
        new_epoch: outcome.new_epoch,
        new_ek: &outcome.new_ek,
    };
    let backup = RotateBackup::take(&args.dir, ctx.epoch, outcome.new_epoch, &rec_text)?;
    let staged = (|| -> Result<(u64, bool)> {
        snapshot_old_recipients(&args.dir, ctx.epoch, &rec_text)?;
        rotate::commit_rotation(&args.dir, ctx.vault_id, &outcome, &generator, generated_at)?;
        // commit_rotation lays an empty new-epoch manifest. With --reseal it
        // is replaced by one naming the re-sealed objects; without --reseal
        // the vault is empty (non-empty vaults were refused above), so the
        // empty manifest is exact.
        let objects = if args.reseal {
            rotate::reseal(
                &args.dir,
                ctx.vault_id,
                &keys,
                &rotate::RotationStamp {
                    generator: &generator,
                    generated_at,
                },
            )?
        } else {
            0
        };
        let policy_resealed = rotate::reseal_policy(&args.dir, ctx.vault_id, &keys)?;
        verify_new_epoch(&args.dir, ctx.vault_id, outcome.new_epoch, &outcome.new_ek)?;
        bump_header_epoch(&args.dir, outcome.new_epoch, &outcome.new_ek, ctx.vault_id)?;
        // If this operator kept access, the committed vault must load.
        if operator_kept(&outcome.new_recipients.recipients, ctx.key_id, &own_public) {
            cmd::load_vault(&args.dir, &isk)?;
        }
        Ok((objects, policy_resealed))
    })();
    drop(isk);
    let (objects, policy_resealed) = finish_or_restore(staged, &backup, &args.dir)?;

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
        "; vault is empty, so the drop without --reseal is incomplete revocation (the former recipient keeps its old-epoch wrap)"
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

/// True when `r` is this operator's own recipient entry.
fn is_own(r: &Recipient, own_key_id: kdf::KeyId, own_public: &[u8; 32]) -> bool {
    match r {
        Recipient::Symmetric { key_id, .. } => *key_id == own_key_id,
        Recipient::X25519 { public, .. } => cmd::x25519_public_matches(public, own_public),
        Recipient::Hybrid { .. } => false,
    }
}

fn operator_kept(keep: &[Recipient], own_key_id: kdf::KeyId, own_public: &[u8; 32]) -> bool {
    keep.iter().any(|r| is_own(r, own_key_id, own_public))
}

/// A usable X25519 recipient public: 32 bytes, not a low-order point (a
/// low-order public makes the wrap's shared secret all-zero).
fn x25519_public_usable(public_b64: &str) -> bool {
    let Ok(bytes) = Base64::decode_vec(public_b64) else {
        return false;
    };
    let Ok(pk) = <[u8; 32]>::try_from(bytes.as_slice()) else {
        return false;
    };
    let probe = x25519_dalek::StaticSecret::from([0x42u8; 32]);
    probe
        .diffie_hellman(&x25519_dalek::PublicKey::from(pk))
        .was_contributory()
}

/// Lockout guard (fail closed, before any write).
///
/// - A symmetric recipient is re-wrapped under the rotating key's ISK, so a
///   symmetric recipient that is NOT this operator would be silently
///   re-wrapped to a key it cannot derive; refuse and say how to proceed.
/// - Every kept X25519 public must be a usable curve point.
/// - At least one kept recipient must be able to open the new epoch.
fn check_keep_reachable(keep: &[Recipient], own_key_id: kdf::KeyId) -> Result<()> {
    let mut reachable = 0usize;
    for r in keep {
        match r {
            Recipient::Symmetric { key_id, .. } => {
                if *key_id != own_key_id {
                    return Err(Error::Format(format!(
                        "symmetric recipient {} can only be re-wrapped by its own key; \
                         rotate with that key or --drop-recipient it (refusing: it would be locked out)",
                        cmd::hex(&key_id.0)
                    )));
                }
                reachable += 1;
            }
            Recipient::X25519 { key_id, public, .. } => {
                if !x25519_public_usable(public) {
                    return Err(Error::Format(format!(
                        "x25519 recipient {} has an unusable public key (refusing rotate)",
                        cmd::hex(&key_id.0)
                    )));
                }
                reachable += 1;
            }
            Recipient::Hybrid { .. } => {}
        }
    }
    if reachable == 0 {
        return Err(Error::Format(
            "rotate would leave no recipient able to open the vault (refusing lockout)".into(),
        ));
    }
    Ok(())
}

/// Check the planned wraps before commit: every recipient this operator can
/// open must unwrap to exactly the new EK; X25519 wraps for other
/// identities must at least parse for their stored public.
fn verify_new_wraps(
    outcome: &rotate::RotateOutcome,
    isk: &kdf::IdentitySecret,
    vault_id: kdf::VaultId,
    own_public: &[u8; 32],
) -> Result<()> {
    let own_key_id = kdf::derive_key_id(isk)?;
    let epoch = outcome.new_epoch;
    for r in &outcome.new_recipients.recipients {
        if !is_own(r, own_key_id, own_public) {
            continue;
        }
        let ek = match r {
            Recipient::Symmetric { .. } => recipients::unwrap_symmetric(r, isk, vault_id, epoch)?,
            Recipient::X25519 { .. } => {
                let sk = cmd::key::x25519_secret(isk.as_bytes());
                recipients::unwrap_x25519(r, &sk, vault_id, epoch)?
            }
            Recipient::Hybrid { .. } => return Err(Error::NotImplemented),
        };
        if !geode_grotto::zero::ct_eq(ek.as_bytes(), outcome.new_ek.as_bytes()) {
            return Err(Error::AuthFail);
        }
    }
    Ok(())
}

/// Before the header bump commits the rotation: the new-epoch manifest must
/// authenticate under the new EK and every object it names must open.
fn verify_new_epoch(
    root: &Path,
    vault_id: kdf::VaultId,
    epoch: Epoch,
    ek: &EpochKey,
) -> Result<()> {
    let manifest = cmd::load_manifest(root, ek, vault_id, epoch)?;
    for e in &manifest.entries {
        if e.kind == geode_grotto::manifest::EntryKind::Dir {
            continue;
        }
        let raw = geode_grotto::vault::read_object(root, epoch, &e.object_id)?;
        if raw.len() < geode_grotto::object::HEADER_SIZE {
            return Err(Error::AuthFail);
        }
        let bind: &[u8] = if e.bind { e.path.as_bytes() } else { b"" };
        let (hs, body) = raw.split_at(geode_grotto::object::HEADER_SIZE);
        geode_grotto::object::open_object(ek, hs, body, bind)?;
    }
    Ok(())
}

/// On a failed rotate, restore the old epoch. A restore that itself fails is
/// reported together with the original error (never swallowed).
fn finish_or_restore<T>(staged: Result<T>, backup: &RotateBackup, root: &Path) -> Result<T> {
    match staged {
        Ok(v) => Ok(v),
        Err(e) => match backup.restore(root) {
            Ok(()) => Err(e),
            Err(r) => Err(Error::Format(format!(
                "rotate failed: {e}; restoring the previous epoch ALSO failed: {r} \
                 (vault may be inconsistent; check header.json, recipients.json and epochs/)"
            ))),
        },
    }
}

/// What rotate restores if any step fails: the vault stays on the old epoch.
struct RotateBackup {
    recipients: String,
    header: Vec<u8>,
    policy: Option<Vec<u8>>,
    new_epoch_dir: Option<PathBuf>,
    /// The old-epoch recipients snapshot rotate is about to create (only
    /// when it does not exist yet), removed on restore.
    old_snapshot: Option<PathBuf>,
}

impl RotateBackup {
    fn take(root: &Path, old_epoch: Epoch, new_epoch: Epoch, rec_text: &str) -> Result<Self> {
        let header = std::fs::read(root.join("header.json")).map_err(Error::Io)?;
        let pol = geode_grotto::policy::policy_path(root);
        let policy = if pol.exists() {
            Some(std::fs::read(&pol).map_err(Error::Io)?)
        } else {
            None
        };
        let dir = rotate::epoch_recipients_path(root, new_epoch)
            .parent()
            .map(Path::to_path_buf);
        let new_epoch_dir = dir.filter(|d| !d.exists());
        let snap = rotate::epoch_recipients_path(root, old_epoch);
        let old_snapshot = (!snap.exists()).then_some(snap);
        Ok(Self {
            recipients: rec_text.to_string(),
            header,
            policy,
            new_epoch_dir,
            old_snapshot,
        })
    }

    /// Put every file rotate may have written back. All steps are attempted;
    /// the first error (if any) is returned with the path it hit.
    fn restore(&self, root: &Path) -> Result<()> {
        let mut first: Option<String> = None;
        let mut note = |what: &Path, r: Result<()>| {
            if let Err(e) = r {
                if first.is_none() {
                    first = Some(format!("{}: {e}", what.display()));
                }
            }
        };
        let rec = root.join("recipients.json");
        note(
            &rec,
            geode_grotto::vault::write_atomic(&rec, self.recipients.as_bytes()),
        );
        let hdr = root.join("header.json");
        note(&hdr, geode_grotto::vault::write_atomic(&hdr, &self.header));
        if let Some(p) = &self.policy {
            let pol = geode_grotto::policy::policy_path(root);
            note(&pol, geode_grotto::vault::write_atomic(&pol, p));
        }
        if let Some(d) = &self.new_epoch_dir {
            if d.exists() {
                note(d, std::fs::remove_dir_all(d).map_err(Error::Io));
            }
        }
        if let Some(s) = &self.old_snapshot {
            if s.exists() {
                note(s, std::fs::remove_file(s).map_err(Error::Io));
            }
        }
        match first {
            None => Ok(()),
            Some(msg) => Err(Error::Format(format!("restore: {msg}"))),
        }
    }
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
        root: geode_grotto::manifest::entries_root(&[])?,
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

#[cfg(test)]
mod rotate_restore_tests {
    use super::*;

    fn vault_like(root: &Path) {
        std::fs::create_dir_all(root.join("epochs/00000001")).unwrap();
        std::fs::write(root.join("recipients.json"), b"OLD-RECS").unwrap();
        std::fs::write(root.join("header.json"), b"OLD-HEADER").unwrap();
    }

    #[test]
    fn restore_undoes_snapshot_and_new_epoch() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        vault_like(root);
        let b = RotateBackup::take(root, Epoch(1), Epoch(2), "OLD-RECS").unwrap();
        snapshot_old_recipients(root, Epoch(1), "OLD-RECS").unwrap();
        std::fs::create_dir_all(root.join("epochs/00000002/objects")).unwrap();
        std::fs::write(root.join("recipients.json"), b"NEW").unwrap();
        std::fs::write(root.join("header.json"), b"NEW").unwrap();
        b.restore(root).unwrap();
        assert!(!rotate::epoch_recipients_path(root, Epoch(1)).exists());
        assert!(!root.join("epochs/00000002").exists());
        assert_eq!(
            std::fs::read(root.join("recipients.json")).unwrap(),
            b"OLD-RECS"
        );
        assert_eq!(
            std::fs::read(root.join("header.json")).unwrap(),
            b"OLD-HEADER"
        );
    }

    #[test]
    fn restore_keeps_preexisting_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        vault_like(root);
        snapshot_old_recipients(root, Epoch(1), "EARLIER").unwrap();
        let b = RotateBackup::take(root, Epoch(1), Epoch(2), "OLD-RECS").unwrap();
        b.restore(root).unwrap();
        let snap = rotate::epoch_recipients_path(root, Epoch(1));
        assert_eq!(std::fs::read(snap).unwrap(), b"EARLIER");
    }

    #[test]
    fn restore_error_is_reported_with_original() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        vault_like(root);
        let b = RotateBackup::take(root, Epoch(1), Epoch(2), "OLD-RECS").unwrap();
        // A non-empty directory where header.json was: the restore rename
        // fails even with elevated privileges.
        std::fs::remove_file(root.join("header.json")).unwrap();
        std::fs::create_dir_all(root.join("header.json/blocker")).unwrap();
        let err = finish_or_restore::<()>(Err(Error::AuthFail), &b, root).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("rotate failed"), "{msg}");
        assert!(msg.contains("ALSO failed"), "{msg}");
        assert!(msg.contains("header.json"), "{msg}");
        // The other restore steps still ran.
        assert_eq!(
            std::fs::read(root.join("recipients.json")).unwrap(),
            b"OLD-RECS"
        );
        assert_ne!(crate::output::exit_family(&err).1, 0);
    }

    #[test]
    fn restore_ok_returns_original_error() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        vault_like(root);
        let b = RotateBackup::take(root, Epoch(1), Epoch(2), "OLD-RECS").unwrap();
        let err = finish_or_restore::<()>(Err(Error::AuthFail), &b, root).unwrap_err();
        assert!(matches!(err, Error::AuthFail));
    }
}
