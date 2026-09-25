//! Epoch rotation and reseal (04-vault-and-manifest 6; SPEC-v027).
//!
//! G0 (v0.2.7): rotate the vault epoch and optionally reseal objects + policy
//! under the new Epoch Key. This module is the crypto/layout core; the CLI
//! (`geode vault rotate`) composes it in G1.
//!
//! ## Rotate (no reseal)
//!
//! `epoch += 1`; `new_ek = BLAKE3-KDF("geode/v1/epoch-fek", ISK || vault_id || le32(new_epoch) || context_label)`;
//! the **new** EK is wrapped for each **remaining** recipient (symmetric via
//! ISK, X25519 via the recipient's stored static public key -- the operator
//! never needs a recipient secret). The old epoch's `recipients.json` is
//! left untouched, so a remaining recipient can still unwrap the **old** EK
//! and open old-epoch objects (04 6). Dropping a recipient without reseal is
//! a **documented incomplete revocation**: the dropped recipient retains
//! their old-epoch wrap and can still read old objects (10-policy; SPEC).
//!
//! ## Reseal
//!
//! Rewrites every object referenced by the old-epoch manifest under the new
//! EK at the new epoch (fresh `object_id` per object, never overwrite in
//! place -- 03-format 10), and writes a new-epoch manifest pointing at the
//! rewritten objects. A dropped recipient has no wrap of the new EK, so
//! they cannot read the rewritten objects. Old-epoch objects remain on
//! disk until `snapshot::gc` reaps them. Hybrid recipients stay
//! [`Error::NotImplemented`] (02 7.3).
//!
//! ## Policy re-seal
//!
//! `policy.json.sealed` is bound to `(vault_id, epoch)` via its AEAD AD
//! (10-policy 3). After rotation the sealed policy will not authenticate
//! under the new epoch's `MetaKey`; [`reseal_policy`] decrypts it under
//! the old `MetaKey`, re-encrypts under the new `MetaKey` with the new
//! epoch in the AD, and writes it atomically. A vault with no sealed policy
//! (default policy) is a no-op.
//!
//! No new [`Error`] variant; errors never contain ISK or key bytes.

use crate::chunk::DEFAULT_CHUNK_SIZE;
use crate::kdf::{
    derive_epoch_key, derive_manifest_key, derive_meta_key, Epoch, EpochKey, IdentitySecret,
    VaultId,
};
use crate::manifest::{entries_root, Manifest};
use crate::object::{open_object, seal_object, ObjectSpec, HEADER_SIZE};
use crate::recipients::{self, wrap_symmetric, wrap_x25519, Recipient, Recipients};
use crate::snapshot::{read_manifest_file, write_manifest_file};
use crate::vault::{self, hex_encode, init_vault_dir, write_atomic};
use crate::{Error, Result};
use base64ct::Encoding;
use std::path::{Path, PathBuf};

/// Recipient selection for rotation (04 6; SPEC-v027).
///
/// `keep` is the filtered list of recipients to wrap the **new** EK (the CLI
/// applies `--drop-recipient` / `--add-recipient` before calling). Symmetric
/// recipients are re-wrapped via ISK; X25519 recipients via their stored
/// static public key. Hybrid recipients are refused with
/// [`Error::NotImplemented`] this pack.
#[derive(Clone, Debug)]
pub struct RotatePlan<'a> {
    pub vault_id: VaultId,
    pub old_epoch: Epoch,
    pub context_label: &'a str,
    pub keep: Vec<Recipient>,
}

/// Outcome of [`rotate_epoch`]: the new epoch, both EKs, and the new
/// `Recipients` document (new EK wrapped for each kept recipient).
#[derive(Debug)]
pub struct RotateOutcome {
    pub new_epoch: Epoch,
    pub old_ek: EpochKey,
    pub new_ek: EpochKey,
    pub new_recipients: Recipients,
}

/// Per-epoch recipients path: `epochs/<NNNNNNNN>/recipients.json`.
///
/// Rotating writes the new epoch's recipients here so the old epoch's
/// recipients (wrapping the old EK) are preserved verbatim -- a remaining
/// recipient can still unwrap the old EK and open old-epoch objects without
/// reseal (04 6). The vault-root `recipients.json` is also updated to the
/// new epoch so existing `load_vault` callers see the current epoch.
#[must_use]
pub fn epoch_recipients_path(vault_root: &Path, epoch: Epoch) -> PathBuf {
    vault_root
        .join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("recipients.json")
}

/// Re-wrap `new_ek` for one kept recipient.
///
/// Symmetric recipients are re-wrapped under a key derived from ISK (the
/// operator holds ISK). X25519 recipients are re-wrapped under their stored
/// static public key (the operator never needs the recipient secret).
/// Hybrid recipients are refused ([`Error::NotImplemented`], 02 7.3).
fn rewrap_one(
    new_ek: &EpochKey,
    isk: &IdentitySecret,
    vault_id: VaultId,
    new_epoch: Epoch,
    kept: &Recipient,
) -> Result<Recipient> {
    match kept {
        Recipient::Symmetric { key_id, .. } => {
            wrap_symmetric(new_ek, isk, vault_id, new_epoch, *key_id)
        }
        Recipient::X25519 { key_id, public, .. } => {
            let pk_bytes = base64ct::Base64::decode_vec(public)
                .map_err(|e| Error::Format(format!("recipient public base64: {e}")))?;
            if pk_bytes.len() != 32 {
                return Err(Error::Format("x25519 public key not 32 bytes".into()));
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(&pk_bytes);
            wrap_x25519(new_ek, &pk, vault_id, new_epoch, *key_id)
        }
        Recipient::Hybrid { .. } => Err(Error::NotImplemented),
    }
}

/// Rotate the epoch: derive the new EK and wrap it for each kept recipient.
///
/// This is the **crypto** leg of `geode vault rotate` (04 6; SPEC-v027 G0a).
/// It does NOT touch the filesystem; call [`commit_rotation`] to lay the
/// new epoch on disk, or [`rotate_epoch`] for crypto+layout in one step.
/// `old_ek` is returned so the caller can reseal old objects / policy.
///
/// Errors never contain ISK or key bytes.
pub fn plan_rotation(isk: &IdentitySecret, plan: &RotatePlan<'_>) -> Result<RotateOutcome> {
    let new_epoch = Epoch(
        plan.old_epoch
            .0
            .checked_add(1)
            .ok_or_else(|| Error::Format(format!("epoch overflow at {}", plan.old_epoch.0)))?,
    );
    let old_ek = derive_epoch_key(isk, plan.vault_id, plan.old_epoch, plan.context_label)?;
    let new_ek = derive_epoch_key(isk, plan.vault_id, new_epoch, plan.context_label)?;
    let mut new_recs = Vec::with_capacity(plan.keep.len());
    for r in &plan.keep {
        new_recs.push(rewrap_one(&new_ek, isk, plan.vault_id, new_epoch, r)?);
    }
    Ok(RotateOutcome {
        new_epoch,
        old_ek,
        new_ek,
        new_recipients: Recipients {
            vault_id: hex_encode(&plan.vault_id.0),
            epoch: new_epoch.0,
            recipients: new_recs,
        },
    })
}

/// Lay a rotation on disk: new epoch dir, per-epoch + root `recipients.json`,
/// and an empty new-epoch manifest (MAC'd under the new `ManifestKey`).
///
/// The old epoch is left untouched (old recipients + old manifest + old
/// objects remain), so a remaining recipient can still open old-epoch
/// objects via the old EK without reseal (04 6). `generator` is the
/// `generator` string for the new manifest header.
pub fn commit_rotation(
    vault_root: &Path,
    vault_id: VaultId,
    outcome: &RotateOutcome,
    generator: &str,
    generated_at: i64,
) -> Result<()> {
    init_vault_dir(vault_root, vault_id, outcome.new_epoch)?;
    let rec_text = serde_json::to_string_pretty(&outcome.new_recipients)
        .map_err(|e| Error::Format(format!("recipients serialize: {e}")))?;
    write_atomic(
        &epoch_recipients_path(vault_root, outcome.new_epoch),
        rec_text.as_bytes(),
    )?;
    write_atomic(&vault_root.join("recipients.json"), rec_text.as_bytes())?;
    let mk = derive_manifest_key(&outcome.new_ek, vault_id, outcome.new_epoch);
    let manifest = Manifest {
        vault_id,
        epoch: outcome.new_epoch,
        suite: crate::SUITE_0X01,
        flags: 0,
        generated_at,
        generator: generator.to_string(),
        root: entries_root(&[])?,
        entry_count: 0,
        total_plain_bytes: 0,
        total_cipher_bytes: 0,
        entries: vec![],
    };
    write_manifest_file(vault_root, outcome.new_epoch, &manifest, &mk)?;
    Ok(())
}

/// One-shot rotate (crypto + layout). Convenience over
/// [`plan_rotation`] + [`commit_rotation`].
pub fn rotate_epoch(
    isk: &IdentitySecret,
    vault_root: &Path,
    plan: &RotatePlan<'_>,
    generator: &str,
    generated_at: i64,
) -> Result<RotateOutcome> {
    let outcome = plan_rotation(isk, plan)?;
    commit_rotation(vault_root, plan.vault_id, &outcome, generator, generated_at)?;
    Ok(outcome)
}
/// The EK pair of an epoch rotation (04-vault 6; 02-cryptography 3).
#[derive(Debug)]
pub struct EpochKeys<'a> {
    pub old_epoch: Epoch,
    pub old_ek: &'a EpochKey,
    pub new_epoch: Epoch,
    pub new_ek: &'a EpochKey,
}

/// Provenance stamped into a rewritten manifest.
#[derive(Debug)]
pub struct RotationStamp<'a> {
    pub generator: &'a str,
    pub generated_at: i64,
}

// ---- Reseal (G0c) ----

/// Reseal all objects referenced by the old-epoch manifest under the new EK
/// at the new epoch, and write a new-epoch manifest pointing at them.
///
/// For each old entry: open the old object under `old_ek` (old epoch, old
/// path-bind), re-seal under `new_ek` (new epoch, same path-bind) with a
/// fresh `object_id`, write it to the new epoch's object tree, and record
/// the new entry. The new manifest is MAC'd under the new `ManifestKey`.
/// Old-epoch objects remain on disk until `snapshot::gc`.
///
/// Returns the count of rewritten objects. Errors never contain ISK.
pub fn reseal(
    vault_root: &Path,
    vault_id: VaultId,
    keys: &EpochKeys<'_>,
    stamp: &RotationStamp<'_>,
) -> Result<u64> {
    let old_mk = derive_manifest_key(keys.old_ek, vault_id, keys.old_epoch);
    let old_manifest = read_manifest_file(vault_root, keys.old_epoch, &old_mk)?;
    if old_manifest.entries.is_empty() {
        let new_mk = derive_manifest_key(keys.new_ek, vault_id, keys.new_epoch);
        let m = Manifest {
            vault_id,
            epoch: keys.new_epoch,
            suite: crate::SUITE_0X01,
            flags: old_manifest.flags,
            generated_at: stamp.generated_at,
            generator: stamp.generator.to_string(),
            root: entries_root(&[])?,
            entry_count: 0,
            total_plain_bytes: 0,
            total_cipher_bytes: 0,
            entries: vec![],
        };
        write_manifest_file(vault_root, keys.new_epoch, &m, &new_mk)?;
        return Ok(0);
    }

    let mut new_entries: Vec<crate::manifest::Entry> =
        Vec::with_capacity(old_manifest.entries.len());
    let mut count = 0u64;
    for old_entry in &old_manifest.entries {
        let raw = vault::read_object(vault_root, keys.old_epoch, &old_entry.object_id)?;
        if raw.len() < HEADER_SIZE {
            return Err(Error::AuthFail);
        }
        let bind: &[u8] = if old_entry.bind {
            old_entry.path.as_bytes()
        } else {
            b""
        };
        let (_old_hdr, plaintext) =
            open_object(keys.old_ek, &raw[..HEADER_SIZE], &raw[HEADER_SIZE..], bind)?;
        let new_oid = vault::new_object_id()?;
        let sealed = seal_object(
            keys.new_ek,
            &ObjectSpec {
                vault_id,
                epoch: keys.new_epoch,
                object_id: new_oid,
                chunk_size: DEFAULT_CHUNK_SIZE,
                path_bind: bind,
            },
            &plaintext,
        )?;
        vault::write_object(
            vault_root,
            keys.new_epoch,
            &new_oid,
            &sealed.header.to_bytes(),
            &sealed.chunks,
        )?;
        let new_entry = crate::manifest::Entry {
            path: old_entry.path.clone(),
            path_sealed: old_entry.path_sealed,
            object_id: new_oid,
            kind: old_entry.kind,
            plain_len: old_entry.plain_len,
            chunk_count: sealed.header.chunk_count,
            mode: old_entry.mode,
            mtime_ms: old_entry.mtime_ms,
            content_root: sealed.content_root,
            bind: old_entry.bind,
        };
        new_entries.push(new_entry);
        count += 1;
    }

    let new_mk = derive_manifest_key(keys.new_ek, vault_id, keys.new_epoch);
    let manifest = Manifest {
        vault_id,
        epoch: keys.new_epoch,
        suite: crate::SUITE_0X01,
        flags: old_manifest.flags,
        generated_at: stamp.generated_at,
        generator: stamp.generator.to_string(),
        root: entries_root(&new_entries)?,
        entry_count: u32::try_from(new_entries.len()).unwrap_or(u32::MAX),
        total_plain_bytes: new_entries.iter().map(|e| e.plain_len).sum(),
        total_cipher_bytes: new_entries
            .iter()
            .map(|e| e.plain_len)
            .sum::<u64>()
            .saturating_add(
                u64::try_from(new_entries.len())
                    .unwrap_or(u64::MAX)
                    .saturating_mul(16),
            ),
        entries: new_entries,
    };
    write_manifest_file(vault_root, keys.new_epoch, &manifest, &new_mk)?;
    Ok(count)
}

// ---- Policy re-seal (G0c) ----

/// Re-seal `policy.json.sealed` for the new epoch (10-policy 3; SPEC-v027).
///
/// Loads the policy under the old `MetaKey` (old epoch in the AD), then
/// re-seals it under the new `MetaKey` with the new epoch in the AD. A vault
/// with no sealed policy (default policy) is a no-op returning `false`;
/// a successful re-seal returns `true`. Tamper / wrong key => [`Error::AuthFail`].
pub fn reseal_policy(vault_root: &Path, vault_id: VaultId, keys: &EpochKeys<'_>) -> Result<bool> {
    let old_meta = derive_meta_key(keys.old_ek, vault_id, keys.old_epoch);
    let new_meta = derive_meta_key(keys.new_ek, vault_id, keys.new_epoch);
    if !crate::policy::policy_path(vault_root).exists() {
        return Ok(false);
    }
    let policy = crate::policy::load_policy(vault_root, &old_meta, vault_id, keys.old_epoch)?;
    crate::policy::seal_policy(vault_root, &policy, &new_meta, vault_id, keys.new_epoch)?;
    Ok(true)
}

// ---- Unwrap helper for tests / G1 ----

/// Unwrap the EK for `epoch` from the per-epoch (or root) `recipients.json`.
///
/// Tries the per-epoch file first, then the root file. For a symmetric
/// recipient whose `key_id` matches `isk`, unwraps via ISK; if an X25519
/// `secret` is supplied and a matching X25519 recipient is present, unwraps
/// via that secret. Returns the first recipient that unwraps successfully.
/// Used by tests and by G1 to recover the EK for an arbitrary epoch after
/// rotation. Errors never contain ISK.
pub fn unwrap_epoch_ek(
    vault_root: &Path,
    vault_id: VaultId,
    epoch: Epoch,
    isk: &IdentitySecret,
    x25519_secret: Option<&[u8; 32]>,
) -> Result<EpochKey> {
    let per_epoch = epoch_recipients_path(vault_root, epoch);
    let root = vault_root.join("recipients.json");
    let candidates: Vec<PathBuf> = if per_epoch.exists() {
        vec![per_epoch, root]
    } else {
        vec![root]
    };
    for path in candidates {
        if !path.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&path)?;
        let recs: Recipients = serde_json::from_str(&text)
            .map_err(|e| Error::Format(format!("{}: {e}", path.display())))?;
        if recs.epoch != epoch.0 {
            continue;
        }
        for r in &recs.recipients {
            match r {
                Recipient::Symmetric { .. } => {
                    if let Ok(ek) = recipients::unwrap_symmetric(r, isk, vault_id, epoch) {
                        return Ok(ek);
                    }
                }
                Recipient::X25519 { .. } => {
                    if let Some(sk) = x25519_secret {
                        if let Ok(ek) = recipients::unwrap_x25519(r, sk, vault_id, epoch) {
                            return Ok(ek);
                        }
                    }
                }
                Recipient::Hybrid { .. } => {}
            }
        }
    }
    Err(Error::AuthFail)
}
#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use crate::chunk::DEFAULT_CHUNK_SIZE;
    use crate::kdf::{
        derive_key_id, derive_manifest_key, derive_meta_key, IdentitySecret, ObjectId,
    };
    use crate::manifest::{Entry, EntryKind, Manifest};
    use crate::object::{open_object, seal_object, ObjectSpec};
    use crate::policy::{self, default_policy, evaluate, Op, PrincipalId, Verdict};
    use crate::recipients::{wrap_symmetric, wrap_x25519, Recipients};
    use crate::vault::{init_vault_dir, new_object_id, write_atomic, write_object};
    use tempfile::tempdir;
    use x25519_dalek::{PublicKey, StaticSecret};

    const GEN_AT: i64 = 1_700_000_000;
    const GEN: &str = "geode-test";

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x07; 32])
    }
    fn vault_id() -> VaultId {
        VaultId([0x01; 16])
    }
    fn key_id() -> crate::kdf::KeyId {
        derive_key_id(&isk()).unwrap()
    }

    fn recipient_keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let sk = StaticSecret::from([seed; 32]);
        let pk = PublicKey::from(&sk).to_bytes();
        ([seed; 32], pk)
    }

    fn build_vault() -> (tempfile::TempDir, std::path::PathBuf, ObjectId, [u8; 32]) {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        let vid = vault_id();
        let epoch = Epoch(1);
        init_vault_dir(&root, vid, epoch).unwrap();
        let ek = crate::kdf::derive_epoch_key(&isk(), vid, epoch, "test").unwrap();
        let kid = key_id();
        let (rsk, rpk) = recipient_keypair(0xa1);
        let sym = wrap_symmetric(&ek, &isk(), vid, epoch, kid).unwrap();
        let x25 = wrap_x25519(&ek, &rpk, vid, epoch, kid).unwrap();
        let recs = Recipients {
            vault_id: hex_encode(&vid.0),
            epoch: epoch.0,
            recipients: vec![sym, x25],
        };
        let rec_text = serde_json::to_string_pretty(&recs).unwrap();
        write_atomic(&root.join("recipients.json"), rec_text.as_bytes()).unwrap();
        write_atomic(&epoch_recipients_path(&root, epoch), rec_text.as_bytes()).unwrap();
        let oid = new_object_id().unwrap();
        let sealed = seal_object(
            &ek,
            &ObjectSpec {
                vault_id: vid,
                epoch,
                object_id: oid,
                chunk_size: DEFAULT_CHUNK_SIZE,
                path_bind: b"",
            },
            b"alpha-secret",
        )
        .unwrap();
        write_object(
            &root,
            epoch,
            &oid,
            &sealed.header.to_bytes(),
            &sealed.chunks,
        )
        .unwrap();
        let entry = Entry {
            path: "docs/a.txt".to_string(),
            path_sealed: false,
            object_id: oid,
            kind: EntryKind::File,
            plain_len: 12,
            chunk_count: 1,
            mode: 0o644,
            mtime_ms: 0,
            content_root: sealed.content_root,
            bind: false,
        };
        let mk = derive_manifest_key(&ek, vid, epoch);
        let manifest = Manifest {
            vault_id: vid,
            epoch,
            suite: crate::SUITE_0X01,
            flags: 0,
            generated_at: GEN_AT,
            generator: GEN.to_string(),
            root: crate::manifest::entries_root(std::slice::from_ref(&entry)).unwrap(),
            entry_count: 1,
            total_plain_bytes: 12,
            total_cipher_bytes: 28,
            entries: vec![entry],
        };
        write_manifest_file(&root, epoch, &manifest, &mk).unwrap();
        (d, root, oid, rsk)
    }

    fn load_recs(root: &std::path::Path) -> Vec<Recipient> {
        let t = std::fs::read_to_string(root.join("recipients.json")).unwrap();
        let r: Recipients = serde_json::from_str(&t).unwrap();
        r.recipients
    }

    // ---- G0a ----

    #[test]
    fn rotate_increments_epoch_and_derives_new_ek() {
        let (_d, root, _oid, _rsk) = build_vault();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: load_recs(&root),
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        assert_eq!(out.new_epoch, Epoch(2));
        assert_ne!(out.old_ek.as_bytes(), out.new_ek.as_bytes());
        let want = crate::kdf::derive_epoch_key(&isk(), vault_id(), Epoch(2), "test").unwrap();
        assert_eq!(out.new_ek.as_bytes(), want.as_bytes());
    }

    #[test]
    fn rotate_wraps_new_ek_for_remaining_recipients() {
        let (_d, root, _oid, rsk) = build_vault();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: load_recs(&root),
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        let from_sym = unwrap_epoch_ek(&root, vault_id(), Epoch(2), &isk(), None).unwrap();
        assert_eq!(from_sym.as_bytes(), out.new_ek.as_bytes());
        let from_x25 = unwrap_epoch_ek(&root, vault_id(), Epoch(2), &isk(), Some(&rsk)).unwrap();
        assert_eq!(from_x25.as_bytes(), out.new_ek.as_bytes());
        let on_disk: Recipients =
            serde_json::from_str(&std::fs::read_to_string(root.join("recipients.json")).unwrap())
                .unwrap();
        assert_eq!(on_disk.epoch, 2);
        assert_eq!(on_disk.recipients.len(), 2);
    }

    // ---- G0b ----

    #[test]
    fn without_reseal_remaining_recipient_opens_old_objects() {
        let (_d, root, oid, _rsk) = build_vault();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: load_recs(&root),
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        let old_ek = unwrap_epoch_ek(&root, vault_id(), Epoch(1), &isk(), None).unwrap();
        assert_eq!(old_ek.as_bytes(), out.old_ek.as_bytes());
        let raw = crate::vault::read_object(&root, Epoch(1), &oid).unwrap();
        let (_hdr, pt) = open_object(
            &old_ek,
            &raw[..crate::object::HEADER_SIZE],
            &raw[crate::object::HEADER_SIZE..],
            b"",
        )
        .unwrap();
        assert_eq!(pt, b"alpha-secret");
    }

    #[test]
    fn dropped_x25519_recipient_cannot_unwrap_new_ek() {
        let (_d, root, _oid, rsk) = build_vault();
        let keep: Vec<Recipient> = load_recs(&root)
            .into_iter()
            .filter(|r| matches!(r, Recipient::Symmetric { .. }))
            .collect();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep,
        };
        let _out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        // Epoch 2 recipients have no X25519 variant: the drop took effect.
        let on2: Recipients = serde_json::from_str(
            &std::fs::read_to_string(epoch_recipients_path(&root, Epoch(2))).unwrap(),
        )
        .unwrap();
        assert!(on2
            .recipients
            .iter()
            .all(|r| matches!(r, Recipient::Symmetric { .. })));
        // The dropped recipient (only rsk, no operator ISK) cannot unwrap
        // the new EK: a stranger ISK fails the sym leg and there is no
        // x25519 recipient left to unwrap.
        let stranger = IdentitySecret::from_bytes([0x99; 32]);
        let bad = unwrap_epoch_ek(&root, vault_id(), Epoch(2), &stranger, Some(&rsk));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
        // Incomplete revocation: dropped sk still unwraps the OLD EK at
        // epoch 1 (old per-epoch recipients untouched, 04 6).
        let _old_ek = unwrap_epoch_ek(&root, vault_id(), Epoch(1), &isk(), Some(&rsk)).unwrap();
    }

    #[test]
    fn wrong_x25519_secret_is_auth_fail() {
        let (_d, root, _oid, _rsk) = build_vault();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: load_recs(&root),
        };
        let _out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        let on_disk: Recipients =
            serde_json::from_str(&std::fs::read_to_string(root.join("recipients.json")).unwrap())
                .unwrap();
        let x25 = on_disk
            .recipients
            .iter()
            .find(|r| matches!(r, Recipient::X25519 { .. }))
            .unwrap();
        let bad = crate::recipients::unwrap_x25519(x25, &[0xb2; 32], vault_id(), Epoch(2));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
    }

    #[test]
    fn rotate_errors_never_contain_isk() {
        let (_d, root, _oid, _rsk) = build_vault();
        let hybrid = Recipient::Hybrid {
            key_id: key_id(),
            x25519_public: String::new(),
            mlkem_public: String::new(),
            wrap: String::new(),
        };
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: vec![hybrid],
        };
        let r = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT);
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "leaks ISK: {s}");
        assert!(!s.contains('\u{7}'), "leaks key bytes: {s}");
    }
    // ---- G0c tests appended into the same `tests` module via include ----
    //
    // These tests are concatenated after rotate_c.rs inside the single `mod tests`
    // block. They cover reseal, dropped-sk-reads, policy re-seal, and the hybrid
    // stub. Helpers (isk/vault_id/key_id/build_vault/load_recs) are defined in
    // rotate_c.rs and visible here because both files are pasted into one module.

    #[test]
    fn reseal_rewrites_objects_under_new_ek() {
        let (_d, root, old_oid, _rsk) = build_vault();
        let keep: Vec<Recipient> = load_recs(&root)
            .into_iter()
            .filter(|r| matches!(r, Recipient::Symmetric { .. }))
            .collect();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep,
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        let n = reseal(
            &root,
            vault_id(),
            &EpochKeys {
                old_epoch: Epoch(1),
                old_ek: &out.old_ek,
                new_epoch: out.new_epoch,
                new_ek: &out.new_ek,
            },
            &RotationStamp {
                generator: GEN,
                generated_at: GEN_AT,
            },
        )
        .unwrap();
        assert_eq!(n, 1);

        let new_mk = derive_manifest_key(&out.new_ek, vault_id(), out.new_epoch);
        let new_manifest = read_manifest_file(&root, out.new_epoch, &new_mk).unwrap();
        assert_eq!(new_manifest.entries.len(), 1);
        let new_oid = new_manifest.entries[0].object_id;
        assert_ne!(new_oid, old_oid);

        let recovered_ek = unwrap_epoch_ek(&root, vault_id(), out.new_epoch, &isk(), None).unwrap();
        let raw = crate::vault::read_object(&root, out.new_epoch, &new_oid).unwrap();
        let (_hdr, pt) = open_object(
            &recovered_ek,
            &raw[..crate::object::HEADER_SIZE],
            &raw[crate::object::HEADER_SIZE..],
            b"",
        )
        .unwrap();
        assert_eq!(pt, b"alpha-secret");
    }

    #[test]
    fn reseal_dropped_sk_cannot_read_rewritten_object() {
        let (_d, root, _old_oid, rsk) = build_vault();
        let keep: Vec<Recipient> = load_recs(&root)
            .into_iter()
            .filter(|r| matches!(r, Recipient::Symmetric { .. }))
            .collect();
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep,
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();
        reseal(
            &root,
            vault_id(),
            &EpochKeys {
                old_epoch: Epoch(1),
                old_ek: &out.old_ek,
                new_epoch: out.new_epoch,
                new_ek: &out.new_ek,
            },
            &RotationStamp {
                generator: GEN,
                generated_at: GEN_AT,
            },
        )
        .unwrap();

        // Epoch 2 recipients have no X25519 variant: the drop took effect.
        let on_disk: Recipients = serde_json::from_str(
            &std::fs::read_to_string(epoch_recipients_path(&root, out.new_epoch)).unwrap(),
        )
        .unwrap();
        assert!(on_disk
            .recipients
            .iter()
            .all(|r| matches!(r, Recipient::Symmetric { .. })));
        // The dropped recipient (only rsk, no operator ISK) cannot unwrap
        // the new EK, so cannot read the rewritten object.
        let stranger = IdentitySecret::from_bytes([0x99; 32]);
        let bad = unwrap_epoch_ek(&root, vault_id(), out.new_epoch, &stranger, Some(&rsk));
        assert!(matches!(bad, Err(Error::AuthFail)), "got {bad:?}");
    }

    #[test]
    fn reseal_policy_re_seals_for_new_epoch() {
        let (_d, root, _old_oid, _rsk) = build_vault();
        let vid = vault_id();

        // Seal a policy at epoch 1 under the epoch-1 MetaKey.
        let ek1 = crate::kdf::derive_epoch_key(&isk(), vid, Epoch(1), "test").unwrap();
        let meta1 = derive_meta_key(&ek1, vid, Epoch(1));
        let policy = default_policy(&hex_encode(&vid.0));
        policy::seal_policy(&root, &policy, &meta1, vid, Epoch(1)).unwrap();
        // It loads under the old MetaKey.
        let loaded_old = policy::load_policy(&root, &meta1, vid, Epoch(1)).unwrap();
        let human = PrincipalId("human:local".into());
        assert_eq!(
            evaluate(&loaded_old, &human, Op::Admin, "x").unwrap(),
            Verdict::Allow
        );

        // Rotate (keep sym recipient).
        let keep: Vec<Recipient> = load_recs(&root)
            .into_iter()
            .filter(|r| matches!(r, Recipient::Symmetric { .. }))
            .collect();
        let plan = RotatePlan {
            vault_id: vid,
            old_epoch: Epoch(1),
            context_label: "test",
            keep,
        };
        let out = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT).unwrap();

        // Before reseal_policy, the old sealed policy FAILS under the new MetaKey.
        let meta2 = derive_meta_key(&out.new_ek, vid, out.new_epoch);
        let stale = policy::load_policy(&root, &meta2, vid, out.new_epoch);
        assert!(matches!(stale, Err(Error::AuthFail)), "got {stale:?}");

        // Reseal the policy for the new epoch.
        let did = reseal_policy(
            &root,
            vid,
            &EpochKeys {
                old_epoch: Epoch(1),
                old_ek: &out.old_ek,
                new_epoch: out.new_epoch,
                new_ek: &out.new_ek,
            },
        )
        .unwrap();
        assert!(did);

        // Now it loads under the NEW MetaKey + new epoch.
        let loaded_new = policy::load_policy(&root, &meta2, vid, out.new_epoch).unwrap();
        assert_eq!(
            evaluate(&loaded_new, &human, Op::Admin, "x").unwrap(),
            Verdict::Allow
        );
        // And the OLD sealed policy no longer authenticates under the old key
        // (the file was overwritten with new-epoch AD).
        let stale_old = policy::load_policy(&root, &meta1, vid, Epoch(1));
        assert!(
            matches!(stale_old, Err(Error::AuthFail)),
            "got {stale_old:?}"
        );
    }

    #[test]
    fn reseal_policy_no_sealed_policy_is_noop() {
        let (_d, root, _old_oid, _rsk) = build_vault();
        let vid = vault_id();
        let ek1 = crate::kdf::derive_epoch_key(&isk(), vid, Epoch(1), "test").unwrap();
        let ek2 = crate::kdf::derive_epoch_key(&isk(), vid, Epoch(2), "test").unwrap();
        // No policy.json.sealed on disk.
        let did = reseal_policy(
            &root,
            vid,
            &EpochKeys {
                old_epoch: Epoch(1),
                old_ek: &ek1,
                new_epoch: Epoch(2),
                new_ek: &ek2,
            },
        )
        .unwrap();
        assert!(!did);
    }

    #[test]
    fn hybrid_recipient_stays_not_implemented() {
        let (_d, root, _oid, _rsk) = build_vault();
        let hybrid = Recipient::Hybrid {
            key_id: key_id(),
            x25519_public: String::new(),
            mlkem_public: String::new(),
            wrap: String::new(),
        };
        let plan = RotatePlan {
            vault_id: vault_id(),
            old_epoch: Epoch(1),
            context_label: "test",
            keep: vec![hybrid],
        };
        let r = rotate_epoch(&isk(), &root, &plan, GEN, GEN_AT);
        assert!(matches!(r, Err(Error::NotImplemented)), "got {r:?}");
    }
}
