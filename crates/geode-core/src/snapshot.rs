//! Snapshots and garbage collection (04-vault-and-manifest 7).
//!
//! G1a (v0.2.1): a snapshot is an authenticated copy of the current epoch
//! `manifest.json` plus a named alias, stored at
//! `epochs/<NNNNNNNN>/snapshots/<name>.json`. Snapshots do not copy objects.
//! `gc` deletes `.gobj` files unreferenced by the current manifest and all
//! named snapshots; live objects are untouched and still verify.
//!
//! Authentication: each snapshot envelope carries a `snapshot_mac` (16-byte
//! AEGIS-256-X2 tag) under the epoch `ManifestKey` with AD `geode/v1/snapshot`,
//! binding `vault_id` + `epoch` + `name` + `created_at` + the embedded
//! manifest body. The embedded manifest body retains its own `manifest_mac`,
//! so a restored snapshot is independently verifiable as a manifest.

use crate::kdf::{Epoch, ObjectId};
use crate::manifest::{self, canonicalize, snapshot_mac, Manifest};
use crate::vault::{self, write_atomic};
use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// On-disk snapshot envelope at `epochs/N/snapshots/<name>.json`.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct SnapshotEnvelope {
    pub vault_id: String,
    pub epoch: u32,
    pub name: String,
    pub created_at: i64,
    pub manifest: serde_json::Value,
    pub snapshot_mac: String,
}

/// Report from a `gc` run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GcReport {
    pub dropped: u64,
    pub kept: u64,
    pub dropped_paths: Vec<PathBuf>,
}

/// Validate a snapshot name: `^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`.
///
/// Prevents path traversal, hidden files, and reserved `.`/`..`.
pub fn validate_snapshot_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 64 {
        return Err(Error::Format(format!(
            "snapshot name length must be 1..=64: {name:?}"
        )));
    }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_alphanumeric() {
        return Err(Error::Format(format!(
            "snapshot name must start alphanumeric: {name:?}"
        )));
    }
    for c in name.chars() {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return Err(Error::Format(format!(
                "snapshot name has bad char {c:?} in {name:?}"
            )));
        }
    }
    Ok(())
}

fn epoch_dir(vault_root: &Path, epoch: Epoch) -> PathBuf {
    vault_root.join("epochs").join(format!("{:08}", epoch.0))
}

fn snapshots_dir(vault_root: &Path, epoch: Epoch) -> PathBuf {
    epoch_dir(vault_root, epoch).join("snapshots")
}

fn snapshot_path(vault_root: &Path, epoch: Epoch, name: &str) -> PathBuf {
    snapshots_dir(vault_root, epoch).join(format!("{name}.json"))
}

fn read_json_value(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text).map_err(|e| Error::Format(format!("{}: {e}", path.display())))
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Format(format!("missing string field {field}")))
}

/// Verify `mac_field` (hex) over the JCS-canonicalized JSON minus that field.
fn verify_json_mac(
    manifest_key: &[u8; 32],
    value: &serde_json::Value,
    mac_field: &str,
    mac_fn: fn(&[u8; 32], &[u8]) -> Result<[u8; 16]>,
) -> Result<()> {
    let mac_hex = json_str(value, mac_field).map_err(|_| Error::AuthFail)?;
    let want_bytes = vault::hex_decode(mac_hex).map_err(|_| Error::AuthFail)?;
    if want_bytes.len() != 16 {
        return Err(Error::AuthFail);
    }
    let mut want = [0u8; 16];
    want.copy_from_slice(&want_bytes);
    let mut body = value.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove(mac_field);
    }
    let canon = canonicalize(&body)?;
    let got = mac_fn(manifest_key, &canon)?;
    // TODO(G5): constant-time compare (matches geode-core G5 note).
    if got != want {
        return Err(Error::AuthFail);
    }
    Ok(())
}

/// Read + verify the on-disk `manifest.json` for an epoch, returning the
/// authenticated `Manifest`. Mirrors the CLI's manifest leg of `load_vault`
/// so `gc` can trust the referenced object-id set.
pub fn read_manifest_file(
    vault_root: &Path,
    epoch: Epoch,
    manifest_key: &[u8; 32],
) -> Result<Manifest> {
    let mpath = vault::manifest_path(vault_root, epoch);
    let value = read_json_value(&mpath)?;
    verify_json_mac(manifest_key, &value, "manifest_mac", manifest::manifest_mac)?;
    let mut body = value;
    if let Some(o) = body.as_object_mut() {
        o.remove("manifest_mac");
    }
    serde_json::from_value(body).map_err(|e| Error::Format(format!("manifest.json: {e}")))
}

/// Write a `Manifest` to `manifest.json` atomically with a fresh
/// `manifest_mac` (03-format 5). Same wire format as the CLI's writer so a
/// restored snapshot verifies under `load_vault`.
pub fn write_manifest_file(
    vault_root: &Path,
    epoch: Epoch,
    manifest: &Manifest,
    manifest_key: &[u8; 32],
) -> Result<()> {
    let mut value = serde_json::to_value(manifest)
        .map_err(|e| Error::Format(format!("manifest serialize: {e}")))?;
    let canon = canonicalize(&value)?;
    let mac = manifest::manifest_mac(manifest_key, &canon)?;
    if let Some(o) = value.as_object_mut() {
        o.insert(
            "manifest_mac".into(),
            serde_json::Value::String(vault::hex_encode(&mac)),
        );
    }
    let text = serde_json::to_string_pretty(&value)
        .map_err(|e| Error::Format(format!("manifest serialize: {e}")))?;
    write_atomic(&vault::manifest_path(vault_root, epoch), text.as_bytes())
}

/// Create a snapshot: copy the current epoch `manifest.json` (already
/// MAC'd) into an authenticated envelope at
/// `epochs/N/snapshots/<name>.json`. Returns the snapshot path. Overwrites
/// an existing snapshot of the same name atomically.
pub fn create_snapshot(
    vault_root: &Path,
    epoch: Epoch,
    name: &str,
    manifest_key: &[u8; 32],
    created_at: i64,
) -> Result<PathBuf> {
    validate_snapshot_name(name)?;
    let manifest_value = read_json_value(&vault::manifest_path(vault_root, epoch))?;
    // Reuse the manifest's own vault_id/epoch so the envelope is consistent
    // with the embedded body (an attacker cannot rebind them). `VaultId` /
    // `Epoch` are newtypes over byte arrays, so they serialize as JSON arrays;
    // deserialize the typed `Manifest` to read them safely rather than
    // treating `vault_id` as a string.
    let parsed: Manifest = serde_json::from_value(manifest_value.clone())
        .map_err(|e| Error::Format(format!("manifest parse: {e}")))?;
    let vid = vault::hex_encode(&parsed.vault_id.0);
    let ep = parsed.epoch.0;
    let mut env = serde_json::Map::new();
    env.insert("vault_id".into(), serde_json::Value::String(vid));
    env.insert("epoch".into(), serde_json::Value::Number(ep.into()));
    env.insert("name".into(), serde_json::Value::String(name.to_string()));
    env.insert(
        "created_at".into(),
        serde_json::Value::Number(serde_json::Number::from(created_at)),
    );
    env.insert("manifest".into(), manifest_value);
    let env_value = serde_json::Value::Object(env);
    let canon = canonicalize(&env_value)?;
    let mac = snapshot_mac(manifest_key, &canon)?;
    let mut with_mac = env_value;
    if let Some(o) = with_mac.as_object_mut() {
        o.insert(
            "snapshot_mac".into(),
            serde_json::Value::String(vault::hex_encode(&mac)),
        );
    }
    let text = serde_json::to_string_pretty(&with_mac)
        .map_err(|e| Error::Format(format!("snapshot serialize: {e}")))?;
    let dest = snapshot_path(vault_root, epoch, name);
    write_atomic(&dest, text.as_bytes())?;
    Ok(dest)
}

/// List snapshot names for an epoch, sorted lexicographically. Returns an
/// empty vec if the snapshots directory does not exist.
pub fn list_snapshots(vault_root: &Path, epoch: Epoch) -> Result<Vec<String>> {
    let dir = snapshots_dir(vault_root, epoch);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut names = Vec::new();
    for e in std::fs::read_dir(&dir)? {
        let e = e?;
        let p = e.path();
        if !p.is_file() {
            continue;
        }
        if let Some(stem) = p.file_stem().and_then(|s| s.to_str()) {
            if p.extension().and_then(|s| s.to_str()) == Some("json")
                && validate_snapshot_name(stem).is_ok()
            {
                names.push(stem.to_string());
            }
        }
    }
    names.sort();
    Ok(names)
}

/// Read + verify a snapshot envelope. Returns the authenticated envelope.
pub fn read_snapshot(
    vault_root: &Path,
    epoch: Epoch,
    name: &str,
    manifest_key: &[u8; 32],
) -> Result<SnapshotEnvelope> {
    validate_snapshot_name(name)?;
    let value = read_json_value(&snapshot_path(vault_root, epoch, name))?;
    verify_json_mac(manifest_key, &value, "snapshot_mac", snapshot_mac)?;
    let env: SnapshotEnvelope = serde_json::from_value(value)
        .map_err(|e| Error::Format(format!("snapshot envelope: {e}")))?;
    if env.epoch != epoch.0 {
        return Err(Error::Format(format!(
            "snapshot epoch {} != requested {}",
            env.epoch, epoch.0
        )));
    }
    if env.name != name {
        return Err(Error::Format(format!(
            "snapshot name {:?} != requested {:?}",
            env.name, name
        )));
    }
    Ok(env)
}

/// Restore a snapshot: verify it, then return the embedded manifest body
/// (still carrying its own `manifest_mac`) for the caller to write back to
/// `manifest.json`. Does not delete objects — see `gc`.
pub fn restore_snapshot_body(
    vault_root: &Path,
    epoch: Epoch,
    name: &str,
    manifest_key: &[u8; 32],
) -> Result<Vec<u8>> {
    let env = read_snapshot(vault_root, epoch, name, manifest_key)?;
    // The embedded manifest must itself verify as a manifest before we hand
    // it back, so a restored manifest.json passes `load_vault`.
    verify_json_mac(
        manifest_key,
        &env.manifest,
        "manifest_mac",
        manifest::manifest_mac,
    )?;
    let text = serde_json::to_string_pretty(&env.manifest)
        .map_err(|e| Error::Format(format!("restore serialize: {e}")))?;
    Ok(text.into_bytes())
}

/// Object ids referenced by the current manifest and all named snapshots.
fn referenced_object_ids(
    vault_root: &Path,
    epoch: Epoch,
    manifest_key: &[u8; 32],
) -> Result<Vec<ObjectId>> {
    let mut ids = Vec::new();
    let current = read_manifest_file(vault_root, epoch, manifest_key)?;
    ids.extend(current.entries.iter().map(|e| e.object_id));
    for name in list_snapshots(vault_root, epoch)? {
        let env = read_snapshot(vault_root, epoch, &name, manifest_key)?;
        // The embedded manifest body is already authenticated by snapshot_mac;
        // deserialize to pull object ids.
        let m: Manifest = serde_json::from_value(env.manifest.clone())
            .map_err(|e| Error::Format(format!("snapshot {name} manifest: {e}")))?;
        ids.extend(m.entries.iter().map(|e| e.object_id));
    }
    Ok(ids)
}

/// Parse an `ObjectId` from a `.gobj` filename stem (32 hex chars).
fn object_id_from_filename(stem: &str) -> Result<ObjectId> {
    let bytes = vault::hex_decode(stem)?;
    if bytes.len() != 16 {
        return Err(Error::Format(format!(
            "object filename {stem:?} is not 16 bytes"
        )));
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(&bytes);
    Ok(ObjectId(a))
}

/// Garbage-collect unreferenced `.gobj` files for an epoch.
///
/// Walks `epochs/N/objects/**/*.gobj`, deletes any whose `object_id` is not
/// referenced by the current manifest or any named snapshot, and removes
/// empty shard directories. The current manifest and all snapshots are
/// MAC-verified before any deletion, so an attacker cannot pin a target
/// object by adding a fake entry. Live (referenced) objects are untouched.
/// Build the GC plan: a `GcReport` (with `dropped_paths` populated for every
/// unreferenced `.gobj`) plus the list of shard directories that would become
/// empty and be pruned. Performs **no** filesystem mutation. The current
/// manifest and all named snapshots are MAC-verified up front (via
/// `referenced_object_ids`), so a tampered manifest fails closed before the
/// plan is returned.
fn gc_plan(
    vault_root: &Path,
    epoch: Epoch,
    manifest_key: &[u8; 32],
) -> Result<(GcReport, Vec<PathBuf>)> {
    let mut report = GcReport::default();
    let referenced: std::collections::HashSet<[u8; 16]> =
        referenced_object_ids(vault_root, epoch, manifest_key)?
            .into_iter()
            .map(|oid| oid.0)
            .collect();

    let mut prune_shards: Vec<PathBuf> = Vec::new();
    let objects = epoch_dir(vault_root, epoch).join("objects");
    if !objects.is_dir() {
        return Ok((report, prune_shards));
    }
    let mut shard_dirs: Vec<PathBuf> = Vec::new();
    for shard in std::fs::read_dir(&objects)? {
        let shard = shard?;
        let sp = shard.path();
        if sp.is_dir() {
            shard_dirs.push(sp);
        }
    }
    shard_dirs.sort();
    for sp in shard_dirs {
        let mut keep_in_shard = 0u64;
        let mut entries: Vec<_> = std::fs::read_dir(&sp)?.collect::<std::result::Result<_, _>>()?;
        entries.sort_by_key(std::fs::DirEntry::path);
        for e in entries {
            let p = e.path();
            if !p.is_file() || p.extension().and_then(|s| s.to_str()) != Some("gobj") {
                continue;
            }
            let stem = p
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| Error::Format(format!("bad object filename {}", p.display())))?;
            let oid = object_id_from_filename(stem)?;
            if referenced.contains(&oid.0) {
                report.kept += 1;
                keep_in_shard += 1;
            } else {
                report.dropped += 1;
                report.dropped_paths.push(p);
            }
        }
        if keep_in_shard == 0 {
            prune_shards.push(sp);
        }
    }
    Ok((report, prune_shards))
}

/// Preview garbage collection without deleting anything.
///
/// Returns the same `GcReport` that [`gc`] would produce, with `dropped_paths`
/// listing every unreferenced `.gobj` that *would* be removed and `kept`
/// counting the live objects. No files or directories are touched; the TUI
/// can show this to the operator for confirmation before running [`gc`].
///
/// Like [`gc`], the current manifest and all named snapshots are MAC-verified
/// before the plan is built, so a tampered manifest fails closed here too.
#[must_use = "preview results should be shown to the operator"]
pub fn gc_preview(vault_root: &Path, epoch: Epoch, manifest_key: &[u8; 32]) -> Result<GcReport> {
    let (report, _prune) = gc_plan(vault_root, epoch, manifest_key)?;
    Ok(report)
}

/// Garbage-collect unreferenced `.gobj` files for an epoch.
///
/// Walks `epochs/N/objects/**/*.gobj`, deletes any whose `object_id` is not
/// referenced by the current manifest or any named snapshot, and removes
/// empty shard directories. The current manifest and all snapshots are
/// MAC-verified before any deletion, so an attacker cannot pin a target
/// object by adding a fake entry. Live (referenced) objects are untouched.
///
/// For a no-mutation preview, use [`gc_preview`].
pub fn gc(vault_root: &Path, epoch: Epoch, manifest_key: &[u8; 32]) -> Result<GcReport> {
    let (report, prune_shards) = gc_plan(vault_root, epoch, manifest_key)?;
    for p in &report.dropped_paths {
        std::fs::remove_file(p)?;
    }
    // Best-effort removal of now-empty shard dirs.
    for sp in prune_shards {
        let _ = std::fs::remove_dir(&sp);
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::DEFAULT_CHUNK_SIZE;
    use crate::kdf::{
        derive_epoch_key, derive_manifest_key, EpochKey, IdentitySecret, ObjectId, VaultId,
    };
    use crate::manifest::{entries_root, Entry, EntryKind};
    use crate::object::{open_object, seal_object};
    use crate::vault::{init_vault_dir, new_object_id, write_object};
    use tempfile::tempdir;

    fn isk() -> IdentitySecret {
        IdentitySecret::from_bytes([0x07; 32])
    }
    fn ek(vid: VaultId, epoch: Epoch) -> EpochKey {
        derive_epoch_key(&isk(), vid, epoch, "test").unwrap()
    }
    fn mk(vid: VaultId, epoch: Epoch) -> [u8; 32] {
        derive_manifest_key(&ek(vid, epoch), vid, epoch)
    }

    fn build_vault() -> (tempfile::TempDir, PathBuf, VaultId, Epoch) {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        let vid = VaultId([0x01; 16]);
        let epoch = Epoch(1);
        init_vault_dir(&root, vid, epoch).unwrap();
        (d, root, vid, epoch)
    }

    /// Seal `plaintext` under `path`, write the object, return its `object_id`.
    fn seal_write(root: &Path, vid: VaultId, epoch: Epoch, path: &str, pt: &[u8]) -> ObjectId {
        let e = ek(vid, epoch);
        let oid = new_object_id().unwrap();
        let sealed =
            seal_object(&e, vid, epoch, oid, DEFAULT_CHUNK_SIZE, path.as_bytes(), pt).unwrap();
        write_object(root, epoch, &oid, &sealed.header.to_bytes(), &sealed.chunks).unwrap();
        oid
    }

    fn entry(path: &str, oid: ObjectId, plain_len: u64, root_hash: [u8; 32]) -> Entry {
        Entry {
            path: path.to_string(),
            path_sealed: false,
            object_id: oid,
            kind: EntryKind::File,
            plain_len,
            chunk_count: 1,
            mode: 0o644,
            mtime_ms: 0,
            content_root: root_hash,
            bind: false,
        }
    }

    fn manifest_for(vid: VaultId, epoch: Epoch, entries: Vec<Entry>) -> Manifest {
        let mut m = Manifest {
            vault_id: vid,
            epoch,
            suite: crate::SUITE_0X01,
            flags: 0,
            generated_at: 1_700_000_000,
            generator: "geode-test".to_string(),
            root: [0u8; 32],
            entry_count: u32::try_from(entries.len()).unwrap(),
            total_plain_bytes: entries.iter().map(|e| e.plain_len).sum(),
            total_cipher_bytes: entries.iter().map(|e| e.plain_len).sum(),
            entries,
        };
        m.root = entries_root(&m.entries);
        m
    }

    fn write_manifest(root: &Path, vid: VaultId, epoch: Epoch, entries: Vec<Entry>) {
        let m = manifest_for(vid, epoch, entries);
        write_manifest_file(root, epoch, &m, &mk(vid, epoch)).unwrap();
    }

    #[test]
    fn validate_name_accepts_good() {
        assert!(validate_snapshot_name("pre-agent-run").is_ok());
        assert!(validate_snapshot_name("a").is_ok());
        assert!(validate_snapshot_name("snapshot.2026-09-15").is_ok());
        assert!(validate_snapshot_name(&"x".repeat(64)).is_ok());
    }

    #[test]
    fn validate_name_rejects_bad() {
        assert!(validate_snapshot_name("").is_err());
        assert!(validate_snapshot_name(&"x".repeat(65)).is_err());
        assert!(validate_snapshot_name(".hidden").is_err());
        assert!(validate_snapshot_name("../escape").is_err());
        assert!(validate_snapshot_name("a/b").is_err());
        assert!(validate_snapshot_name("a b").is_err());
        assert!(validate_snapshot_name("-dash").is_err());
    }

    #[test]
    fn create_list_read_roundtrip() {
        let (_d, root, vid, epoch) = build_vault();
        let oid = seal_write(&root, vid, epoch, "docs/a.txt", b"alpha");
        write_manifest(
            &root,
            vid,
            epoch,
            vec![entry("docs/a.txt", oid, 5, [0u8; 32])],
        );
        let key = mk(vid, epoch);

        let p = create_snapshot(&root, epoch, "pre-run", &key, 1_700_000_001).unwrap();
        assert!(p.ends_with("epochs/00000001/snapshots/pre-run.json"));
        assert_eq!(
            list_snapshots(&root, epoch).unwrap(),
            vec!["pre-run".to_string()]
        );

        let env = read_snapshot(&root, epoch, "pre-run", &key).unwrap();
        assert_eq!(env.name, "pre-run");
        assert_eq!(env.epoch, 1);
        assert_eq!(env.vault_id, vault::hex_encode(&vid.0));
        // Embedded manifest carries one entry referencing our object.
        let m: Manifest = serde_json::from_value(env.manifest.clone()).unwrap();
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].object_id, oid);
    }

    #[test]
    fn list_empty_when_no_snapshots() {
        let (_d, root, _vid, epoch) = build_vault();
        assert_eq!(list_snapshots(&root, epoch).unwrap(), Vec::<String>::new());
    }

    #[test]
    fn list_sorted() {
        let (_d, root, vid, epoch) = build_vault();
        let oid = seal_write(&root, vid, epoch, "x", b"x");
        write_manifest(&root, vid, epoch, vec![entry("x", oid, 1, [0u8; 32])]);
        let key = mk(vid, epoch);
        create_snapshot(&root, epoch, "zeta", &key, 1).unwrap();
        create_snapshot(&root, epoch, "alpha", &key, 2).unwrap();
        create_snapshot(&root, epoch, "mid", &key, 3).unwrap();
        assert_eq!(
            list_snapshots(&root, epoch).unwrap(),
            vec!["alpha", "mid", "zeta"]
        );
    }

    #[test]
    fn read_wrong_key_is_auth_fail() {
        let (_d, root, vid, epoch) = build_vault();
        let oid = seal_write(&root, vid, epoch, "x", b"x");
        write_manifest(&root, vid, epoch, vec![entry("x", oid, 1, [0u8; 32])]);
        let key = mk(vid, epoch);
        create_snapshot(&root, epoch, "s", &key, 1).unwrap();
        let wrong = [0x99; 32];
        let r = read_snapshot(&root, epoch, "s", &wrong);
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn tampered_snapshot_mac_is_auth_fail() {
        let (_d, root, vid, epoch) = build_vault();
        let oid = seal_write(&root, vid, epoch, "x", b"x");
        write_manifest(&root, vid, epoch, vec![entry("x", oid, 1, [0u8; 32])]);
        let key = mk(vid, epoch);
        create_snapshot(&root, epoch, "s", &key, 1).unwrap();
        let sp = snapshot_path(&root, epoch, "s");
        let mut txt = std::fs::read_to_string(&sp).unwrap();
        // Flip one hex char in snapshot_mac.
        let idx = txt.find("snapshot_mac").unwrap();
        let hex_idx = idx + "snapshot_mac\": \"".len();
        let bytes = txt.as_bytes();
        let ch = bytes[hex_idx];
        let flipped = if ch == b'0' { b'1' } else { b'0' };
        txt.replace_range(hex_idx..=hex_idx, std::str::from_utf8(&[flipped]).unwrap());
        std::fs::write(&sp, txt).unwrap();
        let r = read_snapshot(&root, epoch, "s", &key);
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn restore_returns_verifiable_manifest_body() {
        let (_d, root, vid, epoch) = build_vault();
        let oid = seal_write(&root, vid, epoch, "docs/a.txt", b"alpha");
        write_manifest(
            &root,
            vid,
            epoch,
            vec![entry("docs/a.txt", oid, 5, [0u8; 32])],
        );
        let key = mk(vid, epoch);
        create_snapshot(&root, epoch, "snap1", &key, 1).unwrap();

        let body = restore_snapshot_body(&root, epoch, "snap1", &key).unwrap();
        // Writing the restored body back to manifest.json must re-verify.
        write_atomic(&vault::manifest_path(&root, epoch), &body).unwrap();
        let m = read_manifest_file(&root, epoch, &key).unwrap();
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].object_id, oid);
    }

    #[test]
    fn gc_no_op_when_all_referenced() {
        let (_d, root, vid, epoch) = build_vault();
        let a = seal_write(&root, vid, epoch, "a", b"a");
        let b = seal_write(&root, vid, epoch, "b", b"b");
        write_manifest(
            &root,
            vid,
            epoch,
            vec![entry("a", a, 1, [0u8; 32]), entry("b", b, 1, [0u8; 32])],
        );
        let key = mk(vid, epoch);
        let report = gc(&root, epoch, &key).unwrap();
        assert_eq!(
            report,
            GcReport {
                dropped: 0,
                kept: 2,
                dropped_paths: Vec::new()
            }
        );
    }

    #[test]
    fn gc_drops_unreferenced_keeps_referenced() {
        let (_d, root, vid, epoch) = build_vault();
        let live = seal_write(&root, vid, epoch, "live", b"live");
        let dead = seal_write(&root, vid, epoch, "dead", b"dead");
        write_manifest(&root, vid, epoch, vec![entry("live", live, 4, [0u8; 32])]);
        let key = mk(vid, epoch);
        let report = gc(&root, epoch, &key).unwrap();
        assert_eq!(report.dropped, 1);
        assert_eq!(report.kept, 1);
        assert_eq!(report.dropped_paths.len(), 1);
        // dead object is gone, live object remains.
        assert!(!vault::object_path(&root, epoch, &dead).unwrap().exists());
        assert!(vault::object_path(&root, epoch, &live).unwrap().exists());
    }

    #[test]
    fn gc_keeps_snapshot_referenced_even_when_not_in_current_manifest() {
        let (_d, root, vid, epoch) = build_vault();
        let keep = seal_write(&root, vid, epoch, "keep", b"keep");
        let pinned = seal_write(&root, vid, epoch, "pinned", b"pinned");
        // `orphan` is written to disk but never appears in any manifest or
        // snapshot — e.g. a leftover from an interrupted seal.
        let orphan = seal_write(&root, vid, epoch, "orphan", b"orphan");
        let key = mk(vid, epoch);
        // Manifest references keep + pinned; snapshot pins both.
        write_manifest(
            &root,
            vid,
            epoch,
            vec![
                entry("keep", keep, 4, [0u8; 32]),
                entry("pinned", pinned, 6, [0u8; 32]),
            ],
        );
        create_snapshot(&root, epoch, "snap", &key, 1).unwrap();
        // Rewrite manifest to drop `pinned` from the current view. The
        // snapshot still pins it, so gc MUST keep it; `orphan` is referenced
        // by neither current manifest nor any snapshot and is dropped.
        write_manifest(&root, vid, epoch, vec![entry("keep", keep, 4, [0u8; 32])]);
        let report = gc(&root, epoch, &key).unwrap();
        assert_eq!(report.dropped, 1, "only the orphan object is dropped");
        assert_eq!(report.kept, 2, "keep + snapshot-pinned survive");
        assert!(vault::object_path(&root, epoch, &keep).unwrap().exists());
        assert!(vault::object_path(&root, epoch, &pinned).unwrap().exists());
        assert!(!vault::object_path(&root, epoch, &orphan).unwrap().exists());
    }

    #[test]
    fn live_objects_still_verify_after_gc() {
        let (_d, root, vid, epoch) = build_vault();
        let e = ek(vid, epoch);
        let live = seal_write(&root, vid, epoch, "live.txt", b"live content");
        let _dead = seal_write(&root, vid, epoch, "dead.txt", b"dead content");
        write_manifest(
            &root,
            vid,
            epoch,
            vec![entry("live.txt", live, 12, [0u8; 32])],
        );
        let key = mk(vid, epoch);
        let _report = gc(&root, epoch, &key).unwrap();
        // Re-open the live object from disk and decrypt.
        let bytes = crate::vault::read_object(&root, epoch, &live).unwrap();
        let hdr = &bytes[..crate::object::HEADER_SIZE];
        let chunks = &bytes[crate::object::HEADER_SIZE..];
        let (_h, pt) = open_object(&e, hdr, chunks, b"live.txt").unwrap();
        assert_eq!(pt, b"live content");
    }

    #[test]
    fn gc_with_tampered_manifest_mac_is_auth_fail_no_deletion() {
        let (_d, root, vid, epoch) = build_vault();
        let live = seal_write(&root, vid, epoch, "live", b"live");
        let target = seal_write(&root, vid, epoch, "target", b"target");
        write_manifest(&root, vid, epoch, vec![entry("live", live, 4, [0u8; 32])]);
        let key = mk(vid, epoch);
        // Attacker flips a hex char in manifest_mac; gc MUST verify the MAC
        // before trusting the referenced set, and abort with AuthFail.
        let mpath = vault::manifest_path(&root, epoch);
        let mut txt = std::fs::read_to_string(&mpath).unwrap();
        let idx = txt.find("manifest_mac").unwrap();
        let hex_idx = idx + "manifest_mac\": \"".len();
        let ch = txt.as_bytes()[hex_idx];
        let flipped = if ch == b'0' { b'1' } else { b'0' };
        txt.replace_range(hex_idx..=hex_idx, std::str::from_utf8(&[flipped]).unwrap());
        std::fs::write(&mpath, txt).unwrap();
        let r = gc(&root, epoch, &key);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "tampered manifest MUST fail gc"
        );
        // Nothing deleted because gc aborted before deletion.
        assert!(vault::object_path(&root, epoch, &live).unwrap().exists());
        assert!(vault::object_path(&root, epoch, &target).unwrap().exists());
    }

    #[test]
    fn gc_preview_reports_but_deletes_nothing() {
        let (_d, root, vid, epoch) = build_vault();
        let live = seal_write(&root, vid, epoch, "live", b"live");
        let dead = seal_write(&root, vid, epoch, "dead", b"dead");
        write_manifest(&root, vid, epoch, vec![entry("live", live, 4, [0u8; 32])]);
        let key = mk(vid, epoch);
        let preview = gc_preview(&root, epoch, &key).unwrap();
        // Same plan as gc would produce.
        assert_eq!(preview.dropped, 1);
        assert_eq!(preview.kept, 1);
        assert_eq!(preview.dropped_paths.len(), 1);
        // Nothing deleted: both objects still on disk.
        assert!(vault::object_path(&root, epoch, &live).unwrap().exists());
        assert!(vault::object_path(&root, epoch, &dead).unwrap().exists());
        // A subsequent real gc drops exactly what preview flagged.
        let report = gc(&root, epoch, &key).unwrap();
        assert_eq!(report, preview);
        assert!(!vault::object_path(&root, epoch, &dead).unwrap().exists());
    }

    #[test]
    fn gc_preview_with_tampered_manifest_is_auth_fail_no_deletion() {
        let (_d, root, vid, epoch) = build_vault();
        let live = seal_write(&root, vid, epoch, "live", b"live");
        let target = seal_write(&root, vid, epoch, "target", b"target");
        write_manifest(&root, vid, epoch, vec![entry("live", live, 4, [0u8; 32])]);
        let key = mk(vid, epoch);
        let mpath = vault::manifest_path(&root, epoch);
        let mut txt = std::fs::read_to_string(&mpath).unwrap();
        let idx = txt.find("manifest_mac").unwrap();
        let hex_idx = idx + "manifest_mac\": \"".len();
        let ch = txt.as_bytes()[hex_idx];
        let flipped = if ch == b'0' { b'1' } else { b'0' };
        txt.replace_range(hex_idx..=hex_idx, std::str::from_utf8(&[flipped]).unwrap());
        std::fs::write(&mpath, txt).unwrap();
        let r = gc_preview(&root, epoch, &key);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "tampered manifest MUST fail gc_preview"
        );
        // Preview mutates nothing.
        assert!(vault::object_path(&root, epoch, &live).unwrap().exists());
        assert!(vault::object_path(&root, epoch, &target).unwrap().exists());
    }

    #[test]
    fn gc_no_objects_dir_is_noop() {
        let (_d, root, vid, epoch) = build_vault();
        // No manifest, no objects -> read_manifest_file fails, but objects dir
        // exists empty. gc should fail on manifest read, not silently pass.
        let key = mk(vid, epoch);
        let r = gc(&root, epoch, &key);
        assert!(r.is_err());
    }
}
