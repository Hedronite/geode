//! Token-gated agent operations: list / read / write (06-agent-plane 3, 4, 6).
//!
//! G0 (v0.2.2): the reference-monitor leg that sits between an unsealed
//! `GTOK` token and the existing `object` / `vault` / `manifest` primitives.
//! The caller holds `EK` from an unlocked session (the long-lived
//! `geode agent serve` unwraps EK once); this module never sees the ISK.
//!
//! Enforcement order (06-agent-plane 6 — confusion defenses):
//! 1. `token::inspect` verifies the MAC + TTL. Expired / not-yet-valid ->
//!    [`Error::TokenInvalid`]; tamper / wrong EK -> [`Error::AuthFail`].
//! 2. Op must be in `token.allow_ops`, else [`Error::PolicyDeny`].
//! 3. Path is normalized **strictly**: any `..` segment is rejected before
//!    open (06 §6.2). `scratch/../keys/x` is NOT resolved into `keys/x`.
//! 4. The normalized path must live under one of `token.allow_prefix`,
//!    else (with `leak_denies` default off) [`Error::Io`](`NotFound`) so the
//!    principal cannot enumerate outside its grant; with `leak_denies` on,
//!    [`Error::PolicyDeny`] (06 §6.4).
//! 5. Object files are opened only via the manifest's `object_id` -> vault
//!    shard path; a symlinked or escaping object file is rejected before
//!    open (06 §6.3).
//!
//! No new [`Error`] variant is added — `output.rs` / `cmd/mod.rs` match
//! exhaustively. Errors never contain ISK or key material.

use crate::chunk::DEFAULT_CHUNK_SIZE;
use crate::kdf::{derive_manifest_key, Epoch, EpochKey, ObjectId};
use crate::manifest::{entries_root, Entry, EntryKind, Manifest};
use crate::object::{self, HEADER_SIZE};
use crate::policy::{prefix_covers, Op};
use crate::snapshot::read_manifest_file;
use crate::token::{self, Token};
use crate::vault as corevault;
use crate::{Error, Result};
use std::path::Path;

/// Default read cap: 64 KiB (06-agent-plane 4).
pub const DEFAULT_READ_CAP: u64 = 64 * 1024;

/// Read rendering mode (06-agent-plane 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    Text,
    Hex,
    Hash,
}

impl ReadMode {
    fn includes_body(self) -> bool {
        matches!(self, ReadMode::Text | ReadMode::Hex)
    }
}

/// One listed entry (06-agent-plane 3 `geode_list`).
#[derive(Clone, Debug)]
pub struct ListedEntry {
    pub path: String,
    pub plain_len: u64,
    pub content_root: [u8; 32],
}

/// Outcome of a token-gated read (06-agent-plane 4).
///
/// `sha256` is always the hash of the **full** plaintext (not the preview),
/// so a truncated read still lets the agent address the artifact by hash.
/// `body` is `Preview { .. }` only when `truncated`; `None` in `Hash` mode.
#[derive(Clone, Debug)]
pub struct ReadOutcome {
    pub path: String,
    pub plain_len: u64,
    pub truncated: bool,
    pub sha256: [u8; 32],
    pub body: ReadBody,
}

/// Body of a read outcome.
#[derive(Clone, Debug)]
pub enum ReadBody {
    /// Full plaintext (not truncated).
    Full(Vec<u8>),
    /// First `max_bytes` of the plaintext (truncated). `text` is `Some` iff
    /// the preview is valid UTF-8 and the requested mode was `Text`.
    Preview {
        bytes: Vec<u8>,
        text: Option<String>,
    },
    /// `Hash` mode: no body returned, only the digest.
    None,
}

/// Outcome of a token-gated write (06-agent-plane 3 `geode_write`).
#[derive(Clone, Debug)]
pub struct WriteOutcome {
    pub path: String,
    pub object_id: ObjectId,
    pub plain_len: u64,
    pub content_root: [u8; 32],
}

/// Code-owned path gate for the Jev remainder (prefix + `..` only).
///
/// Jev must never be asked when this fails. TTL / MAC stay in
/// [`crate::token::inspect`]; this function does not see a token.
pub fn code_scope_path(path: &str, prefixes: &[String]) -> Result<String> {
    let norm = normalize_strict(path)?;
    let covered = prefixes.iter().any(|g| {
        prefix_covers(g, &norm) || {
            let g = g.trim_end_matches('/');
            g.is_empty() || norm == g || norm.starts_with(&format!("{g}/"))
        }
    });
    if covered {
        Ok(norm)
    } else {
        Err(Error::PolicyDeny)
    }
}

/// Normalize a vault-relative path **strictly** for agent ops (06 §6.2).
///
/// Unlike [`crate::policy::normalize_path`], this rejects ANY `..` segment
/// (not only ones that escape the root), so `scratch/../keys/x` is denied
/// before open rather than resolved into `keys/x`. Also rejects absolute
/// paths, empty paths, and NUL bytes.
fn normalize_strict(path: &str) -> Result<String> {
    if path.is_empty() {
        return Err(Error::Format("agent path is empty".into()));
    }
    if path.contains('\0') {
        return Err(Error::Format("agent path has NUL".into()));
    }
    let trimmed = path.trim_start_matches("./").trim_start_matches('/');
    let mut parts: Vec<&str> = Vec::new();
    for seg in trimmed.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                // 06 §6.2: deny before open. Do not pop-and-continue.
                return Err(Error::Format("agent path has '..' segment".into()));
            }
            s => parts.push(s),
        }
    }
    if parts.is_empty() {
        return Err(Error::Format("agent path reduces to empty".into()));
    }
    Ok(parts.join("/"))
}

/// Verify the token grants `op` and that `norm_path` is under an allow prefix.
///
/// Returns `Ok(())` if both hold. Op missing -> [`Error::PolicyDeny`].
/// Prefix miss -> [`Error::PolicyDeny`] when `leak_denies`, else
/// [`Error::Io`](`std::io::ErrorKind::NotFound`) (06 §6.4, default off).
fn authorize(token: &Token, op: Op, norm_path: &str, leak_denies: bool) -> Result<()> {
    if !token.allow_ops.contains(&op) {
        return Err(Error::PolicyDeny);
    }
    let covered = token
        .allow_prefix
        .iter()
        .any(|p| prefix_covers(p, norm_path));
    if covered {
        Ok(())
    } else if leak_denies {
        Err(Error::PolicyDeny)
    } else {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "agent path not under allow prefix",
        )))
    }
}

/// Load + authenticate the manifest for the token's (`vault_id`, `epoch`)
/// under `ek`. The token's ids are authoritative for derivation; a token
/// minted under a different EK fails `inspect` with `AuthFail` first.
/// Authorize the `list` prefix-arg as a directory under the grant.
///
/// Unlike a leaf path, a list prefix may be the directory itself (e.g.
/// `scratch/` normalizes to `scratch`), which `prefix_covers` would
/// reject against a `scratch/` grant on the boundary. We compare the
/// prefix-arg as a directory: equal to the grant dir, or nested under it.
fn authorize_list_prefix(token: &Token, norm_prefix: &str, leak_denies: bool) -> Result<()> {
    if !token.allow_ops.contains(&Op::List) {
        return Err(Error::PolicyDeny);
    }
    let covered = token.allow_prefix.iter().any(|g| {
        let g = g.trim_end_matches('/');
        g.is_empty() || norm_prefix == g || norm_prefix.starts_with(&format!("{g}/"))
    });
    if covered {
        Ok(())
    } else if leak_denies {
        Err(Error::PolicyDeny)
    } else {
        Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "agent prefix not under allow prefix",
        )))
    }
}

fn load_manifest(ek: &EpochKey, token: &Token, vault_root: &Path) -> Result<Manifest> {
    let mk = derive_manifest_key(ek, token.vault_id, token.epoch);
    read_manifest_file(vault_root, token.epoch, &mk)
}

/// Reject a symlinked or vault-escaping object file **before** open
/// (06 §6.3). `candidate` is the constructed shard path; we check it is not
/// itself a symlink and that its canonical form stays inside the canonical
/// vault root.
fn assert_within_vault(vault_root: &Path, candidate: &Path) -> Result<()> {
    let root_canon = vault_root.canonicalize().map_err(Error::Io)?;
    match std::fs::symlink_metadata(candidate) {
        Ok(meta) => {
            if meta.is_symlink() {
                return Err(Error::PolicyDeny);
            }
            if let Ok(canon) = candidate.canonicalize() {
                if !canon.starts_with(&root_canon) {
                    return Err(Error::PolicyDeny);
                }
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Io(e)),
        Err(e) => Err(Error::Io(e)),
    }
}

/// SHA-256 of `data` (06-agent-plane 4 truncated-read digest).
fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut b = [0u8; 32];
    b.copy_from_slice(&out);
    b
}

/// Sum of on-disk cipher bytes for `entries` via file metadata (accurate,
/// one `stat` per object). Keeps `total_cipher_bytes` honest on write.
fn cipher_bytes_total(vault_root: &Path, epoch: Epoch, entries: &[Entry]) -> Result<u64> {
    let mut total = 0u64;
    for e in entries {
        let p = corevault::object_path(vault_root, epoch, &e.object_id)?;
        let len = std::fs::symlink_metadata(&p).map_err(Error::Io)?.len();
        total = total.saturating_add(len);
    }
    Ok(total)
}

/// `geode_list` (06-agent-plane 3): list manifest entries under `prefix`
/// that the token is allowed to see.
///
/// `prefix` is itself vault-relative and MUST be covered by one of the
/// token's `allow_prefix` entries (so an agent cannot enumerate outside its
/// grant by passing a wide prefix). `leak_denies` follows the same rule as
/// reads (06 §6.4).
pub fn list(
    ek: &EpochKey,
    vault_root: &Path,
    sealed_token: &[u8],
    now: i64,
    prefix: &str,
    leak_denies: bool,
) -> Result<Vec<ListedEntry>> {
    let token = token::inspect(sealed_token, ek, now)?;
    let norm_prefix = normalize_strict(prefix)?;
    authorize_list_prefix(&token, &norm_prefix, leak_denies)?;
    let manifest = load_manifest(ek, &token, vault_root)?;
    let mut out = Vec::new();
    for e in &manifest.entries {
        // Stored path is the manifest key (sealed form when `path_sealed`).
        // For plaintext-name vaults (the agent-plane default) this is the
        // operator-facing path; sealed-name vaults are out of G0 scope.
        if prefix_covers(&norm_prefix, &e.path) {
            out.push(ListedEntry {
                path: e.path.clone(),
                plain_len: e.plain_len,
                content_root: e.content_root,
            });
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

/// `geode_read` (06-agent-plane 4): read one object under a live token.
///
/// `max_bytes` is the requested cap; `None` means the default 64 KiB. The
/// **hard** cap is `token.max_bytes`, so the effective cap is
/// `min(max_bytes.unwrap_or(DEFAULT_READ_CAP), token.max_bytes)`. Oversize
/// reads return [`ReadOutcome`] with `truncated == true`, the SHA-256 of the
/// full plaintext, and a preview (first cap bytes; UTF-8 text preview when
/// `mode == Text` and the preview is valid UTF-8). `Hash` mode returns only
/// the digest.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // MCP tool entry
pub fn read(
    ek: &EpochKey,
    vault_root: &Path,
    sealed_token: &[u8],
    now: i64,
    path: &str,
    max_bytes: Option<u64>,
    mode: ReadMode,
    leak_denies: bool,
) -> Result<ReadOutcome> {
    let token = token::inspect(sealed_token, ek, now)?;
    let norm = normalize_strict(path)?;
    authorize(&token, Op::Read, &norm, leak_denies)?;
    let manifest = load_manifest(ek, &token, vault_root)?;
    let entry = manifest
        .entries
        .iter()
        .find(|e| e.path == norm)
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "agent path not in manifest",
            ))
        })?;
    let oid = entry.object_id;
    let obj_path = corevault::object_path(vault_root, token.epoch, &oid)?;
    assert_within_vault(vault_root, &obj_path)?;
    let raw = corevault::read_object(vault_root, token.epoch, &oid)?;
    if raw.len() < HEADER_SIZE {
        return Err(Error::AuthFail);
    }
    let bind: &[u8] = if entry.bind {
        entry.path.as_bytes()
    } else {
        b""
    };
    let (_, plaintext) = object::open_object(ek, &raw[..HEADER_SIZE], &raw[HEADER_SIZE..], bind)?;

    let plain_len = u64::try_from(plaintext.len()).unwrap_or(u64::MAX);
    let cap = max_bytes.unwrap_or(DEFAULT_READ_CAP).min(token.max_bytes);
    let truncated = plain_len > cap;
    let sha = sha256(&plaintext);

    let body = if mode.includes_body() {
        if truncated {
            let n = usize::try_from(cap)
                .unwrap_or(plaintext.len())
                .min(plaintext.len());
            let bytes = plaintext[..n].to_vec();
            let text = if mode == ReadMode::Text {
                String::from_utf8(bytes.clone()).ok()
            } else {
                None
            };
            ReadBody::Preview { bytes, text }
        } else {
            ReadBody::Full(plaintext)
        }
    } else {
        ReadBody::None
    };

    Ok(ReadOutcome {
        path: norm,
        plain_len,
        truncated: truncated && mode.includes_body(),
        sha256: sha,
        body,
    })
}

/// `geode_write` (06-agent-plane 3, 4): seal `body` at `path` under a live
/// token and commit it to the vault + manifest.
///
/// `body.len()` MUST be `<= token.max_bytes` (the write body cap), else
/// [`Error::PolicyDeny`]. The path MUST live under an allow prefix. A new
/// `object_id` is allocated (03-format 10 — never overwrite in place); the
/// manifest is updated (same-path entry replaced) and re-MAC'd atomically.
/// `now` is unix seconds; `mtime_ms` is derived as `now * 1000`.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // MCP tool entry
pub fn write(
    ek: &EpochKey,
    vault_root: &Path,
    sealed_token: &[u8],
    now: i64,
    path: &str,
    body: &[u8],
    leak_denies: bool,
) -> Result<WriteOutcome> {
    let token = token::inspect(sealed_token, ek, now)?;
    let norm = normalize_strict(path)?;
    authorize(&token, Op::Write, &norm, leak_denies)?;

    // Write body cap = token.max_bytes (06-agent-plane 4).
    if u64::try_from(body.len()).unwrap_or(u64::MAX) > token.max_bytes {
        return Err(Error::PolicyDeny);
    }

    let oid = corevault::new_object_id()?;
    let sealed = object::seal_object(
        ek,
        token.vault_id,
        token.epoch,
        oid,
        DEFAULT_CHUNK_SIZE,
        b"",
        body,
    )?;
    let header_bytes = sealed.header.to_bytes();
    let obj_path =
        corevault::write_object(vault_root, token.epoch, &oid, &header_bytes, &sealed.chunks)?;
    assert_within_vault(vault_root, &obj_path)?;

    let plain_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
    let outcome = WriteOutcome {
        path: norm.clone(),
        object_id: oid,
        plain_len,
        content_root: sealed.content_root,
    };

    // Commit to the manifest: replace any same-path entry, recompute root +
    // totals, re-MAC atomically. A failure here leaves the orphan object on
    // disk (gc reclaims it later) rather than a manifest naming a
    // half-written object.
    let mk = derive_manifest_key(ek, token.vault_id, token.epoch);
    let mut manifest = read_manifest_file(vault_root, token.epoch, &mk)?;
    manifest.entries.retain(|e| e.path != norm);
    manifest.entries.push(Entry {
        path: norm,
        path_sealed: false,
        object_id: oid,
        kind: EntryKind::File,
        plain_len,
        chunk_count: sealed.header.chunk_count,
        mode: 0o644,
        mtime_ms: now.saturating_mul(1000),
        content_root: sealed.content_root,
        bind: false,
    });
    manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));
    manifest.entry_count = u32::try_from(manifest.entries.len())
        .map_err(|_| Error::Format("entry_count overflow".into()))?;
    manifest.root = entries_root(&manifest.entries)?;
    manifest.total_plain_bytes = manifest.entries.iter().map(|e| e.plain_len).sum();
    manifest.total_cipher_bytes = cipher_bytes_total(vault_root, token.epoch, &manifest.entries)?;
    manifest.generated_at = now;
    crate::snapshot::write_manifest_file(vault_root, token.epoch, &manifest, &mk)?;

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::too_many_lines)]
    use super::*;
    use crate::kdf::{Epoch, IdentitySecret, VaultId};
    use crate::manifest::Manifest;
    use crate::snapshot::write_manifest_file;
    use crate::token::{issue, TokenId, DEFAULT_TTL_SECS};
    use tempfile::tempdir;

    const NOW: i64 = 1_700_000_000;

    fn ek() -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn manifest_key() -> [u8; 32] {
        derive_manifest_key(&ek(), VaultId([0x01; 16]), Epoch(1))
    }

    /// Token granting list/read/write on `scratch/` and `out/`.
    fn sealed_token(now: i64, ttl: u64, max_bytes: u64) -> Vec<u8> {
        let t = Token {
            token_id: TokenId([0xa5; 16]),
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            principal_id: crate::policy::PrincipalId("agent:facet-coder-3".into()),
            not_before: now,
            not_after: now + i64::try_from(ttl).unwrap_or(i64::MAX),
            allow_ops: vec![Op::List, Op::Read, Op::Write],
            allow_prefix: vec!["scratch/".into(), "out/".into()],
            max_bytes,
        };
        issue(&t, &ek()).unwrap()
    }

    /// Build a vault dir with `seed` objects sealed + a MAC'd manifest naming
    /// them. Returns the temp dir (kept alive for the test's lifetime).
    fn setup_vault(seeds: &[(&str, &[u8])]) -> tempfile::TempDir {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let mut entries = Vec::new();
        for (path, body) in seeds {
            let oid = corevault::new_object_id().unwrap();
            let sealed = object::seal_object(
                &ek(),
                VaultId([0x01; 16]),
                Epoch(1),
                oid,
                DEFAULT_CHUNK_SIZE,
                b"",
                body,
            )
            .unwrap();
            let hb = sealed.header.to_bytes();
            corevault::write_object(&root, Epoch(1), &oid, &hb, &sealed.chunks).unwrap();
            entries.push(Entry {
                path: (*path).to_string(),
                path_sealed: false,
                object_id: oid,
                kind: EntryKind::File,
                plain_len: u64::try_from(body.len()).unwrap(),
                chunk_count: sealed.header.chunk_count,
                mode: 0o644,
                mtime_ms: NOW.saturating_mul(1000),
                content_root: sealed.content_root,
                bind: false,
            });
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path));
        let m = Manifest {
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            suite: crate::SUITE_0X01,
            flags: 0,
            generated_at: NOW,
            generator: "test".into(),
            root: entries_root(&entries).unwrap(),
            entry_count: u32::try_from(entries.len()).unwrap(),
            total_plain_bytes: entries.iter().map(|e| e.plain_len).sum(),
            total_cipher_bytes: 0,
            entries,
        };
        write_manifest_file(&root, Epoch(1), &m, &manifest_key()).unwrap();
        d
    }

    #[test]
    fn list_allow_prefix_works() {
        let d = setup_vault(&[
            ("scratch/plan.md", b"plan"),
            ("scratch/notes/a.md", b"a"),
            ("out/report.txt", b"r"),
            ("keys/prod.pem", b"secret"),
        ]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let got = list(&ek(), &root, &tok, NOW, "scratch/", false).unwrap();
        let paths: Vec<_> = got.into_iter().map(|e| e.path).collect();
        assert_eq!(paths, vec!["scratch/notes/a.md", "scratch/plan.md"]);
    }

    #[test]
    fn list_other_prefix_denied_not_found_default() {
        let d = setup_vault(&[("keys/prod.pem", b"x")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = list(&ek(), &root, &tok, NOW, "keys/", false);
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn list_other_prefix_policy_deny_when_leak_denies() {
        let d = setup_vault(&[("keys/prod.pem", b"x")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = list(&ek(), &root, &tok, NOW, "keys/", true);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn read_allow_prefix_roundtrips() {
        let d = setup_vault(&[("scratch/plan.md", b"hello agent")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        )
        .unwrap();
        assert!(!o.truncated);
        assert_eq!(o.plain_len, 11);
        match o.body {
            ReadBody::Full(b) => assert_eq!(b, b"hello agent"),
            other => panic!("expected Full, got {other:?}"),
        }
    }

    #[test]
    fn read_other_prefix_denied_not_found() {
        let d = setup_vault(&[("keys/prod.pem", b"secret")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "keys/prod.pem",
            None,
            ReadMode::Text,
            false,
        );
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn read_missing_path_under_allow_prefix_is_not_found() {
        let d = setup_vault(&[("scratch/plan.md", b"x")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/missing.md",
            None,
            ReadMode::Text,
            false,
        );
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn expired_token_is_token_invalid() {
        let d = setup_vault(&[("scratch/plan.md", b"x")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, 60, 1 << 20);
        let r = read(
            &ek(),
            &root,
            &tok,
            NOW + 61,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        );
        assert!(matches!(r, Err(Error::TokenInvalid)), "got {r:?}");
    }

    #[test]
    fn dotdot_in_path_denied_before_open() {
        let d = setup_vault(&[("keys/prod.pem", b"secret")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        // scratch/../keys/x must NOT resolve into keys/x
        let r = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/../keys/prod.pem",
            None,
            ReadMode::Text,
            false,
        );
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
        let r2 = list(&ek(), &root, &tok, NOW, "scratch/../keys", false);
        assert!(matches!(r2, Err(Error::Format(_))), "got {r2:?}");
    }

    #[test]
    fn read_oversize_truncated_with_sha256_and_preview() {
        use sha2::{Digest, Sha256};
        let big = vec![0x41u8; 100_000]; // > 64 KiB default cap
        let d = setup_vault(&[("scratch/big.bin", &big)]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/big.bin",
            None,
            ReadMode::Text,
            false,
        )
        .unwrap();
        assert!(o.truncated, "truncated");
        assert_eq!(o.plain_len, 100_000);
        let mut want = [0u8; 32];
        let mut h = Sha256::new();
        h.update(&big);
        want.copy_from_slice(&h.finalize());
        assert_eq!(o.sha256, want);
        match o.body {
            ReadBody::Preview { bytes, text } => {
                assert_eq!(bytes.len(), usize::try_from(DEFAULT_READ_CAP).unwrap());
                assert!(text.is_some());
                assert_eq!(
                    text.unwrap().len(),
                    usize::try_from(DEFAULT_READ_CAP).unwrap()
                );
            }
            other => panic!("expected Preview, got {other:?}"),
        }
    }

    #[test]
    fn read_hard_cap_clamps_to_token_max_bytes() {
        let big = vec![0x42u8; 100_000];
        let d = setup_vault(&[("scratch/big.bin", &big)]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1024);
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/big.bin",
            None,
            ReadMode::Hex,
            false,
        )
        .unwrap();
        assert!(o.truncated);
        match o.body {
            ReadBody::Preview { bytes, text } => {
                assert_eq!(bytes.len(), 1024);
                assert!(text.is_none(), "hex mode has no text preview");
            }
            other => panic!("expected Preview, got {other:?}"),
        }
        let o2 = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/big.bin",
            Some(50_000),
            ReadMode::Hex,
            false,
        )
        .unwrap();
        match o2.body {
            ReadBody::Preview { bytes, .. } => assert_eq!(bytes.len(), 1024),
            other => panic!("expected Preview, got {other:?}"),
        }
    }

    #[test]
    fn read_hash_mode_returns_no_body() {
        let d = setup_vault(&[("scratch/plan.md", b"hello agent")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Hash,
            false,
        )
        .unwrap();
        assert!(!o.truncated, "hash mode is never truncated");
        assert!(matches!(o.body, ReadBody::None));
        assert_eq!(o.plain_len, 11);
        assert_ne!(o.sha256, [0u8; 32]);
    }

    #[test]
    fn write_seals_and_is_listable() {
        let d = setup_vault(&[]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let w = write(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/new.md",
            b"fresh bytes",
            false,
        )
        .unwrap();
        assert_eq!(w.path, "scratch/new.md");
        assert_eq!(w.plain_len, 11);
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/new.md",
            None,
            ReadMode::Text,
            false,
        )
        .unwrap();
        match o.body {
            ReadBody::Full(b) => assert_eq!(b, b"fresh bytes"),
            other => panic!("expected Full, got {other:?}"),
        }
        let got = list(&ek(), &root, &tok, NOW, "scratch/", false).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].path, "scratch/new.md");
    }

    #[test]
    fn write_replaces_same_path() {
        let d = setup_vault(&[("scratch/plan.md", b"old")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        write(&ek(), &root, &tok, NOW, "scratch/plan.md", b"new", false).unwrap();
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        )
        .unwrap();
        match o.body {
            ReadBody::Full(b) => assert_eq!(b, b"new"),
            other => panic!("expected Full, got {other:?}"),
        }
        let got = list(&ek(), &root, &tok, NOW, "scratch/", false).unwrap();
        assert_eq!(got.len(), 1);
    }

    #[test]
    fn write_oversize_body_is_policy_deny() {
        let d = setup_vault(&[]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 16);
        let big = vec![0u8; 17];
        let r = write(&ek(), &root, &tok, NOW, "scratch/x", &big, false);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
    }

    #[test]
    fn write_outside_prefix_denied() {
        let d = setup_vault(&[]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = write(&ek(), &root, &tok, NOW, "keys/x", b"x", false);
        assert!(
            matches!(r, Err(Error::Io(ref e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn missing_op_is_policy_deny() {
        let d = setup_vault(&[("scratch/plan.md", b"x")]);
        let root = d.path().join("v.geode");
        let t = Token {
            token_id: TokenId([0xb1; 16]),
            vault_id: VaultId([0x01; 16]),
            epoch: Epoch(1),
            principal_id: crate::policy::PrincipalId("agent:facet-coder-3".into()),
            not_before: NOW,
            not_after: NOW + 900,
            allow_ops: vec![Op::List, Op::Read],
            allow_prefix: vec!["scratch/".into()],
            max_bytes: 1 << 20,
        };
        let tok = issue(&t, &ek()).unwrap();
        let r = write(&ek(), &root, &tok, NOW, "scratch/x", b"x", false);
        assert!(matches!(r, Err(Error::PolicyDeny)), "got {r:?}");
        let o = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        )
        .unwrap();
        assert_eq!(o.plain_len, 1);
    }

    #[test]
    fn symlinked_object_file_denied_before_open() {
        let d = setup_vault(&[("scratch/plan.md", b"real")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let manifest = crate::snapshot::read_manifest_file(
            &root,
            Epoch(1),
            &derive_manifest_key(&ek(), VaultId([0x01; 16]), Epoch(1)),
        )
        .unwrap();
        let entry = manifest
            .entries
            .iter()
            .find(|e| e.path == "scratch/plan.md")
            .unwrap();
        let p = crate::vault::object_path(&root, Epoch(1), &entry.object_id).unwrap();
        std::fs::remove_file(&p).unwrap();
        let outside = d.path().join("outside.txt");
        std::fs::write(&outside, b"not the vault").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, &p).unwrap();
        #[cfg(not(unix))]
        std::fs::write(&p, b"real").unwrap();
        let r = read(
            &ek(),
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        );
        #[cfg(unix)]
        assert!(
            matches!(r, Err(Error::PolicyDeny)),
            "symlink-out MUST be denied, got {r:?}"
        );
        #[cfg(not(unix))]
        {
            let o = r.unwrap();
            assert!(matches!(o.body, ReadBody::Full(_)));
        }
    }

    #[test]
    fn code_scope_path_covers_grant_and_rejects_dotdot() {
        let prefixes = vec!["scratch/".into(), "out/".into()];
        assert_eq!(
            code_scope_path("scratch/note.md", &prefixes).unwrap(),
            "scratch/note.md"
        );
        assert_eq!(code_scope_path("scratch/", &prefixes).unwrap(), "scratch");
        assert!(matches!(
            code_scope_path("scratch/../keys/x", &prefixes),
            Err(Error::Format(_))
        ));
        assert!(matches!(
            code_scope_path("keys/prod.pem", &prefixes),
            Err(Error::PolicyDeny)
        ));
    }

    #[test]
    fn errors_never_contain_isk() {
        let isk2 = crate::kdf::IdentitySecret::from_bytes([0x99; 32]);
        let ek2 =
            crate::kdf::derive_epoch_key(&isk2, VaultId([0x01; 16]), Epoch(1), "test").unwrap();
        let d = setup_vault(&[("scratch/plan.md", b"x")]);
        let root = d.path().join("v.geode");
        let tok = sealed_token(NOW, DEFAULT_TTL_SECS, 1 << 20);
        let r = read(
            &ek2,
            &root,
            &tok,
            NOW,
            "scratch/plan.md",
            None,
            ReadMode::Text,
            false,
        );
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "error leaks ISK: {s}");
        assert!(!s.contains('\u{99}'), "error leaks key bytes: {s}");
    }
}
