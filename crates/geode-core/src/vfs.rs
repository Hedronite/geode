//! Kernel-free VFS read + write (08-mount 3; 02-cryptography 4.4).
//!
//! G0 (v0.2.5): a shipped core function `read_range` that maps
//! `(vault_root, epoch, object_id, path_bind, off, len)` to a plaintext
//! slice **without** `/dev/fuse` or any kernel backend. It decrypts only
//! the chunk(s) the byte range touches, not the whole object -- a one-byte
//! read at offset 1 GiB of a multi-GiB object decrypts one chunk, not the
//! whole file (08-mount 8: the difference between a demo and a workstation
//! tool).
//!
//! G0 (v0.2.9): the read-write path, still kernel-free. [`Vfs`] is one
//! in-memory mounted session over a single vault epoch (08-mount 3):
//!
//! - `create` / `mkdir` / `rename` / `unlink` mutate the in-memory namespace
//!   ([`Vfs::list`] / [`Vfs::readdir`]) and mark the vault dirty.
//! - `write` / `truncate` are copy-on-write over an open plaintext buffer:
//!   only the chunk indices a mutation touches are dirty
//!   ([`Vfs::dirty_chunks`]).
//! - `fsync` / `close` allocate a **fresh `object_id`**, seal the buffer into
//!   a new `.gobj`, and replace the manifest entry (03-format 10: never
//!   overwrite an object in place). The previous `.gobj` is left intact and
//!   stays readable; reclaiming it is `snapshot::gc`'s job.
//! - `unmount` persists the authenticated manifest so a reopen sees the
//!   mutation (08-mount 3). `sync_if_due` does the same once
//!   [`DEFAULT_SYNC_INTERVAL_SECS`] has passed while dirty.
//!
//! Truncate and extend are chunk-independent: a flush re-chunks the plaintext
//! from scratch (08-mount 3). The read-only path ([`read_range`] /
//! [`read_all`], and [`Vfs::read_range`] on a flushed file) is unchanged and
//! still works while a session is mounted.
//!
//! Directories are first-class manifest rows: `mkdir` allocates a fresh
//! `object_id` and pushes an entry with `kind: dir`, `plain_len 0`,
//! `chunk_count 0` (03-format 5; `schemas/vault.manifest.schema.json`). An
//! empty-directory row names **no** `.gobj` body, so it survives unmount and
//! a reopen lists it. A path whose parent was never `mkdir`-ed still appears
//! as an implied directory (the ancestor set of the manifest paths) for the
//! life of the session, but it has no row of its own.
//!
//! Missing path = `Error::Io(NotFound)`. Tamper / bind mismatch =
//! `Error::AuthFail`. Namespace misuse (exists, not empty, escaping path) =
//! `Error::Format`. No ISK in errors; no new `Error` variant.
//!
//! The on-disk object layout is `header(108) || chunk_records`, where each
//! chunk record is `tag(16) || ciphertext` and `ciphertext.len() ==
//! min(chunk_size, remaining_plain)` (02-cryptography 4.4; 03-format 4).
//! `read_range` parses the header, verifies the header tag, locates the
//! touched chunk record(s) by counting forward from chunk 0, decrypts
//! each with `aead::open_chunk` under the chunk AD, and slices the joined
//! plaintext to the requested `[off, off+len)`.

use crate::aead::{open_chunk, ChunkAd};
use crate::chunk::validate_chunk_size;
use crate::kdf::{derive_manifest_key, Epoch, EpochKey, ObjectId, VaultId};
use crate::manifest::{entries_root, Entry, EntryKind, Manifest};
use crate::object::{self, compute_header_tag, path_bind_hash, ObjectHeader, HEADER_SIZE};
use crate::snapshot::{read_manifest_file, write_manifest_file};
use crate::vault as corevault;
use crate::{Error, Result};
use std::collections::{BTreeMap, BTreeSet};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Maximum bytes a single `read_range` call will return. Guards against a
/// caller asking for `u64::MAX` bytes and forcing a huge allocation; the
/// VFS layer pages reads anyway. 1 GiB is far above any reasonable single
/// read for v1.
pub const MAX_READ_LEN: u64 = 1 << 30;

/// Maximum bytes a single `Vfs::write` call will accept (mirrors
/// [`MAX_READ_LEN`] -- a larger write should be paged by the caller).
pub const MAX_WRITE_LEN: u64 = 1 << 30;

/// Working-buffer cap for one open file. The kernel-free VFS keeps one
/// plaintext buffer per open file in memory, so this cap is memory-shaped
/// rather than the on-disk `--max-file-bytes` 64 GiB.
pub const MAX_FILE_LEN: u64 = 1 << 32;

/// Default `--sync-interval` (08-mount 3): while the manifest is dirty,
/// persist it once this many seconds have passed since the last persist.
pub const DEFAULT_SYNC_INTERVAL_SECS: u64 = 5;

/// `object_id` of a manifest entry that a session created or mutated but has
/// not yet flushed to a `.gobj` (see [`Vfs::fsync`]). Never written to disk:
/// [`Vfs::unmount`] / [`Vfs::sync_if_due`] flush every pending entry first, so
/// the on-disk manifest never names a half-written object (03-format 10).
pub const PENDING_OBJECT_ID: ObjectId = ObjectId([0u8; 16]);

/// Read a plaintext byte range from a sealed object without mounting.
///
/// `off` is the byte offset into the plaintext; `len` is the requested
/// length. The call decrypts only the chunk(s) the range touches
/// (`first_chunk = off / chunk_size`, `last_chunk = (off+len-1) / chunk_size`),
/// not the whole object. Returns the sliced plaintext
/// `plaintext[off .. off + actual_len]`, where `actual_len` is clamped to
/// `plain_len - off` and `MAX_READ_LEN`.
///
/// Errors:
/// - `off >= plain_len` or `len == 0` -> empty `Vec` (not an error).
/// - Missing object file -> `Error::Io(NotFound)`.
/// - Bad header / tag mismatch / path-bind mismatch / corrupt chunk ->
///   `Error::AuthFail`.
/// - Truncated file -> `Error::Format`.
/// - `len > MAX_READ_LEN` -> `Error::Format` (caller should page).
///
/// No ISK or key bytes appear in any error `Display`. No new `Error` variant.
#[allow(clippy::cast_possible_truncation)]
pub fn read_range(
    ek: &EpochKey,
    vault_root: &Path,
    epoch: Epoch,
    object_id: ObjectId,
    path_bind: &[u8],
    off: u64,
    len: u64,
) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_READ_LEN {
        return Err(Error::Format(format!(
            "read_range len {len} exceeds MAX_READ_LEN {MAX_READ_LEN}; page the read"
        )));
    }

    // Read the whole object file (header + chunk records). The *decryption*
    // is bounded to the touched chunks; the *read* is the whole file because
    // the chunk records are contiguous and we must seek forward from chunk
    // 0 to find chunk `i` (no per-chunk index on disk). A future index is
    // out of scope for G0.
    let raw = corevault::read_object(vault_root, epoch, &object_id)?;
    if raw.len() < HEADER_SIZE {
        return Err(Error::Format(format!(
            "object file too short: {} < {HEADER_SIZE}",
            raw.len()
        )));
    }
    let (header_bytes, chunk_bytes) = raw.split_at(HEADER_SIZE);
    let header = ObjectHeader::from_bytes(header_bytes)?;

    // Header tag (every read).
    let want = compute_header_tag(ek, &header);
    // TODO(G5): constant-time compare. Correct for G0; harden later.
    if want != header.header_tag {
        return Err(Error::AuthFail);
    }
    if header.object_id != object_id {
        return Err(Error::AuthFail);
    }

    // Path bind: if the header was sealed with a bind, the caller MUST supply
    // the matching path. A moved object fails open (02 4.3).
    let effective_bind: Vec<u8> = if header.path_bind_hash == [0u8; 32] {
        Vec::new()
    } else {
        if header.path_bind_hash != path_bind_hash(path_bind) {
            return Err(Error::AuthFail);
        }
        path_bind.to_vec()
    };

    let cs = u64::from(header.chunk_size);
    if cs == 0 {
        return Err(Error::Format("chunk_size 0 in header".into()));
    }
    let plain_len = header.plain_len;

    // Clamp the range to the plaintext.
    if off >= plain_len {
        return Ok(Vec::new());
    }
    let end = off.saturating_add(len).min(plain_len);
    if end <= off {
        return Ok(Vec::new());
    }
    let want_len = end - off;

    let first_chunk = off / cs;
    let last_chunk = (end - 1) / cs;
    let chunk_count = u64::from(header.chunk_count);
    if first_chunk >= chunk_count {
        return Ok(Vec::new());
    }
    let last_chunk = last_chunk.min(chunk_count.saturating_sub(1));

    // Walk chunk records from 0 to last_chunk, decrypting only the touched
    // ones. Records are `tag(16) || ciphertext` with
    // `ct_len = min(chunk_size, remaining_plain)`.
    let mut decrypted: Vec<u8> = Vec::new();
    let mut offset = 0usize;
    let mut touched_started = false;
    for i in 0..=last_chunk {
        if offset + 16 > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let remaining_plain = plain_len - i * cs;
        let this_plain = cs.min(remaining_plain);
        let rec_len = 16 + this_plain as usize;
        if offset + rec_len > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let rec = &chunk_bytes[offset..offset + rec_len];
        if i >= first_chunk {
            if !touched_started {
                touched_started = true;
            }
            let ad = ChunkAd {
                suite: header.suite,
                vault_id: header.vault_id,
                epoch: header.epoch,
                object_id: header.object_id,
                chunk_index: i,
                plain_len: header.plain_len,
                chunk_size: header.chunk_size,
                path_bind: effective_bind.clone(),
            };
            let pt = open_chunk(ek, &ad, rec)?;
            decrypted.extend_from_slice(&pt);
        }
        offset += rec_len;
    }

    // Slice within the touched-chunk plaintext.
    let local_off = (off - first_chunk * cs) as usize;
    let local_end = local_off + want_len as usize;
    if local_end > decrypted.len() {
        return Err(Error::AuthFail);
    }
    Ok(decrypted[local_off..local_end].to_vec())
}

/// `read_range` at offset 0 -- convenience for whole-object reads that
/// still only decrypt touched chunks (here, all of them).
pub fn read_all(
    ek: &EpochKey,
    vault_root: &Path,
    epoch: Epoch,
    object_id: ObjectId,
    path_bind: &[u8],
) -> Result<Vec<u8>> {
    read_range(ek, vault_root, epoch, object_id, path_bind, 0, MAX_READ_LEN)
}

// ---------------------------------------------------------------------------
// v0.2.9 / G0: read-write VFS (08-mount 3)
// ---------------------------------------------------------------------------

/// Kind of a namespace node returned by [`Vfs::readdir`] / [`Vfs::stat`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeKind {
    Dir,
    File,
    Symlink,
}

/// One namespace node (a directory is implied by paths; see the module docs).
#[derive(Clone, Debug)]
pub struct VfsNode {
    pub path: String,
    pub kind: NodeKind,
    pub plain_len: u64,
    pub object_id: ObjectId,
    /// File: the manifest entry's `mtime_ms`. Directory: the session time of
    /// its last namespace mutation (a directory has no manifest row).
    pub mtime_ms: i64,
}

/// An open file's plaintext working buffer and its copy-on-write dirty set.
#[derive(Debug)]
struct OpenFile {
    path: String,
    plain: Vec<u8>,
    dirty: bool,
    /// Chunk indices this session has modified since the last flush.
    dirty_chunks: BTreeSet<u64>,
}

/// One in-memory mounted session over a vault epoch (08-mount 3).
///
/// Owns the authenticated manifest, the implied-directory set, and the open
/// plaintext buffers. Nothing here touches `/dev/fuse`; the FUSE adapter is a
/// thin caller of these methods.
#[derive(Debug)]
pub struct Vfs {
    ek: EpochKey,
    root: PathBuf,
    vault_id: VaultId,
    epoch: Epoch,
    manifest_key: [u8; 32],
    manifest: Manifest,
    /// Implied directories, keyed by path, holding the session time of their
    /// last namespace mutation. GDE1 has no directory manifest row
    /// (03-format 5), so a directory is a namespace fact (module docs).
    dirs: BTreeMap<String, i64>,
    open: BTreeMap<String, OpenFile>,
    chunk_size: u32,
    dirty: bool,
    last_sync_ms: i64,
    sync_interval_ms: i64,
}

/// A vault-relative path, normalized. `..` is resolved (and rejected when it
/// escapes the root) by the human-path normalizer (10-policy 2.4).
fn norm(path: &str) -> Result<String> {
    crate::policy::normalize_path(path)
}

fn not_found(what: &str) -> Error {
    Error::Io(std::io::Error::new(
        ErrorKind::NotFound,
        format!("vfs path not found: {what}"),
    ))
}

/// POSIX EISDIR, expressed with the shipped `Error` variants (no new variant).
fn is_a_directory(what: &str) -> Error {
    Error::Format(format!("vfs: {what} is a directory"))
}

fn parent_of(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((p, _)) => p,
        None => "",
    }
}

/// Every ancestor directory of `path`, nearest first (`a/b/c` -> `a/b`, `a`).
fn ancestors(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = parent_of(path);
    while !cur.is_empty() {
        out.push(cur.to_string());
        cur = parent_of(cur);
    }
    out
}

/// The chunk AD bind for an entry: the entry path when it was sealed with
/// `BIND_PATHS` (09-git), otherwise the empty bind (02 4.3).
fn bind_for(entry: &Entry) -> Vec<u8> {
    if entry.bind {
        entry.path.clone().into_bytes()
    } else {
        Vec::new()
    }
}

/// Slice an in-memory buffer the way [`read_range`] slices plaintext.
#[allow(clippy::cast_possible_truncation)]
fn slice_buffer(buf: &[u8], off: u64, len: u64) -> Result<Vec<u8>> {
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_READ_LEN {
        return Err(Error::Format(format!(
            "vfs read len {len} exceeds MAX_READ_LEN {MAX_READ_LEN}; page the read"
        )));
    }
    let total = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    if off >= total {
        return Ok(Vec::new());
    }
    let end = off.saturating_add(len).min(total);
    Ok(buf[off as usize..end as usize].to_vec())
}

impl Vfs {
    /// Open a mounted session: authenticate + load the epoch manifest under a
    /// key derived from `ek`, then rebuild the implied-directory set.
    ///
    /// A manifest whose `vault_id` / `epoch` do not match the arguments is
    /// `Error::AuthFail` (it cannot be this vault's manifest). `chunk_size`
    /// comes from the vault header's `chunk_size_default` (03-format 3).
    pub fn open(
        ek: &EpochKey,
        vault_root: &Path,
        vault_id: VaultId,
        epoch: Epoch,
        chunk_size: u32,
        now_ms: i64,
    ) -> Result<Self> {
        validate_chunk_size(chunk_size)?;
        let manifest_key = derive_manifest_key(ek, vault_id, epoch);
        let manifest = read_manifest_file(vault_root, epoch, &manifest_key)?;
        if manifest.vault_id != vault_id || manifest.epoch != epoch {
            return Err(Error::AuthFail);
        }
        let mut dirs: BTreeMap<String, i64> = BTreeMap::new();
        for e in &manifest.entries {
            if e.kind.is_dir() {
                dirs.insert(e.path.clone(), e.mtime_ms);
            }
        }
        for e in &manifest.entries {
            for a in ancestors(&e.path) {
                dirs.entry(a).or_insert(0);
            }
        }
        Ok(Self {
            ek: EpochKey::from_bytes(*ek.as_bytes()),
            root: vault_root.to_path_buf(),
            vault_id,
            epoch,
            manifest_key,
            manifest,
            dirs,
            open: BTreeMap::new(),
            chunk_size,
            dirty: false,
            last_sync_ms: now_ms,
            sync_interval_ms: i64::try_from(DEFAULT_SYNC_INTERVAL_SECS).unwrap_or(5) * 1000,
        })
    }

    /// The in-memory manifest (sorted by path).
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        &self.manifest
    }

    /// Manifest entries -- files, directories and symlinks (sorted by path).
    /// A file created but not yet flushed still carries [`PENDING_OBJECT_ID`].
    #[must_use]
    pub fn list(&self) -> &[Entry] {
        &self.manifest.entries
    }

    /// Is the namespace / manifest dirty since the last persist?
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Paths with an open (unflushed) plaintext buffer.
    #[must_use]
    pub fn open_paths(&self) -> Vec<String> {
        self.open.keys().cloned().collect()
    }

    /// Look up one entry: file, directory (`kind: dir` row), or symlink.
    pub fn stat(&self, path: &str) -> Result<VfsNode> {
        let norm = norm(path)?;
        if let Some(e) = self.entry_at(&norm) {
            return Ok(VfsNode {
                path: e.path,
                kind: match e.kind {
                    EntryKind::File => NodeKind::File,
                    EntryKind::Dir => NodeKind::Dir,
                    EntryKind::Symlink => NodeKind::Symlink,
                },
                plain_len: e.plain_len,
                object_id: e.object_id,
                mtime_ms: e.mtime_ms,
            });
        }
        if let Some(mtime_ms) = self.dirs.get(&norm) {
            return Ok(VfsNode {
                path: norm,
                kind: NodeKind::Dir,
                plain_len: 0,
                object_id: PENDING_OBJECT_ID,
                mtime_ms: *mtime_ms,
            });
        }
        Err(not_found(path))
    }

    /// Immediate children of `dir` (`""` is the vault root), sorted by path.
    pub fn readdir(&self, dir: &str) -> Result<Vec<VfsNode>> {
        let norm = norm(dir)?;
        if !norm.is_empty() && !self.dirs.contains_key(&norm) {
            return Err(not_found(dir));
        }
        let mut out: Vec<VfsNode> = Vec::new();
        for (d, mtime_ms) in &self.dirs {
            // A directory with its own `kind: dir` row is listed from the
            // manifest below; this loop covers only implied directories.
            if parent_of(d) == norm && !self.has_entry(d) {
                out.push(VfsNode {
                    path: d.clone(),
                    kind: NodeKind::Dir,
                    plain_len: 0,
                    object_id: PENDING_OBJECT_ID,
                    mtime_ms: *mtime_ms,
                });
            }
        }
        for e in &self.manifest.entries {
            if parent_of(&e.path) == norm {
                out.push(VfsNode {
                    path: e.path.clone(),
                    kind: match e.kind {
                        EntryKind::File => NodeKind::File,
                        EntryKind::Dir => NodeKind::Dir,
                        EntryKind::Symlink => NodeKind::Symlink,
                    },
                    plain_len: e.plain_len,
                    object_id: e.object_id,
                    mtime_ms: e.mtime_ms,
                });
            }
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    }

    /// Create an empty file. The parent directory must exist (POSIX ENOENT).
    /// The entry is pending ([`PENDING_OBJECT_ID`]) until [`Vfs::fsync`].
    pub fn create(&mut self, path: &str, mode: u32, now_ms: i64) -> Result<()> {
        let norm = norm(path)?;
        if norm.is_empty() {
            return Err(Error::Format("vfs create: empty path".into()));
        }
        if self.entry_at(&norm).is_some() || self.dirs.contains_key(&norm) {
            return Err(Error::Format(format!("vfs create: {norm} exists")));
        }
        let parent = parent_of(&norm);
        if !parent.is_empty() && !self.dirs.contains_key(parent) {
            return Err(not_found(parent));
        }
        self.touch_dir(parent, now_ms);
        self.manifest.entries.push(Entry {
            path: norm,
            path_sealed: false,
            object_id: PENDING_OBJECT_ID,
            kind: EntryKind::File,
            plain_len: 0,
            chunk_count: 0,
            mode,
            mtime_ms: now_ms,
            content_root: [0u8; 32],
            bind: false,
        });
        self.recompute()?;
        self.dirty = true;
        Ok(())
    }

    /// Create a directory: push a `kind: dir` manifest row and mark dirty.
    ///
    /// The row carries a fresh `object_id` (the schema requires one) with
    /// `plain_len 0` / `chunk_count 0`; **no** `.gobj` body is written, so an
    /// empty directory costs no object and still survives unmount
    /// (03-format 5; PM ruling v029).
    pub fn mkdir(&mut self, path: &str, mode: u32, now_ms: i64) -> Result<()> {
        let norm = norm(path)?;
        if norm.is_empty() {
            return Err(Error::Format("vfs mkdir: empty path".into()));
        }
        if self.dirs.contains_key(&norm) || self.entry_at(&norm).is_some() {
            return Err(Error::Format(format!("vfs mkdir: {norm} exists")));
        }
        let parent = parent_of(&norm);
        if !parent.is_empty() && !self.dirs.contains_key(parent) {
            return Err(not_found(parent));
        }
        self.touch_dir(parent, now_ms);
        self.dirs.insert(norm.clone(), now_ms);
        self.manifest.entries.push(Entry {
            path: norm,
            path_sealed: false,
            object_id: corevault::new_object_id()?,
            kind: EntryKind::Dir,
            plain_len: 0,
            chunk_count: 0,
            mode,
            mtime_ms: now_ms,
            content_root: [0u8; 32],
            bind: false,
        });
        self.recompute()?;
        self.dirty = true;
        Ok(())
    }

    /// Write `data` at byte offset `off` (copy-on-write; the touched chunk
    /// indices become dirty). Writing past EOF extends with zeroes; a
    /// zero-length write is a no-op and does not extend (POSIX).
    pub fn write(&mut self, path: &str, off: u64, data: &[u8]) -> Result<()> {
        let norm = norm(path)?;
        let n = u64::try_from(data.len()).unwrap_or(u64::MAX);
        if n == 0 {
            return Ok(());
        }
        if n > MAX_WRITE_LEN {
            return Err(Error::Format(format!(
                "vfs write len {n} exceeds MAX_WRITE_LEN {MAX_WRITE_LEN}; page the write"
            )));
        }
        let entry = self.entry_at(&norm).ok_or_else(|| not_found(&norm))?;
        if entry.kind.is_dir() {
            return Err(is_a_directory(&norm));
        }
        let end = off
            .checked_add(n)
            .ok_or_else(|| Error::Format("vfs write offset overflow".into()))?;
        if end > MAX_FILE_LEN {
            return Err(Error::Format(format!(
                "vfs write end {end} exceeds MAX_FILE_LEN {MAX_FILE_LEN}"
            )));
        }
        self.ensure_handle(&norm, &entry)?;
        let cs = u64::from(self.chunk_size);
        let h = self.handle_mut(&norm)?;
        let old_len = h.plain.len() as u64;
        if end > old_len {
            h.plain.resize(end as usize, 0);
        }
        let start = off.min(old_len);
        h.plain[off as usize..end as usize].copy_from_slice(data);
        for i in start / cs..=(end - 1) / cs {
            h.dirty_chunks.insert(i);
        }
        h.dirty = true;
        self.dirty = true;
        Ok(())
    }

    /// Read a byte range from the open buffer, or (for a flushed file) through
    /// the shipped read-only path. Same clamping rules as [`read_range`].
    pub fn read_range(&self, path: &str, off: u64, len: u64) -> Result<Vec<u8>> {
        let norm = norm(path)?;
        let entry = self.entry_at(&norm).ok_or_else(|| not_found(&norm))?;
        if entry.kind.is_dir() {
            return Err(is_a_directory(&norm));
        }
        if let Some(h) = self.open.get(&norm) {
            return slice_buffer(&h.plain, off, len);
        }
        if entry.object_id == PENDING_OBJECT_ID {
            return slice_buffer(&[], off, len);
        }
        let bind = bind_for(&entry);
        self::read_range(
            &self.ek,
            &self.root,
            self.epoch,
            entry.object_id,
            &bind,
            off,
            len,
        )
    }

    /// Truncate (or zero-extend) to `len` bytes. Chunks are independent:
    /// only the chunk indices covering the changed region become dirty.
    pub fn truncate(&mut self, path: &str, len: u64) -> Result<()> {
        let norm = norm(path)?;
        if len > MAX_FILE_LEN {
            return Err(Error::Format(format!(
                "vfs truncate len {len} exceeds MAX_FILE_LEN {MAX_FILE_LEN}"
            )));
        }
        let entry = self.entry_at(&norm).ok_or_else(|| not_found(&norm))?;
        if entry.kind.is_dir() {
            return Err(is_a_directory(&norm));
        }
        self.ensure_handle(&norm, &entry)?;
        let cs = u64::from(self.chunk_size);
        let h = self.handle_mut(&norm)?;
        let old_len = h.plain.len() as u64;
        if len == old_len {
            return Ok(());
        }
        let lo = len.min(old_len);
        let hi = len.max(old_len);
        for i in lo / cs..=(hi - 1) / cs {
            h.dirty_chunks.insert(i);
        }
        h.plain.resize(len as usize, 0);
        h.dirty = true;
        self.dirty = true;
        Ok(())
    }

    /// Chunk indices this session has modified since the last flush
    /// (empty for a file with no open buffer).
    pub fn dirty_chunks(&self, path: &str) -> Result<Vec<u64>> {
        let norm = norm(path)?;
        let entry = self.entry_at(&norm).ok_or_else(|| not_found(&norm))?;
        if entry.kind.is_dir() {
            return Err(is_a_directory(&norm));
        }
        Ok(self
            .open
            .get(&norm)
            .map(|h| h.dirty_chunks.iter().copied().collect())
            .unwrap_or_default())
    }

    /// Flush one file: allocate a fresh `object_id`, write a new `.gobj`, and
    /// replace the manifest entry (03-format 10). A clean, already-flushed file
    /// is a no-op returning its current `object_id`.
    pub fn fsync(&mut self, path: &str, now_ms: i64) -> Result<ObjectId> {
        let norm = norm(path)?;
        let entry = self.entry_at(&norm).ok_or_else(|| not_found(&norm))?;
        if entry.kind.is_dir() {
            // A `kind: dir` row names no object body: there is nothing to
            // flush, and no `.gobj` is written for an empty directory.
            return Ok(entry.object_id);
        }
        let pending = entry.object_id == PENDING_OBJECT_ID;
        let dirty = self.open.get(&norm).is_some_and(|h| h.dirty);
        if !pending && !dirty {
            return Ok(entry.object_id);
        }
        self.ensure_handle(&norm, &entry)?;
        let plain = self
            .open
            .get(&norm)
            .map(|h| h.plain.clone())
            .unwrap_or_default();
        let oid = corevault::new_object_id()?;
        let bind = bind_for(&entry);
        let sealed = object::seal_object(
            &self.ek,
            self.vault_id,
            self.epoch,
            oid,
            self.chunk_size,
            &bind,
            &plain,
        )?;
        corevault::write_object(
            &self.root,
            self.epoch,
            &oid,
            &sealed.header.to_bytes(),
            &sealed.chunks,
        )?;
        if let Some(e) = self.manifest.entries.iter_mut().find(|e| e.path == norm) {
            e.object_id = oid;
            e.plain_len = u64::try_from(plain.len()).unwrap_or(u64::MAX);
            e.chunk_count = sealed.header.chunk_count;
            e.content_root = sealed.content_root;
            e.mtime_ms = now_ms;
        }
        if let Some(h) = self.open.get_mut(&norm) {
            h.dirty = false;
            h.dirty_chunks.clear();
        }
        self.recompute()?;
        self.dirty = true;
        Ok(oid)
    }

    /// `fsync` then drop the open buffer.
    pub fn close(&mut self, path: &str, now_ms: i64) -> Result<ObjectId> {
        let norm = norm(path)?;
        let oid = self.fsync(&norm, now_ms)?;
        self.open.remove(&norm);
        Ok(oid)
    }

    /// Rename a file, or a directory (moving every entry beneath it). `to`
    /// must not exist; its parent must.
    pub fn rename(&mut self, from: &str, to: &str, now_ms: i64) -> Result<()> {
        let from = norm(from)?;
        let to = norm(to)?;
        if from.is_empty() || to.is_empty() {
            return Err(Error::Format("vfs rename: empty path".into()));
        }
        if from == to {
            return Ok(());
        }
        if self.entry_at(&to).is_some() || self.dirs.contains_key(&to) {
            return Err(Error::Format(format!("vfs rename: {to} exists")));
        }
        let parent = parent_of(&to);
        if !parent.is_empty() && !self.dirs.contains_key(parent) {
            return Err(not_found(parent));
        }

        if self.dirs.contains_key(&from) {
            let from_prefix = format!("{from}/");
            let to_prefix = format!("{to}/");
            for e in &mut self.manifest.entries {
                if let Some(rest) = e.path.strip_prefix(&from_prefix) {
                    e.path = format!("{to_prefix}{rest}");
                    e.mtime_ms = now_ms;
                }
            }
            // The directory's own `kind: dir` row moves with it; implied
            // directories have no row and ride along in the map below.
            if let Some(e) = self.manifest.entries.iter_mut().find(|e| e.path == from) {
                debug_assert!(e.kind.is_dir(), "a dirs-map entry without a dir row");
                e.path = to.clone();
                e.mtime_ms = now_ms;
            }
            let moved: Vec<String> = self
                .dirs
                .keys()
                .filter(|d| {
                    d.as_str() == from.as_str() || d.as_str().starts_with(from_prefix.as_str())
                })
                .cloned()
                .collect();
            for d in &moved {
                self.dirs.remove(d);
            }
            for d in &moved {
                let nd = if d == &from {
                    to.clone()
                } else {
                    format!("{to_prefix}{}", d.strip_prefix(&from_prefix).unwrap_or(""))
                };
                self.dirs.insert(nd, now_ms);
            }
            self.touch_dir(parent_of(&to), now_ms);
            self.rekey_open(&from, &to, &from_prefix, &to_prefix);
        } else if let Some(entry) = self.entry_at(&from) {
            debug_assert_eq!(entry.path, from);
            if let Some(e) = self.manifest.entries.iter_mut().find(|e| e.path == from) {
                e.path = to.clone();
                e.mtime_ms = now_ms;
            }
            self.touch_dir(parent_of(&to), now_ms);
            self.rekey_open(&from, &to, &format!("{from}/"), &format!("{to}/"));
        } else {
            return Err(not_found(&from));
        }
        self.recompute()?;
        self.dirty = true;
        Ok(())
    }

    /// Unlink a file (the old `.gobj` stays; `snapshot::gc` reclaims it), or
    /// remove an empty directory -- dropping its `kind: dir` row if it has one
    /// (POSIX ENOTEMPTY otherwise).
    pub fn unlink(&mut self, path: &str, now_ms: i64) -> Result<()> {
        let norm = norm(path)?;
        if norm.is_empty() {
            return Err(Error::Format("vfs unlink: empty path".into()));
        }
        let entry = self.entry_at(&norm);
        let dir_row = entry.as_ref().is_some_and(|e| e.kind.is_dir());
        if let Some(e) = entry {
            if !e.kind.is_dir() {
                self.manifest.entries.retain(|x| x.path != norm);
                self.open.remove(&norm);
                self.touch_dir(parent_of(&norm), now_ms);
                self.recompute()?;
                self.dirty = true;
                return Ok(());
            }
        }
        if dir_row || self.dirs.contains_key(&norm) {
            let prefix = format!("{norm}/");
            let has_children = self
                .manifest
                .entries
                .iter()
                .any(|e| e.path.starts_with(&prefix))
                || self
                    .dirs
                    .keys()
                    .any(|d| d.as_str().starts_with(prefix.as_str()));
            if has_children {
                return Err(Error::Format(format!(
                    "vfs unlink: {norm} is a non-empty directory"
                )));
            }
            if dir_row {
                self.manifest.entries.retain(|e| e.path != norm);
            }
            self.dirs.remove(&norm);
            self.touch_dir(parent_of(&norm), now_ms);
            self.recompute()?;
            self.dirty = true;
            return Ok(());
        }
        Err(not_found(&norm))
    }

    /// Unmount: flush every open buffer, persist the authenticated manifest,
    /// and clear the dirty flag (08-mount 3). The session stays usable.
    pub fn unmount(&mut self, now_ms: i64) -> Result<()> {
        self.persist(now_ms)
    }

    /// Persist on the `--sync-interval` (default [`DEFAULT_SYNC_INTERVAL_SECS`])
    /// when dirty. Returns whether a persist happened.
    pub fn sync_if_due(&mut self, now_ms: i64) -> Result<bool> {
        if !self.dirty {
            return Ok(false);
        }
        if now_ms.saturating_sub(self.last_sync_ms) < self.sync_interval_ms {
            return Ok(false);
        }
        self.persist(now_ms)?;
        Ok(true)
    }

    // -- internals ----------------------------------------------------------

    fn entry_at(&self, path: &str) -> Option<Entry> {
        self.manifest
            .entries
            .iter()
            .find(|e| e.path == path)
            .cloned()
    }

    fn has_entry(&self, path: &str) -> bool {
        self.manifest.entries.iter().any(|e| e.path == path)
    }

    /// Open (or lazily load) the plaintext buffer for `path`.
    fn ensure_handle(&mut self, path: &str, entry: &Entry) -> Result<()> {
        if self.open.contains_key(path) {
            return Ok(());
        }
        let plain = if entry.object_id == PENDING_OBJECT_ID {
            Vec::new()
        } else {
            let bind = bind_for(entry);
            self::read_all(&self.ek, &self.root, self.epoch, entry.object_id, &bind)?
        };
        self.open.insert(
            path.to_string(),
            OpenFile {
                path: path.to_string(),
                plain,
                dirty: false,
                dirty_chunks: BTreeSet::new(),
            },
        );
        Ok(())
    }

    fn handle_mut(&mut self, path: &str) -> Result<&mut OpenFile> {
        self.open
            .get_mut(path)
            .ok_or_else(|| Error::Format(format!("vfs: {path} has no open buffer")))
    }

    /// POSIX: a namespace mutation updates the parent directory's time. Both
    /// views are stamped -- the session map and the `kind: dir` manifest row
    /// that survives unmount. The vault root is not in the map, so an empty
    /// `dir` is a no-op.
    fn touch_dir(&mut self, dir: &str, now_ms: i64) {
        if let Some(m) = self.dirs.get_mut(dir) {
            *m = now_ms;
        }
        if let Some(e) = self
            .manifest
            .entries
            .iter_mut()
            .find(|e| e.path == dir && e.kind.is_dir())
        {
            e.mtime_ms = now_ms;
        }
    }

    /// Re-key open buffers after a rename (file or directory subtree).
    fn rekey_open(&mut self, from: &str, to: &str, from_prefix: &str, to_prefix: &str) {
        let keys: Vec<String> = self
            .open
            .keys()
            .filter(|k| k.as_str() == from || k.starts_with(from_prefix))
            .cloned()
            .collect();
        for k in keys {
            if let Some(mut h) = self.open.remove(&k) {
                let nk = if k == from {
                    to.to_string()
                } else {
                    format!("{to_prefix}{}", k.strip_prefix(from_prefix).unwrap_or(""))
                };
                h.path = nk.clone();
                self.open.insert(nk, h);
            }
        }
    }

    /// Re-sort entries and refresh the derived manifest fields.
    fn recompute(&mut self) -> Result<()> {
        self.manifest.entries.sort_by(|a, b| a.path.cmp(&b.path));
        self.manifest.entry_count = u32::try_from(self.manifest.entries.len())
            .map_err(|_| Error::Format("entry_count overflow".into()))?;
        self.manifest.root = entries_root(&self.manifest.entries);
        self.manifest.total_plain_bytes = self.manifest.entries.iter().map(|e| e.plain_len).sum();
        self.manifest.total_cipher_bytes = self.cipher_bytes_total()?;
        Ok(())
    }

    /// Sum of the on-disk `.gobj` sizes for every flushed file entry.
    fn cipher_bytes_total(&self) -> Result<u64> {
        let mut total = 0u64;
        for e in &self.manifest.entries {
            // A `kind: dir` row names no `.gobj` body, and a pending file
            // entry has not been sealed yet: neither has ciphertext bytes.
            if e.kind.is_dir() || e.object_id == PENDING_OBJECT_ID {
                continue;
            }
            let p = corevault::object_path(&self.root, self.epoch, &e.object_id)?;
            total += std::fs::metadata(&p)?.len();
        }
        Ok(total)
    }

    /// Flush every buffer + pending entry, then MAC + atomically write the
    /// manifest. The on-disk manifest never names a half-written object.
    fn persist(&mut self, now_ms: i64) -> Result<()> {
        let open: Vec<String> = self.open.keys().cloned().collect();
        for p in open {
            self.fsync(&p, now_ms)?;
        }
        let pending: Vec<String> = self
            .manifest
            .entries
            .iter()
            .filter(|e| e.object_id == PENDING_OBJECT_ID)
            .map(|e| e.path.clone())
            .collect();
        for p in pending {
            self.fsync(&p, now_ms)?;
        }
        if self.dirty {
            self.manifest.generated_at = now_ms / 1000;
            self.recompute()?;
            write_manifest_file(&self.root, self.epoch, &self.manifest, &self.manifest_key)?;
            self.dirty = false;
        }
        self.last_sync_ms = now_ms;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chunk::DEFAULT_CHUNK_SIZE;
    use crate::kdf::{Epoch, IdentitySecret, VaultId};
    use crate::object;
    use crate::vault as corevault;
    use tempfile::tempdir;

    /// Chunk size the RW tests use: 64 KiB keeps multi-chunk buffers cheap.
    const CS: u32 = 64 << 10;

    fn ek() -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn manifest_key() -> [u8; 32] {
        derive_manifest_key(&ek(), VaultId([0x01; 16]), Epoch(1))
    }

    /// Seal `body` into a vault object and write it; return (dir, `object_id`).
    fn fixture(body: &[u8], chunk_size: u32) -> (tempfile::TempDir, ObjectId) {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let sealed = object::seal_object(
            &ek(),
            VaultId([0x01; 16]),
            Epoch(1),
            oid,
            chunk_size,
            b"",
            body,
        )
        .unwrap();
        let hb = sealed.header.to_bytes();
        corevault::write_object(&root, Epoch(1), &oid, &hb, &sealed.chunks).unwrap();
        (d, oid)
    }

    /// A vault with an empty, authenticated manifest -- the mount start state.
    fn vfs_fixture() -> (tempfile::TempDir, VaultId) {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        let vid = VaultId([0x01; 16]);
        corevault::init_vault_dir(&root, vid, Epoch(1)).unwrap();
        let m = Manifest {
            vault_id: vid,
            epoch: Epoch(1),
            suite: crate::SUITE_0X01,
            flags: 0,
            generated_at: 0,
            generator: "test".into(),
            root: entries_root(&[]),
            entry_count: 0,
            total_plain_bytes: 0,
            total_cipher_bytes: 0,
            entries: Vec::new(),
        };
        write_manifest_file(&root, Epoch(1), &m, &manifest_key()).unwrap();
        (d, vid)
    }

    fn open_vfs_at(d: &tempfile::TempDir, vid: VaultId, now_ms: i64) -> Vfs {
        Vfs::open(&ek(), &d.path().join("v.geode"), vid, Epoch(1), CS, now_ms).unwrap()
    }

    fn open_vfs(d: &tempfile::TempDir, vid: VaultId) -> Vfs {
        open_vfs_at(d, vid, 0)
    }

    // ---- read-only path (v0.2.5, unchanged) -------------------------------

    #[test]
    fn read_range_offset_zero_small_object() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_offset_zero_exact_chunk_boundary() {
        let cs = 64 << 10;
        let body = vec![0x5a; cs as usize];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, u64::from(cs)).unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_mid_chunk_small() {
        // 11-byte object. Read [4, 8) -- mid-chunk, offset > 0.
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 4, 4).unwrap();
        assert_eq!(got, b"o wo");
    }

    #[test]
    #[allow(clippy::cast_possible_truncation)]
    fn read_range_mid_chunk_large_object() {
        // Multi-chunk object (3 chunks + tail). Read a slice that starts
        // mid-chunk in chunk 1 and ends mid-chunk in chunk 2 -- the VFS
        // path that proves we decrypt only the touched chunks.
        let cs = 64 << 10;
        let body = vec![0x5a; (cs as usize) * 3 + 10];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let off = u64::from(cs) + 100;
        let len: u64 = u64::from(cs) - 50 + 5;
        let want = &body[off as usize..(off + len) as usize];
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", off, len).unwrap();
        assert_eq!(got, want);
        assert_eq!(got.len() as u64, len);
    }

    #[test]
    fn read_range_clamps_to_plain_len() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 4, 100).unwrap();
        assert_eq!(got, b"o world");
    }

    #[test]
    fn read_range_off_past_end_is_empty() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 100, 10).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn read_range_zero_len_is_empty() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, 0).unwrap();
        assert!(got.is_empty());
    }

    #[test]
    fn read_range_missing_object_is_not_found() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, 10);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn read_range_flipped_chunk_bit_is_auth_fail() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[HEADER_SIZE + 16] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn read_range_flipped_header_tag_is_auth_fail() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[92] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn read_range_wrong_object_id_is_not_found() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let mut other = oid;
        other.0[0] ^= 0x01;
        let r = read_range(&ek(), &root, Epoch(1), other, b"", 0, body.len() as u64);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn read_range_path_bind_mismatch_is_auth_fail() {
        let cs = 64 << 10;
        let body = vec![0x41; cs as usize];
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        corevault::init_vault_dir(&root, VaultId([0x01; 16]), Epoch(1)).unwrap();
        let oid = corevault::new_object_id().unwrap();
        let sealed = object::seal_object(
            &ek(),
            VaultId([0x01; 16]),
            Epoch(1),
            oid,
            cs,
            b"docs/plan.md",
            &body,
        )
        .unwrap();
        let hb = sealed.header.to_bytes();
        corevault::write_object(&root, Epoch(1), &oid, &hb, &sealed.chunks).unwrap();
        let r = read_range(
            &ek(),
            &root,
            Epoch(1),
            oid,
            b"docs/other.md",
            0,
            u64::from(cs),
        );
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
        let got = read_range(
            &ek(),
            &root,
            Epoch(1),
            oid,
            b"docs/plan.md",
            0,
            u64::from(cs),
        )
        .unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_all_roundtrips() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let got = read_all(&ek(), &root, Epoch(1), oid, b"").unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_all_multi_chunk() {
        let cs = 64 << 10;
        let body = vec![0x5a; (cs as usize) * 3 + 10];
        let (d, oid) = fixture(&body, cs);
        let root = d.path().join("v.geode");
        let got = read_all(&ek(), &root, Epoch(1), oid, b"").unwrap();
        assert_eq!(got, body);
    }

    #[test]
    fn read_range_over_max_len_is_format_error() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, MAX_READ_LEN + 1);
        assert!(matches!(r, Err(Error::Format(_))), "got {r:?}");
    }

    #[test]
    fn errors_never_contain_isk() {
        let body = b"hello world";
        let (d, oid) = fixture(body, DEFAULT_CHUNK_SIZE);
        let root = d.path().join("v.geode");
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        let mut raw = std::fs::read(&p).unwrap();
        raw[92] ^= 0x01;
        std::fs::write(&p, &raw).unwrap();
        let r = read_range(&ek(), &root, Epoch(1), oid, b"", 0, body.len() as u64);
        let s = format!("{}", r.unwrap_err());
        assert!(!s.contains("ISK"), "leaks ISK: {s}");
        assert!(!s.contains('\u{7}'), "leaks key bytes: {s}");
    }

    // ---- G0a: write / truncate / extend are copy-on-write ----------------

    #[test]
    fn write_then_read_back_roundtrips() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let mut vfs = open_vfs(&d, vid);
        vfs.mkdir("docs", 0o755, 0).unwrap();
        vfs.create("docs/plan.md", 0o644, 0).unwrap();
        vfs.write("docs/plan.md", 0, b"hello world").unwrap();
        // Before the flush the read is served from the open buffer.
        assert_eq!(
            vfs.read_range("docs/plan.md", 0, 11).unwrap(),
            b"hello world"
        );
        let oid = vfs.fsync("docs/plan.md", 1_000).unwrap();
        // After the flush the SHIPPED read-only path (no /dev/fuse) agrees.
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, 11).unwrap();
        assert_eq!(got, b"hello world");
        assert_eq!(vfs.read_range("docs/plan.md", 6, 5).unwrap(), b"world");
    }

    #[test]
    fn write_is_copy_on_write_and_keeps_the_old_object() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let body = vec![0x5a; CS as usize * 3 + 10];
        let mut vfs = open_vfs(&d, vid);
        vfs.create("big.bin", 0o644, 0).unwrap();
        vfs.write("big.bin", 0, &body).unwrap();
        // Every chunk the write touched is dirty (3 full + a tail chunk).
        assert_eq!(vfs.dirty_chunks("big.bin").unwrap(), vec![0, 1, 2, 3]);
        let old = vfs.fsync("big.bin", 1_000).unwrap();
        assert!(
            vfs.dirty_chunks("big.bin").unwrap().is_empty(),
            "flush clears the dirty set"
        );

        // Second pass: overwrite 3 bytes inside chunk 2 only.
        let off = 2 * u64::from(CS) + 100;
        vfs.write("big.bin", off, b"XYZ").unwrap();
        assert_eq!(
            vfs.dirty_chunks("big.bin").unwrap(),
            vec![2],
            "only the touched chunk is dirty"
        );
        let new = vfs.fsync("big.bin", 2_000).unwrap();
        assert_ne!(new, old, "flush allocates a new object_id");

        // The old object was not mutated: it still reads back its old body.
        let total = u64::try_from(body.len()).unwrap();
        let old_pt = read_range(&ek(), &root, Epoch(1), old, b"", 0, total).unwrap();
        assert_eq!(old_pt, body);
        assert!(
            corevault::object_path(&root, Epoch(1), &old)
                .unwrap()
                .exists(),
            "the superseded .gobj is left on disk (gc reclaims it)"
        );

        let new_pt = read_range(&ek(), &root, Epoch(1), new, b"", 0, total).unwrap();
        assert_eq!(new_pt.len(), body.len());
        assert_eq!(&new_pt[off as usize..off as usize + 3], b"XYZ");
        assert_eq!(&new_pt[..off as usize], &body[..off as usize]);
        assert_eq!(&new_pt[off as usize + 3..], &body[off as usize + 3..]);
    }

    #[test]
    fn write_past_eof_extends_with_zeroes() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let mut vfs = open_vfs(&d, vid);
        vfs.create("sparse.bin", 0o644, 0).unwrap();
        vfs.write("sparse.bin", 0, b"abc").unwrap();
        let off = u64::from(CS) + 3;
        vfs.write("sparse.bin", off, b"Z").unwrap();
        let oid = vfs.fsync("sparse.bin", 1).unwrap();
        let end = off + 1;
        let got = read_range(&ek(), &root, Epoch(1), oid, b"", 0, end).unwrap();
        assert_eq!(&got[..3], b"abc");
        assert!(
            got[3..off as usize].iter().all(|b| *b == 0),
            "sparse hole is zero"
        );
        assert_eq!(got[off as usize], b'Z');
        assert_eq!(got.len() as u64, end);
    }

    #[test]
    fn zero_len_write_does_not_extend() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.create("f", 0o644, 0).unwrap();
        vfs.write("f", 1_000, b"").unwrap();
        assert!(
            vfs.dirty_chunks("f").unwrap().is_empty(),
            "a zero-length write touches nothing"
        );
        let oid = vfs.fsync("f", 1).unwrap();
        assert_ne!(oid, PENDING_OBJECT_ID);
        assert_eq!(vfs.list()[0].object_id, oid);
        assert_eq!(vfs.list()[0].plain_len, 0);
    }

    #[test]
    fn truncate_shrinks_and_extend_grows_chunk_independently() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let body = vec![0x41; CS as usize * 3];
        let mut vfs = open_vfs(&d, vid);
        vfs.create("f.bin", 0o644, 0).unwrap();
        vfs.write("f.bin", 0, &body).unwrap();
        let _ = vfs.fsync("f.bin", 10).unwrap();

        // Shrink: only the chunks that lost bytes are dirty (chunks 1 and 2).
        let shrunk = u64::from(CS) + 5;
        vfs.truncate("f.bin", shrunk).unwrap();
        assert_eq!(vfs.dirty_chunks("f.bin").unwrap(), vec![1, 2]);
        let oid = vfs.fsync("f.bin", 20).unwrap();
        assert_eq!(
            read_range(&ek(), &root, Epoch(1), oid, b"", 0, shrunk).unwrap(),
            &body[..shrunk as usize]
        );
        assert!(
            read_range(&ek(), &root, Epoch(1), oid, b"", shrunk, 10)
                .unwrap()
                .is_empty(),
            "the truncated tail is gone"
        );

        // Extend past the old end: the prefix survives, the tail is zeroes.
        let grown = u64::from(CS) * 4 + 7;
        vfs.truncate("f.bin", grown).unwrap();
        let oid2 = vfs.fsync("f.bin", 30).unwrap();
        let got = read_range(&ek(), &root, Epoch(1), oid2, b"", 0, grown).unwrap();
        assert_eq!(got.len() as u64, grown);
        assert_eq!(&got[..shrunk as usize], &body[..shrunk as usize]);
        assert!(got[shrunk as usize..].iter().all(|b| *b == 0));
    }

    #[test]
    fn write_and_truncate_over_the_file_cap_are_format_errors() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.create("f", 0o644, 0).unwrap();
        // The gate is on the resulting end offset, so this needs one byte.
        let r = vfs.write("f", MAX_FILE_LEN, b"x");
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = vfs.truncate("f", MAX_FILE_LEN + 1);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        // Neither refused op may have mutated the pending entry.
        assert_eq!(vfs.list()[0].plain_len, 0);
        assert!(vfs.dirty_chunks("f").unwrap().is_empty());
    }

    // ---- G0b: namespace mutations + fresh object_id on flush -------------

    #[test]
    fn create_unlink_and_list() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.mkdir("scratch", 0o755, 0).unwrap();
        vfs.create("scratch/a.md", 0o644, 0).unwrap();
        vfs.create("scratch/b.md", 0o644, 0).unwrap();
        let paths: Vec<String> = vfs.list().iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, vec!["scratch", "scratch/a.md", "scratch/b.md"]);

        let kids: Vec<String> = vfs
            .readdir("scratch")
            .unwrap()
            .into_iter()
            .map(|n| n.path)
            .collect();
        assert_eq!(kids, vec!["scratch/a.md", "scratch/b.md"]);

        vfs.unlink("scratch/a.md", 0).unwrap();
        let paths: Vec<String> = vfs.list().iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, vec!["scratch", "scratch/b.md"]);
        let r = vfs.unlink("scratch/a.md", 0);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "got {r:?}"
        );
    }

    #[test]
    fn create_refuses_duplicates_and_missing_parents() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.mkdir("a", 0o755, 0).unwrap();
        vfs.create("a/f", 0o644, 0).unwrap();
        assert!(vfs.create("a/f", 0o644, 0).is_err(), "EEXIST");
        assert!(vfs.create("a", 0o644, 0).is_err(), "dir exists at path");
        let r = vfs.create("missing/f", 0o644, 0);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "ENOENT parent, got {r:?}"
        );
    }

    #[test]
    fn fsync_allocates_new_object_id_and_writes_gobj() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let mut vfs = open_vfs(&d, vid);
        vfs.create("x", 0o644, 7).unwrap();
        assert_eq!(
            vfs.list()[0].object_id,
            PENDING_OBJECT_ID,
            "a created-but-unflushed entry is pending"
        );
        let oid = vfs.fsync("x", 42).unwrap();
        assert_ne!(oid, PENDING_OBJECT_ID);
        let p = corevault::object_path(&root, Epoch(1), &oid).unwrap();
        assert!(p.exists(), "fsync writes the .gobj");
        assert_eq!(std::fs::metadata(&p).unwrap().len(), HEADER_SIZE as u64);

        let e = &vfs.list()[0];
        assert_eq!(e.object_id, oid);
        assert_eq!(e.plain_len, 0);
        assert_eq!(e.chunk_count, 0);
        assert_eq!(e.mtime_ms, 42);
        assert_eq!(vfs.fsync("x", 43).unwrap(), oid, "clean fsync is a no-op");
    }

    #[test]
    fn mkdir_readdir_rename_unlink_namespace() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.mkdir("a", 0o755, 0).unwrap();
        assert!(vfs.mkdir("a", 0o755, 0).is_err(), "EEXIST");
        let r = vfs.mkdir("missing/b", 0o755, 0);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "ENOENT parent, got {r:?}"
        );

        let root_kids = vfs.readdir("").unwrap();
        assert_eq!(
            root_kids.len(),
            1,
            "a dir row is listed once, not once per source"
        );
        assert_eq!(root_kids[0].path, "a");
        assert_eq!(root_kids[0].kind, NodeKind::Dir);
        assert_eq!(vfs.stat("a").unwrap().kind, NodeKind::Dir);
        assert_eq!(vfs.list()[0].kind, EntryKind::Dir);

        vfs.create("a/f", 0o644, 0).unwrap();
        vfs.write("a/f", 0, b"body").unwrap();
        vfs.rename("a/f", "a/g", 5).unwrap();
        let g = vfs.list().iter().find(|e| e.path == "a/g").expect("a/g");
        assert_eq!(g.kind, EntryKind::File);
        assert_eq!(
            vfs.stat("a").unwrap().mtime_ms,
            5,
            "renaming into a directory stamps its time"
        );
        let gone = vfs.stat("a/f");
        assert!(
            matches!(&gone, Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "got {gone:?}"
        );

        // Renaming the directory moves its row, its children and re-keys the
        // buffer.
        vfs.rename("a", "b", 6).unwrap();
        assert_eq!(
            vfs.list().iter().find(|e| e.path == "b/g").unwrap().path,
            "b/g"
        );
        assert_eq!(vfs.stat("b").unwrap().kind, NodeKind::Dir);
        assert!(vfs.list().iter().all(|e| e.path != "a" && e.path != "a/g"));
        assert_eq!(vfs.stat("b").unwrap().mtime_ms, 6);
        assert!(
            matches!(&vfs.readdir("a"), Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "the old directory is gone"
        );
        assert_eq!(vfs.read_range("b/g", 0, 4).unwrap(), b"body");

        // A non-empty directory cannot be unlinked.
        assert!(vfs.unlink("b", 7).is_err(), "ENOTEMPTY");
        vfs.unlink("b/g", 7).unwrap();
        vfs.unlink("b", 7).unwrap();
        assert!(vfs.list().is_empty());
        assert!(vfs.readdir("").unwrap().is_empty());
    }

    #[test]
    fn mkdir_persists_a_kind_dir_row_and_reopen_lists_it() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        let dir_id;
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.mkdir("scratch", 0o755, 5).unwrap();
            let row = vfs
                .list()
                .iter()
                .find(|e| e.path == "scratch")
                .expect("mkdir pushes a manifest row")
                .clone();
            assert_eq!(row.kind, EntryKind::Dir);
            assert_eq!(row.plain_len, 0);
            assert_eq!(row.chunk_count, 0);
            assert_eq!(row.mode, 0o755);
            assert_eq!(row.mtime_ms, 5);
            assert_ne!(
                row.object_id, PENDING_OBJECT_ID,
                "a dir row carries a real object_id"
            );
            dir_id = row.object_id;
            vfs.unmount(6).unwrap();
        }
        // An empty directory names no object body: no `.gobj` is written.
        assert!(!corevault::object_path(&root, Epoch(1), &dir_id)
            .unwrap()
            .exists());

        let vfs2 = open_vfs(&d, vid);
        let node = vfs2.stat("scratch").unwrap();
        assert_eq!(node.kind, NodeKind::Dir);
        assert_eq!(node.mtime_ms, 5);
        let kids = vfs2.readdir("").unwrap();
        assert_eq!(kids.len(), 1, "reopen lists the directory exactly once");
        assert_eq!(kids[0].path, "scratch");
        assert_eq!(kids[0].kind, NodeKind::Dir);

        let on_disk = read_manifest_file(&root, Epoch(1), &manifest_key()).unwrap();
        let row = on_disk
            .entries
            .iter()
            .find(|e| e.path == "scratch")
            .expect("the dir row persisted");
        assert_eq!(row.kind, EntryKind::Dir);
        assert_eq!(row.object_id, dir_id);
        assert_eq!(row.plain_len, 0);
        assert_eq!(row.chunk_count, 0);
        assert_eq!(on_disk.entry_count, 1);
        assert_eq!(on_disk.total_plain_bytes, 0);
        assert_eq!(
            on_disk.total_cipher_bytes, 0,
            "a directory row contributes no ciphertext bytes"
        );
    }

    #[test]
    fn dir_rows_survive_rename_and_unlink_across_reopen() {
        let (d, vid) = vfs_fixture();
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.mkdir("a", 0o755, 1).unwrap();
            vfs.mkdir("a/b", 0o700, 2).unwrap();
            vfs.rename("a", "c", 3).unwrap();
            assert_eq!(vfs.stat("c").unwrap().kind, NodeKind::Dir);
            assert_eq!(vfs.stat("c/b").unwrap().kind, NodeKind::Dir);
            assert!(vfs.list().iter().all(|e| e.path != "a" && e.path != "a/b"));
            vfs.unmount(4).unwrap();
        }
        let vfs2 = open_vfs(&d, vid);
        let paths: Vec<String> = vfs2.list().iter().map(|e| e.path.clone()).collect();
        assert_eq!(paths, vec!["c", "c/b"]);
        let kids = vfs2.readdir("c").unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].path, "c/b");
        assert_eq!(kids[0].kind, NodeKind::Dir);

        // Dropping the leaf row then the parent row empties the manifest.
        let mut vfs3 = open_vfs(&d, vid);
        vfs3.unlink("c/b", 5).unwrap();
        assert!(vfs3.unlink("c", 5).is_ok());
        assert!(vfs3.list().is_empty());
        vfs3.unmount(6).unwrap();
        let vfs4 = open_vfs(&d, vid);
        assert!(vfs4.list().is_empty());
        assert!(vfs4.readdir("").unwrap().is_empty());
    }

    #[test]
    fn dir_rows_reject_reads_and_writes() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.mkdir("d", 0o755, 0).unwrap();
        assert!(matches!(&vfs.read_range("d", 0, 1), Err(Error::Format(_))));
        assert!(matches!(&vfs.write("d", 0, b"x"), Err(Error::Format(_))));
        assert!(matches!(&vfs.truncate("d", 1), Err(Error::Format(_))));
        assert!(matches!(&vfs.dirty_chunks("d"), Err(Error::Format(_))));
        assert!(vfs.create("d", 0o644, 0).is_err(), "EEXIST at a dir row");
        // `fsync` on a directory is a no-op that keeps the row's object_id.
        let id = vfs.stat("d").unwrap().object_id;
        assert_eq!(vfs.fsync("d", 9).unwrap(), id);
        assert_eq!(vfs.stat("d").unwrap().object_id, id);
    }

    #[test]
    fn paths_without_dir_rows_read_as_implied_directories() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.mkdir("docs", 0o755, 0).unwrap();
            vfs.create("docs/plan.md", 0o644, 0).unwrap();
            vfs.write("docs/plan.md", 0, b"x").unwrap();
            vfs.unmount(1).unwrap();
        }
        // A manifest written without dir rows (another tool): the ancestor is
        // still listed as an implied directory for the session.
        let mut m = read_manifest_file(&root, Epoch(1), &manifest_key()).unwrap();
        m.entries.retain(|e| e.kind != EntryKind::Dir);
        m.entry_count = 1;
        m.root = entries_root(&m.entries);
        m.total_plain_bytes = 1;
        write_manifest_file(&root, Epoch(1), &m, &manifest_key()).unwrap();

        let vfs2 = open_vfs(&d, vid);
        assert_eq!(vfs2.list().len(), 1, "only the file has a row");
        let kids = vfs2.readdir("").unwrap();
        assert_eq!(kids.len(), 1);
        assert_eq!(kids[0].path, "docs");
        assert_eq!(kids[0].kind, NodeKind::Dir);
        assert_eq!(vfs2.stat("docs").unwrap().kind, NodeKind::Dir);
        assert_eq!(vfs2.read_range("docs/plan.md", 0, 1).unwrap(), b"x");
    }

    #[test]
    fn rename_missing_is_not_found_and_dest_must_be_free() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        vfs.create("f", 0o644, 0).unwrap();
        let r = vfs.rename("missing", "x", 0);
        assert!(
            matches!(&r, Err(Error::Io(e)) if e.kind() == ErrorKind::NotFound),
            "got {r:?}"
        );
        assert!(vfs.rename("f", "f", 0).is_ok(), "same path is a no-op");
        vfs.create("g", 0o644, 0).unwrap();
        assert!(vfs.rename("f", "g", 0).is_err(), "EEXIST at destination");
    }

    // ---- G0c: persist on unmount, reopen, RO still works, no ISK ---------

    #[test]
    fn unmount_persists_manifest_and_reopen_sees_it() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.mkdir("docs", 0o755, 0).unwrap();
            vfs.create("docs/plan.md", 0o644, 0).unwrap();
            vfs.write("docs/plan.md", 0, b"hello world").unwrap();
            vfs.unmount(1_000).unwrap();
            assert!(!vfs.is_dirty());
        }

        // Reopen: the persisted manifest names the file, and the shipped
        // read-only path reads it back with no kernel.
        let vfs2 = open_vfs(&d, vid);
        let e = vfs2
            .list()
            .iter()
            .find(|e| e.path == "docs/plan.md")
            .expect("entry persisted")
            .clone();
        assert_eq!(e.plain_len, 11);
        assert_eq!(e.chunk_count, 1);
        assert_ne!(e.content_root, [0u8; 32]);
        assert_eq!(
            vfs2.read_range("docs/plan.md", 0, 11).unwrap(),
            b"hello world"
        );
        let got = read_range(&ek(), &root, Epoch(1), e.object_id, b"", 0, 11).unwrap();
        assert_eq!(got, b"hello world");
    }

    #[test]
    fn unmount_flushes_a_pending_empty_file() {
        let (d, vid) = vfs_fixture();
        let root = d.path().join("v.geode");
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.create("empty.txt", 0o644, 7).unwrap();
            vfs.unmount(7).unwrap();
        }
        let vfs2 = open_vfs(&d, vid);
        let e = vfs2.list()[0].clone();
        assert_ne!(e.object_id, PENDING_OBJECT_ID);
        assert_eq!(e.plain_len, 0);
        assert!(corevault::object_path(&root, Epoch(1), &e.object_id)
            .unwrap()
            .exists());
        assert!(vfs2.read_range("empty.txt", 0, 10).unwrap().is_empty());
    }

    #[test]
    fn unmount_then_reopen_roundtrips_a_multi_chunk_write() {
        let (d, vid) = vfs_fixture();
        let body = vec![0x5a; CS as usize * 3 + 10];
        {
            let mut vfs = open_vfs(&d, vid);
            vfs.create("big.bin", 0o644, 0).unwrap();
            vfs.write("big.bin", 0, &body).unwrap();
            vfs.unmount(1).unwrap();
        }
        let vfs2 = open_vfs(&d, vid);
        assert_eq!(
            vfs2.read_range("big.bin", 0, u64::try_from(body.len()).unwrap())
                .unwrap(),
            body
        );
        assert_eq!(vfs2.list()[0].chunk_count, 4);
    }

    #[test]
    fn reopen_rejects_a_manifest_from_another_vault() {
        let (d, _vid) = vfs_fixture();
        // The manifest MAC is bound to (EK, vault_id, epoch); a different
        // vault_id cannot authenticate this manifest.
        let r = Vfs::open(
            &ek(),
            &d.path().join("v.geode"),
            VaultId([0x02; 16]),
            Epoch(1),
            CS,
            0,
        );
        assert!(matches!(r, Err(Error::AuthFail)), "got {r:?}");
    }

    #[test]
    fn sync_interval_defaults_to_five_seconds() {
        assert_eq!(DEFAULT_SYNC_INTERVAL_SECS, 5);
    }

    #[test]
    fn sync_if_due_persists_only_when_dirty_and_due() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs_at(&d, vid, 1_000_000);
        assert!(
            !vfs.sync_if_due(1_002_000).unwrap(),
            "a clean vault has nothing to persist"
        );
        assert!(!vfs.is_dirty());

        vfs.create("x.md", 0o644, 1_000_500).unwrap();
        vfs.write("x.md", 0, b"hi").unwrap();
        let _ = vfs.fsync("x.md", 1_000_500).unwrap();
        assert!(vfs.is_dirty());
        assert!(
            !vfs.sync_if_due(1_003_000).unwrap(),
            "2.5 s < the 5 s interval"
        );
        assert!(vfs.sync_if_due(1_005_000).unwrap(), "due at 5 s");
        assert!(!vfs.is_dirty());

        let on_disk =
            read_manifest_file(&d.path().join("v.geode"), Epoch(1), &manifest_key()).unwrap();
        assert_eq!(on_disk.entry_count, 1);
        assert_eq!(on_disk.entries[0].path, "x.md");
        assert_eq!(on_disk.entries[0].plain_len, 2);
        assert_ne!(on_disk.total_cipher_bytes, 0);
    }

    #[test]
    fn manifest_never_names_a_pending_object() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs_at(&d, vid, 0);
        vfs.create("pending.md", 0o644, 0).unwrap();
        assert!(vfs.is_dirty());
        vfs.unmount(10).unwrap();
        let on_disk =
            read_manifest_file(&d.path().join("v.geode"), Epoch(1), &manifest_key()).unwrap();
        assert_ne!(on_disk.entries[0].object_id, PENDING_OBJECT_ID);
        assert!(corevault::object_path(
            &d.path().join("v.geode"),
            Epoch(1),
            &on_disk.entries[0].object_id
        )
        .unwrap()
        .exists());
    }

    #[test]
    fn mount_errors_never_contain_key_material() {
        let (d, vid) = vfs_fixture();
        let mut vfs = open_vfs(&d, vid);
        let mut msgs = Vec::new();
        msgs.push(format!("{}", vfs.unlink("missing", 0).unwrap_err()));
        msgs.push(format!("{}", vfs.rename("missing", "x", 0).unwrap_err()));
        msgs.push(format!("{}", vfs.write("missing", 0, b"x").unwrap_err()));
        msgs.push(format!("{}", vfs.truncate("missing", 1).unwrap_err()));
        msgs.push(format!(
            "{}",
            vfs.create("../escape", 0o644, 0).unwrap_err()
        ));
        msgs.push(format!("{}", vfs.mkdir("no/parent", 0o755, 0).unwrap_err()));
        let r = vfs.mkdir("dir", 0o755, 0);
        assert!(r.is_ok());
        msgs.push(format!("{}", vfs.read_range("dir", 0, 1).unwrap_err()));
        msgs.push(format!("{}", vfs.read_range("missing", 0, 1).unwrap_err()));
        let ek_bytes = *ek().as_bytes();
        let ek_hex = corevault::hex_encode(&ek_bytes);
        for s in &msgs {
            assert!(!s.contains("ISK"), "leaks ISK: {s}");
            assert!(!s.contains('\u{7}'), "leaks key bytes: {s}");
            assert!(!s.contains(&ek_hex), "leaks EK hex: {s}");
            assert!(!s.contains(&format!("{ek_bytes:?}")), "leaks EK bytes: {s}");
        }
    }
}
