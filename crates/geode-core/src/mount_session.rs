//! `MountSession` -- the kernel-free mount session over the shipped VFS
//! (08-mount 3; SPEC-v030 G0).
//!
//! `fuser` lives in `geode-cli` behind the `fuse` feature and **never** here:
//! a core build stays free of a FUSE dependency, and everything below is
//! exercised by kernel-free tests -- no `/dev/fuse`, no mountpoint.
//!
//! A session owns one [`Vfs`] over one vault epoch plus its [`MountMode`]:
//!
//! - [`MountMode::ReadOnly`] refuses every mutating call before it reaches the
//!   VFS (POSIX EROFS). 08-mount 7 keeps `--read-only` the recommended
//!   agent-adjacent default.
//! - [`MountMode::ReadWrite`] passes create / mkdir / write / truncate /
//!   rename / unlink / fsync through to the VFS, which is copy-on-write and
//!   persists the authenticated manifest on [`MountSession::unmount`].
//!
//! Reads are identical in both modes. Errors never carry ISK or key bytes, and
//! no new [`Error`] variant is introduced -- the CLI's `output.rs` matches
//! exhaustively.

use crate::kdf::{Epoch, EpochKey, ObjectId, VaultId};
use crate::manifest::{Entry, Manifest};
use crate::vfs::{self, Vfs, VfsNode};
use crate::{Error, Result};
use std::path::Path;

/// Mount mode (08-mount 3, 7; SPEC-v030).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountMode {
    /// Reads only. Every mutating call is refused (POSIX EROFS).
    ReadOnly,
    /// Reads plus copy-on-write writes; the manifest persists on unmount.
    ReadWrite,
}

impl MountMode {
    /// Is this the read-only mode?
    #[must_use]
    pub fn is_read_only(self) -> bool {
        matches!(self, Self::ReadOnly)
    }
}

/// One kernel-free mount session over a vault epoch.
#[derive(Debug)]
pub struct MountSession {
    vfs: Vfs,
    mode: MountMode,
}

impl MountSession {
    /// Open a session: authenticate + load the epoch manifest under a key
    /// derived from `ek` (see [`Vfs::open`]).
    ///
    /// `chunk_size` comes from the vault header's `chunk_size_default`
    /// (03-format 3); `now_ms` seeds the `--sync-interval` clock.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)] // wire/format shape
    pub fn open(
        ek: &EpochKey,
        vault_root: &Path,
        vault_id: VaultId,
        epoch: Epoch,
        chunk_size: u32,
        mode: MountMode,
        now_ms: i64,
    ) -> Result<Self> {
        Ok(Self {
            vfs: Vfs::open(ek, vault_root, vault_id, epoch, chunk_size, now_ms)?,
            mode,
        })
    }

    /// The session's mount mode.
    #[must_use]
    pub fn mode(&self) -> MountMode {
        self.mode
    }

    /// Does this session refuse mutations (08-mount 7)?
    #[must_use]
    pub fn is_read_only(&self) -> bool {
        self.mode.is_read_only()
    }

    /// Has the mounted manifest changed since the last persist?
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.vfs.is_dirty()
    }

    /// The in-memory manifest (sorted by path).
    #[must_use]
    pub fn manifest(&self) -> &Manifest {
        self.vfs.manifest()
    }

    /// Manifest entries -- files, directories and symlinks (sorted by path).
    #[must_use]
    pub fn list(&self) -> &[Entry] {
        self.vfs.list()
    }

    /// Look up one path (`kind: dir` rows included).
    pub fn stat(&self, path: &str) -> Result<VfsNode> {
        self.vfs.stat(path)
    }

    /// Immediate children of `dir` (`""` is the vault root).
    pub fn readdir(&self, dir: &str) -> Result<Vec<VfsNode>> {
        self.vfs.readdir(dir)
    }

    /// Read `len` bytes at `off`. Same clamping rules as [`vfs::read_range`].
    pub fn read(&self, path: &str, off: u64, len: u64) -> Result<Vec<u8>> {
        self.vfs.read_range(path, off, len)
    }

    /// Read a whole entry from offset 0 (clamped to its plaintext length).
    pub fn read_all(&self, path: &str) -> Result<Vec<u8>> {
        self.vfs.read_range(path, 0, vfs::MAX_READ_LEN)
    }

    /// Chunk indices this session has modified since the last flush.
    pub fn dirty_chunks(&self, path: &str) -> Result<Vec<u64>> {
        self.vfs.dirty_chunks(path)
    }

    /// Create an empty file (parent must exist). Refused when read-only.
    pub fn create(&mut self, path: &str, mode: u32, now_ms: i64) -> Result<()> {
        self.writable("create")?;
        self.vfs.create(path, mode, now_ms)
    }

    /// Create a directory: a persisted `kind: dir` row with no object body.
    /// Refused when read-only.
    pub fn mkdir(&mut self, path: &str, mode: u32, now_ms: i64) -> Result<()> {
        self.writable("mkdir")?;
        self.vfs.mkdir(path, mode, now_ms)
    }

    /// Write `data` at `off` (copy-on-write). Refused when read-only.
    pub fn write(&mut self, path: &str, off: u64, data: &[u8]) -> Result<()> {
        self.writable("write")?;
        self.vfs.write(path, off, data)
    }

    /// Truncate (or zero-extend) to `len`. Refused when read-only.
    pub fn truncate(&mut self, path: &str, len: u64) -> Result<()> {
        self.writable("truncate")?;
        self.vfs.truncate(path, len)
    }

    /// Rename a file or directory (moving its `kind: dir` row with it).
    /// Refused when read-only.
    pub fn rename(&mut self, from: &str, to: &str, now_ms: i64) -> Result<()> {
        self.writable("rename")?;
        self.vfs.rename(from, to, now_ms)
    }

    /// Unlink a file, or remove an empty directory. Refused when read-only.
    pub fn unlink(&mut self, path: &str, now_ms: i64) -> Result<()> {
        self.writable("unlink")?;
        self.vfs.unlink(path, now_ms)
    }

    /// Flush one file: a fresh `object_id` and a new `.gobj` (03-format 10).
    ///
    /// Allowed on a read-only session: nothing can be dirty, so this is the
    /// no-op POSIX allows for `fsync` on a read-only descriptor.
    pub fn fsync(&mut self, path: &str, now_ms: i64) -> Result<ObjectId> {
        self.vfs.fsync(path, now_ms)
    }

    /// `fsync` then drop the open buffer. Allowed on a read-only session.
    pub fn close(&mut self, path: &str, now_ms: i64) -> Result<ObjectId> {
        self.vfs.close(path, now_ms)
    }

    /// Persist on the `--sync-interval` if the manifest is dirty since the last
    /// persist (08-mount 3). Always `false` on a read-only session.
    pub fn sync_if_due(&mut self, now_ms: i64) -> Result<bool> {
        if self.is_read_only() {
            return Ok(false);
        }
        self.vfs.sync_if_due(now_ms)
    }

    /// Unmount: persist the authenticated manifest (08-mount 3).
    ///
    /// A read-only session never mutated anything, so unmount does **not**
    /// rewrite the manifest on disk.
    pub fn unmount(&mut self, now_ms: i64) -> Result<()> {
        if self.is_read_only() {
            debug_assert!(
                !self.vfs.is_dirty(),
                "a read-only session cannot have a dirty manifest"
            );
            return Ok(());
        }
        self.vfs.unmount(now_ms)
    }

    /// The read-only gate. Refusals carry no key material and use the shipped
    /// `Error` variants (no new variant; POSIX EROFS is a usage error here).
    fn writable(&self, op: &str) -> Result<()> {
        if self.is_read_only() {
            return Err(Error::Format(format!(
                "mount session is read-only: {op} refused (08-mount 3)"
            )));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdf::{derive_manifest_key, IdentitySecret};
    use crate::manifest::{entries_root, EntryKind};
    use crate::snapshot::{read_manifest_file, write_manifest_file};
    use crate::vault as corevault;
    use crate::vfs::NodeKind;
    use tempfile::tempdir;

    /// Chunk size the tests use: 64 KiB keeps multi-chunk buffers cheap.
    const CS: u32 = 64 << 10;

    fn ek() -> EpochKey {
        let isk = IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }

    fn manifest_key() -> [u8; 32] {
        derive_manifest_key(&ek(), VaultId([0x01; 16]), Epoch(1))
    }

    /// A vault with an empty, authenticated manifest -- what a mount starts on.
    fn fixture() -> (tempfile::TempDir, VaultId) {
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

    fn open_session(
        d: &tempfile::TempDir,
        vid: VaultId,
        mode: MountMode,
        now_ms: i64,
    ) -> MountSession {
        MountSession::open(
            &ek(),
            &d.path().join("v.geode"),
            vid,
            Epoch(1),
            CS,
            mode,
            now_ms,
        )
        .unwrap()
    }

    // ---- G0a: read / write roundtrip, copy-on-write, no /dev/fuse --------

    #[test]
    fn write_then_read_roundtrips_and_the_old_object_survives() {
        let (d, vid) = fixture();
        let root = d.path().join("v.geode");
        let body = vec![0x5a; CS as usize * 3 + 10];
        let off = 2 * u64::from(CS) + 100;
        let off_i = usize::try_from(off).unwrap();
        let mut want = body.clone();
        want[off_i..off_i + 3].copy_from_slice(b"XYZ");
        let total = u64::try_from(body.len()).unwrap();

        let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
        s.create("big.bin", 0o644, 1).unwrap();
        s.write("big.bin", 0, &body).unwrap();
        assert_eq!(s.dirty_chunks("big.bin").unwrap(), vec![0, 1, 2, 3]);
        let old = s.fsync("big.bin", 2).unwrap();
        assert!(
            s.dirty_chunks("big.bin").unwrap().is_empty(),
            "flush clears the dirty set"
        );

        // Copy-on-write: touching one chunk allocates a new object and leaves
        // the superseded one byte-for-byte readable.
        s.write("big.bin", off, b"XYZ").unwrap();
        assert_eq!(s.dirty_chunks("big.bin").unwrap(), vec![2]);
        let new = s.fsync("big.bin", 3).unwrap();
        assert_ne!(new, old, "flush allocates a fresh object_id");
        assert_eq!(s.read_all("big.bin").unwrap(), want);
        let old_pt = vfs::read_range(&ek(), &root, Epoch(1), old, b"", 0, total).unwrap();
        assert_eq!(
            old_pt, body,
            "the superseded .gobj still reads its old body"
        );
        s.unmount(4).unwrap();

        // Reopen: the write persisted through the authenticated manifest.
        let s2 = open_session(&d, vid, MountMode::ReadOnly, 5);
        assert_eq!(s2.read_all("big.bin").unwrap(), want);
        assert_eq!(s2.read("big.bin", off, 3).unwrap(), b"XYZ");
    }

    // ---- G0b: create / mkdir / rename / unlink / fsync -------------------

    #[test]
    fn create_mkdir_rename_unlink_and_fsync_go_through_the_session() {
        let (d, vid) = fixture();
        let root = d.path().join("v.geode");
        let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
        s.mkdir("scratch", 0o755, 1).unwrap();
        s.create("scratch/a.md", 0o644, 2).unwrap();
        s.write("scratch/a.md", 0, b"hello mount").unwrap();
        let oid = s.fsync("scratch/a.md", 3).unwrap();
        assert!(corevault::object_path(&root, Epoch(1), &oid)
            .unwrap()
            .exists());
        assert_eq!(s.stat("scratch/a.md").unwrap().kind, NodeKind::File);
        assert_eq!(s.read_all("scratch/a.md").unwrap(), b"hello mount");

        s.rename("scratch/a.md", "scratch/b.md", 4).unwrap();
        let names: Vec<String> = s.list().iter().map(|e| e.path.clone()).collect();
        assert_eq!(names, vec!["scratch", "scratch/b.md"]);
        assert_eq!(s.read_all("scratch/b.md").unwrap(), b"hello mount");

        s.unlink("scratch/b.md", 5).unwrap();
        let names: Vec<String> = s.list().iter().map(|e| e.path.clone()).collect();
        assert_eq!(names, vec!["scratch"], "the dir row is the entry left");

        // `fsync` on the directory row is a no-op that keeps its object_id.
        let dir_id = s.stat("scratch").unwrap().object_id;
        assert_eq!(s.fsync("scratch", 6).unwrap(), dir_id);
        s.unmount(7).unwrap();
    }

    #[test]
    fn unmount_persists_a_kind_dir_row_and_reopen_lists_it() {
        let (d, vid) = fixture();
        let root = d.path().join("v.geode");
        {
            let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
            s.mkdir("scratch", 0o755, 5).unwrap();
            s.unmount(6).unwrap();
        }
        let on_disk = read_manifest_file(&root, Epoch(1), &manifest_key()).unwrap();
        let row = on_disk
            .entries
            .iter()
            .find(|e| e.path == "scratch")
            .expect("the dir row persisted");
        assert_eq!(row.kind, EntryKind::Dir);
        assert_eq!(row.plain_len, 0);
        assert_eq!(row.chunk_count, 0);
        assert_ne!(row.object_id, vfs::PENDING_OBJECT_ID);

        let s2 = open_session(&d, vid, MountMode::ReadOnly, 7);
        assert_eq!(s2.stat("scratch").unwrap().kind, NodeKind::Dir);
        let kids = s2.readdir("").unwrap();
        assert_eq!(kids.len(), 1, "reopen lists the directory exactly once");
        assert_eq!(kids[0].path, "scratch");
        assert_eq!(kids[0].kind, NodeKind::Dir);
    }

    // ---- G0c: read-only refuses writes; no ISK in errors -----------------

    #[test]
    fn read_only_session_rejects_every_write_and_still_reads() {
        let (d, vid) = fixture();
        {
            let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
            s.create("a.md", 0o644, 1).unwrap();
            s.write("a.md", 0, b"hello").unwrap();
            s.unmount(2).unwrap();
        }
        let mut ro = open_session(&d, vid, MountMode::ReadOnly, 3);
        assert!(ro.is_read_only());
        assert_eq!(ro.mode(), MountMode::ReadOnly);
        assert!(ro.mode().is_read_only());
        assert_eq!(ro.read_all("a.md").unwrap(), b"hello");
        assert_eq!(ro.read("a.md", 0, 5).unwrap(), b"hello");

        let r = ro.create("new.md", 0o644, 4);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = ro.mkdir("newdir", 0o755, 4);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = ro.write("a.md", 0, b"no");
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = ro.truncate("a.md", 1);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = ro.rename("a.md", "b.md", 5);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");
        let r = ro.unlink("a.md", 5);
        assert!(matches!(&r, Err(Error::Format(_))), "got {r:?}");

        assert!(!ro.is_dirty(), "a refused write must not dirty the session");
        assert_eq!(ro.read_all("a.md").unwrap(), b"hello", "the file is intact");
        assert_eq!(ro.readdir("").unwrap().len(), 1);
        assert!(!ro.sync_if_due(999_999).unwrap(), "nothing dirty to sync");
        ro.unmount(6).unwrap();
    }

    #[test]
    fn read_only_unmount_does_not_rewrite_the_manifest() {
        let (d, vid) = fixture();
        {
            let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
            s.create("a.md", 0o644, 1).unwrap();
            s.write("a.md", 0, b"hello").unwrap();
            s.unmount(2).unwrap();
        }
        let mpath = corevault::manifest_path(&d.path().join("v.geode"), Epoch(1));
        let before = std::fs::read(&mpath).unwrap();
        let mut ro = open_session(&d, vid, MountMode::ReadOnly, 9_000);
        assert_eq!(ro.read_all("a.md").unwrap(), b"hello");
        ro.unmount(99_000).unwrap();
        assert_eq!(
            std::fs::read(&mpath).unwrap(),
            before,
            "a read-only unmount must not touch the manifest"
        );
    }

    #[test]
    fn session_errors_never_contain_key_material() {
        let (d, vid) = fixture();
        {
            let mut s = open_session(&d, vid, MountMode::ReadWrite, 0);
            s.mkdir("d", 0o755, 1).unwrap();
            s.unmount(2).unwrap();
        }
        let mut ro = open_session(&d, vid, MountMode::ReadOnly, 3);
        let mut msgs = Vec::new();
        let r = ro.write("d", 0, b"x");
        msgs.push(format!("{}", r.unwrap_err()));
        let r = ro.read("d", 0, 1);
        msgs.push(format!("{}", r.unwrap_err()));
        let r = ro.read("missing", 0, 1);
        msgs.push(format!("{}", r.unwrap_err()));
        let r = ro.rename("missing", "x", 4);
        msgs.push(format!("{}", r.unwrap_err()));
        let r = ro.unlink("missing", 4);
        msgs.push(format!("{}", r.unwrap_err()));

        let ek_hex = corevault::hex_encode(ek().as_bytes());
        for s in &msgs {
            assert!(!s.contains("ISK"), "leaks ISK: {s}");
            assert!(!s.contains('\u{7}'), "leaks key bytes: {s}");
            assert!(!s.contains(&ek_hex), "leaks EK hex: {s}");
        }
    }
}
