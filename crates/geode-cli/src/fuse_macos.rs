//! macOS FUSE session (08-mount 2; SPEC-v031 G0).
//!
//! FUSE-T or macFUSE, via `fuser`, behind feature `fuse`. This file is
//! compiled on Darwin without that feature so a missing driver still exits 1.
//! `fuser` is not linked unless the feature is on, and it stays out of
//! `geode-grotto`. Linux unmount stays in `fuse_linux` and is not reimplemented here.
//!
//! When a driver is loaded, the session calls `MountSession`. Otherwise
//! `geode mount` returns an error that names FUSE-T or macFUSE. Darwin
//! unmount is `umount`.

use std::path::Path;

use geode_grotto::{Error, Result};

/// Bundles, device nodes, and mount helpers. A path that exists means that
/// driver is installed. Citadel has none of these; do not install one.
const DRIVER_MARKERS: &[&str] = &[
    "/Library/Filesystems/macfuse.fs",
    "/Library/Filesystems/osxfuse.fs",
    "/Library/Filesystems/fuse-t.fs",
    "/dev/fuse",
    "/dev/macfuse",
    "/usr/local/bin/mount_macfuse",
    "/usr/local/bin/mount_fuse-t",
    "/opt/homebrew/bin/mount_macfuse",
    "/opt/homebrew/bin/mount_fuse-t",
];

fn driver_loaded() -> bool {
    DRIVER_MARKERS.iter().any(|path| Path::new(path).exists())
}

fn accepted_mode(read_only: bool) -> &'static str {
    if read_only {
        "accepted read-only"
    } else {
        "accepted read-write"
    }
}

/// Foreground mount, or a named refusal when FUSE-T and macFUSE are absent.
pub(super) fn mount_foreground(
    vault: &Path,
    mountpoint: &Path,
    read_only: bool,
    key: &Path,
) -> Result<()> {
    if !driver_loaded() {
        return Err(Error::Format(format!(
            "mount needs FUSE-T or macFUSE; neither driver is loaded; {}",
            accepted_mode(read_only)
        )));
    }
    #[cfg(feature = "fuse")]
    {
        session::mount_foreground(vault, mountpoint, read_only, key)
    }
    #[cfg(not(feature = "fuse"))]
    {
        let _ = (vault, mountpoint, key);
        Err(Error::Format(format!(
            "FUSE-T or macFUSE is loaded but this build has no feature fuse; {}",
            accepted_mode(read_only)
        )))
    }
}

/// `geode unmount` on Darwin calls `umount`.
pub(super) fn unmount_mountpoint(mountpoint: &Path) -> Result<()> {
    let out = std::process::Command::new("umount")
        .arg(mountpoint)
        .output()
        .map_err(Error::Io)?;
    if out.status.success() {
        return Ok(());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    Err(Error::Format(format!(
        "umount {} failed: {err}",
        mountpoint.display()
    )))
}

#[cfg(feature = "fuse")]
mod session {
    use std::collections::BTreeMap;
    use std::ffi::OsStr;
    use std::path::Path;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use fuser::{
        FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyCreate, ReplyData,
        ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyOpen, ReplyWrite, Request,
    };
    use geode_grotto::mount_session::{MountMode, MountSession};
    use geode_grotto::vfs::NodeKind;
    use geode_grotto::{Error, Result};

    use super::super::super::{load_isk, load_vault};

    const ROOT_INO: u64 = 1;
    const TTL: Duration = Duration::ZERO;
    const BLKSIZE: u32 = 4096;

    const ENOENT: i32 = 2;
    const EIO: i32 = 5;
    const EEXIST: i32 = 17;
    const ENOTDIR: i32 = 20;
    const EISDIR: i32 = 21;
    const EINVAL: i32 = 22;
    const EROFS: i32 = 30;
    const ENOTEMPTY: i32 = 39;

    const O_ACCMODE: i32 = 3;
    const O_WRONLY: i32 = 1;
    const O_RDWR: i32 = 2;

    struct Node {
        path: String,
        parent: u64,
        kind: NodeKind,
        perm: u16,
        size: u64,
        mtime_ms: i64,
    }

    struct NodeSpec {
        path: String,
        parent: u64,
        kind: NodeKind,
        perm: u16,
        size: u64,
        mtime_ms: i64,
    }

    struct Inodes {
        by_ino: BTreeMap<u64, Node>,
        by_path: BTreeMap<String, u64>,
        next: u64,
    }

    impl Inodes {
        fn new() -> Self {
            let mut by_ino = BTreeMap::new();
            let mut by_path = BTreeMap::new();
            by_ino.insert(
                ROOT_INO,
                Node {
                    path: String::new(),
                    parent: ROOT_INO,
                    kind: NodeKind::Dir,
                    perm: 0o755,
                    size: 0,
                    mtime_ms: 0,
                },
            );
            by_path.insert(String::new(), ROOT_INO);
            Self {
                by_ino,
                by_path,
                next: ROOT_INO + 1,
            }
        }

        fn path(&self, ino: u64) -> Option<String> {
            self.by_ino.get(&ino).map(|n| n.path.clone())
        }

        fn intern(&mut self, spec: NodeSpec) -> u64 {
            if let Some(&ino) = self.by_path.get(&spec.path) {
                return ino;
            }
            let ino = self.next;
            self.next = self.next.saturating_add(1);
            self.by_path.insert(spec.path.clone(), ino);
            self.by_ino.insert(
                ino,
                Node {
                    path: spec.path,
                    parent: spec.parent,
                    kind: spec.kind,
                    perm: spec.perm,
                    size: spec.size,
                    mtime_ms: spec.mtime_ms,
                },
            );
            ino
        }

        fn set_size(&mut self, ino: u64, size: u64) {
            if let Some(n) = self.by_ino.get_mut(&ino) {
                n.size = size;
            }
        }

        fn set_perm(&mut self, ino: u64, perm: u16) {
            if let Some(n) = self.by_ino.get_mut(&ino) {
                n.perm = perm;
            }
        }

        fn retarget(&mut self, from: &str, to: &str) {
            let keys: Vec<String> = self
                .by_path
                .keys()
                .filter(|k| k.as_str() == from || k.starts_with(&format!("{from}/")))
                .cloned()
                .collect();
            for k in keys {
                let Some(ino) = self.by_path.remove(&k) else {
                    continue;
                };
                let nk = if k == from {
                    to.to_owned()
                } else {
                    format!("{to}{}", &k[from.len()..])
                };
                if let Some(n) = self.by_ino.get_mut(&ino) {
                    n.path.clone_from(&nk);
                }
                self.by_path.insert(nk, ino);
            }
        }

        fn forget_path(&mut self, path: &str) {
            let keys: Vec<String> = self
                .by_path
                .keys()
                .filter(|k| k.as_str() == path || k.starts_with(&format!("{path}/")))
                .cloned()
                .collect();
            for k in keys {
                if let Some(ino) = self.by_path.remove(&k) {
                    self.by_ino.remove(&ino);
                }
            }
        }
    }

    struct GeodeFs {
        session: MountSession,
        inodes: Inodes,
        persisted: bool,
    }

    fn now_ms() -> i64 {
        i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis()),
        )
        .unwrap_or(i64::MAX)
    }

    fn stamp(ms: i64) -> SystemTime {
        match u64::try_from(ms) {
            Ok(v) => UNIX_EPOCH + Duration::from_millis(v),
            Err(_) => UNIX_EPOCH,
        }
    }

    fn fuse_errno(err: &Error) -> i32 {
        // `Error::Io(NotFound)` is how the VFS reports a missing path, and that
        // `io::Error` has no raw errno. Match the text so lookup of a new name is
        // ENOENT (the kernel will not CREATE on EIO).
        let msg = err.to_string();
        if msg.contains("read-only") {
            return EROFS;
        }
        if msg.contains("not found") {
            return ENOENT;
        }
        if msg.contains("is a directory") {
            return EISDIR;
        }
        if msg.contains("non-empty") {
            return ENOTEMPTY;
        }
        if msg.contains("exists") {
            return EEXIST;
        }
        match err {
            Error::Io(io) => io.raw_os_error().unwrap_or(EIO),
            _ => EIO,
        }
    }

    fn join_path(parent: &str, name: &str) -> String {
        if parent.is_empty() {
            name.to_owned()
        } else {
            format!("{parent}/{name}")
        }
    }

    fn file_type(kind: NodeKind) -> FileType {
        match kind {
            NodeKind::Dir => FileType::Directory,
            NodeKind::File => FileType::RegularFile,
            NodeKind::Symlink => FileType::Symlink,
        }
    }

    fn default_perm(kind: NodeKind) -> u16 {
        match kind {
            NodeKind::Dir => 0o755,
            NodeKind::File | NodeKind::Symlink => 0o644,
        }
    }

    fn mode_perm(mode: u32, umask: u32, kind: NodeKind) -> u16 {
        let bits = mode & !umask & 0o7777;
        u16::try_from(bits).unwrap_or(default_perm(kind))
    }

    fn open_for_write(flags: i32) -> bool {
        matches!(flags & O_ACCMODE, O_WRONLY | O_RDWR)
    }

    fn chunk_size_of(root: &Path) -> Result<u32> {
        let text = std::fs::read_to_string(root.join("header.json")).map_err(Error::Io)?;
        let value: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| Error::Format(format!("header.json: {e}")))?;
        let n = value
            .get("chunk_size_default")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Error::Format("header.json missing chunk_size_default".into()))?;
        u32::try_from(n).map_err(|_| Error::Format("chunk_size_default overflow".into()))
    }

    impl GeodeFs {
        fn open(vault: &Path, key: &Path, read_only: bool) -> Result<Self> {
            let isk = load_isk(key)?;
            let ctx = load_vault(vault, &isk)?;
            drop(isk);
            let chunk_size = chunk_size_of(vault)?;
            let mode = if read_only {
                MountMode::ReadOnly
            } else {
                MountMode::ReadWrite
            };
            let session = MountSession::open(
                &ctx.ek,
                &ctx.root,
                ctx.vault_id,
                ctx.epoch,
                chunk_size,
                mode,
                now_ms(),
            )?;
            Ok(Self {
                session,
                inodes: Inodes::new(),
                persisted: false,
            })
        }

        fn persist(&mut self) {
            if self.persisted {
                return;
            }
            self.persisted = true;
            if let Err(e) = self.session.unmount(now_ms()) {
                eprintln!("geode mount: persist on unmount failed: {e}");
            }
        }

        fn attr(&self, ino: u64, req: &Request<'_>) -> Option<FileAttr> {
            let node = self.inodes.by_ino.get(&ino)?;
            let ts = stamp(node.mtime_ms);
            let size = match node.kind {
                NodeKind::Dir => 0,
                NodeKind::File | NodeKind::Symlink => node.size,
            };
            let nlink = match node.kind {
                NodeKind::Dir => 2,
                NodeKind::File | NodeKind::Symlink => 1,
            };
            Some(FileAttr {
                ino,
                size,
                blocks: size.div_ceil(512),
                atime: ts,
                mtime: ts,
                ctime: ts,
                crtime: ts,
                kind: file_type(node.kind),
                perm: node.perm,
                nlink,
                uid: req.uid(),
                gid: req.gid(),
                rdev: 0,
                blksize: BLKSIZE,
                flags: 0,
            })
        }

        fn ensure(&mut self, path: &str, parent: u64) -> std::result::Result<u64, i32> {
            if path.is_empty() {
                return Ok(ROOT_INO);
            }
            if let Some(&ino) = self.inodes.by_path.get(path) {
                return Ok(ino);
            }
            let node = self.session.stat(path).map_err(|e| fuse_errno(&e))?;
            let perm = default_perm(node.kind);
            let size = match node.kind {
                NodeKind::Dir => 0,
                NodeKind::File | NodeKind::Symlink => node.plain_len,
            };
            Ok(self.inodes.intern(NodeSpec {
                path: node.path,
                parent,
                kind: node.kind,
                perm,
                size,
                mtime_ms: node.mtime_ms,
            }))
        }

        fn child(&self, parent: u64, name: &OsStr) -> std::result::Result<String, i32> {
            let name = name.to_str().ok_or(EINVAL)?;
            if name.is_empty() || name.contains('/') || name.contains('\0') {
                return Err(EINVAL);
            }
            let parent_path = self.inodes.path(parent).ok_or(ENOENT)?;
            if parent != ROOT_INO {
                let kind = self
                    .inodes
                    .by_ino
                    .get(&parent)
                    .map(|n| n.kind)
                    .ok_or(ENOENT)?;
                if kind != NodeKind::Dir {
                    return Err(ENOTDIR);
                }
            }
            if name == "." {
                return Ok(parent_path);
            }
            if name == ".." {
                let up = self
                    .inodes
                    .by_ino
                    .get(&parent)
                    .map(|n| n.parent)
                    .ok_or(ENOENT)?;
                return self.inodes.path(up).ok_or(ENOENT);
            }
            Ok(join_path(&parent_path, name))
        }

        fn refuse_write(&self) -> Option<i32> {
            self.session.is_read_only().then_some(EROFS)
        }
    }

    impl Drop for GeodeFs {
        fn drop(&mut self) {
            self.persist();
        }
    }

    impl Filesystem for GeodeFs {
        fn destroy(&mut self) {
            self.persist();
        }

        fn lookup(&mut self, req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
            let path = match self.child(parent, name) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let ino = match self.ensure(&path, parent) {
                Ok(ino) => ino,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            match self.attr(ino, req) {
                Some(attr) => reply.entry(&TTL, &attr, 0),
                None => reply.error(ENOENT),
            }
        }

        fn getattr(&mut self, req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
            match self.attr(ino, req) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(ENOENT),
            }
        }

        fn setattr(
            &mut self,
            req: &Request<'_>,
            ino: u64,
            mode: Option<u32>,
            _uid: Option<u32>,
            _gid: Option<u32>,
            size: Option<u64>,
            _atime: Option<fuser::TimeOrNow>,
            _mtime: Option<fuser::TimeOrNow>,
            _ctime: Option<SystemTime>,
            _fh: Option<u64>,
            _crtime: Option<SystemTime>,
            _chgtime: Option<SystemTime>,
            _bkuptime: Option<SystemTime>,
            _flags: Option<u32>,
            reply: ReplyAttr,
        ) {
            let Some(path) = self.inodes.path(ino) else {
                reply.error(ENOENT);
                return;
            };
            if size.is_some() || mode.is_some() {
                if let Some(err) = self.refuse_write() {
                    reply.error(err);
                    return;
                }
            }
            if let Some(len) = size {
                if let Err(e) = self.session.truncate(&path, len) {
                    reply.error(fuse_errno(&e));
                    return;
                }
                self.inodes.set_size(ino, len);
            }
            if let Some(mode) = mode {
                self.inodes
                    .set_perm(ino, mode_perm(mode, 0, NodeKind::File));
            }
            match self.attr(ino, req) {
                Some(attr) => reply.attr(&TTL, &attr),
                None => reply.error(ENOENT),
            }
        }

        fn mkdir(
            &mut self,
            req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            mode: u32,
            umask: u32,
            reply: ReplyEntry,
        ) {
            self.make_dir(req, parent, name, mode, umask, reply);
        }

        fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            self.remove(parent, name, false, reply);
        }

        fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
            self.remove(parent, name, true, reply);
        }

        fn rename(
            &mut self,
            _req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            newparent: u64,
            newname: &OsStr,
            flags: u32,
            reply: ReplyEmpty,
        ) {
            if flags != 0 {
                reply.error(EINVAL);
                return;
            }
            if let Some(err) = self.refuse_write() {
                reply.error(err);
                return;
            }
            let from = match self.child(parent, name) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let to = match self.child(newparent, newname) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            if let Err(e) = self.session.rename(&from, &to, now_ms()) {
                reply.error(fuse_errno(&e));
                return;
            }
            self.inodes.retarget(&from, &to);
            reply.ok();
        }

        fn open(&mut self, _req: &Request<'_>, ino: u64, flags: i32, reply: ReplyOpen) {
            if self.inodes.path(ino).is_none() {
                reply.error(ENOENT);
                return;
            }
            if open_for_write(flags) {
                if let Some(err) = self.refuse_write() {
                    reply.error(err);
                    return;
                }
            }
            reply.opened(ino, 0);
        }

        fn read(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            size: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyData,
        ) {
            let Some(path) = self.inodes.path(ino) else {
                reply.error(ENOENT);
                return;
            };
            let Ok(off) = u64::try_from(offset) else {
                reply.error(EINVAL);
                return;
            };
            match self.session.read(&path, off, u64::from(size)) {
                Ok(buf) => reply.data(&buf),
                Err(e) => reply.error(fuse_errno(&e)),
            }
        }

        fn write(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            data: &[u8],
            _write_flags: u32,
            _flags: i32,
            _lock_owner: Option<u64>,
            reply: ReplyWrite,
        ) {
            if let Some(err) = self.refuse_write() {
                reply.error(err);
                return;
            }
            let Some(path) = self.inodes.path(ino) else {
                reply.error(ENOENT);
                return;
            };
            let Ok(off) = u64::try_from(offset) else {
                reply.error(EINVAL);
                return;
            };
            if let Err(e) = self.session.write(&path, off, data) {
                eprintln!("geode mount: write {path}: {e}");
                reply.error(fuse_errno(&e));
                return;
            }
            let end = off.saturating_add(u64::try_from(data.len()).unwrap_or(0));
            let cur = self.inodes.by_ino.get(&ino).map_or(0, |n| n.size);
            if end > cur {
                self.inodes.set_size(ino, end);
            }
            let n = u32::try_from(data.len()).unwrap_or(u32::MAX);
            reply.written(n);
        }

        fn flush(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            _lock_owner: u64,
            reply: ReplyEmpty,
        ) {
            self.sync_ino(ino, reply);
        }

        fn release(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            _flags: i32,
            _lock_owner: Option<u64>,
            _flush: bool,
            reply: ReplyEmpty,
        ) {
            self.sync_ino(ino, reply);
        }

        fn fsync(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            _datasync: bool,
            reply: ReplyEmpty,
        ) {
            self.sync_ino(ino, reply);
        }

        fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
            match self.inodes.by_ino.get(&ino).map(|n| n.kind) {
                Some(NodeKind::Dir) => reply.opened(ino, 0),
                Some(_) => reply.error(ENOTDIR),
                None => reply.error(ENOENT),
            }
        }

        fn readdir(
            &mut self,
            _req: &Request<'_>,
            ino: u64,
            _fh: u64,
            offset: i64,
            mut reply: ReplyDirectory,
        ) {
            let Some(path) = self.inodes.path(ino) else {
                reply.error(ENOENT);
                return;
            };
            let parent = self.inodes.by_ino.get(&ino).map_or(ROOT_INO, |n| n.parent);
            let children = match self.session.readdir(&path) {
                Ok(rows) => rows,
                Err(e) => {
                    reply.error(fuse_errno(&e));
                    return;
                }
            };
            let mut entries: Vec<(u64, FileType, String)> = Vec::new();
            entries.push((ino, FileType::Directory, ".".to_owned()));
            entries.push((parent, FileType::Directory, "..".to_owned()));
            for row in children {
                let name = row
                    .path
                    .rsplit_once('/')
                    .map_or(row.path.clone(), |(_, leaf)| leaf.to_owned());
                let child = match self.ensure(&row.path, ino) {
                    Ok(child) => child,
                    Err(err) => {
                        reply.error(err);
                        return;
                    }
                };
                entries.push((child, file_type(row.kind), name));
            }
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            for (i, (child, kind, name)) in entries.into_iter().enumerate().skip(start) {
                let next = i64::try_from(i.saturating_add(1)).unwrap_or(i64::MAX);
                if reply.add(child, next, kind, name) {
                    break;
                }
            }
            reply.ok();
        }

        fn releasedir(
            &mut self,
            _req: &Request<'_>,
            _ino: u64,
            _fh: u64,
            _flags: i32,
            reply: ReplyEmpty,
        ) {
            reply.ok();
        }

        fn create(
            &mut self,
            req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            mode: u32,
            umask: u32,
            _flags: i32,
            reply: ReplyCreate,
        ) {
            if let Some(err) = self.refuse_write() {
                reply.error(err);
                return;
            }
            let path = match self.child(parent, name) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let perm = mode_perm(mode, umask, NodeKind::File);
            if let Err(e) = self.session.create(&path, u32::from(perm), now_ms()) {
                eprintln!("geode mount: create {path}: {e}");
                reply.error(fuse_errno(&e));
                return;
            }
            let ino = self.inodes.intern(NodeSpec {
                path,
                parent,
                kind: NodeKind::File,
                perm,
                size: 0,
                mtime_ms: now_ms(),
            });
            match self.attr(ino, req) {
                Some(attr) => reply.created(&TTL, &attr, 0, ino, 0),
                None => reply.error(EIO),
            }
        }
    }

    impl GeodeFs {
        #[allow(clippy::too_many_arguments)] // fuser callback signature
        fn make_dir(
            &mut self,
            req: &Request<'_>,
            parent: u64,
            name: &OsStr,
            mode: u32,
            umask: u32,
            reply: ReplyEntry,
        ) {
            if let Some(err) = self.refuse_write() {
                reply.error(err);
                return;
            }
            let path = match self.child(parent, name) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            let perm = mode_perm(mode, umask, NodeKind::Dir);
            if let Err(e) = self.session.mkdir(&path, u32::from(perm), now_ms()) {
                reply.error(fuse_errno(&e));
                return;
            }
            let ino = self.inodes.intern(NodeSpec {
                path,
                parent,
                kind: NodeKind::Dir,
                perm,
                size: 0,
                mtime_ms: now_ms(),
            });
            match self.attr(ino, req) {
                Some(attr) => reply.entry(&TTL, &attr, 0),
                None => reply.error(EIO),
            }
        }

        fn remove(&mut self, parent: u64, name: &OsStr, dir: bool, reply: ReplyEmpty) {
            if let Some(err) = self.refuse_write() {
                reply.error(err);
                return;
            }
            let path = match self.child(parent, name) {
                Ok(p) => p,
                Err(err) => {
                    reply.error(err);
                    return;
                }
            };
            if dir {
                let kind = self.session.stat(&path).map_or(NodeKind::File, |n| n.kind);
                if kind != NodeKind::Dir {
                    reply.error(ENOTDIR);
                    return;
                }
            }
            if let Err(e) = self.session.unlink(&path, now_ms()) {
                reply.error(fuse_errno(&e));
                return;
            }
            self.inodes.forget_path(&path);
            reply.ok();
        }

        fn sync_ino(&mut self, ino: u64, reply: ReplyEmpty) {
            let Some(path) = self.inodes.path(ino) else {
                reply.error(ENOENT);
                return;
            };
            if path.is_empty() {
                reply.ok();
                return;
            }
            if let Err(e) = self.session.close(&path, now_ms()) {
                eprintln!("geode mount: close {path}: {e}");
                reply.error(fuse_errno(&e));
                return;
            }
            if let Err(e) = self.session.sync_if_due(now_ms()) {
                reply.error(fuse_errno(&e));
                return;
            }
            reply.ok();
        }
    }

    /// Foreground mount. Blocks until `geode unmount` (`umount`).
    pub(super) fn mount_foreground(
        vault: &Path,
        mountpoint: &Path,
        read_only: bool,
        key: &Path,
    ) -> Result<()> {
        if !mountpoint.is_dir() {
            return Err(Error::Format(format!(
                "mountpoint {} is not a directory",
                mountpoint.display()
            )));
        }
        let fs = GeodeFs::open(vault, key, read_only)?;
        let mut options = vec![
            MountOption::FSName("geode".to_owned()),
            MountOption::DefaultPermissions,
            MountOption::NoAtime,
            MountOption::NoDev,
            MountOption::NoSuid,
        ];
        if read_only {
            options.push(MountOption::RO);
        } else {
            options.push(MountOption::RW);
        }
        fuser::mount2(fs, mountpoint, &options).map_err(Error::Io)?;
        Ok(())
    }
}
