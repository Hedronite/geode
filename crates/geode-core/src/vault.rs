//! Vault directory layout and atomic writes (03-format 2, 10).
//!
//! G2: a vault is a directory (GEODE, header.json, recipients.json, epochs/).
//! Writes are temp + fsync + rename. Mutation allocates a new `object_id`.

use crate::kdf::{Epoch, ObjectId, VaultId};
use crate::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

/// One-line GEODE sentinel file contents (03-format 11).
pub const GEODE_SENTINEL: &str = "GDE1 vault\nhttps://hedronite.com\nThis directory is a Geode ciphertext tree. It is useless without a recipient.\n";

const HEX_CHARS: &[u8] = b"0123456789abcdef";

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize] as char);
        s.push(HEX_CHARS[(b & 0xf) as usize] as char);
    }
    s
}

/// Decode a lowercase-hex string into bytes (len must be even, >=0).
pub(crate) fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::Format(format!("odd-length hex: {s}")));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_nibble(b[i])?;
        let lo = hex_nibble(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(c: u8) -> Result<u8> {
    Ok(match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => return Err(Error::Format(format!("bad hex char {c:?}"))),
    })
}

/// Path of the manifest for an epoch (03-format 2).
#[must_use]
pub fn manifest_path(root: &Path, epoch: Epoch) -> PathBuf {
    root.join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("manifest.json")
}

/// Object files are sharded by the first 2 hex chars of `object_id`
/// (03-format 2): `epochs/N/objects/xx/<object_id>.gobj`
fn shard_dir(objects_root: &Path, object_id: &ObjectId) -> PathBuf {
    let hex = hex_encode(&object_id.0);
    objects_root.join(&hex[..2])
}

/// `dest.parent()` is `""` for a bare relative path; treat that as `.` so
/// relative writes keep working and `.` becomes the existing ancestor.
fn dir_or_dot(path: &Path) -> &Path {
    if path.as_os_str().is_empty() {
        Path::new(".")
    } else {
        path
    }
}

/// Atomic write: temp + fsync(file) + rename + fsync directories
/// (03-format 10, revised for G-7).
///
/// The temp file is created in the same directory as `dest`, so the rename is
/// atomic on one filesystem. Order is fixed: write, file `sync_all`, rename,
/// then `sync_all` on the destination directory (and, when the write created
/// new directories such as a shard `objects/xx/`, on every newly created
/// directory's parent, bottom-up). All sync errors propagate. A failed rename
/// removes the temp file and returns the exact rename error.
pub fn write_atomic(dest: &Path, data: &[u8]) -> Result<()> {
    write_atomic_with(
        dest,
        data,
        |file| file.sync_all(),
        |from, to| std::fs::rename(from, to),
        |dir| {
            #[cfg(test)]
            record_dir_sync(dir);
            std::fs::File::open(dir)?.sync_all()
        },
    )
}

/// The ordering seam behind [`write_atomic`]. Production passes the real
/// file-sync, rename, and directory-sync operations; tests inject closures
/// that record the call order and fail individual steps.
fn write_atomic_with(
    dest: &Path,
    data: &[u8],
    sync_file: impl Fn(&std::fs::File) -> std::io::Result<()>,
    rename: impl Fn(&Path, &Path) -> std::io::Result<()>,
    sync_dir: impl Fn(&Path) -> std::io::Result<()>,
) -> Result<()> {
    let parent = dir_or_dot(
        dest.parent()
            .ok_or_else(|| Error::Format("dest has no parent".into()))?,
    );
    // Walk up to the first existing ancestor so a brand-new shard directory
    // tells us every directory whose entry must be persisted. A bare relative
    // destination (`"note.txt"`) has the empty parent, which is `.`.
    let mut missing = Vec::new();
    let mut cursor = parent;
    while !cursor.exists() {
        let up = dir_or_dot(
            cursor
                .parent()
                .ok_or_else(|| Error::Format("dest has no existing ancestor".into()))?,
        );
        missing.push(cursor.to_path_buf());
        cursor = up;
    }
    std::fs::create_dir_all(parent)?;
    let tmp = parent.join(format!(".gde-tmp-{}", hex_encode(&random_bytes(8)?)));
    let written = {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(data)
            .map_err(Error::Io)
            .and_then(|()| sync_file(&f).map_err(Error::Io))
    };
    if let Err(err) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(err);
    }
    if let Err(rename_err) = rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(Error::Io(rename_err));
    }
    // Persist the rename, then every directory entry created above it.
    let mut dirs = Vec::with_capacity(missing.len() + 1);
    dirs.push(parent.to_path_buf());
    for dir in &missing {
        let up = dir_or_dot(dir.parent().unwrap_or_else(|| Path::new("")));
        dirs.push(up.to_path_buf());
    }
    dirs.sort();
    dirs.dedup();
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    for dir in dirs {
        sync_dir(&dir).map_err(Error::Io)?;
    }
    Ok(())
}

fn random_bytes(n: usize) -> Result<Vec<u8>> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(b)
}

/// Allocate a fresh 16-byte `object_id` via the OS CSPRNG (03-format 10).
pub fn new_object_id() -> Result<ObjectId> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(ObjectId(b))
}

/// Allocate a fresh 16-byte `vault_id` (02-cryptography 3).
pub fn new_vault_id() -> Result<VaultId> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    Ok(VaultId(b))
}

/// Initialize a vault directory (03-format 2; 04-vault 1).
///
/// Creates GEODE and epochs/<NNNNNNNN>/objects/. The caller writes
/// header.json, recipients.json, and manifest.json via their own modules.
pub fn init_vault_dir(root: &Path, _vault_id: VaultId, epoch: Epoch) -> Result<()> {
    std::fs::create_dir_all(root)?;
    write_atomic(&root.join("GEODE"), GEODE_SENTINEL.as_bytes())?;
    let epoch_dir = root.join("epochs").join(format!("{:08}", epoch.0));
    std::fs::create_dir_all(epoch_dir.join("objects"))?;
    Ok(())
}

/// Path for an object file inside a vault epoch (03-format 2).
///
/// Pure: it never creates the shard directory. Writers reach
/// [`write_atomic`], which creates and syncs every missing directory on the
/// path; reads must not have a directory side effect.
pub fn object_path(vault_root: &Path, epoch: Epoch, object_id: &ObjectId) -> Result<PathBuf> {
    let objects = vault_root
        .join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("objects");
    Ok(shard_dir(&objects, object_id).join(format!("{}.gobj", hex_encode(&object_id.0))))
}

/// Write a sealed object (header bytes + chunk bytes) atomically to the
/// vault. A new `object_id` is allocated by the caller before sealing; this
/// function never overwrites in place (03-format 10).
pub fn write_object(
    vault_root: &Path,
    epoch: Epoch,
    object_id: &ObjectId,
    header_bytes: &[u8],
    chunk_bytes: &[u8],
) -> Result<PathBuf> {
    let p = object_path(vault_root, epoch, object_id)?;
    let mut buf = Vec::with_capacity(header_bytes.len() + chunk_bytes.len());
    buf.extend_from_slice(header_bytes);
    buf.extend_from_slice(chunk_bytes);
    write_atomic(&p, &buf)?;
    Ok(p)
}

/// Read an object file bytes (header + chunks) from the vault.
pub fn read_object(vault_root: &Path, epoch: Epoch, object_id: &ObjectId) -> Result<Vec<u8>> {
    let p = object_path(vault_root, epoch, object_id)?;
    Ok(std::fs::read(&p)?)
}

#[cfg(test)]
thread_local! {
    /// Directory paths whose fsync the current test thread observed.
    static DIR_SYNCS: std::cell::RefCell<Vec<PathBuf>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[cfg(test)]
fn record_dir_sync(dir: &Path) {
    DIR_SYNCS.with(|log| log.borrow_mut().push(dir.to_path_buf()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn init_creates_layout() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        assert!(root.join("GEODE").exists());
        assert!(root
            .join("epochs")
            .join("00000001")
            .join("objects")
            .exists());
        let sentinel = std::fs::read_to_string(root.join("GEODE")).unwrap();
        assert!(sentinel.starts_with("GDE1 vault"));
    }

    #[test]
    fn write_then_read_object() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        let oid = new_object_id().unwrap();
        let hdr =
            b"GDE1placeholderheaderbytespaddingto108bytes!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        let chunks = b"tag+ciphertext";
        let p = write_object(&root, Epoch(1), &oid, hdr, chunks).unwrap();
        assert!(p.exists());
        let read = read_object(&root, Epoch(1), &oid).unwrap();
        assert_eq!(&read[..hdr.len()], hdr);
        assert_eq!(&read[hdr.len()..], chunks);
    }

    #[test]
    fn write_object_syncs_new_shard_and_objects_dir() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        let objects = root.join("epochs").join("00000001").join("objects");
        let oid = ObjectId([0xab; 16]);
        let shard = objects.join("ab");
        assert!(!shard.exists(), "fixture: shard must start missing");
        DIR_SYNCS.with(|log| log.borrow_mut().clear());

        let path = write_object(&root, Epoch(1), &oid, b"header", b"chunks").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"headerchunks");
        assert!(shard.is_dir(), "write_object must create the shard");

        let synced = DIR_SYNCS.with(|log| log.borrow().clone());
        assert!(
            synced.iter().any(|dir| dir == &shard),
            "shard dir was not synced: {synced:?}"
        );
        assert!(
            synced.iter().any(|dir| dir == &objects),
            "objects/ parent was not synced for a new shard: {synced:?}"
        );
    }

    #[test]
    fn object_path_is_pure_and_missing_read_creates_nothing() {
        let d = tempdir().unwrap();
        let root = d.path().join("v.geode");
        init_vault_dir(&root, VaultId([1; 16]), Epoch(1)).unwrap();
        let oid = ObjectId([0xcd; 16]);
        let objects = root.join("epochs").join("00000001").join("objects");
        let shard = objects.join("cd");
        assert!(!shard.exists());

        let path = object_path(&root, Epoch(1), &oid).unwrap();
        assert_eq!(path, shard.join("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd.gobj"));
        assert!(!shard.exists(), "object_path must not create the shard");
        assert!(!path.exists());

        assert!(matches!(
            read_object(&root, Epoch(1), &oid),
            Err(Error::Io(_))
        ));
        assert!(
            !shard.exists(),
            "a failed read must not leave an empty shard directory"
        );

        // Nor a whole epoch directory.
        let _ = object_path(&root, Epoch(2), &oid).unwrap();
        assert!(!root.join("epochs").join("00000002").exists());
    }

    #[test]
    fn atomic_write_replaces_existing() {
        let d = tempdir().unwrap();
        let dest = d.path().join("f.txt");
        write_atomic(&dest, b"v1").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"v1");
        write_atomic(&dest, b"v2").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"v2");
    }

    use std::cell::RefCell;
    use std::io;

    fn dir_name(path: &Path) -> String {
        path.file_name().unwrap().to_string_lossy().into_owned()
    }

    fn no_temp_files(dir: &Path) -> bool {
        std::fs::read_dir(dir).unwrap().all(|e| {
            !e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".gde-tmp-")
        })
    }

    #[test]
    fn write_atomic_orders_file_rename_parent_sync() {
        let d = tempdir().unwrap();
        let dest = d.path().join("f.txt");
        let log = RefCell::new(Vec::<String>::new());
        write_atomic_with(
            &dest,
            b"ordered",
            |_| {
                log.borrow_mut().push("file_sync".into());
                Ok(())
            },
            |tmp, dst| {
                log.borrow_mut().push("rename".into());
                std::fs::rename(tmp, dst)
            },
            |dir| {
                log.borrow_mut().push(format!("dir_sync:{}", dir_name(dir)));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *log.borrow(),
            vec![
                "file_sync".to_owned(),
                "rename".to_owned(),
                format!("dir_sync:{}", dir_name(d.path())),
            ]
        );
        assert_eq!(std::fs::read(&dest).unwrap(), b"ordered");
    }

    #[test]
    fn write_atomic_syncs_new_shard_parent_after_rename() {
        let d = tempdir().unwrap();
        let objects = d.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let dest = objects.join("ab").join("x.gobj");
        let log = RefCell::new(Vec::<String>::new());
        write_atomic_with(
            &dest,
            b"shard",
            |_| {
                log.borrow_mut().push("file_sync".into());
                Ok(())
            },
            |tmp, dst| {
                log.borrow_mut().push("rename".into());
                std::fs::rename(tmp, dst)
            },
            |dir| {
                log.borrow_mut().push(format!("dir_sync:{}", dir_name(dir)));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(
            *log.borrow(),
            vec![
                "file_sync".to_owned(),
                "rename".to_owned(),
                "dir_sync:ab".to_owned(),
                "dir_sync:objects".to_owned(),
            ],
            "new shard dir must sync itself and its parent, after the rename"
        );
    }

    #[test]
    fn write_atomic_rename_error_is_returned_and_temp_removed() {
        let d = tempdir().unwrap();
        let dest = d.path().join("f.txt");
        let log = RefCell::new(Vec::<String>::new());
        let err = write_atomic_with(
            &dest,
            b"x",
            |_| Ok(()),
            |_, _| {
                log.borrow_mut().push("rename".into());
                Err(io::Error::other("rename-injected"))
            },
            |_| {
                log.borrow_mut().push("dir_sync".into());
                Ok(())
            },
        )
        .unwrap_err();
        match err {
            Error::Io(e) => assert_eq!(e.to_string(), "rename-injected"),
            other => panic!("want the injected io error, got {other:?}"),
        }
        assert_eq!(*log.borrow(), vec!["rename".to_owned()]);
        assert!(!dest.exists());
        assert!(no_temp_files(d.path()));
    }

    #[test]
    fn write_atomic_sync_errors_propagate() {
        let d = tempdir().unwrap();
        let dest = d.path().join("f.txt");
        let err = write_atomic_with(
            &dest,
            b"x",
            |_| Err(io::Error::other("file-sync")),
            |tmp, dst| std::fs::rename(tmp, dst),
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.to_string() == "file-sync"));
        assert!(no_temp_files(d.path()));
        assert!(!dest.exists());

        let err = write_atomic_with(
            &dest,
            b"x",
            |_| Ok(()),
            |tmp, dst| std::fs::rename(tmp, dst),
            |_| Err(io::Error::other("dir-sync")),
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.to_string() == "dir-sync"));
        // The rename completed before the failing directory sync.
        assert_eq!(std::fs::read(&dest).unwrap(), b"x");
    }

    #[test]
    fn write_atomic_grandparent_sync_error_propagates() {
        let d = tempdir().unwrap();
        let objects = d.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let dest = objects.join("cd").join("x.gobj");
        let err = write_atomic_with(
            &dest,
            b"x",
            |_| Ok(()),
            |tmp, dst| std::fs::rename(tmp, dst),
            |dir| {
                if dir_name(dir) == "objects" {
                    Err(io::Error::other("grand-sync"))
                } else {
                    Ok(())
                }
            },
        )
        .unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.to_string() == "grand-sync"));
        assert_eq!(std::fs::read(&dest).unwrap(), b"x");
    }

    /// Relative destinations keep working: the empty parent is `.`. Runs in a
    /// child process with its own cwd so no other parallel test sees a cwd
    /// change.
    #[test]
    fn relative_paths_sync_dot_ancestor() {
        if std::env::var_os("GEODE_RELATIVE_PATH_CHILD").is_some() {
            relative_paths_child();
            return;
        }
        let d = tempdir().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "vault::tests::relative_paths_sync_dot_ancestor",
                "--test-threads=1",
            ])
            .env("GEODE_RELATIVE_PATH_CHILD", "1")
            .current_dir(d.path())
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "relative-path child failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("1 passed"),
            "child did not run exactly this test: {}",
            String::from_utf8_lossy(&out.stdout)
        );
    }

    fn relative_paths_child() {
        // Production path: bare, one new directory, and a nested chain.
        for dest in ["bare.txt", "newtop/x.bin", "newtop3/a/b.bin"] {
            write_atomic(Path::new(dest), b"relative").unwrap();
            assert_eq!(std::fs::read(dest).unwrap(), b"relative");
        }

        fn seam_dirs(dest: &str) -> Vec<String> {
            let log = RefCell::new(Vec::<String>::new());
            write_atomic_with(
                Path::new(dest),
                b"seam",
                |_| Ok(()),
                |tmp, dst| std::fs::rename(tmp, dst),
                |dir| {
                    log.borrow_mut().push(dir.to_string_lossy().into_owned());
                    Ok(())
                },
            )
            .unwrap();
            log.into_inner()
        }

        assert_eq!(seam_dirs("seam-bare.txt"), vec![".".to_owned()]);
        let one = seam_dirs("seam-newtop/x.bin");
        for want in [".", "seam-newtop"] {
            assert!(
                one.iter().any(|dir| dir == want),
                "sync dirs {one:?} missing {want}"
            );
        }
        let nested = seam_dirs("seam-newtop3/a/b.bin");
        for want in [".", "seam-newtop3", "seam-newtop3/a"] {
            assert!(
                nested.iter().any(|dir| dir == want),
                "sync dirs {nested:?} missing {want}"
            );
        }
    }

    #[test]
    fn write_atomic_new_shard_roundtrip_leaves_no_temp() {
        let d = tempdir().unwrap();
        let objects = d.path().join("objects");
        std::fs::create_dir(&objects).unwrap();
        let dest = objects.join("ef").join("deep").join("note.bin");
        write_atomic(&dest, b"roundtrip").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"roundtrip");
        assert!(no_temp_files(&objects.join("ef").join("deep")));
        assert!(no_temp_files(&objects.join("ef")));
        assert!(no_temp_files(&objects));
    }

    #[test]
    fn new_ids_are_unique() {
        let a = new_object_id().unwrap();
        let b = new_object_id().unwrap();
        assert_ne!(a.0, b.0);
    }
}
