//! Key file path resolution and permission hygiene (02-cryptography 6.1; 03-format 8).
//!
//! G0b (v0.2.0): default key path + refuse group/world-readable key files.
//! The package rename to `geode-grotto` is G1, not here.

use crate::{Error, Result};
use std::path::{Path, PathBuf};

/// Default identity key path:
/// `$XDG_CONFIG_HOME/hedronite/geode/default.gkey`, or
/// `~/.config/hedronite/geode/default.gkey` when `XDG_CONFIG_HOME` is
/// unset, empty, or relative (02-cryptography 6.1; 03-format 8).
///
/// Returns `None` when neither `XDG_CONFIG_HOME` nor `HOME` is set; the
/// caller decides what to do (typically error out).
#[must_use]
pub fn default_key_path() -> Option<PathBuf> {
    let config = xdg_config_home()?;
    Some(config.join("hedronite").join("geode").join("default.gkey"))
}

/// Resolve the XDG config home directory.
///
/// Honors `XDG_CONFIG_HOME` only when it is absolute and non-empty; otherwise
/// falls back to `$HOME/.config`. Returns `None` when `HOME` is also unset.
fn xdg_config_home() -> Option<PathBuf> {
    if let Some(v) = std::env::var_os("XDG_CONFIG_HOME") {
        let p = PathBuf::from(&v);
        if !p.as_os_str().is_empty() && p.is_absolute() {
            return Some(p);
        }
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".config"))
}

/// Refuse a key file that is group- or world-readable (02-cryptography 6.1).
///
/// On Unix, a key file MUST NOT have group or other read bits set. The spec
/// says permissions MUST be 0600; this check refuses any file whose mode has
/// `0o044` bits set (group-read | other-read). A missing file is not a
/// permission failure -- the IO error surfaces to the caller.
#[cfg(unix)]
pub fn check_key_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).map_err(Error::Io)?;
    let mode = md.mode();
    if mode & 0o044 != 0 {
        return Err(Error::Format(format!(
            "key file {} is group- or world-readable (mode 0o{mode:o}); \
             Geode refuses to load it (02-cryptography 6.1). \
             Run: chmod 0600 {}",
            path.display(),
            path.display(),
        )));
    }
    Ok(())
}

/// Non-Unix platforms have no mode bits to check; the CLI may still warn.
#[cfg(not(unix))]
pub fn check_key_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

/// Read a key file's bytes after checking permissions.
///
/// A group/world-readable file fails before any byte is read into memory.
/// A missing file returns the underlying IO error (the caller
/// distinguishes "not found" from "refused").
pub fn load_key_file_bytes(path: &Path) -> Result<Vec<u8>> {
    check_key_file_permissions(path)?;
    Ok(std::fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_path_uses_xdg_config_home() {
        let d = tempdir().unwrap();
        let dir = d.path().join("xdgcfg");
        std::fs::create_dir_all(&dir).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &dir);
        std::env::remove_var("HOME");
        let p = default_key_path().unwrap();
        assert_eq!(p, dir.join("hedronite").join("geode").join("default.gkey"));
        std::env::remove_var("XDG_CONFIG_HOME");
    }

    #[test]
    fn default_path_falls_back_to_home() {
        std::env::remove_var("XDG_CONFIG_HOME");
        let d = tempdir().unwrap();
        std::env::set_var("HOME", d.path());
        let p = default_key_path().unwrap();
        assert_eq!(
            p,
            d.path()
                .join(".config")
                .join("hedronite")
                .join("geode")
                .join("default.gkey")
        );
        std::env::remove_var("HOME");
    }

    #[test]
    fn default_path_none_without_home_or_xdg() {
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
        assert!(default_key_path().is_none());
    }

    #[test]
    fn default_path_ignores_relative_xdg() {
        std::env::set_var("XDG_CONFIG_HOME", "relative/path");
        let d = tempdir().unwrap();
        std::env::set_var("HOME", d.path());
        let p = default_key_path().unwrap();
        assert_eq!(
            p,
            d.path()
                .join(".config")
                .join("hedronite")
                .join("geode")
                .join("default.gkey")
        );
        std::env::remove_var("XDG_CONFIG_HOME");
        std::env::remove_var("HOME");
    }

    #[cfg(unix)]
    #[test]
    fn check_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"data").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = check_key_file_permissions(&f);
        assert!(
            matches!(r, Err(Error::Format(_))),
            "world-readable key MUST be refused, got {r:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn check_refuses_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"data").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let r = check_key_file_permissions(&f);
        assert!(matches!(r, Err(Error::Format(_))));
    }

    #[cfg(unix)]
    #[test]
    fn check_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"data").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(check_key_file_permissions(&f).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn check_accepts_0400() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"data").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(check_key_file_permissions(&f).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn load_refuses_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"secret").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let r = load_key_file_bytes(&f);
        assert!(matches!(r, Err(Error::Format(_))));
    }

    #[cfg(unix)]
    #[test]
    fn load_reads_0600() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempdir().unwrap();
        let f = d.path().join("k.gkey");
        std::fs::write(&f, b"secret").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        let bytes = load_key_file_bytes(&f).unwrap();
        assert_eq!(bytes, b"secret");
    }
}
