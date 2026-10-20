//! `geode scan` — find secret-looking values in files before they are
//! captured or committed.
//!
//! Output names the path, line, column, rule and a keyed fingerprint. It
//! never prints the matched bytes, an excerpt, or context, and nothing is
//! written to the audit log. Fingerprints are keyed by a key derived from
//! `--key` (or `GEODE_KEY_FILE`) when one is given, otherwise by a per-user
//! random key at `~/.config/hedronite/geode/scan.key`, so an allowlist made
//! under one key does not match under another.
//!
//! Fail closed: an unreadable file, a file over `--max-bytes`, a symlink
//! that resolves outside its scan root, or a special file is an error
//! (exit 1), never a skip. Binary files are scanned. A Geode key file
//! inside a scan root is always a finding and cannot be allowlisted.

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use clap::Args;
use geode_grotto::{Error, Result};
use geode_redact::scan::{Finding, Fingerprint, Rule, ScanKey, Scanner, Thresholds};

use crate::{cmd, GlobalArgs, OutMode};

/// `--hook` exit status when anything is found.
const EXIT_FINDINGS: i32 = 2;
/// Default allowlist, relative to the working directory.
const DEFAULT_ALLOW: &str = ".geode/scan-allow";

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Files or directories to scan.
    #[arg(value_name = "PATH", required = true)]
    pub paths: Vec<PathBuf>,
    /// Print one JSON document.
    #[arg(long)]
    pub json: bool,
    /// Exit 2 on any finding, 0 when clean, and 1 on any error.
    #[arg(long)]
    pub hook: bool,
    /// Fingerprints to suppress, one per line. Default `.geode/scan-allow` when it exists.
    #[arg(long, value_name = "FILE")]
    pub allow: Option<PathBuf>,
    /// Largest file to scan, in bytes. A larger file is an error.
    #[arg(long, value_name = "N", default_value_t = 16 * 1024 * 1024)]
    pub max_bytes: u64,
    /// Minimum entropy, in bits per character, for a base64-like run.
    #[arg(long, value_name = "BITS", default_value_t = 4.0)]
    pub base64_bits: f64,
    /// Minimum entropy, in bits per character, for a hex run.
    #[arg(long, value_name = "BITS", default_value_t = 3.0)]
    pub hex_bits: f64,
}

struct Hit {
    path: String,
    finding: Finding,
}

pub fn run(args: &ScanArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let key = match &global.key {
        Some(path) => ScanKey::from_isk(cmd::load_isk(path)?.as_bytes()),
        None => load_or_create_scan_key(&scan_key_path()?)?,
    };
    let scanner = Scanner::new(key).with_thresholds(Thresholds {
        base64_bits: args.base64_bits,
        hex_bits: args.hex_bits,
        ..Thresholds::default()
    });
    let allow = load_allow(args.allow.as_deref())?;
    let protected = protected_paths(global);

    let mut hits: Vec<Hit> = Vec::new();
    let mut files = 0u64;
    for root in &args.paths {
        scan_root(
            root,
            args.max_bytes,
            &scanner,
            &protected,
            &mut hits,
            &mut files,
        )?;
    }

    let before = hits.len();
    hits.retain(|h| {
        h.finding.rule == Rule::GeodeKeyFile || !allow.contains(&h.finding.fingerprint)
    });
    let suppressed = before - hits.len();

    if args.json || matches!(out, OutMode::Json) {
        let findings: Vec<serde_json::Value> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "path": h.path,
                    "line": h.finding.line,
                    "col": h.finding.col,
                    "rule": h.finding.rule.id(),
                    "fingerprint": h.finding.fingerprint.to_string(),
                })
            })
            .collect();
        let doc = serde_json::json!({
            "version": 1,
            "clean": hits.is_empty(),
            "suppressed": suppressed,
            "findings": findings,
        });
        println!("{doc}");
    } else {
        for h in &hits {
            println!(
                "{}:{}:{}: {} {}",
                h.path,
                h.finding.line,
                h.finding.col,
                h.finding.rule.id(),
                h.finding.fingerprint
            );
        }
        println!("{} finding(s) in {files} file(s)", hits.len());
        println!("{suppressed} suppressed by allowlist");
    }
    let _ = std::io::stdout().flush();

    if args.hook && !hits.is_empty() {
        std::process::exit(EXIT_FINDINGS);
    }
    Ok(())
}

/// Walk one root. Symlinks are never followed; one that resolves outside
/// the root is an error.
fn scan_root(
    root: &Path,
    max_bytes: u64,
    scanner: &Scanner,
    protected: &BTreeSet<PathBuf>,
    hits: &mut Vec<Hit>,
    files: &mut u64,
) -> Result<()> {
    let canon_root = root
        .canonicalize()
        .map_err(|e| Error::Format(format!("cannot open {}: {e}", root.display())))?;
    for entry in walkdir::WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
    {
        let entry = entry.map_err(|e| {
            let path = e
                .path()
                .map_or_else(|| root.display().to_string(), |p| p.display().to_string());
            Error::Format(format!("cannot read {path}: {e}"))
        })?;
        let path = entry.path();
        let ft = entry.file_type();
        if ft.is_dir() {
            continue;
        }
        if ft.is_symlink() {
            let target = path.canonicalize().map_err(|e| {
                Error::Format(format!("cannot resolve symlink {}: {e}", path.display()))
            })?;
            if !target.starts_with(&canon_root) {
                return Err(Error::Format(format!(
                    "symlink {} resolves outside the scan root",
                    path.display()
                )));
            }
            // The target is inside the root and is scanned as itself.
            continue;
        }
        if !ft.is_file() {
            return Err(Error::Format(format!(
                "{} is not a regular file",
                path.display()
            )));
        }
        let data = read_capped(path, max_bytes)?;
        *files += 1;
        let shown = path.display().to_string();
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        if protected.contains(&canon) || path.file_name().is_some_and(|n| n == "default.gkey") {
            hits.push(Hit {
                path: shown,
                finding: scanner.whole_file(Rule::GeodeKeyFile, &data),
            });
            continue;
        }
        hits.extend(scanner.scan(&data).into_iter().map(|finding| Hit {
            path: shown.clone(),
            finding,
        }));
    }
    Ok(())
}

fn read_capped(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let too_big = || {
        Error::Format(format!(
            "{} is larger than --max-bytes {max_bytes}",
            path.display()
        ))
    };
    let unreadable =
        |e: std::io::Error| Error::Format(format!("cannot read {}: {e}", path.display()));
    let file = fs::File::open(path).map_err(unreadable)?;
    if file.metadata().map_err(unreadable)?.len() > max_bytes {
        return Err(too_big());
    }
    let mut data = Vec::new();
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut data)
        .map_err(unreadable)?;
    if data.len() as u64 > max_bytes {
        return Err(too_big());
    }
    Ok(data)
}

/// Fingerprints from the allowlist. Anything but a fingerprint, a comment
/// or a blank line is an error; the line itself is never echoed.
fn load_allow(explicit: Option<&Path>) -> Result<BTreeSet<Fingerprint>> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => {
            let p = PathBuf::from(DEFAULT_ALLOW);
            if !p.exists() {
                return Ok(BTreeSet::new());
            }
            p
        }
    };
    let text = fs::read_to_string(&path)
        .map_err(|e| Error::Format(format!("cannot read allowlist {}: {e}", path.display())))?;
    let mut set = BTreeSet::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fp = line.parse::<Fingerprint>().map_err(|_| {
            Error::Format(format!(
                "allowlist {} line {}: not a fingerprint (32 lowercase hex characters)",
                path.display(),
                i + 1
            ))
        })?;
        set.insert(fp);
    }
    Ok(set)
}

/// Key files that are always findings: the scan key, the default identity
/// key, and any `--key` in use.
fn protected_paths(global: &GlobalArgs) -> BTreeSet<PathBuf> {
    [
        scan_key_path().ok(),
        cmd::default_key_path(),
        global.key.clone(),
    ]
    .into_iter()
    .flatten()
    .filter_map(|p| p.canonicalize().ok())
    .collect()
}

/// `$XDG_CONFIG_HOME/hedronite/geode/scan.key`, else
/// `~/.config/hedronite/geode/scan.key`.
fn scan_key_path() -> Result<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(xdg).join("hedronite/geode/scan.key"));
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config/hedronite/geode/scan.key"))
        .ok_or_else(|| {
            Error::Format("cannot place scan.key: neither XDG_CONFIG_HOME nor HOME is set".into())
        })
}

/// Read the per-user scan key, creating it (32 random bytes, mode 0600,
/// `create_new`) on first use.
fn load_or_create_scan_key(path: &Path) -> Result<ScanKey> {
    match read_scan_key(path) {
        Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {}
        other => return other,
    }
    if let Some(dir) = path.parent() {
        create_private_dir(dir)
            .map_err(|e| Error::Format(format!("cannot create {}: {e}", dir.display())))?;
    }
    let mut bytes = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|e| Error::Format(format!("random: {e}")))?;
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(path) {
        Ok(mut f) => {
            f.write_all(bytes.as_ref())
                .and_then(|()| f.sync_all())
                .map_err(|e| Error::Format(format!("cannot write {}: {e}", path.display())))?;
            Ok(ScanKey::from_bytes(*bytes))
        }
        // Another scan created it first.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => read_scan_key(path),
        Err(e) => Err(Error::Format(format!(
            "cannot create {}: {e}",
            path.display()
        ))),
    }
}

fn read_scan_key(path: &Path) -> Result<ScanKey> {
    let data = match fs::read(path) {
        Ok(d) => zeroize::Zeroizing::new(d),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Error::Io(e)),
        Err(e) => {
            return Err(Error::Format(format!(
                "cannot read {}: {e}",
                path.display()
            )))
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|e| Error::Format(format!("cannot read {}: {e}", path.display())))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(Error::Format(format!(
                "{} must be mode 0600",
                path.display()
            )));
        }
    }
    let bytes: [u8; 32] = data
        .as_slice()
        .try_into()
        .map_err(|_| Error::Format(format!("{} is not a 32-byte scan key", path.display())))?;
    Ok(ScanKey::from_bytes(bytes))
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut b = fs::DirBuilder::new();
    b.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        b.mode(0o700);
    }
    b.create(dir)
}
