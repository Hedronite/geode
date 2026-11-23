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

use base64ct::{Base64, Encoding as _};
use clap::Args;
use geode_grotto::manifest::Manifest;
use geode_grotto::object::HEADER_SIZE;
use geode_grotto::snapshot::{validate_snapshot_name, SnapshotEnvelope};
use geode_grotto::vault::GEODE_SENTINEL;
use geode_grotto::{Error, Result, MAGIC_GDE1, MAGIC_GKEY, MAGIC_GPO2, MAGIC_GPOL, SUITE_0X01};
use geode_redact::scan::{Finding, Fingerprint, Rule, ScanKey, Scanner, Thresholds};
use serde_json::Value;

use crate::{cmd, GlobalArgs, OutMode};

/// `--hook` exit status when anything is found.
const EXIT_FINDINGS: i32 = 2;
/// Default allowlist, relative to the working directory.
const DEFAULT_ALLOW: &str = ".geode/scan-allow";
/// Bound for reading vault metadata during root detection.
const MAX_META_BYTES: u64 = 1024 * 1024;
/// Sealed policy headers: magic + suite + (32-byte nonce + 16-byte tag) or
/// the legacy 16-byte nonce + tag.
const GPO2_HEADER_LEN: usize = 53;
const GPOL_HEADER_LEN: usize = 21;

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
    let mut vault_roots: BTreeSet<PathBuf> = BTreeSet::new();
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
            if is_vault_root(path) {
                vault_roots.insert(path.canonicalize().unwrap_or_else(|_| path.to_path_buf()));
            }
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
        let shown = path.display().to_string();
        let canon = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
        let rel = vault_root_for(&canon, &canon_root, &vault_roots)
            .and_then(|vault| canon.strip_prefix(vault).ok());
        let object_candidate = rel.is_some_and(|r| matches!(vault_path(r), VaultPath::Object));
        // A valid object is ciphertext: peek at its header so a legitimate
        // object over --max-bytes does not fail the scan. The GKEY check
        // still runs on the first bytes before any exemption.
        if object_candidate {
            let len = fs::metadata(path)
                .map_err(|e| Error::Format(format!("cannot read {}: {e}", path.display())))?
                .len();
            let prefix = read_prefix(path, HEADER_SIZE)?;
            *files += 1;
            if protected.contains(&canon) || prefix.starts_with(MAGIC_GKEY) {
                hits.push(Hit {
                    path: shown,
                    finding: scanner.whole_file(Rule::GeodeKeyFile, &prefix),
                });
                continue;
            }
            if len >= HEADER_SIZE as u64 && valid_gobj_header(&prefix) {
                continue;
            }
        }
        let data = read_capped(path, max_bytes)?;
        if !object_candidate {
            *files += 1;
        }
        // Key material fails closed before any vault exemption: a GKEY file
        // renamed to `header.json` inside a vault is still a finding.
        if protected.contains(&canon) || has_gkey_extension(path) || data.starts_with(MAGIC_GKEY) {
            hits.push(Hit {
                path: shown,
                finding: scanner.whole_file(Rule::GeodeKeyFile, &data),
            });
            continue;
        }
        if let Some(rel) = rel {
            match vault_verdict(rel, &data) {
                VaultVerdict::Exempt => continue,
                VaultVerdict::ExemptLabel(label) => {
                    hits.extend(scanner.scan(&label).into_iter().map(|finding| Hit {
                        path: shown.clone(),
                        finding,
                    }));
                    continue;
                }
                VaultVerdict::Scan => {}
            }
        }
        hits.extend(scanner.scan(&data).into_iter().map(|finding| Hit {
            path: shown.clone(),
            finding,
        }));
    }
    Ok(())
}

fn has_gkey_extension(path: &Path) -> bool {
    path.extension()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|ext| ext.eq_ignore_ascii_case("gkey"))
}

fn read_prefix(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let file = fs::File::open(path)
        .map_err(|e| Error::Format(format!("cannot read {}: {e}", path.display())))?;
    let mut data = Vec::new();
    file.take(limit as u64)
        .read_to_end(&mut data)
        .map_err(|e| Error::Format(format!("cannot read {}: {e}", path.display())))?;
    Ok(data)
}

fn read_vault_meta(path: &Path) -> Option<Vec<u8>> {
    let len = fs::metadata(path).ok()?.len();
    if len > MAX_META_BYTES {
        return None;
    }
    fs::read(path).ok()
}

fn is_hex_id(s: &str) -> bool {
    s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn valid_geode_marker(data: &[u8]) -> bool {
    data == GEODE_SENTINEL.as_bytes()
}

/// Strict `header.json`: only the documented keys, expected value types, no
/// trailing bytes. Returns the optional `label` bytes so they are scanned.
fn valid_header(data: &[u8]) -> Option<Vec<u8>> {
    const KEYS: [&str; 10] = [
        "version",
        "suite",
        "flags",
        "vault_id",
        "epoch",
        "chunk_size_default",
        "creator_key_id",
        "created_unix_ms",
        "header_mac",
        "label",
    ];
    let value: Value = serde_json::from_slice(data).ok()?;
    let obj = value.as_object()?;
    if obj.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return None;
    }
    let num = |k: &str| obj.get(k).and_then(Value::as_u64);
    let str_field = |k: &str| obj.get(k).and_then(Value::as_str);
    if num("version") != Some(1)
        || num("suite") != Some(u64::from(SUITE_0X01))
        || num("flags").is_none()
        || !str_field("vault_id").is_some_and(is_hex_id)
        || num("epoch").is_none_or(|e| e > u64::from(u32::MAX))
        || num("chunk_size_default").is_none()
        || !str_field("creator_key_id").is_some_and(is_hex_id)
        || num("created_unix_ms").is_none()
        || !str_field("header_mac").is_some_and(is_hex_id)
    {
        return None;
    }
    match obj.get("label") {
        None => Some(Vec::new()),
        Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
        Some(_) => None,
    }
}

/// Strict `recipients.json`: exact keys, a syntactically valid recipient
/// list with at least one entry, and decodable wraps.
fn valid_recipients(data: &[u8]) -> bool {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        return false;
    };
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != 3
        || obj
            .keys()
            .any(|k| !matches!(k.as_str(), "vault_id" | "epoch" | "recipients"))
        || !obj
            .get("vault_id")
            .and_then(Value::as_str)
            .is_some_and(is_hex_id)
        || obj
            .get("epoch")
            .and_then(Value::as_u64)
            .is_none_or(|e| e > u64::from(u32::MAX))
    {
        return false;
    }
    let Some(recipients) = obj.get("recipients").and_then(Value::as_array) else {
        return false;
    };
    if recipients.is_empty() {
        return false;
    }
    recipients.iter().all(|r| {
        let Some(r) = r.as_object() else {
            return false;
        };
        let Some(kind) = r.get("type").and_then(Value::as_str) else {
            return false;
        };
        let keys: &[&str] = match kind {
            "symmetric" => &["type", "key_id", "wrap"],
            "x25519" => &["type", "key_id", "public", "wrap"],
            "hybrid" => &["type", "key_id", "x25519_public", "mlkem_public", "wrap"],
            _ => return false,
        };
        if r.len() != keys.len() || r.keys().any(|k| !keys.contains(&k.as_str())) {
            return false;
        }
        let Some(key_id) = r.get("key_id").and_then(Value::as_array) else {
            return false;
        };
        if key_id.len() != 16
            || key_id
                .iter()
                .any(|b| b.as_u64().is_none_or(|b| b > u64::from(u8::MAX)))
        {
            return false;
        }
        let decode = |k: &str, min: usize| {
            r.get(k)
                .and_then(Value::as_str)
                .and_then(|s| Base64::decode_vec(s).ok())
                .is_some_and(|b| b.len() >= min)
        };
        if !decode("wrap", 48) {
            return false;
        }
        match kind {
            "x25519" => decode("public", 32),
            "hybrid" => decode("x25519_public", 32) && decode("mlkem_public", 32),
            _ => true,
        }
    })
}

/// Strict manifest envelope: exact top-level and entry keys, a MAC field,
/// and a body that deserializes as the typed `Manifest`.
fn valid_manifest(value: &Value) -> bool {
    const KEYS: [&str; 12] = [
        "vault_id",
        "epoch",
        "suite",
        "flags",
        "generated_at",
        "generator",
        "root",
        "entry_count",
        "total_plain_bytes",
        "total_cipher_bytes",
        "entries",
        "manifest_mac",
    ];
    const ENTRY_KEYS: [&str; 10] = [
        "path",
        "path_sealed",
        "object_id",
        "kind",
        "plain_len",
        "chunk_count",
        "mode",
        "mtime_ms",
        "content_root",
        "bind",
    ];
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != KEYS.len() || obj.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return false;
    }
    if !obj
        .get("manifest_mac")
        .and_then(Value::as_str)
        .is_some_and(is_hex_id)
    {
        return false;
    }
    let Some(entries) = obj.get("entries").and_then(Value::as_array) else {
        return false;
    };
    for entry in entries {
        let Some(entry) = entry.as_object() else {
            return false;
        };
        if entry.len() != ENTRY_KEYS.len()
            || entry.keys().any(|k| !ENTRY_KEYS.contains(&k.as_str()))
        {
            return false;
        }
    }
    let mut body = value.clone();
    let Some(body) = body.as_object_mut() else {
        return false;
    };
    body.remove("manifest_mac");
    serde_json::from_value::<Manifest>(Value::Object(body.clone())).is_ok()
}

/// Strict snapshot envelope, including its embedded manifest.
fn valid_snapshot(value: &Value, expected_name: &str) -> bool {
    const KEYS: [&str; 6] = [
        "vault_id",
        "epoch",
        "name",
        "created_at",
        "manifest",
        "snapshot_mac",
    ];
    let Some(obj) = value.as_object() else {
        return false;
    };
    if obj.len() != KEYS.len() || obj.keys().any(|k| !KEYS.contains(&k.as_str())) {
        return false;
    }
    if !obj
        .get("vault_id")
        .and_then(Value::as_str)
        .is_some_and(is_hex_id)
        || obj
            .get("epoch")
            .and_then(Value::as_u64)
            .is_none_or(|e| e > u64::from(u32::MAX))
        || obj.get("name").and_then(Value::as_str) != Some(expected_name)
        || obj.get("created_at").and_then(Value::as_i64).is_none()
        || !obj
            .get("snapshot_mac")
            .and_then(Value::as_str)
            .is_some_and(is_hex_id)
        || !obj.get("manifest").is_some_and(valid_manifest)
    {
        return false;
    }
    serde_json::from_value::<SnapshotEnvelope>(value.clone()).is_ok()
}

fn valid_policy(data: &[u8]) -> bool {
    if data.len() < 5 || data[4] != SUITE_0X01 {
        return false;
    }
    match data.get(..4) {
        Some(magic) if magic == MAGIC_GPO2 => data.len() >= GPO2_HEADER_LEN,
        Some(magic) if magic == MAGIC_GPOL => data.len() >= GPOL_HEADER_LEN,
        _ => false,
    }
}

fn valid_gobj_header(prefix: &[u8]) -> bool {
    prefix.len() >= HEADER_SIZE && prefix.starts_with(MAGIC_GDE1) && prefix[4] == SUITE_0X01
}

/// A vault root is a directory whose `GEODE` sentinel is exact and whose
/// `header.json` and non-empty `recipients.json` both validate.
fn is_vault_root(dir: &Path) -> bool {
    let is_file = |name: &str| {
        fs::metadata(dir.join(name))
            .map(|m| m.is_file())
            .unwrap_or(false)
    };
    if !is_file("GEODE") || !is_file("header.json") || !is_file("recipients.json") {
        return false;
    }
    let Some(marker) = read_vault_meta(&dir.join("GEODE")) else {
        return false;
    };
    if !valid_geode_marker(&marker) {
        return false;
    }
    let Some(header) = read_vault_meta(&dir.join("header.json")) else {
        return false;
    };
    let Some(recipients) = read_vault_meta(&dir.join("recipients.json")) else {
        return false;
    };
    valid_header(&header).is_some() && valid_recipients(&recipients)
}

/// The nearest detected vault root containing `file`, bounded by the scan
/// root. A file passed directly as the scan root is never exempted.
fn vault_root_for<'a>(
    file: &Path,
    scan_root: &Path,
    vault_roots: &'a BTreeSet<PathBuf>,
) -> Option<&'a Path> {
    let mut dir = file.parent()?;
    loop {
        if let Some(root) = vault_roots.get(dir) {
            return Some(root.as_path());
        }
        if dir == scan_root {
            return None;
        }
        dir = dir.parent()?;
    }
}

#[derive(Clone, Copy)]
enum VaultPath<'a> {
    Marker,
    Header,
    Recipients,
    Manifest,
    Policy,
    Object,
    Snapshot(&'a str),
    Other,
}

/// Classify the documented layout paths. Anything unknown, or a name that
/// does not satisfy the format, is `Other` and scanned normally.
fn vault_path(rel: &Path) -> VaultPath<'_> {
    use std::ffi::OsStr;
    let parts: Vec<&OsStr> = rel.components().map(|c| c.as_os_str()).collect();
    let name = |i: usize| parts.get(i).and_then(|p| p.to_str());
    match parts.as_slice() {
        [only] => match only.to_str() {
            Some("GEODE") => VaultPath::Marker,
            Some("header.json") => VaultPath::Header,
            Some("manifest.json") => VaultPath::Manifest,
            Some("recipients.json") => VaultPath::Recipients,
            Some("policy.json.sealed") => VaultPath::Policy,
            _ => VaultPath::Other,
        },
        [a, epoch, file] if *a == OsStr::new("epochs") => {
            if !valid_epoch(epoch) {
                return VaultPath::Other;
            }
            match file.to_str() {
                Some("manifest.json") => VaultPath::Manifest,
                Some("recipients.json") => VaultPath::Recipients,
                _ => VaultPath::Other,
            }
        }
        [a, epoch, snapshots, file]
            if *a == OsStr::new("epochs") && *snapshots == OsStr::new("snapshots") =>
        {
            if !valid_epoch(epoch) {
                return VaultPath::Other;
            }
            match name(3).and_then(|n| n.strip_suffix(".json")) {
                Some(stem) if validate_snapshot_name(stem).is_ok() => VaultPath::Snapshot(stem),
                _ => VaultPath::Other,
            }
        }
        [a, epoch, objects, shard, object]
            if *a == OsStr::new("epochs") && *objects == OsStr::new("objects") =>
        {
            if !valid_epoch(epoch)
                || !name(3).is_some_and(is_hex_digits::<2>)
                || !name(4).is_some_and(is_gobj)
            {
                return VaultPath::Other;
            }
            VaultPath::Object
        }
        _ => VaultPath::Other,
    }
}

enum VaultVerdict {
    Exempt,
    ExemptLabel(Vec<u8>),
    Scan,
}

/// Exempt only when the path is documented AND the bytes validate as the
/// corresponding container. A mismatch falls through to a normal scan.
fn vault_verdict(rel: &Path, data: &[u8]) -> VaultVerdict {
    match vault_path(rel) {
        VaultPath::Marker if valid_geode_marker(data) => VaultVerdict::Exempt,
        VaultPath::Header => match valid_header(data) {
            Some(label) if label.is_empty() => VaultVerdict::Exempt,
            Some(label) => VaultVerdict::ExemptLabel(label),
            None => VaultVerdict::Scan,
        },
        VaultPath::Recipients if valid_recipients(data) => VaultVerdict::Exempt,
        VaultPath::Manifest => {
            let ok = serde_json::from_slice::<Value>(data).is_ok_and(|v| valid_manifest(&v));
            if ok {
                VaultVerdict::Exempt
            } else {
                VaultVerdict::Scan
            }
        }
        VaultPath::Policy if valid_policy(data) => VaultVerdict::Exempt,
        VaultPath::Object if data.len() >= HEADER_SIZE && valid_gobj_header(data) => {
            VaultVerdict::Exempt
        }
        VaultPath::Snapshot(expected) => {
            let ok =
                serde_json::from_slice::<Value>(data).is_ok_and(|v| valid_snapshot(&v, expected));
            if ok {
                VaultVerdict::Exempt
            } else {
                VaultVerdict::Scan
            }
        }
        _ => VaultVerdict::Scan,
    }
}

fn valid_epoch(epoch: &std::ffi::OsStr) -> bool {
    epoch
        .to_str()
        .is_some_and(|s| s.len() == 8 && s.bytes().all(|b| b.is_ascii_digit()))
}

fn is_gobj(file: &str) -> bool {
    file.strip_suffix(".gobj")
        .is_some_and(|stem| stem.len() == 32 && stem.bytes().all(is_lower_hex))
}

fn is_hex_digits<const N: usize>(s: &str) -> bool {
    s.len() == N && s.bytes().all(is_lower_hex)
}

fn is_lower_hex(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
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
