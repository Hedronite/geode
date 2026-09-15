//! CLI verb modules (G3) — thin adapters over `geode-core`.
//!
//! Shared helpers: raw-form `GKEY` load (02-cryptography 6.1), vault context
//! load (`header.json` + `recipients.json` + `manifest.json`, MAC-checked),
//! event emission matching `schemas/event.schema.json`, and the exit-code
//! mapping (05-cli 3: 2 = auth/integrity, 1 = usage/IO).

#![allow(clippy::module_name_repetitions)]

pub mod key;
pub mod list;
pub mod open;
pub mod seal;
pub mod vault;
pub mod verify;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use geode_core::kdf::{self, Epoch, EpochKey, IdentitySecret, KeyId, VaultId};
use geode_core::manifest::{self, Manifest};
use geode_core::recipients::{self, Recipient, Recipients};
use geode_core::{Error, Result};
use zeroize::Zeroize;

use crate::output::exit;
use crate::OutMode;

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Decode fixed-length lowercase hex.
pub fn unhex(s: &str, out: &mut [u8]) -> Result<()> {
    let s = s.as_bytes();
    if s.len() != out.len() * 2 {
        return Err(Error::Format("bad hex length".into()));
    }
    for (i, pair) in s.chunks(2).enumerate() {
        let hi = (pair[0] as char)
            .to_digit(16)
            .ok_or_else(|| Error::Format("bad hex".into()))?;
        let lo = (pair[1] as char)
            .to_digit(16)
            .ok_or_else(|| Error::Format("bad hex".into()))?;
        #[allow(clippy::cast_possible_truncation)]
        {
            out[i] = ((hi << 4) | lo) as u8;
        }
    }
    Ok(())
}

const GKEY_VERSION: u8 = 1;
const GKEY_KIND_RAW: u8 = 0x00;
const GKEY_KIND_WRAP: u8 = 0x01;

/// Load an identity key file (02-cryptography 6).
///
/// v0.1.0 reads the raw form (6.1). The passphrase-wrapped form (6.2) is
/// unreachable from the CLI until `geode-core` exposes a keyfile API —
/// `Secret32` construction is crate-private by design (G3 handoff note).
pub fn load_isk(path: &Path) -> Result<IdentitySecret> {
    refuse_world_readable(path)?;
    let raw = std::fs::read(path).map_err(Error::Io)?;
    if raw.len() < 6 {
        return Err(Error::Format("key file too short".into()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&raw[0..4]);
    geode_core::assert_magic(&magic, geode_core::MAGIC_GKEY)?;
    if raw[4] != GKEY_VERSION {
        return Err(Error::Format(format!("unsupported GKEY version {}", raw[4])));
    }
    match raw[5] {
        GKEY_KIND_RAW => {
            if raw.len() != 6 + 32 + 16 {
                return Err(Error::Format("raw GKEY wrong length".into()));
            }
            let mut isk = [0u8; 32];
            isk.copy_from_slice(&raw[6..38]);
            let sum = blake3::hash(&isk);
            if raw[38..54] != sum.as_bytes()[..16] {
                return Err(Error::AuthFail);
            }
            let id = IdentitySecret::from_bytes(isk);
            isk.zeroize();
            Ok(id)
        }
        GKEY_KIND_WRAP => Err(Error::Format(
            "passphrase-wrapped GKEY: unwrap needs a geode-core keyfile API (tracked)".into(),
        )),
        other => Err(Error::Format(format!("unknown GKEY kind 0x{other:02x}"))),
    }
}

/// 02-cryptography 6.1: refuse a group/world-readable key file.
#[cfg(unix)]
fn refuse_world_readable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path).map_err(Error::Io)?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(Error::Format(format!(
            "key file {} is group/world-readable; chmod 600 first",
            path.display()
        )));
    }
    Ok(())
}

/// Non-unix builds cannot check permission bits; accept (documented gap).
#[cfg(not(unix))]
fn refuse_world_readable(_path: &Path) -> Result<()> {
    Ok(())
}

/// Default identity path: `$XDG_CONFIG_HOME/hedronite/geode/default.gkey`,
/// falling back to `~/.config/hedronite/geode/default.gkey` (05-cli 2.1).
#[must_use]
pub fn default_key_path() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        if !xdg.is_empty() {
            return Some(PathBuf::from(xdg).join("hedronite/geode/default.gkey"));
        }
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".config/hedronite/geode/default.gkey"))
}

/// `--key` is required for every verb except `keygen`. Resolution order:
/// `--key PATH`, then `GEODE_KEY_FILE` (clap `env`), then the XDG default
/// **when the file exists** (G0a hygiene, v0.2.0). Otherwise a usage error.
pub fn require_key(global: &crate::GlobalArgs) -> Result<PathBuf> {
    if let Some(p) = &global.key {
        return Ok(p.clone());
    }
    if let Some(default) = default_key_path() {
        if default.is_file() {
            return Ok(default);
        }
    }
    Err(Error::Format(
        "missing --key PATH (or GEODE_KEY_FILE, or ~/.config/hedronite/geode/default.gkey)"
            .into(),
    ))
}

/// Path of the manifest for an epoch (03-format 2).
#[must_use]
pub fn manifest_path(root: &Path, epoch: Epoch) -> PathBuf {
    root.join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("manifest.json")
}

/// An opened vault: recipient-checked, MAC-checked, EK in hand.
pub struct VaultCtx {
    pub root: PathBuf,
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub key_id: KeyId,
    pub ek: EpochKey,
    pub manifest: Manifest,
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    serde_json::from_str(&text).map_err(|e| Error::Format(format!("{}: {e}", path.display())))
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Format(format!("missing string field {field}")))
}

fn json_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::Format(format!("missing integer field {field}")))
}

/// Verify `mac_field` (hex) over the JCS-canonicalized JSON minus that field.
fn verify_json_mac(
    manifest_key: &[u8; 32],
    value: &serde_json::Value,
    mac_field: &str,
) -> Result<()> {
    let mac_hex = json_str(value, mac_field).map_err(|_| Error::AuthFail)?;
    let mut want = [0u8; 16];
    unhex(mac_hex, &mut want).map_err(|_| Error::AuthFail)?;
    let mut body = value.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove(mac_field);
    }
    let canon = manifest::canonicalize(&body)?;
    let got = manifest::manifest_mac(manifest_key, &canon)?;
    // TODO(G5): constant-time compare (matches geode-core's own G5 note).
    if got != want {
        return Err(Error::AuthFail);
    }
    Ok(())
}

/// Load a vault: sentinel, `header.json`, `recipients.json`, manifest — all
/// authenticated. Failure to authenticate is `Error::AuthFail` (exit 2).
pub fn load_vault(root: &Path, isk: &IdentitySecret) -> Result<VaultCtx> {
    let sentinel = std::fs::read(root.join("GEODE")).map_err(Error::Io)?;
    if !sentinel.starts_with(b"GDE1 vault") {
        return Err(Error::Format(format!(
            "{} is not a geode vault",
            root.display()
        )));
    }
    let header = read_json(&root.join("header.json"))?;
    let mut vid = [0u8; 16];
    unhex(json_str(&header, "vault_id")?, &mut vid)?;
    let vault_id = VaultId(vid);
    let epoch = Epoch(
        u32::try_from(json_u64(&header, "epoch")?)
            .map_err(|_| Error::Format("epoch overflow".into()))?,
    );
    let key_id = kdf::derive_key_id(isk)?;

    let rec_text = std::fs::read_to_string(root.join("recipients.json")).map_err(Error::Io)?;
    let recs: Recipients = serde_json::from_str(&rec_text)
        .map_err(|e| Error::Format(format!("recipients.json: {e}")))?;
    let mut ek = None;
    for r in &recs.recipients {
        if let Recipient::Symmetric { key_id: kid, .. } = r {
            if *kid == key_id {
                ek = Some(recipients::unwrap_symmetric(r, isk, vault_id, epoch)?);
                break;
            }
        }
    }
    // Not a recipient of this vault: same family as a bad key.
    let ek = ek.ok_or(Error::AuthFail)?;

    let mk = kdf::derive_manifest_key(&ek, vault_id, epoch);
    verify_json_mac(&mk, &header, "header_mac")?;
    let mjson = read_json(&manifest_path(root, epoch))?;
    verify_json_mac(&mk, &mjson, "manifest_mac")?;
    let mut body = mjson;
    if let Some(o) = body.as_object_mut() {
        o.remove("manifest_mac");
    }
    let manifest: Manifest =
        serde_json::from_value(body).map_err(|e| Error::Format(format!("manifest.json: {e}")))?;
    Ok(VaultCtx {
        root: root.to_path_buf(),
        vault_id,
        epoch,
        key_id,
        ek,
        manifest,
    })
}

/// Write `header.json` with a MAC under the manifest key (03-format 3).
pub fn write_header(
    root: &Path,
    fields: serde_json::Value,
    manifest_key: &[u8; 32],
) -> Result<()> {
    let canon = manifest::canonicalize(&fields)?;
    let mac = manifest::manifest_mac(manifest_key, &canon)?;
    let mut v = fields;
    if let Some(o) = v.as_object_mut() {
        o.insert("header_mac".into(), serde_json::Value::String(hex(&mac)));
    }
    let text = serde_json::to_string_pretty(&v)
        .map_err(|e| Error::Format(format!("header serialize: {e}")))?;
    geode_core::vault::write_atomic(&root.join("header.json"), text.as_bytes())
}

/// Write the manifest atomically with a fresh `manifest_mac` (03-format 5).
pub fn write_manifest(ctx: &VaultCtx) -> Result<()> {
    let mk = kdf::derive_manifest_key(&ctx.ek, ctx.vault_id, ctx.epoch);
    let mut value = serde_json::to_value(&ctx.manifest)
        .map_err(|e| Error::Format(format!("manifest serialize: {e}")))?;
    let canon = manifest::canonicalize(&value)?;
    let mac = manifest::manifest_mac(&mk, &canon)?;
    if let Some(o) = value.as_object_mut() {
        o.insert("manifest_mac".into(), serde_json::Value::String(hex(&mac)));
    }
    let text = serde_json::to_string_pretty(&value)
        .map_err(|e| Error::Format(format!("manifest serialize: {e}")))?;
    geode_core::vault::write_atomic(&manifest_path(&ctx.root, ctx.epoch), text.as_bytes())
}

/// Emit a success event (05-cli 4; `schemas/event.schema.json`).
#[allow(clippy::needless_pass_by_value)]
pub fn emit(out: OutMode, verb: &str, extra: serde_json::Value, text: &str) {
    match out {
        OutMode::Json => {
            let mut doc =
                serde_json::json!({"ok": true, "verb": verb, "schema": "geode.event.v1"});
            if let (Some(d), Some(x)) = (doc.as_object_mut(), extra.as_object()) {
                for (k, v) in x {
                    d.insert(k.clone(), v.clone());
                }
            }
            println!("{}", serde_json::to_string(&doc).expect("json encode"));
        }
        OutMode::Text => {
            if !text.is_empty() {
                println!("{text}");
            }
        }
    }
}

/// Emit an error event and exit with the mapped code (05-cli 3).
pub fn fail(out: OutMode, verb: &str, err: &Error) -> ! {
    let (code, code_exit) = map_error(err);
    match out {
        OutMode::Json => {
            println!(
                "{}",
                serde_json::json!({
                    "ok": false,
                    "verb": verb,
                    "schema": "geode.event.v1",
                    "error": {"code": code, "message": err.to_string()},
                })
            );
        }
        OutMode::Text => eprintln!("{}", crate::output::human_error(verb, err)),
    }
    std::process::exit(code_exit);
}

/// 05-cli 3: 2 = authentication/integrity, 1 = usage/IO/config. Scripts MUST
/// be able to distinguish 2 from 1.
fn map_error(err: &Error) -> (&'static str, i32) {
    match err {
        Error::AuthFail => ("auth_fail", exit::AUTH),
        Error::Io(e) if e.kind() == std::io::ErrorKind::NotFound => ("not_found", exit::USAGE),
        Error::Io(_) => ("io", exit::USAGE),
        Error::Format(m) if m.contains("unknown cipher suite") => {
            ("unsupported_suite", exit::AUTH)
        }
        Error::Format(m) if m.contains("unknown magic") => ("auth_fail", exit::AUTH),
        Error::Format(_) | Error::Crypto(_) | Error::NotImplemented => ("usage", exit::USAGE),
        Error::PolicyDeny => ("policy_deny", exit::POLICY),
        Error::TokenInvalid => ("token_invalid", exit::TOKEN),
    }
}
