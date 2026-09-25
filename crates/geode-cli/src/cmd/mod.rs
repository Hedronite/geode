//! CLI verb modules (G3) — thin adapters over `geode-core`.
//!
//! Shared helpers: raw-form `GKEY` load (02-cryptography 6.1), vault context
//! load (`header.json` + `recipients.json` + `manifest.json`, MAC-checked),
//! event emission matching `schemas/event.schema.json`, and the exit-code
//! mapping (05-cli 3: 2 = auth/integrity, 1 = usage/IO).

#![allow(clippy::module_name_repetitions)]

pub mod agent;
pub mod git;
pub mod key;
pub mod keyring;
pub mod list;
pub mod mount;
pub mod open;
pub mod policy;
pub mod seal;
pub mod snapshot;
pub mod vault;
pub mod verify;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use geode_grotto::kdf::{self, Epoch, EpochKey, IdentitySecret, KeyId, VaultId};
use geode_grotto::manifest::{self, Manifest};
use geode_grotto::recipients::{self, Recipient, Recipients};
use geode_grotto::{Error, Result};
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

/// Load an identity key file (02-cryptography 6): raw form (6.1) and
/// passphrase-wrapped form (6.2, via the public wrap API from G5a).
/// Permissions are checked before any byte is read (core `keyfile`).
pub fn load_isk(path: &Path) -> Result<IdentitySecret> {
    let raw = geode_grotto::keyfile::load_key_file_bytes(path)?;
    if raw.len() < 6 {
        return Err(Error::Format("key file too short".into()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&raw[0..4]);
    geode_grotto::assert_magic(&magic, geode_grotto::MAGIC_GKEY)?;
    if raw[4] != GKEY_VERSION {
        return Err(Error::Format(format!(
            "unsupported GKEY version {}",
            raw[4]
        )));
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
        GKEY_KIND_WRAP => {
            // 02-cryptography 6.2: salt[16] m u32 t u32 p u32 nonce[32]
            // tag[16] wrapped_isk[32] — 114 bytes total.
            if raw.len() != 6 + 16 + 12 + 32 + 16 + 32 {
                return Err(Error::Format("wrapped GKEY wrong length".into()));
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&raw[6..22]);
            let u32le = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().expect("4"));
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&raw[34..66]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&raw[66..82]);
            let mut wrapped = [0u8; 32];
            wrapped.copy_from_slice(&raw[82..114]);
            let wk = geode_grotto::wrap::WrappedKey {
                salt: geode_grotto::wrap::WrapSalt(salt),
                argon2_m_kib: u32le(22),
                argon2_t: u32le(26),
                argon2_p: u32le(30),
                wrap_nonce: nonce,
                wrap_tag: tag,
                wrapped_isk: wrapped,
            };
            let pass = passphrase()?;
            geode_grotto::wrap::unwrap_identity_passphrase(&wk, pass.as_bytes())
        }
        other => Err(Error::Format(format!("unknown GKEY kind 0x{other:02x}"))),
    }
}

/// Passphrase for wrapped keys: `GEODE_PASSPHRASE` when set (the startup
/// warning already fired in `main`), else the no-echo prompt.
fn passphrase() -> Result<zeroize::Zeroizing<String>> {
    if let Some(p) = std::env::var_os("GEODE_PASSPHRASE") {
        return Ok(zeroize::Zeroizing::new(p.to_string_lossy().into_owned()));
    }
    crate::output::prompt_passphrase("passphrase: ").map_err(Error::Io)
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
    if let Some(index) = geode_grotto::keyring::default_keyring_path() {
        if let Ok(kr) = geode_grotto::keyring::load_keyring(&index) {
            if let Some(path) = kr
                .default
                .as_deref()
                .and_then(|id| kr.find(id))
                .map(|k| PathBuf::from(&k.path))
            {
                return Ok(path);
            }
        }
    }
    if let Some(default) = default_key_path() {
        if default.is_file() {
            return Ok(default);
        }
    }
    Err(Error::Format(
        "missing --key PATH (or GEODE_KEY_FILE, config default_key, or          ~/.config/hedronite/geode/default.gkey)"
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
    if !geode_grotto::zero::ct_eq(&got, &want) {
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
pub fn write_header(root: &Path, fields: serde_json::Value, manifest_key: &[u8; 32]) -> Result<()> {
    let canon = manifest::canonicalize(&fields)?;
    let mac = manifest::manifest_mac(manifest_key, &canon)?;
    let mut v = fields;
    if let Some(o) = v.as_object_mut() {
        o.insert("header_mac".into(), serde_json::Value::String(hex(&mac)));
    }
    let text = serde_json::to_string_pretty(&v)
        .map_err(|e| Error::Format(format!("header serialize: {e}")))?;
    geode_grotto::vault::write_atomic(&root.join("header.json"), text.as_bytes())
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
    geode_grotto::vault::write_atomic(&manifest_path(&ctx.root, ctx.epoch), text.as_bytes())
}

/// Emit a success event (05-cli 4; `schemas/event.schema.json`).
#[allow(clippy::needless_pass_by_value)]
pub fn emit(out: OutMode, verb: &str, extra: serde_json::Value, text: &str) {
    match out {
        OutMode::Json => {
            // agent_token_issue emits hex armor in  (06-agent-plane 2);
            // assert_event_safe rejects GTOK magic in values — guard metadata only.
            let doc = if verb == "agent_token_issue" {
                let token = extra.get("token").cloned();
                let mut meta = extra.clone();
                if let Some(o) = meta.as_object_mut() {
                    o.remove("token");
                }
                let mut doc = geode_grotto::event::build_event(verb, true, meta)
                    .unwrap_or_else(|e| fail(out, verb, &e));
                if let (Some(t), Some(o)) = (token, doc.as_object_mut()) {
                    o.insert("token".into(), t);
                }
                doc
            } else {
                match geode_grotto::event::build_event(verb, true, extra) {
                    Ok(doc) => doc,
                    Err(e) => fail(out, verb, &e),
                }
            };
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
            let doc = geode_grotto::event::build_error_event(verb, code, &err.to_string())
                .unwrap_or_else(|_| serde_json::json!({
                    "ok": false, "verb": verb, "schema": "geode.event.v1",
                    "error": {"code": code, "message": "redacted: event safety check failed"},
                }));
            println!("{doc}");
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
        Error::Format(m) if m.contains("unknown cipher suite") => ("unsupported_suite", exit::AUTH),
        Error::Format(m) if m.contains("unknown magic") => ("auth_fail", exit::AUTH),
        Error::Format(_) | Error::Crypto(_) | Error::NotImplemented => ("usage", exit::USAGE),
        Error::PolicyDeny => ("policy_deny", exit::POLICY),
        Error::TokenInvalid => ("token_invalid", exit::TOKEN),
        Error::Locked => ("locked", exit::LOCKED),
    }
}
