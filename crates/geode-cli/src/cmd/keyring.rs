//! `geode keyring` — named identity keys (05-cli 2.1), a thin CLI over
//! `geode_grotto::keyring` (G1a). The index is `keyring.json`
//! (`schemas/keyring.schema.json`): labels, paths, and key ids only —
//! never secret material. The first added key becomes the keyring `default` when none is
//! set (and we say so when it happens).

use std::path::Path;

use geode_grotto::keyring::{self, KeyringKey};
use geode_grotto::{Error, Result};

use crate::{cmd, KeyringArgs, KeyringCmd, OutMode};

fn index_path() -> Result<std::path::PathBuf> {
    keyring::default_keyring_path()
        .ok_or_else(|| Error::Format("no config dir (XDG_CONFIG_HOME and HOME unset)".into()))
}

/// `true` when the key file at `path` is passphrase-wrapped (kind 0x01).
fn is_wrapped(path: &Path) -> Result<bool> {
    let raw = geode_grotto::keyfile::load_key_file_bytes(path)?;
    if raw.len() < 6 {
        return Err(Error::Format("key file too short".into()));
    }
    Ok(raw[5] == 1)
}

pub fn run(args: &KeyringArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        KeyringCmd::List => list(out),
        KeyringCmd::Add { path, label } => add(path, label, out),
    }
}

fn list(out: OutMode) -> Result<()> {
    let kr = keyring::load_keyring(&index_path()?)?;
    match out {
        OutMode::Json => {
            for k in &kr.keys {
                let is_default = kr.default.as_deref() == Some(k.id.as_str());
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "verb": "keyring",
                        "schema": "geode.event.v1",
                        "label": k.label,
                        "key_id": k.id,
                        "path": k.path,
                        "default": is_default,
                    })
                );
            }
            cmd::emit(
                out,
                "keyring",
                serde_json::json!({"files": kr.keys.len()}),
                "",
            );
        }
        OutMode::Text => {
            if kr.keys.is_empty() {
                println!("(keyring empty — geode keyring add PATH --label NAME)");
            }
            for k in &kr.keys {
                let mark = if kr.default.as_deref() == Some(k.id.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!("{mark} {:<16} {}  {}", k.label, k.id, k.path);
            }
        }
    }
    Ok(())
}

fn add(path: &Path, label: &str, out: OutMode) -> Result<()> {
    check_label(label)?;
    let path = path.canonicalize().map_err(|e| {
        Error::Io(std::io::Error::new(
            e.kind(),
            format!("{}: {e}", path.display()),
        ))
    })?;
    let wrapped = is_wrapped(&path)?;
    // Deriving the key_id proves the file is a loadable GKEY. Wrapped keys
    // unwrap via GEODE_PASSPHRASE or the no-echo prompt.
    let isk = cmd::load_isk(&path)?;
    let key_id = cmd::hex(&geode_grotto::kdf::derive_key_id(&isk)?.0);
    drop(isk);

    let note = register(&path, label, &key_id, wrapped)?;

    cmd::emit(
        out,
        "keyring",
        serde_json::json!({
            "label": label,
            "key_id": key_id,
            "path": path.display().to_string(),
        }),
        &format!("added {label} = {key_id} ({}){note}", path.display()),
    );
    Ok(())
}

fn check_label(label: &str) -> Result<()> {
    if label.is_empty() || label.chars().count() > 64 {
        return Err(Error::Format("label must be 1-64 chars".into()));
    }
    Ok(())
}

/// Refuse a label that is malformed or already in the keyring.
pub(crate) fn check_label_free(label: &str) -> Result<()> {
    check_label(label)?;
    let kr = keyring::load_keyring(&index_path()?)?;
    if kr.keys.iter().any(|k| k.label == label) {
        return Err(Error::Format(format!("label {label} already in keyring")));
    }
    Ok(())
}

/// Add a key (canonical `path`) to the index. Returns a note when it became
/// the keyring default. Shared by `keyring add` and `keygen --keychain`.
pub(crate) fn register(path: &Path, label: &str, key_id: &str, wrapped: bool) -> Result<String> {
    check_label(label)?;
    let index = index_path()?;
    let mut kr = keyring::load_keyring(&index)?;
    if kr.keys.iter().any(|k| k.label == label) {
        return Err(Error::Format(format!("label {label} already in keyring")));
    }
    kr.keys
        .retain(|k| k.id != key_id && k.path != path.display().to_string());
    kr.keys.push(KeyringKey {
        id: key_id.to_string(),
        path: path.display().to_string(),
        label: label.to_string(),
        hybrid: None,
        has_passphrase: wrapped.then_some(true),
    });
    // The first added key becomes the default when none is set.
    let mut note = String::new();
    if kr.default.is_none() {
        kr.default = Some(key_id.to_string());
        note = " (set as keyring default)".to_string();
    }
    keyring::save_keyring(&index, &kr)?;
    Ok(note)
}

/// The wrap passphrase `keygen --keychain` stored for the key at `path`,
/// when the index lists that path as wrapped and the OS keychain holds an
/// entry for its key id. Any miss is `None`; the caller then prompts.
pub(crate) fn keychain_passphrase(path: &Path) -> Option<zeroize::Zeroizing<String>> {
    let canon = path.canonicalize().ok()?.display().to_string();
    let kr = keyring::load_keyring(&index_path().ok()?).ok()?;
    let k = kr
        .keys
        .iter()
        .find(|k| k.path == canon && k.has_passphrase == Some(true))?;
    if !keyring::os_store_available() {
        return None;
    }
    let secret = zeroize::Zeroizing::new(keyring::load_secret_os(&k.id).ok()?);
    std::str::from_utf8(&secret)
        .ok()
        .map(|p| zeroize::Zeroizing::new(p.to_owned()))
}
