//! `geode keyring` — named identity keys (05-cli 2.1).
//!
//! Storage (per-user, non-secret): `$XDG_CONFIG_HOME/hedronite/geode/`
//!   - `keyring.toml` — `[[key]]` entries: label, path, key_id
//!   - `config.toml`  — `default_key = "path"` (first added key becomes the
//!     default when none is configured; say so when it happens)
//!
//! Key files themselves are never copied into the keyring; entries are
//! pointers. `key_id` is public (02-cryptography 6.3).

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use geode_core::{Error, Result};

use crate::{cmd, OutMode};

#[derive(Args, Debug)]
pub struct KeyringArgs {
    #[command(subcommand)]
    pub cmd: KeyringCmd,
}

#[derive(Subcommand, Debug)]
pub enum KeyringCmd {
    /// List known keys (label, key_id, path).
    List,
    /// Register a key file under a label.
    Add(AddArgs),
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// Path to an existing GKEY file.
    #[arg(value_name = "PATH")]
    pub path: PathBuf,
    /// Human label for this key.
    #[arg(long, value_name = "NAME")]
    pub label: String,
}

#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct Keyring {
    #[serde(default)]
    key: Vec<KeyringEntry>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct KeyringEntry {
    label: String,
    path: String,
    key_id: String,
}

/// Per-user config directory: parent of the default key path.
fn config_dir() -> Result<PathBuf> {
    geode_core::keyfile::default_key_path()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .ok_or_else(|| {
            Error::Format("no config dir (XDG_CONFIG_HOME and HOME unset)".into())
        })
}

fn keyring_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("keyring.toml"))
}

fn load_keyring() -> Result<Keyring> {
    let path = keyring_path()?;
    if !path.exists() {
        return Ok(Keyring::default());
    }
    let text = std::fs::read_to_string(&path).map_err(Error::Io)?;
    toml::from_str(&text).map_err(|e| Error::Format(format!("keyring.toml: {e}")))
}

fn save_keyring(keyring: &Keyring) -> Result<()> {
    let path = keyring_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(Error::Io)?;
    }
    let text =
        toml::to_string_pretty(keyring).map_err(|e| Error::Format(format!("keyring: {e}")))?;
    geode_core::vault::write_atomic(&path, text.as_bytes())
}

/// `key_id` for a key file: derived directly for raw keys; wrapped keys are
/// unwrapped (passphrase via `GEODE_PASSPHRASE` or the no-echo prompt).
fn key_id_of(path: &Path) -> Result<String> {
    let isk = cmd::load_isk(path)?;
    let id = geode_core::kdf::derive_key_id(&isk)?;
    Ok(cmd::hex(&id.0))
}

pub fn run(args: &KeyringArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        KeyringCmd::List => list(out),
        KeyringCmd::Add(a) => add(a, out),
    }
}

fn list(out: OutMode) -> Result<()> {
    let keyring = load_keyring()?;
    match out {
        OutMode::Json => {
            for k in &keyring.key {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "verb": "keyring_list",
                        "schema": "geode.event.v1",
                        "key_id": k.key_id,
                        "path": k.path,
                    })
                );
            }
            cmd::emit(
                out,
                "keyring_list",
                serde_json::json!({"files": keyring.key.len()}),
                "",
            );
        }
        OutMode::Text => {
            if keyring.key.is_empty() {
                println!("(keyring empty — geode keyring add PATH --label NAME)");
            }
            for k in &keyring.key {
                println!("{:<16} {}  {}", k.label, k.key_id, k.path);
            }
        }
    }
    Ok(())
}

fn add(args: &AddArgs, out: OutMode) -> Result<()> {
    if args.label.is_empty() || args.label.len() > 64 {
        return Err(Error::Format("label must be 1-64 chars".into()));
    }
    let path = args
        .path
        .canonicalize()
        .map_err(|e| Error::Io(std::io::Error::new(e.kind(), format!("{}: {e}", args.path.display()))))?;
    let key_id = key_id_of(&path)?;

    let mut keyring = load_keyring()?;
    if keyring.key.iter().any(|k| k.label == args.label) {
        return Err(Error::Format(format!("label {} already in keyring", args.label)));
    }
    keyring.key.retain(|k| k.path != path.display().to_string());
    keyring.key.push(KeyringEntry {
        label: args.label.clone(),
        path: path.display().to_string(),
        key_id: key_id.clone(),
    });
    save_keyring(&keyring)?;

    // Config: first added key becomes `default_key` when none is set.
    let mut note = String::new();
    let mut config = cmd::load_config()?;
    if config.default_key.is_none() {
        config.default_key = Some(path.display().to_string());
        cmd::save_config(&config)?;
        note = format!(" (set as default_key in {})", cmd::config_path()?.display());
    }

    cmd::emit(
        out,
        "keyring_add",
        serde_json::json!({
            "key_id": key_id,
            "path": path.display().to_string(),
        }),
        &format!("added {} = {} ({}){}", args.label, key_id, path.display(), note),
    );
    Ok(())
}
