//! `geode keygen` — write a `GKEY` identity file (02-cryptography 6).
//!
//! Protected by default: with no mode flag the key is passphrase-wrapped
//! (6.2, kind 0x01) via the public wrap API (G5a). `--keychain` wraps it
//! with a random passphrase held in the OS keychain (`cmd/keyring.rs`).
//! Only `--insecure-plaintext` writes the raw form (6.1, kind 0x00). A
//! non-TTY stdin with no mode flag and no passphrase source is refused:
//! no prompt, no file.

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};

use base64ct::{Base64, Encoding};
use clap::Args;
use geode_grotto::kdf::{self, IdentitySecret, KeyId};
use geode_grotto::wrap::{self, Argon2Params};
use geode_grotto::{Error, Result};
use zeroize::Zeroizing;

use crate::{cmd, OutMode};

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Destination key file (default ./secret.gkey, with a warning).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Keep the key's passphrase in the OS keychain (macOS Keychain or
    /// Secret Service) instead of prompting. The file on disk stays
    /// wrapped, and the key is added to `geode keyring`.
    #[arg(long, conflicts_with = "insecure_plaintext")]
    pub keychain: bool,
    /// Write the key unwrapped. Anyone who can read the file holds the
    /// identity. Use it for throwaway test keys only.
    #[arg(long)]
    pub insecure_plaintext: bool,
    /// Deprecated: a passphrase is now the default. Accepted and ignored.
    #[arg(long, conflicts_with_all = ["keychain", "insecure_plaintext"])]
    pub password: bool,
    /// Weaker Argon2id parameters for constrained hosts (passphrase mode).
    #[arg(long)]
    pub cheap: bool,
}

/// How the new key is protected on disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    /// Wrapped with an operator passphrase (the default).
    Passphrase,
    /// Wrapped with a random passphrase held in the OS keychain.
    Keychain,
    /// Raw ISK on disk (`--insecure-plaintext`).
    Plaintext,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Passphrase => "passphrase",
            Self::Keychain => "keychain",
            Self::Plaintext => "plaintext",
        }
    }
}

fn mode(args: &KeygenArgs) -> Result<Mode> {
    let mode = if args.keychain {
        Mode::Keychain
    } else if args.insecure_plaintext {
        Mode::Plaintext
    } else {
        Mode::Passphrase
    };
    if args.cheap && mode != Mode::Passphrase {
        return Err(Error::Format(
            "--cheap applies to the passphrase mode; it does not apply to \
             --insecure-plaintext or --keychain"
                .into(),
        ));
    }
    Ok(mode)
}

pub fn run(args: &KeygenArgs, out: OutMode) -> Result<()> {
    let mode = mode(args)?;
    if args.password {
        eprintln!(
            "geode: warning: --password is deprecated; a passphrase is now the \
             keygen default"
        );
    }
    // Refuse before anything is written: a non-TTY stdin cannot answer a
    // prompt, and the default must never fall back to plaintext.
    if mode == Mode::Passphrase && env_passphrase().is_none() && !std::io::stdin().is_terminal() {
        return Err(Error::Format(
            "keygen: stdin is not a terminal, so no passphrase can be typed. \
             Pass --keychain, or --insecure-plaintext for a throwaway test key"
                .into(),
        ));
    }
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from("secret.gkey"));
    if args.path.is_none() {
        crate::output::print_keygen_default_path_warning();
    }
    let label = match mode {
        Mode::Keychain => Some(keychain_label(&path)?),
        Mode::Passphrase | Mode::Plaintext => None,
    };

    // Every secret below is `Zeroizing` (or `IdentitySecret`), so it is
    // wiped on drop on every branch, including `?` returns.
    let mut isk = Zeroizing::new([0u8; 32]);
    getrandom::fill(isk.as_mut()).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    let id = IdentitySecret::from_bytes(*isk);
    let key_id = kdf::derive_key_id(&id)?;

    let mut keychain_pass = None;
    let buf = match mode {
        Mode::Passphrase => {
            let pass = passphrase_confirmed()?;
            let params = if args.cheap {
                Argon2Params::DEFAULT_CHEAP
            } else {
                Argon2Params::DEFAULT_DESKTOP
            };
            wrapped_gkey(&id, pass.as_bytes(), params)?
        }
        Mode::Keychain => {
            // 256 random bits: Argon2 hardness adds nothing here, so the
            // cheap parameters keep every unlock fast.
            let mut raw = Zeroizing::new([0u8; 32]);
            getrandom::fill(raw.as_mut()).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
            let pass = Zeroizing::new(cmd::hex(raw.as_ref()));
            let buf = wrapped_gkey(&id, pass.as_bytes(), Argon2Params::DEFAULT_CHEAP)?;
            keychain_pass = Some(pass);
            buf
        }
        Mode::Plaintext => {
            eprintln!(
                "geode: warning: --insecure-plaintext writes the identity key \
                 unwrapped; anyone who can read {} holds it",
                path.display()
            );
            let sum = blake3::hash(isk.as_ref());
            let mut buf = Zeroizing::new(Vec::with_capacity(6 + 32 + 16));
            buf.extend_from_slice(geode_grotto::MAGIC_GKEY);
            buf.push(1); // version
            buf.push(0); // kind = raw
            buf.extend_from_slice(isk.as_ref());
            buf.extend_from_slice(&sum.as_bytes()[..16]);
            buf
        }
    };

    write_gkey(&path, &buf)?;
    if let (Some(pass), Some(label)) = (&keychain_pass, &label) {
        if let Err(e) = keychain_store(&path, label, &key_id, pass) {
            // Without the keychain entry the wrapped file is unopenable.
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }
    }

    // 02-cryptography 6.3: every keygen also emits the adjacent `.gpub`
    // (public half only — key_id + X25519 public, never ISK material).
    let gpub = write_gpub(&path, &isk, &key_id)?;

    cmd::emit(
        out,
        "keygen",
        serde_json::json!({
            "key_id": cmd::hex(&key_id.0),
            "path": path.display().to_string(),
            "gpub": gpub.display().to_string(),
            "wrapped": mode != Mode::Plaintext,
            "mode": mode.as_str(),
        }),
        &format!(
            "key_id {} -> {} (public {})",
            cmd::hex(&key_id.0),
            path.display(),
            gpub.display()
        ),
    );
    Ok(())
}

/// The wrapped `GKEY` form (02-cryptography 6.2, kind 0x01).
fn wrapped_gkey(
    id: &IdentitySecret,
    pass: &[u8],
    params: Argon2Params,
) -> Result<Zeroizing<Vec<u8>>> {
    let wk = wrap::wrap_identity_passphrase(id, pass, params)?;
    let mut buf = Zeroizing::new(Vec::with_capacity(6 + 16 + 12 + 32 + 16 + 32));
    buf.extend_from_slice(geode_grotto::MAGIC_GKEY);
    buf.push(1); // version
    buf.push(1); // kind = wrap
    buf.extend_from_slice(&wk.salt.0);
    buf.extend_from_slice(&wk.argon2_m_kib.to_le_bytes());
    buf.extend_from_slice(&wk.argon2_t.to_le_bytes());
    buf.extend_from_slice(&wk.argon2_p.to_le_bytes());
    buf.extend_from_slice(&wk.wrap_nonce);
    buf.extend_from_slice(&wk.wrap_tag);
    buf.extend_from_slice(&wk.wrapped_isk);
    Ok(buf)
}

/// Write the key file 0600 from creation, refusing to overwrite.
fn write_gkey(path: &Path, buf: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
    }
    // 0600 from creation: no world-readable window (02-cryptography 6.1).
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(Error::Io)?;
    f.write_all(buf).map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)?;
    Ok(())
}

/// The `geode keyring` label for a `--keychain` key: the file stem. Checked
/// before any key is generated so a clash writes nothing.
fn keychain_label(path: &Path) -> Result<String> {
    if !geode_grotto::keyring::os_store_available() {
        return Err(Error::Format(
            "--keychain: no OS keychain is available on this host".into(),
        ));
    }
    let label = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    super::keyring::check_label_free(&label)?;
    Ok(label)
}

/// Store the wrap passphrase in the OS keychain under the key id and add
/// the key to `geode keyring`. On failure nothing is left in the keychain.
fn keychain_store(path: &Path, label: &str, key_id: &KeyId, pass: &str) -> Result<()> {
    let id_hex = cmd::hex(&key_id.0);
    let canon = path.canonicalize().map_err(Error::Io)?;
    geode_grotto::keyring::store_secret_os(&id_hex, pass.as_bytes())?;
    match super::keyring::register(&canon, label, &id_hex, true) {
        Ok(note) => {
            if !note.is_empty() {
                eprintln!("geode: {label}{note}");
            }
            Ok(())
        }
        Err(e) => {
            let _ = geode_grotto::keyring::delete_secret_os(&id_hex);
            Err(e)
        }
    }
}

/// Write `<keyfile stem>.gpub` (02-cryptography 6.3): a public JSON
/// document — version, `key_id`, X25519 public (base64). Contains no secret
/// material; written 0644. Refuses to overwrite (same as the `.gkey`).
fn write_gpub(gkey_path: &std::path::Path, isk: &[u8; 32], key_id: &KeyId) -> Result<PathBuf> {
    let gpub_path = gkey_path.with_extension("gpub");
    let doc = serde_json::json!({
        "version": 1,
        "key_id": cmd::hex(&key_id.0),
        "x25519_public": Base64::encode_string(&geode_grotto::recipients::x25519_identity_public(
            &geode_grotto::kdf::IdentitySecret::from_bytes(*isk),
        )),
    });
    let text = serde_json::to_string_pretty(&doc)
        .map_err(|e| Error::Format(format!("gpub serialize: {e}")))?;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }
    let mut f = opts.open(&gpub_path).map_err(Error::Io)?;
    f.write_all(text.as_bytes()).map_err(Error::Io)?;
    f.write_all(b"\n").map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)?;
    Ok(gpub_path)
}

/// Parse a `.gpub` document: (`key_id`, x25519 public bytes). Used by
/// `vault add-recipient`.
pub fn read_gpub(path: &std::path::Path) -> Result<(KeyId, [u8; 32])> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    let doc: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| Error::Format(format!("gpub parse: {e}")))?;
    if doc.get("version").and_then(serde_json::Value::as_u64) != Some(1) {
        return Err(Error::Format("gpub version must be 1".into()));
    }
    let key_id_hex = doc
        .get("key_id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Format("gpub missing key_id".into()))?;
    let mut key_id = [0u8; 16];
    cmd::unhex(key_id_hex, &mut key_id)?;
    let public_b64 = doc
        .get("x25519_public")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Format("gpub missing x25519_public".into()))?;
    let public: [u8; 32] = Base64::decode_vec(public_b64)
        .map_err(|e| Error::Format(format!("gpub public base64: {e}")))?
        .try_into()
        .map_err(|_| Error::Format("gpub x25519_public not 32 bytes".into()))?;
    Ok((KeyId(key_id), public))
}

/// `GEODE_PASSPHRASE`, when set (the startup warning already fired in
/// `main`).
fn env_passphrase() -> Option<Zeroizing<String>> {
    std::env::var_os("GEODE_PASSPHRASE").map(|p| Zeroizing::new(p.to_string_lossy().into_owned()))
}

/// Prompt twice and require a match; `GEODE_PASSPHRASE` skips the prompt.
fn passphrase_confirmed() -> Result<Zeroizing<String>> {
    let p = match env_passphrase() {
        Some(p) => p,
        None => {
            let a = crate::output::prompt_passphrase("new passphrase: ").map_err(Error::Io)?;
            let b = crate::output::prompt_passphrase("confirm passphrase: ").map_err(Error::Io)?;
            if a != b {
                return Err(Error::Format("passphrases do not match".into()));
            }
            a
        }
    };
    if p.is_empty() {
        return Err(Error::Format("empty passphrase refused".into()));
    }
    Ok(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(keychain: bool, insecure_plaintext: bool, cheap: bool) -> KeygenArgs {
        KeygenArgs {
            path: None,
            keychain,
            insecure_plaintext,
            password: false,
            cheap,
        }
    }

    #[test]
    fn no_flag_is_passphrase_mode() {
        assert_eq!(mode(&args(false, false, false)).unwrap(), Mode::Passphrase);
        assert_eq!(mode(&args(false, false, true)).unwrap(), Mode::Passphrase);
    }

    #[test]
    fn only_insecure_plaintext_is_plaintext() {
        assert_eq!(mode(&args(false, true, false)).unwrap(), Mode::Plaintext);
        assert_eq!(mode(&args(true, false, false)).unwrap(), Mode::Keychain);
    }

    #[test]
    fn cheap_does_not_apply_to_plaintext_or_keychain() {
        for a in [args(false, true, true), args(true, false, true)] {
            let e = mode(&a).unwrap_err().to_string();
            assert!(e.contains("does not apply"), "{e}");
        }
    }

    #[test]
    fn wrapped_gkey_is_kind_1_and_unwraps() {
        let id = IdentitySecret::from_bytes([7u8; 32]);
        let buf = wrapped_gkey(&id, b"pw", Argon2Params::DEFAULT_CHEAP).unwrap();
        assert_eq!(&buf[..4], geode_grotto::MAGIC_GKEY);
        assert_eq!((buf[4], buf[5]), (1, 1));
        assert_eq!(buf.len(), 114);
        assert!(!buf.windows(32).any(|w| w == [7u8; 32]), "ISK in clear");
    }
}
