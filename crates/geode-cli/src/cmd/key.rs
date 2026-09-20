//! `geode keygen` — write a `GKEY` identity file (02-cryptography 6):
//! raw form (6.1) by default, passphrase-wrapped form (6.2) with
//! `--password` via the public wrap API (G5a).

use std::io::Write as _;
use std::path::PathBuf;

use base64ct::{Base64, Encoding};
use clap::Args;
use geode_grotto::kdf::{self, IdentitySecret, KeyId};
use geode_grotto::wrap::{self, Argon2Params};
use geode_grotto::{Error, Result};
use zeroize::Zeroize;

use crate::{cmd, OutMode};

/// BLAKE3 domain for the identity's X25519 static secret (02-cryptography
/// 6.3: "derived from BLAKE3-expand(ISK) streams"). CLI-local until the
/// spec pins the exact string; changing it changes every `.gpub`.
const X25519_IDENTITY_DOMAIN: &str = "geode/v1/x25519-identity";

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Destination key file (default ./secret.gkey, with a warning).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Passphrase-wrap the key (02-cryptography 6.2; prompts, no echo).
    #[arg(long)]
    pub password: bool,
    /// Weaker Argon2id parameters for constrained hosts (with --password).
    #[arg(long)]
    pub cheap: bool,
}

pub fn run(args: &KeygenArgs, out: OutMode) -> Result<()> {
    if args.cheap && !args.password {
        return Err(Error::Format(
            "--cheap only makes sense with --password".into(),
        ));
    }
    let path = args
        .path
        .clone()
        .unwrap_or_else(|| PathBuf::from("secret.gkey"));
    if args.path.is_none() {
        crate::output::print_keygen_default_path_warning();
    }

    let mut isk = [0u8; 32];
    getrandom::fill(&mut isk).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;

    let buf = if args.password {
        let pass = passphrase_confirmed()?;
        let params = if args.cheap {
            Argon2Params::DEFAULT_CHEAP
        } else {
            Argon2Params::DEFAULT_DESKTOP
        };
        let wk = wrap::wrap_identity_passphrase(
            &IdentitySecret::from_bytes(isk),
            pass.as_bytes(),
            params,
        )?;
        let mut buf = Vec::with_capacity(6 + 16 + 12 + 32 + 16 + 32);
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
        buf
    } else {
        let sum = blake3::hash(&isk);
        let mut buf = Vec::with_capacity(6 + 32 + 16);
        buf.extend_from_slice(geode_grotto::MAGIC_GKEY);
        buf.push(1); // version
        buf.push(0); // kind = raw
        buf.extend_from_slice(&isk);
        buf.extend_from_slice(&sum.as_bytes()[..16]);
        buf
    };

    let key_id = kdf::derive_key_id(&IdentitySecret::from_bytes(isk))?;

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
    let mut f = opts.open(&path).map_err(Error::Io)?;
    f.write_all(&buf).map_err(Error::Io)?;
    f.sync_all().map_err(Error::Io)?;

    // 02-cryptography 6.3: every keygen also emits the adjacent `.gpub`
    // (public half only — key_id + X25519 public, never ISK material).
    let gpub = write_gpub(&path, &isk, &key_id)?;
    isk.zeroize();

    cmd::emit(
        out,
        "keygen",
        serde_json::json!({
            "key_id": cmd::hex(&key_id.0),
            "path": path.display().to_string(),
            "gpub": gpub.display().to_string(),
            "wrapped": args.password,
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

/// Derive the identity's X25519 static secret from the ISK (BLAKE3-expand
/// stream, 02-cryptography 6.3) and return the public key bytes.
fn x25519_public(isk: &[u8; 32]) -> [u8; 32] {
    let sk_bytes = blake3::derive_key(X25519_IDENTITY_DOMAIN, isk);
    let sk = x25519_dalek::StaticSecret::from(sk_bytes);
    x25519_dalek::PublicKey::from(&sk).to_bytes()
}

/// Write `<keyfile stem>.gpub` (02-cryptography 6.3): a public JSON
/// document — version, `key_id`, X25519 public (base64). Contains no secret
/// material; written 0644. Refuses to overwrite (same as the `.gkey`).
fn write_gpub(gkey_path: &std::path::Path, isk: &[u8; 32], key_id: &KeyId) -> Result<PathBuf> {
    let gpub_path = gkey_path.with_extension("gpub");
    let doc = serde_json::json!({
        "version": 1,
        "key_id": cmd::hex(&key_id.0),
        "x25519_public": Base64::encode_string(&x25519_public(isk)),
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

/// Prompt twice and require a match; `GEODE_PASSPHRASE` skips the prompt
/// (the startup warning already fired in `main`).
fn passphrase_confirmed() -> Result<zeroize::Zeroizing<String>> {
    if let Some(p) = std::env::var_os("GEODE_PASSPHRASE") {
        return Ok(zeroize::Zeroizing::new(p.to_string_lossy().into_owned()));
    }
    let a = crate::output::prompt_passphrase("new passphrase: ").map_err(Error::Io)?;
    let b = crate::output::prompt_passphrase("confirm passphrase: ").map_err(Error::Io)?;
    if a != b {
        return Err(Error::Format("passphrases do not match".into()));
    }
    if a.is_empty() {
        return Err(Error::Format("empty passphrase refused".into()));
    }
    Ok(a)
}
