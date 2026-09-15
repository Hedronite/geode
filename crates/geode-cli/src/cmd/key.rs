//! `geode keygen` — write a `GKEY` identity file (02-cryptography 6):
//! raw form (6.1) by default, passphrase-wrapped form (6.2) with
//! `--password` via the public wrap API (G5a).

use std::io::Write as _;
use std::path::PathBuf;

use clap::Args;
use geode_grotto::kdf::{self, IdentitySecret};
use geode_grotto::wrap::{self, Argon2Params};
use geode_grotto::{Error, Result};
use zeroize::Zeroize;

use crate::{cmd, OutMode};

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
        return Err(Error::Format("--cheap only makes sense with --password".into()));
    }
    let path = args.path.clone().unwrap_or_else(|| PathBuf::from("secret.gkey"));
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
    isk.zeroize();

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

    cmd::emit(
        out,
        "keygen",
        serde_json::json!({
            "key_id": cmd::hex(&key_id.0),
            "path": path.display().to_string(),
            "wrapped": args.password,
        }),
        &format!("key_id {} -> {}", cmd::hex(&key_id.0), path.display()),
    );
    Ok(())
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
