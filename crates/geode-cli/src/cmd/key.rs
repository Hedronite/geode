//! `geode keygen` — write a raw-form `GKEY` identity file (02-cryptography 6.1).

use std::io::Write as _;
use std::path::PathBuf;

use clap::Args;
use geode_core::kdf::{self, IdentitySecret};
use geode_core::{Error, Result};
use zeroize::Zeroize;

use crate::{cmd, OutMode};

#[derive(Args, Debug)]
pub struct KeygenArgs {
    /// Destination key file (default ./secret.gkey, with a warning).
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,
    /// Passphrase wrap (NOT in v0.1.0: needs a geode-core keyfile API).
    #[arg(long)]
    pub password: bool,
    /// Weaker Argon2id parameters for constrained hosts (with --password).
    #[arg(long)]
    pub cheap: bool,
}

pub fn run(args: &KeygenArgs, out: OutMode) -> Result<()> {
    if args.password || args.cheap {
        return Err(Error::Format(
            "--password wrap is not in v0.1.0 (geode-core keyfile API gap; tracked for backend)"
                .into(),
        ));
    }
    let path = args.path.clone().unwrap_or_else(|| PathBuf::from("secret.gkey"));
    if args.path.is_none() {
        eprintln!(
            "warning: writing ./secret.gkey — move it to ~/.config/hedronite/geode/default.gkey"
        );
    }

    let mut isk = [0u8; 32];
    getrandom::fill(&mut isk).map_err(|e| Error::Crypto(format!("getrandom: {e}")))?;
    let sum = blake3::hash(&isk);
    let mut buf = Vec::with_capacity(6 + 32 + 16);
    buf.extend_from_slice(geode_core::MAGIC_GKEY);
    buf.push(1); // version
    buf.push(0); // kind = raw
    buf.extend_from_slice(&isk);
    buf.extend_from_slice(&sum.as_bytes()[..16]);
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
        }),
        &format!("key_id {} -> {}", cmd::hex(&key_id.0), path.display()),
    );
    Ok(())
}
