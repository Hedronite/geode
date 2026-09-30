//! `geode sign` — Ed25519 identity child, cosign-compatible output
//! (SPEC-v033 G1).
//!
//! Two sub-verbs, one unlocked identity file:
//!
//! ```text
//! geode sign pub  [--key PATH] [-o FILE]
//! geode sign blob PATH [--key PATH] [-o FILE]
//! ```
//!
//! The crypto lives in `geode_grotto::sign` (G0): the seed is
//! `blake3::derive_key("geode/v1/ed25519-identity", ISK)` — the sibling of
//! the X25519 child `cmd/key.rs` derives — and never leaves the
//! zeroize-on-drop `SigningIdentity`. This module owns paths, file modes,
//! and exit codes only.
//!
//! Output forms (SPEC-v033 "Derivation"): `pub` writes SPKI PEM
//! (`BEGIN PUBLIC KEY`, DER prefix `302a300506032b6570032100`); `blob`
//! writes standard base64 of the 64-byte signature over the raw payload
//! (RFC 8032, no prehash). Both are the exact bytes `cosign verify-blob`
//! reads, plus one trailing newline. stdout carries those contents when
//! `-o` is omitted; written files are mode `0644` and are never
//! overwritten. `geode key pub` and the `.gpub` document stay X25519.
//!
//! Exit codes (05-cli 3): a missing key exits 1 (usage/IO), a bad
//! passphrase exits 2 (auth), success exits 0. `--output json` adds
//! `key_id`, `algorithm: ed25519`, and the PEM or the signature — all
//! public values, screened by `cmd::emit`; the seed and the ISK are never
//! emitted anywhere.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use geode_grotto::kdf::IdentitySecret;
use geode_grotto::sign::SigningIdentity;
use geode_grotto::{Error, Result};

use crate::cmd::{self, OutMode};

#[derive(Args, Debug)]
pub struct SignArgs {
    #[command(subcommand)]
    pub cmd: SignCmd,
}

#[derive(Subcommand, Debug)]
pub enum SignCmd {
    /// Print the Ed25519 identity public key as SPKI PEM.
    Pub {
        /// Write the PEM to FILE instead of stdout.
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
    },
    /// Sign the raw bytes of PATH (RFC 8032, no prehash).
    Blob {
        /// Payload file to sign.
        #[arg(value_name = "PATH")]
        path: PathBuf,
        /// Write the signature to FILE instead of stdout.
        #[arg(short = 'o', value_name = "FILE")]
        out: Option<PathBuf>,
    },
}

pub fn run(args: &SignArgs, global: &crate::GlobalArgs, mode: OutMode) -> Result<()> {
    match &args.cmd {
        SignCmd::Pub { out } => run_pub(global, out_path(out), mode),
        SignCmd::Blob { path, out } => run_blob(global, path, out_path(out), mode),
    }
}

fn out_path(p: &Option<PathBuf>) -> Option<&Path> {
    p.as_deref()
}

/// Unlock the identity and derive its Ed25519 child (SPEC-v033
/// "Derivation"). The ISK is dropped here; only the signing identity,
/// which prints no key material, escapes.
fn signing_identity(global: &crate::GlobalArgs) -> Result<(SigningIdentity, IdentitySecret)> {
    let path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&path)?;
    let id = SigningIdentity::from_isk(&isk);
    Ok((id, isk))
}

fn run_pub(global: &crate::GlobalArgs, output: Option<&Path>, out: OutMode) -> Result<()> {
    let (id, isk) = signing_identity(global)?;
    let pem = id.public_pem();
    let key_id = kdf_key_id(&isk)?;
    write_or_print(output, &pem, out)?;
    cmd::emit(
        out,
        "sign_pub",
        serde_json::json!({
            "key_id": cmd::hex(&key_id.0),
            "algorithm": "ed25519",
            "pem": pem,
            "output": output.map(|p| p.display().to_string()),
        }),
        "",
    );
    Ok(())
}

fn run_blob(
    global: &crate::GlobalArgs,
    path: &Path,
    output: Option<&Path>,
    out: OutMode,
) -> Result<()> {
    let (id, isk) = signing_identity(global)?;
    let payload = std::fs::read(path).map_err(Error::Io)?;
    let sig = id.sign(&payload);
    let text = format!("{}\n", geode_grotto::sign::signature_base64(&sig));
    let key_id = kdf_key_id(&isk)?;
    write_or_print(output, &text, out)?;
    cmd::emit(
        out,
        "sign_blob",
        serde_json::json!({
            "key_id": cmd::hex(&key_id.0),
            "algorithm": "ed25519",
            "payload": path.display().to_string(),
            "signature_b64": text.trim_end(),
            "output": output.map(|p| p.display().to_string()),
        }),
        "",
    );
    Ok(())
}

/// Key id of the identity (public identifier; the event schema wants it,
/// and it is the same 16-byte hex `keygen` prints).
fn kdf_key_id(isk: &IdentitySecret) -> Result<geode_grotto::kdf::KeyId> {
    geode_grotto::kdf::derive_key_id(isk)
}

/// stdout when no `-o`, otherwise write FILE (mode `0644`, never
/// overwrite). The written bytes are exactly the bytes stdout would have
/// carried, trailing newline included.
fn write_or_print(output: Option<&Path>, text: &str, out: OutMode) -> Result<()> {
    match output {
        Some(path) => {
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o644);
            }
            let mut f = opts.open(path).map_err(Error::Io)?;
            f.write_all(text.as_bytes()).map_err(Error::Io)?;
            f.sync_all().map_err(Error::Io)
        }
        None => {
            if out == OutMode::Text {
                print!("{text}");
                std::io::Write::flush(&mut std::io::stdout()).map_err(Error::Io)?;
            }
            Ok(())
        }
    }
}
