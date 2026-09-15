//! `geode list` / `geode cat` — read-side verbs (05-cli 2.7, 2.8).

#![allow(clippy::cast_possible_truncation)]

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Instant;

use clap::Args;
use geode_grotto::{object, vault as corevault, Error, Result};

use crate::{cmd, GlobalArgs, OutMode};

#[derive(Args, Debug)]
pub struct ListArgs {
    /// Vault to list.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Only entries under this vault-relative prefix.
    #[arg(value_name = "PREFIX")]
    pub prefix: Option<String>,
}

pub fn run(args: &ListArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&args.vault, &isk)?;

    let prefix = args.prefix.as_deref().map(cmd::open::normalize_prefix);
    // Operator-facing paths: sealed names are opened for display
    // (02-cryptography 5); the user prefix is plaintext, so match after open.
    let mut shown: Vec<(&geode_grotto::manifest::Entry, String)> = Vec::new();
    for e in &ctx.manifest.entries {
        let disp = cmd::seal::display_path(&ctx, e)?;
        let matches = match &prefix {
            None => true,
            Some(p) => disp.starts_with(p.as_str()) || disp == p.trim_end_matches('/'),
        };
        if matches {
            shown.push((e, disp));
        }
    }

    match out {
        OutMode::Json => {
            // NDJSON: one schema-valid event per entry, then a summary event.
            for (e, disp) in &shown {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": true,
                        "verb": "list",
                        "schema": "geode.event.v1",
                        "vault_id": cmd::hex(&ctx.vault_id.0),
                        "epoch": ctx.epoch.0,
                        "key_id": cmd::hex(&ctx.key_id.0),
                        "path": disp,
                        "plain_bytes": e.plain_len,
                        "content_root": cmd::hex(&e.content_root),
                    })
                );
            }
            cmd::emit(
                out,
                "list",
                serde_json::json!({
                    "vault_id": cmd::hex(&ctx.vault_id.0),
                    "epoch": ctx.epoch.0,
                    "key_id": cmd::hex(&ctx.key_id.0),
                    "files": shown.len(),
                    "plain_bytes": shown.iter().map(|(e, _)| e.plain_len).sum::<u64>(),
                }),
                "",
            );
        }
        OutMode::Text => {
            for (e, disp) in &shown {
                println!("{:>12}  {:>5}  {}", e.plain_len, e.chunk_count, disp);
            }
            eprintln!(
                "{} entr(y/ies), vault {} epoch {}",
                shown.len(),
                cmd::hex(&ctx.vault_id.0),
                ctx.epoch.0
            );
        }
    }
    Ok(())
}

#[derive(Args, Debug)]
pub struct CatArgs {
    /// Vault to read from.
    #[arg(value_name = "VAULT")]
    pub vault: PathBuf,
    /// Vault-relative path of the object.
    #[arg(value_name = "PATH")]
    pub path: String,
    /// Truncate output to N bytes (`truncated` reports it).
    #[arg(long, value_name = "N")]
    pub max_bytes: Option<u64>,
}

pub fn cat(args: &CatArgs, global: &GlobalArgs, out: OutMode) -> Result<()> {
    let key_path = cmd::require_key(global)?;
    let isk = cmd::load_isk(&key_path)?;
    let ctx = cmd::load_vault(&args.vault, &isk)?;

    let want = args
        .path
        .trim_start_matches("./")
        .trim_start_matches('/')
        .to_string();
    // `PATH` is operator-facing plaintext; match after opening sealed names.
    let mut entry = None;
    let mut entry_disp = String::new();
    for e in &ctx.manifest.entries {
        let disp = cmd::seal::display_path(&ctx, e)?;
        if disp == want {
            entry = Some(e);
            entry_disp = disp;
            break;
        }
    }
    let entry = entry.ok_or_else(|| {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} not in manifest", args.path),
        ))
    })?;

    let start = Instant::now();
    let raw = corevault::read_object(&args.vault, ctx.epoch, &entry.object_id)?;
    let bind: &[u8] = if entry.bind { entry.path.as_bytes() } else { b"" };
    let (_, data) = object::open_object(
        &ctx.ek,
        &raw[..object::HEADER_SIZE],
        &raw[object::HEADER_SIZE..],
        bind,
    )?;

    let plain_len = data.len() as u64;
    let truncated = args.max_bytes.is_some_and(|m| plain_len > m);
    let shown: &[u8] = match args.max_bytes {
        Some(m) => &data[..(m as usize).min(data.len())],
        None => &data,
    };

    match out {
        OutMode::Json => {
            cmd::emit(
                out,
                "cat",
                serde_json::json!({
                    "vault_id": cmd::hex(&ctx.vault_id.0),
                    "epoch": ctx.epoch.0,
                    "key_id": cmd::hex(&ctx.key_id.0),
                    "path": entry_disp,
                    "truncated": truncated,
                    "plain_bytes": plain_len,
                    "content_root": cmd::hex(&entry.content_root),
                    "preview": String::from_utf8_lossy(shown),
                    "elapsed_ms": start.elapsed().as_millis() as u64,
                }),
                "",
            );
        }
        OutMode::Text => {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(shown).map_err(Error::Io)?;
            lock.flush().map_err(Error::Io)?;
        }
    }
    Ok(())
}
