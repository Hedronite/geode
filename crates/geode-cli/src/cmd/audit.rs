//! `geode audit verify` (SPEC-v034 G6). Walks the SQLite hash chain from
//! seq 1. Exit 0 on an intact chain, 2 at the first bad seq, 1 when there
//! is no database to read. The chain law lives in `geode_grotto::audit`;
//! this module only finds the database and reports.
//!
//! Also owns the caller's local audit path, which local `geode run` writes
//! with `custody: false`.

use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use geode_grotto::audit::{self, AuditError};
use geode_grotto::{Error, Result};

use crate::output::exit;
use crate::{cmd, OutMode};

/// `geode audit` — the append-only run and deny log.
#[derive(Args, Debug)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub cmd: AuditCmd,
}

#[derive(Subcommand, Debug)]
pub enum AuditCmd {
    /// Verify the audit hash chain. Exit 0 when intact, 2 at the first bad
    /// seq.
    Verify {
        /// Audit database. Default: the caller's local audit DB,
        /// `$XDG_STATE_HOME/hedronite/geode/audit.db` or
        /// `~/.local/state/hedronite/geode/audit.db`.
        #[arg(long, value_name = "PATH")]
        db: Option<PathBuf>,
    },
}

/// The caller's local audit DB (harmonized spec §8: local `geode run`
/// writes here with `custody: false`).
#[must_use]
pub fn local_db_path() -> Option<PathBuf> {
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .filter(|h| !h.is_empty())
                .map(|h| PathBuf::from(h).join(".local/state"))
        })?;
    Some(state.join("hedronite/geode/audit.db"))
}

/// Mirror one row to the `GEODE_FACET_EVENTS` FIFO, when that names one.
/// Never process stdout. A failure is reported to the chain as
/// `mirror_ok: false` and does not fail the operation.
pub fn mirror(event: &serde_json::Value) -> std::io::Result<()> {
    let Some(path) = std::env::var_os("GEODE_FACET_EVENTS").filter(|v| !v.is_empty()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no mirror configured",
        ));
    };
    let line = serde_json::to_vec(event).map_err(std::io::Error::other)?;
    geode_os::write_fifo_line(Path::new(&path), &line)
}

pub fn run(args: &AuditArgs, out: OutMode) -> Result<()> {
    match &args.cmd {
        AuditCmd::Verify { db } => verify(db.as_deref(), out),
    }
}

fn verify(db: Option<&Path>, out: OutMode) -> Result<()> {
    let path = match db {
        Some(p) => p.to_path_buf(),
        None => {
            local_db_path().ok_or_else(|| Error::Format("no audit db: pass --db PATH".into()))?
        }
    };
    if !path.is_file() {
        return Err(Error::Format(format!("no audit db at {}", path.display())));
    }
    let chain = audit::open(&path).map_err(audit_error)?;
    match chain.verify() {
        Ok(()) => {
            cmd::emit(
                out,
                "audit_verify",
                serde_json::json!({"db": path.display().to_string(), "intact": true}),
                &format!("audit chain intact: {}", path.display()),
            );
            Ok(())
        }
        Err(AuditError::Verify { seq }) => {
            match out {
                OutMode::Json => println!(
                    "{}",
                    serde_json::json!({
                        "verb": "audit_verify",
                        "ok": false,
                        "db": path.display().to_string(),
                        "error": {"code": "audit_broken", "seq": seq},
                    })
                ),
                OutMode::Text => eprintln!("geode: error: audit verify failed at seq {seq}"),
            }
            std::process::exit(exit::AUTH);
        }
        Err(e) => Err(audit_error(e)),
    }
}

fn audit_error(e: AuditError) -> Error {
    match e {
        AuditError::Io(io) => Error::Io(io),
        other => Error::Format(other.to_string()),
    }
}
