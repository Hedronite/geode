//! Append-only SQLite audit chain.
//!
//! The database is the source of truth. A Facet mirror is best-effort and is
//! never written to process stdout. `geode audit verify` is not this module.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::{params, Connection};

use crate::manifest::canonicalize;

/// `prev_hash` of seq 1.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

const ARGV_DOMAIN: &[u8] = b"geode/v1/audit-argv";
const REJECTED_DOMAIN: &[u8] = b"geode/v1/audit-argv-rejected";

/// How argv is committed. The raw argument vector is never stored.
#[derive(Clone, Debug)]
pub enum ArgvCommit {
    /// Hash `argv0` and `args`, then drop `args`.
    Clean { argv0: String, args: Vec<String> },
    /// Hash only the canonical exe path. There is no argument vector here.
    Rejected { exe: String },
}

/// Fields for one new audit row. There is no value, length, or raw argv.
#[derive(Clone, Debug)]
pub struct AuditInput {
    pub ts: i64,
    pub token_id: String,
    pub principal: String,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
    pub vault_id: String,
    pub op: String,
    pub paths: Vec<String>,
    pub exit_code: Option<i32>,
    pub redaction_hits: BTreeMap<String, u64>,
    pub outcome: String,
    pub custody: bool,
    pub hosts: String,
    pub argv: ArgvCommit,
}

/// One stored row. `row_hash` is not part of [`canonical_row`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRow {
    pub seq: i64,
    pub ts: i64,
    pub prev_hash: [u8; 32],
    pub row_hash: [u8; 32],
    pub token_id: String,
    pub principal: String,
    pub peer_uid: Option<u32>,
    pub peer_pid: Option<u32>,
    pub vault_id: String,
    pub op: String,
    pub paths: Vec<String>,
    pub argv0: String,
    pub argv_hash: [u8; 32],
    pub exit_code: Option<i32>,
    pub redaction_hits: BTreeMap<String, u64>,
    pub outcome: String,
    pub custody: bool,
    pub hosts: String,
}

/// Result of an append. The SQLite row exists even when `mirror_ok` is false.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Appended {
    pub row: AuditRow,
    pub mirror_ok: bool,
}

/// Chain or mirror failure. This is not a process exit code.
#[derive(Debug)]
pub enum AuditError {
    Io(std::io::Error),
    Sqlite(rusqlite::Error),
    Verify { seq: i64 },
    Format(String),
}

impl std::fmt::Display for AuditError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "audit io: {err}"),
            Self::Sqlite(err) => write!(f, "audit sqlite: {err}"),
            Self::Verify { seq } => write!(f, "audit verify failed at seq {seq}"),
            Self::Format(msg) => write!(f, "audit format: {msg}"),
        }
    }
}

impl std::error::Error for AuditError {}

impl From<std::io::Error> for AuditError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<rusqlite::Error> for AuditError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Sqlite(err)
    }
}

/// Open or create an append-only WAL database at `path`.
pub fn open(path: &Path) -> Result<Chain, AuditError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS audit (
            seq INTEGER PRIMARY KEY,
            ts INTEGER NOT NULL,
            prev_hash BLOB NOT NULL,
            row_hash BLOB NOT NULL,
            token_id TEXT NOT NULL,
            principal TEXT NOT NULL,
            peer_uid INTEGER,
            peer_pid INTEGER,
            vault_id TEXT NOT NULL,
            op TEXT NOT NULL,
            paths TEXT NOT NULL,
            argv0 TEXT NOT NULL,
            argv_hash BLOB NOT NULL,
            exit_code INTEGER,
            redaction_hits TEXT NOT NULL,
            outcome TEXT NOT NULL,
            custody INTEGER NOT NULL,
            hosts TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit
        BEGIN
            SELECT RAISE(ABORT, 'audit is append-only');
        END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit
        BEGIN
            SELECT RAISE(ABORT, 'audit is append-only');
        END;
        ",
    )?;
    Ok(Chain { conn })
}

/// SQLite chain. The connection is not exposed for updates.
pub struct Chain {
    conn: Connection,
}

impl std::fmt::Debug for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Chain").finish_non_exhaustive()
    }
}

impl Chain {
    /// Append one row, then mirror it. A mirror error leaves the row in place.
    pub fn append<E>(
        &mut self,
        input: AuditInput,
        mirror: impl FnOnce(&serde_json::Value) -> Result<(), E>,
    ) -> Result<Appended, AuditError> {
        let row = self.insert(input)?;
        let payload = facet_event(&row);
        let mirror_ok = mirror(&payload).is_ok();
        Ok(Appended { row, mirror_ok })
    }

    /// Walk seq 1..n. The error names the first bad seq.
    pub fn verify(&self) -> Result<(), AuditError> {
        let rows = self.load_all()?;
        let mut expected_prev = GENESIS_PREV_HASH;
        for (idx, row) in rows.iter().enumerate() {
            let expected_seq = i64::try_from(idx + 1).unwrap_or(i64::MAX);
            if row.seq != expected_seq || row.prev_hash != expected_prev {
                return Err(AuditError::Verify { seq: row.seq });
            }
            let canonical = canonical_row(row)?;
            let hashed = hash_row(&row.prev_hash, &canonical);
            if hashed != row.row_hash {
                return Err(AuditError::Verify { seq: row.seq });
            }
            expected_prev = row.row_hash;
        }
        Ok(())
    }

    fn insert(&mut self, input: AuditInput) -> Result<AuditRow, AuditError> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        let inserted = self.insert_in_tx(input);
        match inserted {
            Ok(row) => {
                self.conn.execute_batch("COMMIT")?;
                Ok(row)
            }
            Err(err) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(err)
            }
        }
    }

    fn insert_in_tx(&self, input: AuditInput) -> Result<AuditRow, AuditError> {
        let (seq, prev_hash) = self.next_link()?;
        let (argv0, argv_hash, outcome) = commit_argv(input.argv, input.outcome);
        let mut row = AuditRow {
            seq,
            ts: input.ts,
            prev_hash,
            row_hash: [0u8; 32],
            token_id: input.token_id,
            principal: input.principal,
            peer_uid: input.peer_uid,
            peer_pid: input.peer_pid,
            vault_id: input.vault_id,
            op: input.op,
            paths: input.paths,
            argv0,
            argv_hash,
            exit_code: input.exit_code,
            redaction_hits: input.redaction_hits,
            outcome,
            custody: input.custody,
            hosts: input.hosts,
        };
        let canonical = canonical_row(&row)?;
        row.row_hash = hash_row(&prev_hash, &canonical);
        self.write_row(&row)?;
        Ok(row)
    }

    fn next_link(&self) -> Result<(i64, [u8; 32]), AuditError> {
        let last: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM audit", [], |row| row.get(0))?;
        let Some(seq) = last else {
            return Ok((1, GENESIS_PREV_HASH));
        };
        let prev: Vec<u8> =
            self.conn
                .query_row("SELECT row_hash FROM audit WHERE seq = ?1", [seq], |row| {
                    row.get(0)
                })?;
        let prev_hash = hash32(&prev)?;
        let next = seq
            .checked_add(1)
            .ok_or_else(|| AuditError::Format("seq overflow".into()))?;
        Ok((next, prev_hash))
    }

    fn write_row(&self, row: &AuditRow) -> Result<(), AuditError> {
        let paths =
            serde_json::to_string(&row.paths).map_err(|err| AuditError::Format(err.to_string()))?;
        let hits = serde_json::to_string(&row.redaction_hits)
            .map_err(|err| AuditError::Format(err.to_string()))?;
        self.conn.execute(
            "
            INSERT INTO audit (
                seq, ts, prev_hash, row_hash, token_id, principal, peer_uid, peer_pid,
                vault_id, op, paths, argv0, argv_hash, exit_code, redaction_hits,
                outcome, custody, hosts
            ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18
            )
            ",
            params![
                row.seq,
                row.ts,
                row.prev_hash.as_slice(),
                row.row_hash.as_slice(),
                row.token_id,
                row.principal,
                row.peer_uid.map(i64::from),
                row.peer_pid.map(i64::from),
                row.vault_id,
                row.op,
                paths,
                row.argv0,
                row.argv_hash.as_slice(),
                row.exit_code.map(i64::from),
                hits,
                row.outcome,
                i64::from(u8::from(row.custody)),
                row.hosts,
            ],
        )?;
        Ok(())
    }

    fn load_all(&self) -> Result<Vec<AuditRow>, AuditError> {
        let mut stmt = self.conn.prepare(
            "
            SELECT seq, ts, prev_hash, row_hash, token_id, principal, peer_uid, peer_pid,
                   vault_id, op, paths, argv0, argv_hash, exit_code, redaction_hits,
                   outcome, custody, hosts
            FROM audit
            ORDER BY seq
            ",
        )?;
        let rows = stmt.query_map([], read_sql_row)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }
}

/// `BLAKE3("geode/v1/audit-argv" ‖ argv0 ‖ 0x00 ‖ arg ‖ …)`.
#[must_use]
pub fn hash_clean_argv(argv0: &str, args: &[&str]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ARGV_DOMAIN);
    hasher.update(argv0.as_bytes());
    for arg in args {
        hasher.update(&[0x00]);
        hasher.update(arg.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

/// `BLAKE3("geode/v1/audit-argv-rejected" ‖ exe)`. The raw argv is not an input.
#[must_use]
pub fn hash_rejected_argv(exe: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(REJECTED_DOMAIN);
    hasher.update(exe.as_bytes());
    *hasher.finalize().as_bytes()
}

/// Canonical JSON of every field except `row_hash`.
pub fn canonical_row(row: &AuditRow) -> Result<Vec<u8>, AuditError> {
    let value = row_value(row);
    canonicalize(&value).map_err(|err| AuditError::Format(err.to_string()))
}

/// Allowlisted Facet mirror. Includes `seq` and `row_hash`. Omits `plain_bytes`.
#[must_use]
pub fn facet_event(row: &AuditRow) -> serde_json::Value {
    let mut value = row_value(row);
    if let Some(obj) = value.as_object_mut() {
        obj.insert(
            "row_hash".to_string(),
            serde_json::Value::String(hex_encode(&row.row_hash)),
        );
    }
    value
}

fn commit_argv(argv: ArgvCommit, outcome: String) -> (String, [u8; 32], String) {
    match argv {
        ArgvCommit::Clean { argv0, args } => {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            let hash = hash_clean_argv(&argv0, &refs);
            drop(args);
            (argv0, hash, outcome)
        }
        ArgvCommit::Rejected { exe } => {
            let hash = hash_rejected_argv(&exe);
            (exe, hash, "argv_rejected".to_string())
        }
    }
}

fn hash_row(prev: &[u8; 32], canonical: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(prev);
    hasher.update(canonical);
    *hasher.finalize().as_bytes()
}

fn row_value(row: &AuditRow) -> serde_json::Value {
    serde_json::json!({
        "seq": row.seq,
        "ts": row.ts,
        "prev_hash": hex_encode(&row.prev_hash),
        "token_id": row.token_id,
        "principal": row.principal,
        "peer_uid": row.peer_uid,
        "peer_pid": row.peer_pid,
        "vault_id": row.vault_id,
        "op": row.op,
        "paths": row.paths,
        "argv0": row.argv0,
        "argv_hash": hex_encode(&row.argv_hash),
        "exit_code": row.exit_code,
        "redaction_hits": row.redaction_hits,
        "outcome": row.outcome,
        "custody": row.custody,
        "hosts": row.hosts,
    })
}

fn read_sql_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditRow> {
    let prev: Vec<u8> = row.get(2)?;
    let row_hash: Vec<u8> = row.get(3)?;
    let argv_hash: Vec<u8> = row.get(12)?;
    let paths_json: String = row.get(10)?;
    let hits_json: String = row.get(14)?;
    let peer_uid: Option<i64> = row.get(6)?;
    let peer_pid: Option<i64> = row.get(7)?;
    let exit_code: Option<i64> = row.get(13)?;
    let custody: i64 = row.get(16)?;
    Ok(AuditRow {
        seq: row.get(0)?,
        ts: row.get(1)?,
        prev_hash: hash32_sql(&prev)?,
        row_hash: hash32_sql(&row_hash)?,
        token_id: row.get(4)?,
        principal: row.get(5)?,
        peer_uid: peer_uid.and_then(|n| u32::try_from(n).ok()),
        peer_pid: peer_pid.and_then(|n| u32::try_from(n).ok()),
        vault_id: row.get(8)?,
        op: row.get(9)?,
        paths: serde_json::from_str(&paths_json).unwrap_or_default(),
        argv0: row.get(11)?,
        argv_hash: hash32_sql(&argv_hash)?,
        exit_code: exit_code.and_then(|n| i32::try_from(n).ok()),
        redaction_hits: serde_json::from_str(&hits_json).unwrap_or_default(),
        outcome: row.get(15)?,
        custody: custody != 0,
        hosts: row.get(17)?,
    })
}

fn hash32_sql(bytes: &[u8]) -> rusqlite::Result<[u8; 32]> {
    let hash: [u8; 32] = bytes.try_into().map_err(|_| {
        rusqlite::Error::FromSqlConversionFailure(
            0,
            rusqlite::types::Type::Blob,
            Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "audit hash is not 32 bytes",
            )),
        )
    })?;
    Ok(hash)
}

fn hash32(bytes: &[u8]) -> Result<[u8; 32], AuditError> {
    bytes
        .try_into()
        .map_err(|_| AuditError::Format("audit hash is not 32 bytes".into()))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUMMY: &str = "sk-dummy-0000QA";

    fn sample(argv: ArgvCommit, outcome: &str) -> AuditInput {
        let mut hits = BTreeMap::new();
        hits.insert("KEY".to_string(), 1);
        AuditInput {
            ts: 1_700_000_000,
            token_id: "tok-1".into(),
            principal: "human:local".into(),
            peer_uid: None,
            peer_pid: Some(42),
            vault_id: "vault".into(),
            op: "run".into(),
            paths: vec!["cfg/dummy.env".into()],
            exit_code: Some(0),
            redaction_hits: hits,
            outcome: outcome.into(),
            custody: false,
            hosts: "unrestricted".into(),
            argv,
        }
    }

    fn chain_in(dir: &Path) -> Chain {
        open(&dir.join("audit.db")).unwrap()
    }

    fn db_has(path: &Path, needle: &str) -> bool {
        let mut files = vec![path.to_path_buf()];
        files.push(path.with_extension("db-wal"));
        let wal = {
            let mut name = path.as_os_str().to_os_string();
            name.push("-wal");
            std::path::PathBuf::from(name)
        };
        files.push(wal);
        files.into_iter().any(|file| {
            std::fs::read(&file)
                .map(|bytes| bytes.windows(needle.len()).any(|w| w == needle.as_bytes()))
                .unwrap_or(false)
        })
    }

    #[test]
    fn chain_starts_at_seq_1_with_zero_prev_hash() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        let appended = chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: vec!["--version".into()],
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        assert!(appended.mirror_ok);
        assert_eq!(appended.row.seq, 1);
        assert_eq!(appended.row.prev_hash, GENESIS_PREV_HASH);
        assert!(chain.verify().is_ok());
        let second = chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: Vec::new(),
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        assert_eq!(second.row.seq, 2);
        assert_eq!(second.row.prev_hash, appended.row.row_hash);
        assert!(chain.verify().is_ok());
    }

    #[test]
    fn tamper_fails_verify_at_that_seq() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: Vec::new(),
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: vec!["a".into()],
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        assert!(chain.verify().is_ok());
        chain
            .conn
            .execute_batch("DROP TRIGGER IF EXISTS audit_no_update")
            .unwrap();
        chain
            .conn
            .execute("UPDATE audit SET outcome = 'tampered' WHERE seq = 2", [])
            .unwrap();
        match chain.verify() {
            Err(AuditError::Verify { seq }) => assert_eq!(seq, 2),
            other => panic!("expected verify failure at seq 2, got {other:?}"),
        }
    }

    #[test]
    fn tamper_of_first_row_fails_at_seq_1() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: Vec::new(),
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        chain
            .conn
            .execute_batch("DROP TRIGGER IF EXISTS audit_no_update")
            .unwrap();
        chain
            .conn
            .execute("UPDATE audit SET hosts = 'tampered' WHERE seq = 1", [])
            .unwrap();
        match chain.verify() {
            Err(AuditError::Verify { seq }) => assert_eq!(seq, 1),
            other => panic!("expected verify failure at seq 1, got {other:?}"),
        }
    }

    #[test]
    fn rejected_argv_hash_omits_the_raw_argv() {
        let exe = "/bin/echo";
        let dirty = format!("{exe} {DUMMY}");
        let rejected = hash_rejected_argv(exe);
        let clean = hash_clean_argv(exe, &[DUMMY]);
        let mut raw = blake3::Hasher::new();
        raw.update(dirty.as_bytes());
        assert_ne!(rejected, *raw.finalize().as_bytes());
        assert_ne!(rejected, clean);

        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        let appended = chain
            .append(
                sample(ArgvCommit::Rejected { exe: exe.into() }, "ok"),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        assert_eq!(appended.row.outcome, "argv_rejected");
        assert_eq!(appended.row.argv0, exe);
        assert_eq!(appended.row.argv_hash, rejected);
        assert!(!appended.row.custody);
        chain
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let db = dir.path().join("audit.db");
        assert!(!db_has(&db, "sk-dummy"), "db contains sk-dummy");
        assert!(!db_has(&db, DUMMY));
    }

    #[test]
    fn row_and_facet_omit_value_length_and_plain_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        let appended = chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: vec!["--version".into()],
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let canonical = canonical_row(&appended.row).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        assert!(parsed.get("row_hash").is_none());
        assert!(parsed.get("plain_bytes").is_none());
        assert!(parsed.get("plain_len").is_none());
        assert!(parsed.get("argv").is_none());
        let facet = facet_event(&appended.row);
        let text = facet.to_string();
        assert!(facet.get("seq").is_some());
        assert!(facet.get("row_hash").is_some());
        assert!(facet.get("plain_bytes").is_none());
        assert!(!text.contains("plain_bytes"));
        assert!(!text.contains("sk-dummy"));
        assert!(!text.contains(DUMMY));
    }

    #[test]
    fn mirror_failure_keeps_the_sqlite_row() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        let appended = chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: Vec::new(),
                    },
                    "ok",
                ),
                |_| Err::<(), &str>("facet down"),
            )
            .unwrap();
        assert!(!appended.mirror_ok);
        assert!(chain.verify().is_ok());
        let count: i64 = chain
            .conn
            .query_row("SELECT COUNT(*) FROM audit", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, 1);
        chain
            .conn
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        assert!(!db_has(&dir.path().join("audit.db"), "sk-dummy"));
    }

    #[test]
    fn update_is_rejected_until_the_trigger_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let mut chain = chain_in(dir.path());
        chain
            .append(
                sample(
                    ArgvCommit::Clean {
                        argv0: "/bin/true".into(),
                        args: Vec::new(),
                    },
                    "ok",
                ),
                |_| Ok::<(), ()>(()),
            )
            .unwrap();
        let blocked = chain
            .conn
            .execute("UPDATE audit SET outcome = 'nope' WHERE seq = 1", []);
        assert!(blocked.is_err());
    }
}
