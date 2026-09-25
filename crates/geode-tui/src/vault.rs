//! `vault.rs` — in-process read side over `geode-grotto` (v0.2.0 G5b).
//!
//! The TUI is an adapter over `geode-grotto`, never a shell-and-parse of
//! `geode` (14-tui §1.1). This module orchestrates the library calls the
//! CLI's `cmd` module makes — key resolution, `GKEY` unwrap, vault open
//! (sentinel + header + manifest MAC), verify (cheap/full), and a bounded
//! preview — so the TUI can inspect/verify/list/preview a real vault with
//! no crypto logic of its own. Every AEAD/MAC/KDF operation is delegated
//! to `geode-grotto`; this file only reads files, wires arguments, and
//! compares MACs the library computes.
//!
//! Secret discipline (14-tui §4): [`open`] consumes the ISK by value and
//! hands it to [`geode_grotto::session::Session::unlock`], which derives
//! EK and **zeroizes ISK before returning**. The session holds only EK +
//! public ids. [`Preview`] plaintext is held in a [`zeroize::Zeroizing`]
//! buffer dropped (zeroized) on row change, close, or lock. No ISK/EK/
//! passphrase is ever painted; only public ids leave this module.

#![cfg_attr(not(feature = "tui"), allow(dead_code))]

use std::path::{Path, PathBuf};

use geode_grotto::aead::{self, ChunkAd};
use geode_grotto::kdf::{
    self, derive_manifest_key, Epoch, EpochKey, IdentitySecret, KeyId, VaultId,
};
use geode_grotto::manifest::{self, Manifest};
use geode_grotto::object::{self, ObjectHeader};
use geode_grotto::session::{Session, DEFAULT_IDLE_LOCK};
use geode_grotto::vault as corevault;
use geode_grotto::{wrap, Error, Result};
use zeroize::Zeroize as _;

/// Preview byte cap (14-tui §8.2; 06 §4 default `max_bytes`). A single
/// bounded buffer — overwritten on the next open, zeroized on close/row
/// change. There is no preview scrollback (14-tui §4 scrollback rule).
pub const PREVIEW_MAX_BYTES: u64 = 64 * 1024;

const GKEY_VERSION: u8 = 1;
const GKEY_KIND_RAW: u8 = 0x00;
const GKEY_KIND_WRAP: u8 = 0x01;

/// Lowercase hex (public chrome only — never fed secret bytes).
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX_CHARS[(b >> 4) as usize] as char);
        out.push(HEX_CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Truncate a hex string for footer chrome, e.g. `ab3f…9c`.
#[must_use]
pub fn hex_short(bytes: &[u8]) -> String {
    let h = hex(bytes);
    if h.len() <= 8 {
        h
    } else {
        format!("{}…{}", &h[..4], &h[h.len() - 2..])
    }
}

fn unhex(s: &str, out: &mut [u8]) -> Result<()> {
    if s.len() != out.len() * 2 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Format(format!("bad hex length/chars: {s}")));
    }
    let nibble = |c: u8| -> Result<u8> {
        Ok(match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => return Err(Error::Format("non-hex char".into())),
        })
    };
    let b = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = (nibble(b[i * 2])? << 4) | nibble(b[i * 2 + 1])?;
    }
    Ok(())
}

/// Resolve the identity key path: `--key`/`GEODE_KEY_FILE`, else the XDG
/// default **when it exists** (G0b hygiene). A missing key is a usage
/// error (exit 1), not auth.
fn resolve_key_path(key: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = key {
        return Ok(p.to_path_buf());
    }
    if let Some(p) = std::env::var_os("GEODE_KEY_FILE") {
        return Ok(PathBuf::from(p));
    }
    match geode_grotto::keyfile::default_key_path() {
        Some(p) if p.exists() => Ok(p),
        _ => Err(Error::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no --key / GEODE_KEY_FILE and no XDG default key",
        ))),
    }
}

/// Passphrase for wrapped `GKEY`: `GEODE_PASSPHRASE` when set (the startup
/// warning already fired in `geode`'s `main`), else a no-echo prompt.
fn passphrase() -> Result<zeroize::Zeroizing<String>> {
    if let Some(p) = std::env::var_os("GEODE_PASSPHRASE") {
        return Ok(zeroize::Zeroizing::new(p.to_string_lossy().into_owned()));
    }
    let p = rpassword::prompt_password("passphrase: ").map_err(Error::Io)?;
    Ok(zeroize::Zeroizing::new(p))
}

/// Load an identity key file (02-cryptography 6): raw form (6.1) and
/// passphrase-wrapped form (6.2). Permissions are checked before any byte
/// is read (`geode-grotto::keyfile`). Mirrors the CLI `cmd::load_isk`.
fn load_isk(path: &Path) -> Result<IdentitySecret> {
    let raw = geode_grotto::keyfile::load_key_file_bytes(path)?;
    if raw.len() < 6 {
        return Err(Error::Format("key file too short".into()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&raw[0..4]);
    geode_grotto::assert_magic(&magic, geode_grotto::MAGIC_GKEY)?;
    if raw[4] != GKEY_VERSION {
        return Err(Error::Format(format!(
            "unsupported GKEY version {}",
            raw[4]
        )));
    }
    match raw[5] {
        GKEY_KIND_RAW => {
            if raw.len() != 6 + 32 + 16 {
                return Err(Error::Format("raw GKEY wrong length".into()));
            }
            let mut isk = [0u8; 32];
            isk.copy_from_slice(&raw[6..38]);
            let sum = blake3::hash(&isk);
            if raw[38..54] != sum.as_bytes()[..16] {
                return Err(Error::AuthFail);
            }
            let id = IdentitySecret::from_bytes(isk);
            isk.zeroize();
            Ok(id)
        }
        GKEY_KIND_WRAP => {
            // 02-cryptography 6.2: salt[16] m u32 t u32 p u32 nonce[32]
            // tag[16] wrapped_isk[32] — 114 bytes total.
            if raw.len() != 6 + 16 + 12 + 32 + 16 + 32 {
                return Err(Error::Format("wrapped GKEY wrong length".into()));
            }
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&raw[6..22]);
            let u32le = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().expect("4"));
            let mut nonce = [0u8; 32];
            nonce.copy_from_slice(&raw[34..66]);
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&raw[66..82]);
            let mut wrapped = [0u8; 32];
            wrapped.copy_from_slice(&raw[82..114]);
            let wk = wrap::WrappedKey {
                salt: wrap::WrapSalt(salt),
                argon2_m_kib: u32le(22),
                argon2_t: u32le(26),
                argon2_p: u32le(30),
                wrap_nonce: nonce,
                wrap_tag: tag,
                wrapped_isk: wrapped,
            };
            let pass = passphrase()?;
            wrap::unwrap_identity_passphrase(&wk, pass.as_bytes())
        }
        other => Err(Error::Format(format!("unknown GKEY kind 0x{other:02x}"))),
    }
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path).map_err(Error::Io)?;
    serde_json::from_str(&text).map_err(|e| Error::Format(format!("{}: {e}", path.display())))
}

fn json_str<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Format(format!("missing string field {field}")))
}

fn json_u64(value: &serde_json::Value, field: &str) -> Result<u64> {
    value
        .get(field)
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| Error::Format(format!("missing integer field {field}")))
}

/// Path of the manifest for an epoch (03-format 2).
#[must_use]
fn manifest_path(root: &Path, epoch: Epoch) -> PathBuf {
    root.join("epochs")
        .join(format!("{:08}", epoch.0))
        .join("manifest.json")
}

/// Verify `mac_field` (hex) over the JCS-canonicalized JSON minus that
/// field. The MAC itself is computed by `geode-grotto::manifest`; this is
/// orchestration only.
fn verify_json_mac(
    manifest_key: &[u8; 32],
    value: &serde_json::Value,
    mac_field: &str,
) -> Result<()> {
    let mac_hex = json_str(value, mac_field).map_err(|_| Error::AuthFail)?;
    let mut want = [0u8; 16];
    unhex(mac_hex, &mut want).map_err(|_| Error::AuthFail)?;
    let mut body = value.clone();
    if let Some(o) = body.as_object_mut() {
        o.remove(mac_field);
    }
    let canon = manifest::canonicalize(&body)?;
    let got = manifest::manifest_mac(manifest_key, &canon)?;
    if !geode_grotto::zero::ct_eq(&got, &want) {
        return Err(Error::AuthFail);
    }
    Ok(())
}

/// An opened vault: header + manifest MAC-checked, EK held by the session.
///
/// `session` owns EK and zeroizes it on lock/drop. `manifest` is public
/// metadata (paths, sizes, content roots) — never secret. `root` is the
/// on-disk vault directory.
#[derive(Debug)]
pub struct VaultCtx {
    root: PathBuf,
    vault_id: VaultId,
    epoch: Epoch,
    key_id: KeyId,
    session: Session,
    manifest: Manifest,
}

impl VaultCtx {
    /// Public `vault_id` (safe for the footer / logs).
    #[must_use]
    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    /// Public `epoch` (safe for the footer).
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Public `key_id` (safe for the footer / logs).
    #[must_use]
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// Manifest root (public; truncated for chrome by the caller).
    #[must_use]
    pub fn manifest_root(&self) -> [u8; 32] {
        self.manifest.root
    }

    /// Manifest entries (public metadata; the tree pane source).
    #[must_use]
    pub fn entries(&self) -> &[geode_grotto::manifest::Entry] {
        &self.manifest.entries
    }

    /// The on-disk vault root.
    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Borrow the live EK, or `Err(Error::Locked)` after a lock.
    pub fn ek(&self) -> Result<&EpochKey> {
        self.session.ek()
    }

    /// `true` after explicit `L` or idle lock (EK dropped).
    #[must_use]
    pub fn is_locked(&self) -> bool {
        self.session.is_locked()
    }

    /// Mutable session (for idle-lock polling / touch).
    pub(crate) fn session_mut(&mut self) -> &mut Session {
        &mut self.session
    }

    /// Lock now: drop and zeroize EK. Idempotent. The manifest stays in
    /// memory (public); the caller drops the whole ctx to return to the
    /// picker (14-tui §3.3).
    pub fn lock(&mut self) {
        self.session.lock();
    }
}

/// Open and authenticate a vault in-process (14-tui §1.1, §3, §13.3).
///
/// Resolves the identity key, unwraps ISK (zeroized by `Session::unlock`
/// before return), derives EK, and verifies the header + manifest MACs
/// under the manifest key. Any tamper or wrong passphrase surfaces
/// `Error::AuthFail` (exit 2) before the TUI is drawn — fail-closed.
///
/// `key` is `--key` / `GEODE_KEY_FILE`; `None` falls back to the XDG
/// default when it exists. `vault` is the on-disk vault directory.
pub fn open(vault: &Path, key: Option<&Path>) -> Result<VaultCtx> {
    let key_path = resolve_key_path(key)?;
    let isk = load_isk(&key_path)?;

    // Sentinel: cheap "is this even a geode vault" check (03-format 11).
    let sentinel = std::fs::read(vault.join("GEODE")).map_err(Error::Io)?;
    if !sentinel.starts_with(b"GDE1 vault") {
        return Err(Error::Format(format!(
            "{} is not a geode vault",
            vault.display()
        )));
    }

    // header.json is read unauthenticated here; the MAC check below
    // catches any tamper (a wrong vault_id/epoch yields a wrong EK and a
    // mismatched header_mac -> AuthFail). Same property as the CLI path.
    let header = read_json(&vault.join("header.json"))?;
    let mut vid = [0u8; 16];
    unhex(json_str(&header, "vault_id")?, &mut vid)?;
    let vault_id = VaultId(vid);
    let epoch = Epoch(
        u32::try_from(json_u64(&header, "epoch")?)
            .map_err(|_| Error::Format("epoch overflow".into()))?,
    );

    // Session::unlock derives EK from ISK + vault_id + epoch + context and
    // zeroizes ISK before returning. Context label "" matches vault init
    // (04-vault 1); the wrapped EK in recipients.json is this same EK.
    let key_id = kdf::derive_key_id(&isk)?;
    let session = Session::unlock(isk, vault_id, epoch, "", DEFAULT_IDLE_LOCK)?;

    let ek = session.ek()?;
    let mk = derive_manifest_key(ek, vault_id, epoch);
    verify_json_mac(&mk, &header, "header_mac")?;
    let mjson = read_json(&manifest_path(vault, epoch))?;
    verify_json_mac(&mk, &mjson, "manifest_mac")?;
    let mut body = mjson;
    if let Some(o) = body.as_object_mut() {
        o.remove("manifest_mac");
    }
    let manifest: Manifest =
        serde_json::from_value(body).map_err(|e| Error::Format(format!("manifest.json: {e}")))?;

    Ok(VaultCtx {
        root: vault.to_path_buf(),
        vault_id,
        epoch,
        key_id,
        session,
        manifest,
    })
}

/// One chunk record by index (record = `tag[16] || ciphertext`). Mirrors
/// the CLI `cmd::verify::check_chunk`; the AEAD open is `geode-grotto`'s.
fn check_chunk(
    ek: &EpochKey,
    header: &ObjectHeader,
    chunks: &[u8],
    index: u32,
    bind: &[u8],
) -> Result<()> {
    let cs = u64::from(header.chunk_size);
    let mut offset = 0usize;
    for j in 0..=index {
        let this_plain = cs.min(header.plain_len - u64::from(j) * cs);
        let rec_len = 16 + usize::try_from(this_plain).unwrap_or(usize::MAX);
        if j == index {
            let rec = chunks
                .get(offset..offset + rec_len)
                .ok_or(Error::AuthFail)?;
            let ad = ChunkAd {
                suite: header.suite,
                vault_id: header.vault_id,
                epoch: header.epoch,
                object_id: header.object_id,
                chunk_index: u64::from(index),
                plain_len: header.plain_len,
                chunk_size: header.chunk_size,
                path_bind: bind.to_vec(),
            };
            aead::open_chunk(ek, &ad, rec)?;
            return Ok(());
        }
        offset += rec_len;
    }
    Err(Error::AuthFail)
}

/// Verify result reported to the footer / verify pane.
#[derive(Clone, Debug)]
pub struct VerifyReport {
    pub mode: &'static str,
    pub files: u32,
    pub chunks_checked: u64,
}

/// Verify a vault: header tag + manifest/header consistency per object,
/// then chunks. `full` opens every chunk; cheap checks the first and last
/// chunk per object (04-vault 4). Mirrors the CLI `cmd::verify::run`.
pub fn verify(ctx: &VaultCtx, full: bool) -> Result<VerifyReport> {
    let ek = ctx.ek()?;
    let mode = if full { "full" } else { "cheap" };
    let mut chunks_checked = 0u64;

    for e in ctx.entries() {
        let raw = corevault::read_object(ctx.root(), ctx.epoch(), &e.object_id)?;
        if raw.len() < object::HEADER_SIZE {
            return Err(Error::AuthFail);
        }
        let header_bytes = &raw[..object::HEADER_SIZE];
        let chunks = &raw[object::HEADER_SIZE..];
        let header = ObjectHeader::from_bytes(header_bytes)?;
        let want = object::compute_header_tag(ek, &header);
        if want != header.header_tag {
            return Err(Error::AuthFail);
        }
        if header.chunk_count != e.chunk_count
            || header.plain_len != e.plain_len
            || header.object_id != e.object_id
        {
            return Err(Error::AuthFail);
        }
        let bind: &[u8] = if e.bind { e.path.as_bytes() } else { b"" };
        let n = header.chunk_count;
        if full {
            object::open_object(ek, header_bytes, chunks, bind)?;
            chunks_checked += u64::from(n);
        } else if n > 0 {
            check_chunk(ek, &header, chunks, 0, bind)?;
            chunks_checked += 1;
            if n > 1 {
                check_chunk(ek, &header, chunks, n - 1, bind)?;
                chunks_checked += 1;
            }
        }
    }

    Ok(VerifyReport {
        mode,
        files: u32::try_from(ctx.entries().len()).unwrap_or(u32::MAX),
        chunks_checked,
    })
}

/// A bounded preview of one object (14-tui §8). `bytes` is the plaintext
/// prefix (at most `max_bytes`), held in a zeroizing buffer. `hash` is a
/// BLAKE3 digest of the **shown** prefix (the Geode family hash, not a
/// second content root); `truncated` is true when the object was larger
/// than the cap. Cleared/zeroized by the caller on row change, close, lock.
#[derive(Debug)]
pub struct Preview {
    pub path: String,
    pub bytes: zeroize::Zeroizing<Vec<u8>>,
    pub plain_len: u64,
    pub truncated: bool,
    pub hash: [u8; 32],
}

impl Default for Preview {
    fn default() -> Self {
        Self {
            path: String::new(),
            bytes: zeroize::Zeroizing::new(Vec::new()),
            plain_len: 0,
            truncated: false,
            hash: [0u8; 32],
        }
    }
}

/// Preview one object: read, authenticate (open), and bound to `max_bytes`.
/// Binary detection (14-tui §8.4): a non-UTF-8 prefix renders as hex in
/// the pane; the buffer here is raw bytes — the draw layer decides text
/// vs hex. Policy is enforced by `geode_read` upstream of the TUI; for
/// the symmetric `human:local` admin principal every path is readable,
/// and `max_bytes` is always applied.
pub fn preview(ctx: &VaultCtx, path: &str, max_bytes: u64) -> Result<Preview> {
    let ek = ctx.ek()?;
    let want = path.trim_start_matches("./").trim_start_matches('/');
    let entry = ctx
        .entries()
        .iter()
        .find(|e| e.path == want)
        .ok_or_else(|| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("{want} not in manifest"),
            ))
        })?;

    let raw = corevault::read_object(ctx.root(), ctx.epoch(), &entry.object_id)?;
    let bind: &[u8] = if entry.bind {
        entry.path.as_bytes()
    } else {
        b""
    };
    let (_hdr, data) = object::open_object(
        ek,
        &raw[..object::HEADER_SIZE],
        &raw[object::HEADER_SIZE..],
        bind,
    )?;

    let plain_len = u64::try_from(data.len()).unwrap_or(u64::MAX);
    let cap = max_bytes.min(PREVIEW_MAX_BYTES);
    let truncated = plain_len > cap;
    let end = usize::try_from(cap).unwrap_or(usize::MAX).min(data.len());
    let mut shown = Vec::with_capacity(end);
    shown.extend_from_slice(&data[..end]);
    let hash = *blake3::hash(&shown).as_bytes();
    // Drop the full plaintext immediately; only the bounded prefix lives.
    drop(data);

    Ok(Preview {
        path: entry.path.clone(),
        bytes: zeroize::Zeroizing::new(shown),
        plain_len,
        truncated,
        hash,
    })
}

fn manifest_key(ctx: &VaultCtx) -> Result<[u8; 32]> {
    Ok(derive_manifest_key(ctx.ek()?, ctx.vault_id(), ctx.epoch()))
}

/// List + MAC-verify named snapshots. Returns core
/// [`geode_grotto::snapshot::SnapshotEnvelope`] values (14-tui §3: no
/// TUI-only snapshot type). Empty dir → empty vec (§7.4 hint).
pub fn list_snapshots(ctx: &VaultCtx) -> Result<Vec<geode_grotto::snapshot::SnapshotEnvelope>> {
    let mk = manifest_key(ctx)?;
    let names = geode_grotto::snapshot::list_snapshots(ctx.root(), ctx.epoch())?;
    let mut out = Vec::with_capacity(names.len());
    for name in names {
        out.push(geode_grotto::snapshot::read_snapshot(
            ctx.root(),
            ctx.epoch(),
            &name,
            &mk,
        )?);
    }
    Ok(out)
}

/// Create a named snapshot of the current manifest (core envelope).
pub fn create_snapshot(ctx: &VaultCtx, name: &str, created_at: i64) -> Result<PathBuf> {
    let mk = manifest_key(ctx)?;
    geode_grotto::snapshot::create_snapshot(ctx.root(), ctx.epoch(), name, &mk, created_at)
}

/// Restore a named snapshot: verified body is written back to
/// `manifest.json`. Caller must re-open the vault so the tree matches.
pub fn restore_snapshot(ctx: &VaultCtx, name: &str) -> Result<()> {
    let mk = manifest_key(ctx)?;
    let body = geode_grotto::snapshot::restore_snapshot_body(ctx.root(), ctx.epoch(), name, &mk)?;
    let dest = ctx
        .root()
        .join("epochs")
        .join(format!("{:08}", ctx.epoch().0))
        .join("manifest.json");
    corevault::write_atomic(&dest, &body)
}

/// Preview `gc` with no filesystem mutation (`gc_preview`).
pub fn gc_preview(ctx: &VaultCtx) -> Result<geode_grotto::snapshot::GcReport> {
    let mk = manifest_key(ctx)?;
    geode_grotto::snapshot::gc_preview(ctx.root(), ctx.epoch(), &mk)
}

/// Run core `gc` (deletes unreferenced `.gobj` files).
pub fn gc(ctx: &VaultCtx) -> Result<geode_grotto::snapshot::GcReport> {
    let mk = manifest_key(ctx)?;
    geode_grotto::snapshot::gc(ctx.root(), ctx.epoch(), &mk)
}
