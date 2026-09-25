//! G5b — in-process operator over `geode-grotto` (frontend-geode).
//!
//! Builds a real vault with the `geode` CLI (subprocess), then drives the
//! TUI's read side — `geode_tui::vault::open`, `verify` (cheap + full),
//! and `preview` — **in-process** via `geode-grotto`. This is the 14-tui
//! §1.1 contract: the TUI calls the library, never spawns `geode` and
//! parses its stdout. The CLI is used only to *build* the fixture; the
//! assertions exercise the library path the TUI uses.
//!
//! Also covers fail-closed (14-tui §13.2): a flipped ciphertext bit makes
//! `verify` return `AuthFail` (exit 2 family), never a "looks fine".

#![allow(clippy::cast_possible_truncation)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use geode_grotto::object;
use std::fmt::Write as _;

/// Path to the built `geode` binary (same fallback as the CLI tests).
fn geode_bin() -> PathBuf {
    let mut tried: Vec<String> = Vec::new();
    for key in ["CARGO_BIN_EXE_GEO_DE", "CARGO_BIN_EXE_geode"] {
        if let Ok(p) = std::env::var(key) {
            let pb = PathBuf::from(&p);
            tried.push(format!("{key}={p}"));
            if pb.is_file() {
                return pb;
            }
        }
    }
    if let Ok(td) = std::env::var("CARGO_TARGET_DIR") {
        let pb = PathBuf::from(&td).join("debug/geode");
        tried.push(format!("CARGO_TARGET_DIR/debug/geode={}", pb.display()));
        if pb.is_file() {
            return pb;
        }
    }
    let target_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target");
    let default_pb = target_root.join("debug/geode");
    tried.push(format!("manifest fallback={}", default_pb.display()));
    if default_pb.is_file() {
        return default_pb;
    }
    if let Ok(entries) = std::fs::read_dir(&target_root) {
        for entry in entries.flatten() {
            if entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                let pb = entry.path().join("debug/geode");
                tried.push(format!("target scan={}", pb.display()));
                if pb.is_file() {
                    return pb;
                }
            }
        }
    }
    panic!(
        "geode binary not found; tried:
  {}",
        tried.join(
            "
  "
        )
    );
}

struct Fixture {
    _tmp: tempfile::TempDir,
    root: PathBuf,
    key: PathBuf,
    vault: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path().to_path_buf();
        let key = root.join("id.gkey");
        let vault = root.join("notes.geode");
        Self {
            _tmp: tmp,
            root,
            key,
            vault,
        }
    }

    fn build(&self) -> String {
        // Raw identity key (no passphrase) so the in-process open path is
        // headless — no tty prompt. `keygen` takes PATH as a positional.
        let k = Command::new(geode_bin())
            .args(["keygen"])
            .arg(&self.key)
            .output()
            .expect("keygen");
        assert!(k.status.success(), "keygen failed");
        // init takes the vault dir as a positional.
        let init = Command::new(geode_bin())
            .args(["vault", "init"])
            .arg(&self.vault)
            .arg("--key")
            .arg(&self.key)
            .output()
            .expect("vault init");
        assert!(init.status.success(), "vault init failed");
        // Seal a *directory* so the manifest entry path is "hello.txt"
        // (sealing a bare file yields an empty rel-path).
        let src_dir = self.root.join("src");
        fs::create_dir_all(&src_dir).expect("mkdir src");
        fs::write(src_dir.join("hello.txt"), b"hello world\n").expect("write src");
        let seal = Command::new(geode_bin())
            .args(["seal"])
            .arg(&src_dir)
            .arg(&self.vault)
            .arg("--key")
            .arg(&self.key)
            .output()
            .expect("seal");
        assert!(seal.status.success(), "seal failed");
        "hello.txt".into()
    }
}

fn object_file(vault: &Path, epoch: u32, object_id: &[u8; 16]) -> PathBuf {
    let mut hex = String::with_capacity(32);
    for b in object_id {
        let _ = write!(hex, "{b:02x}");
    }
    vault
        .join("epochs")
        .join(format!("{epoch:08}"))
        .join("objects")
        .join(&hex[..2])
        .join(format!("{hex}.gobj"))
}

#[test]
fn open_verify_preview_in_process() {
    let fx = Fixture::new();
    let path = fx.build();

    // In-process open: the TUI's vault::open authenticates the sentinel,
    // header MAC, and manifest MAC, and unlocks a Session (ISK zeroized).
    let ctx = geode_tui::vault::open(&fx.vault, Some(&fx.key)).expect("open");
    assert_eq!(ctx.epoch().0, 1);
    assert_eq!(ctx.entries().len(), 1, "one sealed object");
    assert!(!ctx.is_locked());

    // Cheap verify (header + manifest MAC + first/last chunk per object).
    let cheap = geode_tui::vault::verify(&ctx, false).expect("cheap verify");
    assert_eq!(cheap.files, 1, "cheap verify reports the file");
    assert!(cheap.chunks_checked >= 1);

    // Full verify (every chunk authenticated).
    let full = geode_tui::vault::verify(&ctx, true).expect("full verify");
    assert_eq!(full.mode, "full");
    assert!(full.chunks_checked >= 1);

    // Explicit bounded preview (14-tui §8): plaintext prefix only.
    let p = geode_tui::vault::preview(&ctx, &path, 64).expect("preview");
    assert_eq!(p.plain_len, "hello world\n".len() as u64);
    assert!(!p.truncated);
    assert_eq!(&*p.bytes, b"hello world\n");
    // The preview hash is of the shown prefix (BLAKE3), not a secret.
    assert_eq!(p.hash, *blake3::hash(b"hello world\n").as_bytes());

    // Lock drops EK (14-tui §3.3); the ctx is then inert.
    let mut ctx = ctx;
    ctx.lock();
    assert!(ctx.is_locked());
    assert!(geode_tui::vault::verify(&ctx, false).is_err());
}

#[test]
fn flipped_ciphertext_bit_is_auth_fail() {
    let fx = Fixture::new();
    let path = fx.build();
    let ctx = geode_tui::vault::open(&fx.vault, Some(&fx.key)).expect("open");
    let oid = ctx.entries()[0].object_id.0;

    // Flip one bit in the first ciphertext byte (after the header). The
    // manifest MAC still passes (manifest unchanged); the object header
    // tag / chunk AEAD must catch it.
    let obj = object_file(&fx.vault, ctx.epoch().0, &oid);
    let mut buf = fs::read(&obj).expect("read object");
    let at = object::HEADER_SIZE + 16; // first byte of first ciphertext
    buf[at] ^= 0x01;
    fs::write(&obj, &buf).expect("write object");

    let err = geode_tui::vault::verify(&ctx, true).unwrap_err();
    assert!(
        matches!(err, geode_grotto::Error::AuthFail),
        "flipped bit MUST be AuthFail (exit 2), got {err:?}"
    );
    // The preview path must also fail closed — no "show anyway".
    assert!(geode_tui::vault::preview(&ctx, &path, 64).is_err());
}
