//! Golden vector generator for GDE1 suite 0x01 (CHECKLIST G5a).
//!
//! Produces `vectors/v1/{kdf,chunk,wrap}.json` from THIS implementation so a
//! third implementation can claim compatibility. Inputs are fixed and
//! published; outputs are deterministic given those inputs. The wrap vector
//! uses a fixed salt/nonce via [`wrap_identity_passphrase_with`].
//!
//! Run from the repo root:
//!     `cargo run -p geode-core --example generate_vectors -- vectors/v1`
//!
//! The directory argument defaults to `vectors/v1` relative to the current
//! working directory. Files are written atomically.

use std::path::PathBuf;

use geode_core::aead::{derive_chunk_nonce, seal_chunk, ChunkAd};
use geode_core::kdf::{
    derive_epoch_key, derive_key_id, derive_manifest_key, derive_meta_key, derive_name_key, Epoch,
    EpochKey, IdentitySecret, ObjectId, VaultId,
};
use geode_core::wrap::{
    unwrap_identity_passphrase, wrap_identity_passphrase_with, Argon2Params, WrapSalt,
};
use geode_core::{MAGIC_GKEY, SUITE_0X01};

fn hex(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

fn json_pretty(value: &serde_json::Value) -> String {
    serde_json::to_string_pretty(value).expect("serialize") + "\n"
}

fn write_atomic(dest: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension("json.tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, dest)?;
    Ok(())
}

fn kdf_vector(
    isk_seed: [u8; 16],
    vault_id: [u8; 16],
    epoch: u32,
    label: &str,
) -> serde_json::Value {
    // ISK is 32 bytes; pad the 16-byte seed by repeating it.
    let isk_arr = {
        let mut a = [0u8; 32];
        a[..16].copy_from_slice(&isk_seed);
        a[16..].copy_from_slice(&isk_seed);
        a
    };
    let isk = IdentitySecret::from_bytes(isk_arr);
    let vid = VaultId(vault_id);
    let ep = Epoch(epoch);
    let ek = derive_epoch_key(&isk, vid, ep, label).expect("derive EK");
    let name_key = derive_name_key(&ek, vid, ep);
    let meta_key = derive_meta_key(&ek, vid, ep);
    let manifest_key = derive_manifest_key(&ek, vid, ep);
    let key_id = derive_key_id(&isk).expect("derive key id");

    serde_json::json!({
        "suite": SUITE_0X01,
        "isk": hex(&isk_arr),
        "vault_id": hex(&vault_id),
        "epoch": epoch,
        "context_label": label,
        "ek": hex(ek.as_bytes()),
        "name_key": hex(&name_key),
        "meta_key": hex(&meta_key),
        "manifest_key": hex(&manifest_key),
        "key_id": hex(&key_id.0),
    })
}

#[allow(clippy::too_many_arguments)]
fn chunk_vector(
    ek: &EpochKey,
    vault_id: VaultId,
    epoch: Epoch,
    object_id: ObjectId,
    chunk_index: u64,
    plain_len: u64,
    chunk_size: u32,
    plaintext: &[u8],
    path_bind: &[u8],
) -> serde_json::Value {
    let ad = ChunkAd {
        suite: SUITE_0X01,
        vault_id,
        epoch,
        object_id,
        chunk_index,
        plain_len,
        chunk_size,
        path_bind: path_bind.to_vec(),
    };
    let nonce = derive_chunk_nonce(ek, &object_id, chunk_index, epoch);
    let sealed = seal_chunk(ek, &ad, plaintext).expect("seal chunk");
    let (tag, ciphertext) = sealed.split_at(16);

    serde_json::json!({
        "suite": SUITE_0X01,
        "ek": hex(ek.as_bytes()),
        "vault_id": hex(&vault_id.0),
        "epoch": epoch.0,
        "object_id": hex(&object_id.0),
        "chunk_index": chunk_index,
        "plain_len": plain_len,
        "chunk_size": chunk_size,
        "path_bind": hex(path_bind),
        "ad_bytes": hex(&ad.to_bytes()),
        "nonce": hex(&nonce),
        "plaintext": hex(plaintext),
        "ciphertext": hex(ciphertext),
        "tag": hex(tag),
    })
}

fn wrap_vector(
    isk_arr: [u8; 32],
    passphrase: &[u8],
    salt: [u8; 16],
    wrap_nonce: [u8; 32],
    params: Argon2Params,
) -> serde_json::Value {
    let isk = IdentitySecret::from_bytes(isk_arr);
    let wrapped =
        wrap_identity_passphrase_with(&isk, passphrase, WrapSalt(salt), wrap_nonce, params)
            .expect("wrap");
    // Round-trip: right passphrase recovers, wrong passphrase is AuthFail.
    let recovered = unwrap_identity_passphrase(&wrapped, passphrase).expect("unwrap");
    assert_eq!(recovered.as_bytes(), &isk_arr, "wrap round-trip broke");
    let wrong = unwrap_identity_passphrase(&wrapped, b"wrong passphrase");
    assert!(
        matches!(wrong, Err(geode_core::Error::AuthFail)),
        "wrong passphrase must be AuthFail, got {wrong:?}"
    );

    serde_json::json!({
        "magic": std::str::from_utf8(MAGIC_GKEY).unwrap(),
        "suite": SUITE_0X01,
        "passphrase": std::str::from_utf8(passphrase).expect("utf8 passphrase"),
        "salt": hex(&salt),
        "argon2_m_kib": params.m_kib,
        "argon2_t": params.t,
        "argon2_p": params.p,
        "isk": hex(&isk_arr),
        "wrap_nonce": hex(&wrap_nonce),
        "wrap_tag": hex(&wrapped.wrap_tag),
        "wrapped_isk": hex(&wrapped.wrapped_isk),
    })
}

fn main() {
    let dir: PathBuf = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "vectors/v1".to_string())
        .into();

    // Fixed, published test inputs. NOT secrets: deliberate test material.
    let isk_seed: [u8; 16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f,
    ];
    let vault_id: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    let epoch: u32 = 1;
    let label = "geode-test-vectors-v1";

    // kdf.json
    let kdf = kdf_vector(isk_seed, vault_id, epoch, label);
    write_atomic(&dir.join("kdf.json"), json_pretty(&kdf).as_bytes()).expect("write kdf.json");

    // Reconstruct EK for the chunk vector from the same inputs.
    let isk_arr = {
        let mut a = [0u8; 32];
        a[..16].copy_from_slice(&isk_seed);
        a[16..].copy_from_slice(&isk_seed);
        a
    };
    let isk = IdentitySecret::from_bytes(isk_arr);
    let vid = VaultId(vault_id);
    let ep = Epoch(epoch);
    let ek = derive_epoch_key(&isk, vid, ep, label).expect("derive EK");

    // chunk.json: one short chunk exercising the full AD layout + path_bind.
    let object_id = ObjectId([
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae,
        0xaf,
    ]);
    let chunk_size: u32 = 1 << 20; // 1 MiB
    let plaintext0 = b"hello, geode"; // 12 bytes
    let path_bind = b"/vault/objects/a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";

    let chunk0 = chunk_vector(
        &ek,
        vid,
        ep,
        object_id,
        0,
        u64::try_from(plaintext0.len()).unwrap(),
        chunk_size,
        plaintext0,
        path_bind,
    );
    let chunk_doc = serde_json::json!({
        "suite": SUITE_0X01,
        "chunks": [chunk0],
    });
    write_atomic(&dir.join("chunk.json"), json_pretty(&chunk_doc).as_bytes())
        .expect("write chunk.json");

    // wrap.json: deterministic salt/nonce so the vector is reproducible.
    let wrap_salt: [u8; 16] = [
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e,
        0x3f,
    ];
    let wrap_nonce: [u8; 32] = [
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e,
        0x4f, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d,
        0x5e, 0x5f,
    ];
    let passphrase = b"correct horse battery staple";
    let wrap = wrap_vector(
        isk_arr,
        passphrase,
        wrap_salt,
        wrap_nonce,
        Argon2Params::DEFAULT_CHEAP,
    );
    write_atomic(&dir.join("wrap.json"), json_pretty(&wrap).as_bytes()).expect("write wrap.json");

    println!(
        "wrote {kdf} {chunk} {wrap}",
        kdf = dir.join("kdf.json").display(),
        chunk = dir.join("chunk.json").display(),
        wrap = dir.join("wrap.json").display(),
    );
}
