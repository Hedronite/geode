//! Filename sealing with HCTR2-256 (02-cryptography 5).
//!
//! Length-preserving, wide-tweakable encryption of a single path component.
//! The component is bucketed to the next size in [`LENGTH_BUCKETS`] with
//! random-looking padding (BLAKE3-XOF keyed by `NameKey`), then sealed with
//! HCTR2-256 keyed by `NameKey` under a per-(vault, epoch, parent) tweak, and
//! finally encoded as base32hex (RFC 4648, lowercase, no padding).
//!
//! # Integrity (manifest MAC first, pad as defense in depth)
//!
//! The authenticated manifest entry is the primary integrity anchor for a
//! sealed name. As a second wall, the opener re-derives the deterministic
//! pad (`BLAKE3-XOF(NameKey, "pad" || parent_id || component)`) from the
//! recovered component and compares it to the decrypted tail in constant
//! time. The pad is `bucket - len` bytes, so a component whose length is
//! exactly the bucket size has **zero** pad bytes and that second wall is
//! empty; correctness then rests on the MAC'd manifest and the HCTR2 tweak.
//! A wrong key or wrong tweak normally lands on a pad mismatch or a
//! non-UTF-8 component (`AuthFail`), but that is not a universal guarantee.
//! Listing still works on ciphertext names without opening.
//!
//! # Determinism leak (documented)
//!
//! Same plaintext name under the same epoch and parent seals to the same
//! ciphertext name. That leak is documented (01-threat-model 5).

use crate::kdf::{Epoch, VaultId};
use crate::{Error, Result};

use crate::hctr2::Hctr2;
use std::sync::OnceLock;

/// Length buckets for name sealing (02-cryptography 5.2).
///
/// `{16,32,48,64,96,128,192,255}`. Names are padded up to the next bucket
/// with random-looking padding so exact name length is hidden to bucket
/// granularity (01-threat-model 5).
pub const LENGTH_BUCKETS: &[usize] = &[16, 32, 48, 64, 96, 128, 192, 255];

/// Pick the smallest bucket >= `len`, or the largest (255) if `len` exceeds it.
/// Components longer than 255 bytes are rejected (02-cryptography 5.2).
pub fn bucket_for_len(len: usize) -> Result<usize> {
    if len > *LENGTH_BUCKETS.last().unwrap() {
        return Err(Error::Format(format!(
            "name component length {len} exceeds max bucket 255"
        )));
    }
    LENGTH_BUCKETS
        .iter()
        .copied()
        .find(|&b| b >= len)
        .ok_or_else(|| Error::Format("no bucket (impossible)".into()))
}

/// Encoding for sealed names: base32hex (RFC 4648, lowercase, no padding)
/// (02-cryptography 5.4). Not base84, not base91.
pub const NAME_ENCODING: &str = "base32hex";

/// HCTR2 block size in bytes (AES block, 128 bits).
const HCTR2_BLOCK: usize = 16;

/// Build the HCTR2 tweak: `vault_id || le32(epoch) || parent_id` (36 bytes).
fn build_tweak(vault_id: &VaultId, epoch: Epoch, parent_id: &[u8; 16]) -> [u8; 36] {
    let mut t = [0u8; 36];
    t[..16].copy_from_slice(&vault_id.0);
    t[16..20].copy_from_slice(&epoch.0.to_le_bytes());
    t[20..36].copy_from_slice(parent_id);
    t
}

/// Deterministic padding: `BLAKE3-XOF(NameKey, "pad" || parent_id || component)`
/// (02-cryptography 5.2). Keyed BLAKE3 in XOF mode; read `pad_len` bytes.
fn name_pad(
    name_key: &[u8; 32],
    parent_id: &[u8; 16],
    component: &[u8],
    pad_len: usize,
) -> Vec<u8> {
    let mut h = blake3::Hasher::new_keyed(name_key);
    h.update(b"pad");
    h.update(parent_id);
    h.update(component);
    let mut xof = h.finalize_xof();
    let mut buf = [0u8; 255];
    xof.fill(&mut buf[..pad_len]);
    buf[..pad_len].to_vec()
}

fn base32hex_encoding() -> &'static data_encoding::Encoding {
    static ENC: OnceLock<data_encoding::Encoding> = OnceLock::new();
    ENC.get_or_init(|| {
        // RFC 4648 base32hex, lowercase, no padding: "0123456789abcdefghijklmnopqrstuv".
        let mut spec = data_encoding::Specification::new();
        spec.symbols.push_str("0123456789abcdefghijklmnopqrstuv");
        spec.padding = None;
        spec.encoding().expect("valid base32hex spec")
    })
}

fn base32hex_encode(bytes: &[u8]) -> String {
    base32hex_encoding().encode(bytes)
}

fn base32hex_decode(s: &str) -> Result<Vec<u8>> {
    base32hex_encoding()
        .decode(s.as_bytes())
        .map_err(|e| Error::Format(format!("base32hex decode: {e}")))
}

/// Build the HCTR2 cipher keyed by `NameKey` (AES-256, since `NameKey` is 32B).
fn name_cipher(name_key: &[u8; 32]) -> Hctr2 {
    Hctr2::new(name_key)
}

/// Seal a path component and return the raw HCTR2 ciphertext bytes
/// (02-cryptography 5). `seal_name` base32hex-encodes this; this variant
/// is for callers (and vector generation) that want the raw ciphertext.
pub fn seal_name_ciphertext(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    parent_id: &[u8; 16],
    component: &str,
) -> Result<Vec<u8>> {
    let comp = component.as_bytes();
    let bucket = bucket_for_len(comp.len())?;
    // sealed_plain = le8(len) || component || pad ; length = 1 + bucket.
    let pad = name_pad(name_key, parent_id, comp, bucket - comp.len());
    let mut sealed = Vec::with_capacity(1 + bucket);
    sealed.push(u8::try_from(comp.len()).map_err(|_| {
        Error::Format("name component length overflows u8 (impossible; bucket<=255)".into())
    })?);
    sealed.extend_from_slice(comp);
    sealed.extend_from_slice(&pad);
    debug_assert_eq!(sealed.len(), 1 + bucket);
    // HCTR2 requires input >= BLOCK_SIZE (16B); 1 + bucket >= 1 + 16 = 17.
    debug_assert!(sealed.len() >= HCTR2_BLOCK);

    let tweak = build_tweak(vault_id, epoch, parent_id);
    let mut ct = vec![0u8; sealed.len()];
    name_cipher(name_key).encrypt(&mut ct, &sealed, &tweak);
    Ok(ct)
}

/// Seal a single path component under `NameKey` (02-cryptography 5) and
/// return the base32hex (RFC 4648, lowercase, no padding) ciphertext name.
///
/// `name_key`  = `BLAKE3-KDF(EK, "geode/v1/name-key", vault_id || le32(epoch))`
/// `tweak`     = `vault_id || le32(epoch) || parent_id`
/// `pad`       = `BLAKE3-XOF(NameKey, "pad" || parent_id || component)`
///                `[0 .. bucket-len(component)]`
/// `sealed_plain = le8(len) || component || pad`
/// `ciphertext   = HCTR2-256(NameKey, tweak, sealed_plain)`
/// `encoded      = base32hex(ciphertext)`
///
/// `parent_id` is the 16-byte id of the parent directory object; the root
/// parent is `0x00*16`. Returns the base32hex ciphertext name.
pub fn seal_name(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    parent_id: &[u8; 16],
    component: &str,
) -> Result<String> {
    let ct = seal_name_ciphertext(name_key, vault_id, epoch, parent_id, component)?;
    Ok(base32hex_encode(&ct))
}

/// Open a sealed name given the raw HCTR2 ciphertext bytes (02-cryptography 5).
/// `open_name` base32hex-decodes first; this variant takes ciphertext directly.
pub fn open_name_ciphertext(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    parent_id: &[u8; 16],
    ciphertext: &[u8],
) -> Result<String> {
    // HCTR2 minimum is one block; sealed_plain is 1 + bucket >= 17.
    if ciphertext.len() < HCTR2_BLOCK + 1 {
        return Err(Error::AuthFail);
    }
    let bucket = ciphertext.len() - 1;
    if !LENGTH_BUCKETS.contains(&bucket) {
        return Err(Error::AuthFail);
    }

    let tweak = build_tweak(vault_id, epoch, parent_id);
    let mut plain = vec![0u8; ciphertext.len()];
    name_cipher(name_key).decrypt(&mut plain, ciphertext, &tweak);

    let len = usize::from(plain[0]);
    if len > bucket {
        return Err(Error::AuthFail);
    }
    let comp_bytes = &plain[1..=len];
    let component = std::str::from_utf8(comp_bytes).map_err(|_| Error::AuthFail)?;

    // Re-derive the pad from the recovered component and verify the tail.
    let pad = name_pad(name_key, parent_id, comp_bytes, bucket - len);
    if !crate::zero::ct_eq(&plain[1 + len..], &pad[..]) {
        return Err(Error::AuthFail);
    }

    Ok(component.to_string())
}

/// Open a sealed, base32hex-encoded name component (02-cryptography 5).
///
/// Decrypts with `NameKey` + tweak, recovers `len`, slices the component,
/// re-derives the pad and compares it to the decrypted tail. Any mismatch
/// (bad length, bad bucket, non-UTF-8, pad mismatch) => [`Error::AuthFail`].
pub fn open_name(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    parent_id: &[u8; 16],
    encoded: &str,
) -> Result<String> {
    let ct = base32hex_decode(encoded)?;
    open_name_ciphertext(name_key, vault_id, epoch, parent_id, &ct)
}

/// `parent_id` for one path component (02-cryptography 5.3).
///
/// The root component uses `0x00*16`. Directory objects do not exist, so a
/// deeper component's parent id is `BLAKE3(sealed parent path)[0..16]`.
/// The golden vectors under `vectors/v1/name.json` carry raw `parent_id`
/// bytes for their fixed inputs; they do not derive them. The unit test
/// `parent_id_golden` pins this function's exact output bytes.
#[must_use]
pub fn parent_id(sealed_parent: Option<&str>) -> [u8; 16] {
    match sealed_parent {
        None => [0u8; 16],
        Some(parent) => {
            let digest = blake3::hash(parent.as_bytes());
            let mut id = [0u8; 16];
            id.copy_from_slice(&digest.as_bytes()[..16]);
            id
        }
    }
}

/// Seal every component of a vault-relative plaintext path (02-cryptography
/// 5). Components join with `/`; each is sealed under its parent's id.
pub fn seal_rel_path(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    rel: &str,
) -> Result<String> {
    let mut sealed: Vec<String> = Vec::new();
    for component in rel.split('/') {
        let parent = sealed.join("/");
        let pid = if sealed.is_empty() {
            parent_id(None)
        } else {
            parent_id(Some(&parent))
        };
        sealed.push(seal_name(name_key, vault_id, epoch, &pid, component)?);
    }
    Ok(sealed.join("/"))
}

/// Open a sealed vault-relative path back to plaintext components.
pub fn open_rel_path(
    name_key: &[u8; 32],
    vault_id: &VaultId,
    epoch: Epoch,
    sealed: &str,
) -> Result<String> {
    let mut plain: Vec<String> = Vec::new();
    let mut sealed_components: Vec<String> = Vec::new();
    for component in sealed.split('/') {
        let parent = sealed_components.join("/");
        let pid = if sealed_components.is_empty() {
            parent_id(None)
        } else {
            parent_id(Some(&parent))
        };
        plain.push(open_name(name_key, vault_id, epoch, &pid, component)?);
        sealed_components.push(component.to_string());
    }
    Ok(plain.join("/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nk() -> [u8; 32] {
        [
            0x09, 0xad, 0xb2, 0xea, 0x06, 0x17, 0xfa, 0xed, 0x71, 0x7c, 0x63, 0xb9, 0xa9, 0xec,
            0x8e, 0xf0, 0x08, 0x49, 0x72, 0x22, 0x4a, 0x19, 0x6c, 0x5f, 0xc6, 0xa9, 0x0d, 0x11,
            0xfc, 0xff, 0x27, 0x54,
        ]
    }
    fn vid() -> VaultId {
        VaultId([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ])
    }
    const EP: Epoch = Epoch(1);
    const ROOT_PARENT: [u8; 16] = [0u8; 16];

    #[test]
    fn bucket_picks_next_up() {
        assert_eq!(bucket_for_len(1).unwrap(), 16);
        assert_eq!(bucket_for_len(16).unwrap(), 16);
        assert_eq!(bucket_for_len(17).unwrap(), 32);
        assert_eq!(bucket_for_len(200).unwrap(), 255);
    }

    #[test]
    fn bucket_rejects_too_long() {
        assert!(bucket_for_len(256).is_err());
    }

    /// Ruling 2 Option A: a component whose length equals the bucket has a
    /// zero-byte tail pad. The opener still accepts it deterministically; the
    /// MACd manifest is the primary integrity anchor for that case. This test
    /// pins the exact boundary rather than guessing with random tweaks.
    /// Exact output bytes for the parent-id chain. `vectors/v1/name.json`
    /// carries raw parent ids; this test pins how they are derived.
    #[test]
    fn parent_id_golden() {
        assert_eq!(parent_id(None), [0u8; 16]);
        assert_eq!(
            parent_id(Some("docs")),
            [
                0xc2, 0x82, 0x4b, 0x75, 0x61, 0x4d, 0x9c, 0x2b, 0xb4, 0xc0, 0xb7, 0xf9, 0x83, 0xac,
                0x07, 0x53,
            ]
        );
    }

    /// Exact sealed ciphertext for `a/b` under the test key, vault, and epoch.
    #[test]
    fn seal_rel_path_golden() {
        assert_eq!(
            seal_rel_path(&nk(), &vid(), EP, "a/b").unwrap(),
            "ao3vd8s5ni6jbvqefjdo1e8occ10/c10u6umh8d0gi3h71luskcphj780"
        );
    }

    #[test]
    fn exact_bucket_zero_pad_opens_deterministically() {
        let component = b"0123456789abcdef"; // 16 bytes == the 16 bucket
        let mut sealed_plain = vec![16u8];
        sealed_plain.extend_from_slice(component);
        let tweak = build_tweak(&vid(), EP, &ROOT_PARENT);
        let mut ciphertext = vec![0u8; sealed_plain.len()];
        name_cipher(&nk()).encrypt(&mut ciphertext, &sealed_plain, &tweak);
        assert_eq!(
            open_name_ciphertext(&nk(), &vid(), EP, &ROOT_PARENT, &ciphertext).unwrap(),
            "0123456789abcdef"
        );
    }

    #[test]
    fn round_trip_root_short() {
        let sealed = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "hello").unwrap();
        let opened = open_name(&nk(), &vid(), EP, &ROOT_PARENT, &sealed).unwrap();
        assert_eq!(opened, "hello");
    }

    #[test]
    fn round_trip_bucket_boundary() {
        let c16 = "0123456789abcdef";
        let s = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, c16).unwrap();
        assert_eq!(open_name(&nk(), &vid(), EP, &ROOT_PARENT, &s).unwrap(), c16);
        let c17 = "0123456789abcdefg";
        let s2 = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, c17).unwrap();
        assert_eq!(
            open_name(&nk(), &vid(), EP, &ROOT_PARENT, &s2).unwrap(),
            c17
        );
    }

    #[test]
    fn round_trip_unicode() {
        let c = "héllo🌍";
        let s = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, c).unwrap();
        assert_eq!(open_name(&nk(), &vid(), EP, &ROOT_PARENT, &s).unwrap(), c);
    }

    #[test]
    fn round_trip_max_bucket() {
        let c = "x".repeat(255);
        let s = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, &c).unwrap();
        assert_eq!(open_name(&nk(), &vid(), EP, &ROOT_PARENT, &s).unwrap(), c);
    }

    #[test]
    fn determinism_same_inputs_same_ciphertext() {
        let a = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        let b = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        assert_eq!(
            a, b,
            "same (key,epoch,parent,component) MUST be deterministic"
        );
    }

    #[test]
    fn different_parent_yields_different_ciphertext() {
        let a = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        let mut p = [0u8; 16];
        p[0] = 1;
        let b = seal_name(&nk(), &vid(), EP, &p, "secret").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_epoch_yields_different_ciphertext() {
        let a = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        let b = seal_name(&nk(), &vid(), Epoch(2), &ROOT_PARENT, "secret").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn different_key_yields_different_ciphertext() {
        let a = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        let mut k2 = nk();
        k2[0] ^= 1;
        let b = seal_name(&k2, &vid(), EP, &ROOT_PARENT, "secret").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn bit_flip_in_ciphertext_is_auth_fail() {
        let sealed = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "hello").unwrap();
        let mut ct = base32hex_decode(&sealed).unwrap();
        // Flip every bit of the first ciphertext byte: HCTR2 diffuses this
        // across the whole block, so len/pad/UTF-8 checks must fail.
        ct[0] ^= 0xff;
        let tampered = base32hex_encode(&ct);
        let r = open_name(&nk(), &vid(), EP, &ROOT_PARENT, &tampered);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "bit-flip MUST be AuthFail, got {r:?}"
        );
    }

    #[test]
    fn bit_flip_in_tail_is_auth_fail() {
        let sealed = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "hello").unwrap();
        let mut ct = base32hex_decode(&sealed).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        let tampered = base32hex_encode(&ct);
        let r = open_name(&nk(), &vid(), EP, &ROOT_PARENT, &tampered);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "tail bit-flip MUST be AuthFail, got {r:?}"
        );
    }

    #[test]
    fn wrong_key_is_auth_fail() {
        let sealed = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "hello").unwrap();
        let mut k2 = nk();
        k2[0] ^= 1;
        let r = open_name(&k2, &vid(), EP, &ROOT_PARENT, &sealed);
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "wrong key MUST be AuthFail (fail-closed)"
        );
    }

    #[test]
    fn wrong_tweak_is_auth_fail() {
        let sealed = seal_name(&nk(), &vid(), EP, &ROOT_PARENT, "hello").unwrap();
        let mut p = [0u8; 16];
        p[0] = 1;
        let r = open_name(&nk(), &vid(), EP, &p, &sealed);
        assert!(matches!(r, Err(Error::AuthFail)));
        let r2 = open_name(&nk(), &vid(), Epoch(2), &ROOT_PARENT, &sealed);
        assert!(matches!(r2, Err(Error::AuthFail)));
    }

    #[test]
    fn bad_base32hex_is_format_error() {
        let r = open_name(&nk(), &vid(), EP, &ROOT_PARENT, "not-valid-base32!@#");
        assert!(matches!(r, Err(Error::Format(_))));
    }

    #[test]
    fn too_short_ciphertext_is_auth_fail() {
        // 16 bytes (one block) is below the 1 + min_bucket = 17 minimum.
        let ct = vec![0u8; 16];
        let r = open_name(&nk(), &vid(), EP, &ROOT_PARENT, &base32hex_encode(&ct));
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn unknown_bucket_length_is_auth_fail() {
        // 18 bytes => bucket 17, not in LENGTH_BUCKETS.
        let ct = vec![0u8; 18];
        let r = open_name(&nk(), &vid(), EP, &ROOT_PARENT, &base32hex_encode(&ct));
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    use proptest::prelude::*;
    proptest! {
        #[test]
        fn rp3_name_roundtrip(comp in prop::collection::vec(any::<u8>(),1..64).prop_filter("utf8",|v| std::str::from_utf8(v).is_ok())) {
            let c = std::str::from_utf8(&comp).unwrap(); prop_assume!(c.len()<=255);
            let nk=[0x5a;32]; let vid=VaultId([0x11;16]); let parent=[0u8;16];
            let sealed = seal_name(&nk,&vid,Epoch(1),&parent,c).unwrap();
            prop_assert_eq!(open_name(&nk,&vid,Epoch(1),&parent,&sealed).unwrap(), c);
        }
    }
}
