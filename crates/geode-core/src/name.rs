//! Filename sealing with HCTR2-256 (02-cryptography 5).
//!
//! G0b: defines the length buckets and the encoding choice. Seal/open
//! stubs fail closed. No HCTR2 is called yet.

use crate::kdf::EpochKey;
use crate::{Error, Result};

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

/// Seal a single path component under the `NameKey` (derived from `EK`).
///
/// G0b stub. G1 will:
/// `pad = BLAKE3-XOF(NameKey, "pad" || parent_id || component)`
/// `      [0 .. bucket-len(component)]`
/// `sealed_plain = le8(len) || component || pad`
/// `tweak = vault_id || le32(epoch) || parent_id`
/// `ciphertext = HCTR2-256(NameKey, tweak, sealed_plain)`
/// `encoded = base32hex(ciphertext)`
pub fn seal_name(_name_key: &EpochKey, _parent_id: &[u8; 16], _component: &str) -> Result<String> {
    Err(Error::NotImplemented)
}

/// Open a sealed, base32hex-encoded name component.
///
/// G0b stub. G1 returns the plaintext component or [`Error::AuthFail`].
/// Wrong key yields garbage names; list still works as ciphertext names.
pub fn open_name(_name_key: &EpochKey, _parent_id: &[u8; 16], _encoded: &str) -> Result<String> {
    Err(Error::NotImplemented)
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
