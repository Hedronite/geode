//! Chunking (02-cryptography 4.1, 4.2; 03-format 4).
//!
//! G0b: defines the allowed chunk sizes and helpers. The actual seal/open
//! is in [`crate::aead`]; chunk I/O lands in G2.

use crate::Error;

/// Default chunk size: 1 MiB (02-cryptography 4.1).
pub const DEFAULT_CHUNK_SIZE: u32 = 1 << 20;

/// Allowed chunk sizes (02-cryptography 4.1): 64 KiB, 256 KiB, 1 MiB, 4 MiB.
pub const ALLOWED_CHUNK_SIZES: &[u32] = &[64 << 10, 256 << 10, 1 << 20, 4 << 20];

/// Validate a chunk size against the allowed set (02-cryptography 4.1).
pub fn validate_chunk_size(chunk_size: u32) -> Result<(), Error> {
    if ALLOWED_CHUNK_SIZES.contains(&chunk_size) {
        Ok(())
    } else {
        Err(Error::Format(format!(
            "chunk_size {chunk_size} not in allowed set {{64KiB, 256KiB, 1MiB, 4MiB}}"
        )))
    }
}

/// Number of chunks for `plain_len` bytes at `chunk_size` (02-cryptography 4.1).
/// Empty file -> 0 chunks (header-only object).
#[must_use]
pub fn chunk_count(plain_len: u64, chunk_size: u32) -> u32 {
    if plain_len == 0 {
        return 0;
    }
    let cs = u64::from(chunk_size);
    u32::try_from(plain_len.div_ceil(cs)).expect("plain_len capped at 2^63-1; chunk_count fits u32")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_allowed() {
        assert!(validate_chunk_size(DEFAULT_CHUNK_SIZE).is_ok());
    }

    #[test]
    fn rejects_off_size() {
        assert!(validate_chunk_size(100).is_err());
    }

    #[test]
    fn empty_is_zero_chunks() {
        assert_eq!(chunk_count(0, DEFAULT_CHUNK_SIZE), 0);
    }

    #[test]
    fn exactly_one_chunk_at_boundary() {
        assert_eq!(
            chunk_count(u64::from(DEFAULT_CHUNK_SIZE), DEFAULT_CHUNK_SIZE),
            1
        );
    }

    #[test]
    fn rounds_up() {
        assert_eq!(
            chunk_count(u64::from(DEFAULT_CHUNK_SIZE) + 1, DEFAULT_CHUNK_SIZE),
            2
        );
    }
}
