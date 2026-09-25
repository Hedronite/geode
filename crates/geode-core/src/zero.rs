//! Zeroize discipline (02-cryptography 10, SPEC 3.10).
//!
//! Secret material is held in types that zeroize on drop. `Debug` redacts.

use zeroize::Zeroize;

/// A 32-byte secret held in a zeroizing buffer.
///
/// NEVER printed, logged, or serialized. `Debug` shows only the type name.
#[derive(Clone)]
pub struct Secret32(Box<[u8; 32]>);

impl Secret32 {
    /// Construct from raw bytes. Crate-private so no caller outside the
    /// crypto modules can pretend to hold a key.
    pub(crate) fn new_unchecked(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the raw bytes. Crate-private: no leak across the API surface.
    #[must_use]
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Zeroize for Secret32 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Drop for Secret32 {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl std::fmt::Debug for Secret32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret32(**redacted**)")
    }
}


/// Constant-time equality for tags/checksums.
#[must_use]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq as _;
    a.ct_eq(b).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn debug_never_prints_key_bytes() {
        let s = Secret32::new_unchecked([0xde; 32]);
        assert_eq!(format!("{s:?}"), "Secret32(**redacted**)");
    }
    #[test]
    fn zeroize_clears() {
        let mut s = Secret32::new_unchecked([0xde; 32]);
        s.zeroize();
        assert_eq!(s.as_bytes(), &[0u8; 32]);
    }
}
