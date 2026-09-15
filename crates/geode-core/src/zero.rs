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
