//! Zeroize discipline (02-cryptography 10, SPEC 3.10).
//!
//! Secret material is held in types that zeroize on drop. G0b defines the
//! wrappers; G1 fills them with real key bytes.

use zeroize::Zeroize;

/// A 32-byte secret held in a zeroizing buffer.
///
/// NEVER printed, logged, or serialized. `Debug` shows only the type name.
/// G0b: construction is stubbed; G1 derives real ISK / EK / FEK into this.
#[derive(Clone)]
pub struct Secret32(Box<[u8; 32]>);

impl Secret32 {
    /// G0b stub: real construction lands in G1 (ISK from key file, EK from
    /// KDF). This constructor is intentionally not public so no caller can
    /// pretend to have a key.
    #[allow(dead_code)] // G0b: used by G1 KDF / wrap paths.
    pub(crate) fn new_unchecked(bytes: [u8; 32]) -> Self {
        Self(Box::new(bytes))
    }

    /// Borrow the raw bytes. Crate-private: no leak across the API surface.
    #[allow(dead_code)] // G0b: used by G1 seal/open/wrap paths.
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

/// Marker: types that hold secret material and MUST NOT appear in logs,
/// manifests, Facet, Lattice, or stdout. See 01-threat-model 6.2.
pub trait Sealed: Zeroize {}
impl Sealed for Secret32 {}
