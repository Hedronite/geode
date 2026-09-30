//! Ed25519 identity child and cosign-compatible signing (SPEC-v033 G0).
//!
//! The sibling of the X25519 child the CLI derives in `cmd/key.rs`
//! (02-cryptography 6.3): one ISK, two domain strings, two independent
//! identity keys, one per identity file.
//!
//! ```text
//! seed = blake3::derive_key("geode/v1/ed25519-identity", ISK)
//! ```
//!
//! The key material is the 32-byte ISK alone -- no vault id, no epoch, no
//! label, and NOT the wrap context `geode/v1/identity`. The seed is an
//! RFC 8032 Ed25519 secret key (`SigningKey::from_bytes`); signing covers the
//! **raw** payload bytes: no SHA-256 prehash, no Ed25519ph.
//!
//! The public half is SPKI PEM, header `BEGIN PUBLIC KEY`, DER prefix
//! `302a300506032b6570032100` plus the 32 public bytes -- never PKCS#8
//! private, OpenSSH, or raw bytes. The signature wire form is standard padded
//! base64 of the 64 signature bytes; the caller writes the signature file's
//! single trailing newline. No Sigstore bundle, no Rekor.
//!
//! # Secret discipline
//!
//! The seed lives only inside `ed25519-dalek`'s zeroize-on-drop `SigningKey`;
//! `Debug` redacts on every type in this module. Nothing here writes a file:
//! this module owns the crypto, the CLI owns paths and modes (SPEC-v033: "The
//! seed is never a file").

use base64ct::{Base64, Encoding};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use zeroize::ZeroizeOnDrop;

use crate::kdf::IdentitySecret;
use crate::zero::Secret32;
use crate::{Error, Result};

/// BLAKE3 context string for the Ed25519 identity child (SPEC-v033
/// "Derivation"). Changing it changes every Ed25519 identity.
pub const ED25519_IDENTITY_DOMAIN: &str = "geode/v1/ed25519-identity";

/// Context string of the sibling X25519 child, as the CLI derives it
/// (`crates/geode-cli/src/cmd/key.rs`). Pinned here so a test can assert the
/// two children of one ISK do not collide; this module never derives under it.
pub const X25519_SIBLING_DOMAIN: &str = "geode/v1/x25519-identity";

/// SPKI DER prefix of an Ed25519 public key: the `SEQUENCE` of the
/// `AlgorithmIdentifier` `id-Ed25519` (1.3.101.112, parameters absent) plus
/// the unused-bits byte of the `BIT STRING` header (RFC 8410 4). The 32
/// public key bytes follow, for 44 DER bytes total.
pub const SPKI_DER_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// Derive the Ed25519 seed of `isk` (SPEC-v033 "Derivation").
///
/// Secret: the returned [`Secret32`] redacts in `Debug` and zeroizes on drop.
fn derive_seed(isk: &IdentitySecret) -> Secret32 {
    Secret32::new_unchecked(blake3::derive_key(ED25519_IDENTITY_DOMAIN, isk.as_bytes()))
}

/// An unlocked Ed25519 signing identity: the ISK's Ed25519 child.
///
/// The private key stays inside `ed25519-dalek`'s [`SigningKey`], which
/// zeroizes on drop; `Debug` prints no seed and no public key.
pub struct SigningIdentity(SigningKey);

impl SigningIdentity {
    /// Derive this identity's Ed25519 child from the ISK.
    #[must_use]
    pub fn from_isk(isk: &IdentitySecret) -> Self {
        Self(SigningKey::from_bytes(derive_seed(isk).as_bytes()))
    }

    /// Build an identity from a raw 32-byte Ed25519 seed.
    ///
    /// For RFC 8032 test vectors and recovery tooling. Production callers want
    /// [`SigningIdentity::from_isk`]: a raw seed is not a Geode child and
    /// carries no domain separation from the X25519 child.
    #[must_use]
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let seed = Secret32::new_unchecked(seed);
        Self(SigningKey::from_bytes(seed.as_bytes()))
    }

    /// The public half, for verification or printing.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        self.0.verifying_key()
    }

    /// The public half as SPKI PEM, the form `cosign verify-blob --key` reads.
    ///
    /// `-----BEGIN PUBLIC KEY-----`, one line of standard padded base64 of the
    /// 44 DER bytes, `-----END PUBLIC KEY-----`, trailing newline.
    #[must_use]
    pub fn public_pem(&self) -> String {
        let mut der = [0u8; SPKI_DER_PREFIX.len() + 32];
        der[..SPKI_DER_PREFIX.len()].copy_from_slice(&SPKI_DER_PREFIX);
        der[SPKI_DER_PREFIX.len()..].copy_from_slice(&self.verifying_key().to_bytes());
        let body = Base64::encode_string(&der);
        format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n")
    }

    /// Sign the raw `payload` bytes (RFC 8032 pure Ed25519, no prehash).
    #[must_use]
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.0.sign(payload).to_bytes()
    }
}

impl std::fmt::Debug for SigningIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SigningIdentity(**redacted**)")
    }
}

impl ZeroizeOnDrop for SigningIdentity {}

/// Verify a raw-byte signature under `verifying_key`.
///
/// The matching key returns `Ok(())`. A different key, payload, or signature
/// returns [`Error::AuthFail`], as does a non-canonical signature or an
/// invalid public key (`verify_strict` rejects small-order and mixed-order
/// keys). The error carries no key material.
pub fn verify(verifying_key: &VerifyingKey, payload: &[u8], signature: &[u8; 64]) -> Result<()> {
    verifying_key
        .verify_strict(payload, &Signature::from_bytes(signature))
        .map_err(|_| Error::AuthFail)
}

/// Encode a signature for the signature file: standard padded base64 of the
/// 64 signature bytes (SPEC-v033 "Derivation"). The caller appends the single
/// trailing newline.
#[must_use]
pub fn signature_base64(signature: &[u8; 64]) -> String {
    Base64::encode_string(signature)
}

/// Parse that wire form back to 64 signature bytes, tolerating the file's
/// surrounding whitespace. Anything that is not exactly 64 base64 bytes is
/// [`Error::Format`].
pub fn signature_from_base64(text: &str) -> Result<[u8; 64]> {
    Base64::decode_vec(text.trim())
        .map_err(|e| Error::Format(format!("signature base64: {e}")))?
        .try_into()
        .map_err(|_| Error::Format("signature must decode to 64 bytes".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isk(byte: u8) -> IdentitySecret {
        IdentitySecret::from_bytes([byte; 32])
    }

    fn unhex(text: &str) -> Vec<u8> {
        data_encoding::HEXLOWER
            .decode(text.as_bytes())
            .expect("test vector is hex")
    }

    fn hex(bytes: &[u8]) -> String {
        data_encoding::HEXLOWER.encode(bytes)
    }

    /// SPEC-v033 "Derivation": the shipped child is exactly the spec formula --
    /// one context string, the 32-byte ISK, nothing else mixed in.
    #[test]
    fn seed_is_the_spec_formula_over_the_isk_alone() {
        assert_eq!(ED25519_IDENTITY_DOMAIN, "geode/v1/ed25519-identity");
        let isk = isk(0x42);
        assert_eq!(
            derive_seed(&isk).as_bytes(),
            &blake3::derive_key(ED25519_IDENTITY_DOMAIN, isk.as_bytes()),
        );
    }

    #[test]
    fn seed_is_stable_per_isk_and_differs_across_isks() {
        assert_eq!(
            derive_seed(&isk(0x42)).as_bytes(),
            derive_seed(&isk(0x42)).as_bytes(),
        );
        assert_ne!(
            derive_seed(&isk(0x42)).as_bytes(),
            derive_seed(&isk(0x43)).as_bytes(),
        );
    }

    #[test]
    fn seed_does_not_collide_with_the_x25519_sibling() {
        for byte in [0x00, 0x42, 0xff] {
            let isk = isk(byte);
            assert_ne!(
                derive_seed(&isk).as_bytes(),
                &blake3::derive_key(X25519_SIBLING_DOMAIN, isk.as_bytes()),
            );
        }
    }

    /// RFC 8032 7.1 tests 1 and 2, driven through the shipped signer and
    /// verifier. Pure Ed25519 over raw bytes: a SHA-256 prehash or Ed25519ph
    /// would not reproduce these 64 bytes.
    #[test]
    fn rfc8032_vectors_sign_the_raw_message() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
        ];
        for (seed, public, message, signature) in cases {
            let seed: [u8; 32] = unhex(seed).try_into().unwrap();
            let message = unhex(message);
            let signature: [u8; 64] = unhex(signature).try_into().unwrap();

            let id = SigningIdentity::from_seed(seed);
            assert_eq!(hex(&id.verifying_key().to_bytes()), public);
            assert_eq!(id.sign(&message), signature);
            assert!(verify(&id.verifying_key(), &message, &signature).is_ok());
        }
    }

    #[test]
    fn public_pem_is_spki_with_the_pinned_prefix() {
        let id = SigningIdentity::from_seed([0x42; 32]);
        let pem = id.public_pem();

        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{pem}");
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"), "{pem}");
        assert!(!pem.contains("PRIVATE"));

        let body: String = pem
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        assert_eq!(body.len(), 60, "{body}");
        let der = Base64::decode_vec(&body).expect("body is base64");
        assert_eq!(der.len(), 44);
        assert_eq!(&der[..SPKI_DER_PREFIX.len()], &SPKI_DER_PREFIX);
        assert_eq!(
            &der[SPKI_DER_PREFIX.len()..],
            &id.verifying_key().to_bytes()
        );
    }

    #[test]
    fn verify_accepts_the_matching_key_and_rejects_others() {
        let a = SigningIdentity::from_seed([0x11; 32]);
        let b = SigningIdentity::from_seed([0x22; 32]);
        let payload = b"geode payload";
        let signature = a.sign(payload);

        assert!(verify(&a.verifying_key(), payload, &signature).is_ok());
        assert_ne!(a.verifying_key(), b.verifying_key());
        assert!(matches!(
            verify(&b.verifying_key(), payload, &signature),
            Err(Error::AuthFail)
        ));
        assert!(matches!(
            verify(&a.verifying_key(), b"geode payloaD", &signature),
            Err(Error::AuthFail)
        ));

        let mut flipped = signature;
        flipped[63] ^= 0x01;
        assert!(matches!(
            verify(&a.verifying_key(), payload, &flipped),
            Err(Error::AuthFail)
        ));
    }

    #[test]
    fn signature_wire_form_round_trips() {
        let id = SigningIdentity::from_seed([0x33; 32]);
        let signature = id.sign(b"payload");
        let text = signature_base64(&signature);

        assert_eq!(text.len(), 88);
        assert!(text.ends_with("=="), "{text}");
        assert_eq!(signature_from_base64(&text).unwrap(), signature);
        assert_eq!(
            signature_from_base64(&format!("{text}\n")).unwrap(),
            signature
        );
        assert!(signature_from_base64("not base64!").is_err());
        assert!(signature_from_base64("AAAA").is_err());
    }

    #[test]
    fn debug_redacts_the_seed_and_the_isk() {
        let isk = isk(0x42);
        let id = SigningIdentity::from_isk(&isk);
        let shown = format!("{id:?}");

        assert_eq!(shown, "SigningIdentity(**redacted**)");
        assert!(!shown.contains(&hex(derive_seed(&isk).as_bytes())));
        assert!(!shown.contains(&hex(isk.as_bytes())));
    }

    /// The seed is zeroized on drop (G0c): the marker follows from
    /// `ed25519-dalek`'s zeroize-on-drop `SigningKey`, so losing the `zeroize`
    /// feature on `geode-core` stops this compiling.
    #[test]
    fn signing_identity_zeroizes_on_drop() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
        assert_zeroize_on_drop::<SigningIdentity>();
    }

    /// The library writes no key file (G0c): a full derive / PEM / sign pass
    /// leaves the working directory exactly as it was at crate-test start.
    #[test]
    fn public_api_writes_no_file() {
        let cwd = std::env::current_dir().unwrap();
        let before = dir_listing(&cwd);

        let id = SigningIdentity::from_isk(&isk(0x42));
        let _ = id.public_pem();
        let _ = signature_base64(&id.sign(b"payload"));
        let _ = verify(&id.verifying_key(), b"payload", &id.sign(b"payload"));

        assert_eq!(dir_listing(&cwd), before);
    }

    fn dir_listing(dir: &std::path::Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}
