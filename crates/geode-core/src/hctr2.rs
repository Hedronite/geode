//! HCTR2-256 length-preserving tweakable cipher (02-cryptography 5.3).
//!
//! Pure-stable-Rust port of the HCTR2 construction
//! (<https://eprint.iacr.org/2021/1441>) on top of the audited `aes` and
//! `polyval` crates. The workspace forbids `unsafe` and pins stable Rust,
//! and the published `hctr2` crate requires nightly (`split_array_mut`,
//! `#![feature]`), so the mode is wired here from its primitives instead.
//!
//! Key = 32 bytes (AES-256). Tweak = arbitrary bytes. Message >= 16 bytes.
//! Ciphertext length == plaintext length. No separate tag: integrity for
//! name sealing is provided by the caller re-verifying the deterministic
//! pad (see `name::open_name`).
//!
//! Construction (n = 128 bits):
//! ```text
//!   H = AES_K(0^128)            (POLYVAL hash key)
//!   L = AES_K(1^128)            (XCTR base offset)
//!   H_h(T, M) = POLYVAL(H, len_block(T, M) || pad(T) || body(M))
//!   Encrypt(P = Mhead || Ntail):
//!     MM = Mhead ^ H_h(T, Ntail); UU = AES_K(MM); S = MM ^ UU ^ L
//!     V = Ntail ^ XCTR_K(S); U = UU ^ H_h(T, V); C = U || V
//!   Decrypt is the inverse.
//! ```

use aes::Aes256;
use cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use polyval::universal_hash::{UhfBackend, UniversalHash};
use polyval::Polyval;

pub(crate) const BLOCK: usize = 16;
type Blk = [u8; BLOCK];

/// HCTR2 instance keyed by a 32-byte key (AES-256).
pub(crate) struct Hctr2 {
    aes: Aes256,
    h: Blk, // AES_K(0)
    l: Blk, // AES_K(1)
}

impl Hctr2 {
    /// Build from a 32-byte key.
    pub(crate) fn new(key: &[u8; 32]) -> Self {
        let aes = Aes256::new(key.into());
        let mut zero = [0u8; BLOCK];
        let mut one = [0u8; BLOCK];
        one[0] = 1; // bin(1), 128-bit LE
        aes.encrypt_block((&mut zero).into());
        aes.encrypt_block((&mut one).into());
        Self {
            aes,
            h: zero,
            l: one,
        }
    }

    /// Encrypt `plain` (>= 16 bytes) into `ct` (same length) under `tweak`.
    pub(crate) fn encrypt(&self, ct: &mut [u8], plain: &[u8], tweak: &[u8]) {
        assert!(plain.len() >= BLOCK);
        assert_eq!(ct.len(), plain.len());
        let (m_head, n_tail) = plain.split_at(BLOCK);
        let (u_out, v_out) = ct.split_at_mut(BLOCK);
        let hh_n = self.h_hash(tweak, n_tail);
        let mm = xor_block(m_head.try_into().unwrap(), &hh_n);
        let mut uu = mm;
        self.aes.encrypt_block((&mut uu).into());
        let s = xor_block(&xor_block(&mm, &uu), &self.l);
        self.xctr_xor(&s, v_out, n_tail);
        let hh_v = self.h_hash(tweak, v_out);
        let u = xor_block(&uu, &hh_v);
        u_out.copy_from_slice(&u);
        let _ = mm;
    }

    /// Decrypt `ct` (>= 16 bytes) into `plain` (same length) under `tweak`.
    pub(crate) fn decrypt(&self, plain: &mut [u8], ct: &[u8], tweak: &[u8]) {
        assert!(ct.len() >= BLOCK);
        assert_eq!(plain.len(), ct.len());
        let (u_head, v_tail) = ct.split_at(BLOCK);
        let (m_out, n_out) = plain.split_at_mut(BLOCK);
        let hh_v = self.h_hash(tweak, v_tail);
        let uu = xor_block(u_head.try_into().unwrap(), &hh_v);
        let mut mm = uu;
        self.aes.decrypt_block((&mut mm).into());
        let s = xor_block(&xor_block(&mm, &uu), &self.l);
        self.xctr_xor(&s, n_out, v_tail);
        let hh_n = self.h_hash(tweak, n_out);
        let m = xor_block(&mm, &hh_n);
        m_out.copy_from_slice(&m);
        let _ = uu;
    }

    /// `H_h(T, M) = POLYVAL(H, len_block || pad(T) || body(M))` (paper 2.2).
    fn h_hash(&self, tweak: &[u8], msg: &[u8]) -> Blk {
        let mut p = Polyval::new((&self.h).into());
        // Length block: bin(2*|T|_bits + c), c = 2 if |M| % 16 == 0 else 3,
        // encoded as a 128-bit little-endian integer.
        let len_bits = u128::try_from(tweak.len()).unwrap() * 8;
        let lb_val = if msg.len() % BLOCK == 0 {
            2 * len_bits + 2
        } else {
            2 * len_bits + 3
        };
        let mut lb = [0u8; BLOCK];
        lb.copy_from_slice(&lb_val.to_le_bytes());
        p.proc_block(lb.as_slice().try_into().unwrap());
        // pad(T): tweak zero-padded to a 16-byte boundary.
        p.update_padded(tweak);
        // body(M): full blocks, then (if unaligned) a final block = tail || 0x01.
        let nfull = (msg.len() / BLOCK) * BLOCK;
        let (full, tail) = msg.split_at(nfull);
        for chunk in full.chunks_exact(BLOCK) {
            p.proc_block(chunk.try_into().unwrap());
        }
        if !tail.is_empty() {
            let mut blk = [0u8; BLOCK];
            blk[..tail.len()].copy_from_slice(tail);
            blk[tail.len()] = 1;
            p.proc_block(blk.as_slice().try_into().unwrap());
        }
        p.finalize().into()
    }

    /// Write `data ^ XCTR_K(S)` into `out` (|out| == |data|) (paper 2.3).
    fn xctr_xor(&self, s: &Blk, out: &mut [u8], data: &[u8]) {
        assert_eq!(out.len(), data.len());
        let mut ctr: u128 = 1;
        let mut idx = 0;
        while idx < data.len() {
            let mut block = *s;
            let ctr_bytes = ctr.to_le_bytes();
            for i in 0..BLOCK {
                block[i] ^= ctr_bytes[i];
            }
            self.aes.encrypt_block((&mut block).into());
            let take = (data.len() - idx).min(BLOCK);
            for j in 0..take {
                out[idx + j] = data[idx + j] ^ block[j];
            }
            idx += take;
            ctr = ctr.checked_add(1).expect("xctr counter overflow");
        }
    }
}

fn xor_block(a: &Blk, b: &Blk) -> Blk {
    let mut r = [0u8; BLOCK];
    for i in 0..BLOCK {
        r[i] = a[i] ^ b[i];
    }
    r
}
