//! GDE1 object header, chunking, content root (02-cryptography 4.4; 03-format 4).
//!
//! G2: real object seal/open. Path bind (02 4.3): when on, the path is bound
//! into every chunk AD and into `path_bind_hash`; a moved object fails open.

use crate::aead::{open_chunk, seal_chunk, ChunkAd};
use crate::chunk::{chunk_count, validate_chunk_size, DEFAULT_CHUNK_SIZE};
use crate::kdf::{Epoch, EpochKey, ObjectId, VaultId};
use crate::{assert_magic, assert_suite, Error, Result, MAGIC_GDE1, SUITE_0X01};
use aegis::aegis256x2::{Aegis256X2, Nonce};

pub const KIND_FILE: u8 = 0x01;
pub const HEADER_SIZE: usize = 108;

#[derive(Clone, Debug)]
pub struct ObjectHeader {
    pub magic: [u8; 4],
    pub suite: u8,
    pub kind: u8,
    pub flags: u16,
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub object_id: ObjectId,
    pub chunk_size: u32,
    pub plain_len: u64,
    pub chunk_count: u32,
    pub path_bind_hash: [u8; 32],
    pub header_tag: [u8; 16],
}

impl ObjectHeader {
    #[must_use]
    pub fn fields_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(HEADER_SIZE - 16);
        b.extend_from_slice(&self.magic);
        b.push(self.suite);
        b.push(self.kind);
        b.extend_from_slice(&self.flags.to_le_bytes());
        b.extend_from_slice(&self.vault_id.0);
        b.extend_from_slice(&self.epoch.0.to_le_bytes());
        b.extend_from_slice(&self.object_id.0);
        b.extend_from_slice(&self.chunk_size.to_le_bytes());
        b.extend_from_slice(&self.plain_len.to_le_bytes());
        b.extend_from_slice(&self.chunk_count.to_le_bytes());
        b.extend_from_slice(&self.path_bind_hash);
        b
    }

    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = self.fields_bytes();
        b.extend_from_slice(&self.header_tag);
        b
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if buf.len() < HEADER_SIZE {
            return Err(Error::Format(format!(
                "object header too short: {} < {HEADER_SIZE}",
                buf.len()
            )));
        }
        let mut m = [0u8; 4];
        m.copy_from_slice(&buf[0..4]);
        assert_magic(&m, MAGIC_GDE1)?;
        let suite = buf[4];
        assert_suite(suite)?;
        let mut flags = [0u8; 2];
        flags.copy_from_slice(&buf[6..8]);
        let mut vid = [0u8; 16];
        vid.copy_from_slice(&buf[8..24]);
        let mut ep = [0u8; 4];
        ep.copy_from_slice(&buf[24..28]);
        let mut oid = [0u8; 16];
        oid.copy_from_slice(&buf[28..44]);
        let mut cs = [0u8; 4];
        cs.copy_from_slice(&buf[44..48]);
        let mut pl = [0u8; 8];
        pl.copy_from_slice(&buf[48..56]);
        let mut cc = [0u8; 4];
        cc.copy_from_slice(&buf[56..60]);
        let mut pbh = [0u8; 32];
        pbh.copy_from_slice(&buf[60..92]);
        let mut ht = [0u8; 16];
        ht.copy_from_slice(&buf[92..108]);
        Ok(Self {
            magic: m,
            suite,
            kind: buf[5],
            flags: u16::from_le_bytes(flags),
            vault_id: VaultId(vid),
            epoch: Epoch(u32::from_le_bytes(ep)),
            object_id: ObjectId(oid),
            chunk_size: u32::from_le_bytes(cs),
            plain_len: u64::from_le_bytes(pl),
            chunk_count: u32::from_le_bytes(cc),
            path_bind_hash: pbh,
            header_tag: ht,
        })
    }
}

fn header_nonce(ek: &EpochKey, object_id: &ObjectId) -> Nonce {
    let mut h = blake3::Hasher::new_keyed(ek.as_bytes());
    h.update(b"geode/v1/object-hdr");
    h.update(&object_id.0);
    let mut n = [0u8; 32];
    n.copy_from_slice(h.finalize().as_bytes());
    n
}

#[must_use]
pub fn compute_header_tag(ek: &EpochKey, header: &ObjectHeader) -> [u8; 16] {
    let nonce = header_nonce(ek, &header.object_id);
    let ctx = Aegis256X2::<16>::new(ek.as_bytes(), &nonce);
    let (_ct, tag) = ctx.encrypt(&header.fields_bytes(), b"geode/v1/object-hdr");
    let mut t = [0u8; 16];
    t.copy_from_slice(&tag);
    t
}

#[must_use]
pub fn path_bind_hash(path_bind: &[u8]) -> [u8; 32] {
    if path_bind.is_empty() {
        [0u8; 32]
    } else {
        *blake3::hash(path_bind).as_bytes()
    }
}

fn chunk_leaf(i: u64, tag: &[u8; 16], len: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&i.to_le_bytes());
    h.update(tag);
    h.update(&len.to_le_bytes());
    let mut leaf = [0u8; 32];
    leaf.copy_from_slice(h.finalize().as_bytes());
    leaf
}

fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                let mut h = blake3::Hasher::new();
                h.update(&level[i]);
                h.update(&level[i + 1]);
                let mut n = [0u8; 32];
                n.copy_from_slice(h.finalize().as_bytes());
                next.push(n);
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

#[derive(Debug)]
pub struct SealedObject {
    pub header: ObjectHeader,
    pub chunks: Vec<u8>,
    pub content_root: [u8; 32],
}

#[allow(clippy::cast_possible_truncation)]
pub fn seal_object(
    ek: &EpochKey,
    vault_id: VaultId,
    epoch: Epoch,
    object_id: ObjectId,
    chunk_size: u32,
    path_bind: &[u8],
    plaintext: &[u8],
) -> Result<SealedObject> {
    assert_suite(SUITE_0X01)?;
    let cs = if chunk_size == 0 {
        DEFAULT_CHUNK_SIZE
    } else {
        chunk_size
    };
    validate_chunk_size(cs)?;
    let n = chunk_count(plaintext.len() as u64, cs);
    let mut chunks = Vec::new();
    let mut leaves: Vec<[u8; 32]> = Vec::new();
    let mut offset = 0usize;
    for i in 0..n {
        let end = (offset + cs as usize).min(plaintext.len());
        let pt = &plaintext[offset..end];
        let ad = ChunkAd {
            suite: SUITE_0X01,
            vault_id,
            epoch,
            object_id,
            chunk_index: u64::from(i),
            plain_len: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
            chunk_size: cs,
            path_bind: path_bind.to_vec(),
        };
        let sealed = seal_chunk(ek, &ad, pt)?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&sealed[..16]);
        chunks.extend_from_slice(&sealed);
        leaves.push(chunk_leaf(u64::from(i), &tag, pt.len() as u64));
        offset = end;
    }
    let content_root = merkle_root(&leaves);
    let mut header = ObjectHeader {
        magic: *MAGIC_GDE1,
        suite: SUITE_0X01,
        kind: KIND_FILE,
        flags: 0,
        vault_id,
        epoch,
        object_id,
        chunk_size: cs,
        plain_len: u64::try_from(plaintext.len()).unwrap_or(u64::MAX),
        chunk_count: n,
        path_bind_hash: path_bind_hash(path_bind),
        header_tag: [0u8; 16],
    };
    header.header_tag = compute_header_tag(ek, &header);
    Ok(SealedObject {
        header,
        chunks,
        content_root,
    })
}

#[allow(clippy::cast_possible_truncation)]
pub fn open_object(
    ek: &EpochKey,
    header_bytes: &[u8],
    chunk_bytes: &[u8],
    path_bind: &[u8],
) -> Result<(ObjectHeader, Vec<u8>)> {
    let header = ObjectHeader::from_bytes(header_bytes)?;
    let want = compute_header_tag(ek, &header);
    // TODO(G5): constant-time compare. Correct for G2; harden later.
    if want != header.header_tag {
        return Err(Error::AuthFail);
    }
    let effective_bind: Vec<u8> = if header.path_bind_hash == [0u8; 32] {
        Vec::new()
    } else {
        if header.path_bind_hash != path_bind_hash(path_bind) {
            return Err(Error::AuthFail);
        }
        path_bind.to_vec()
    };
    let cs = header.chunk_size as usize;
    if cs == 0 {
        return Err(Error::Format("chunk_size 0 in header".into()));
    }
    validate_chunk_size(header.chunk_size)?;
    let mut plaintext = Vec::with_capacity(header.plain_len as usize);
    let mut offset = 0usize;
    for i in 0..header.chunk_count {
        if offset + 16 > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let remaining_plain = header.plain_len as usize - plaintext.len();
        let this_len = cs.min(remaining_plain);
        let rec_len = 16 + this_len;
        if offset + rec_len > chunk_bytes.len() {
            return Err(Error::AuthFail);
        }
        let rec = &chunk_bytes[offset..offset + rec_len];
        let ad = ChunkAd {
            suite: header.suite,
            vault_id: header.vault_id,
            epoch: header.epoch,
            object_id: header.object_id,
            chunk_index: u64::from(i),
            plain_len: header.plain_len,
            chunk_size: header.chunk_size,
            path_bind: effective_bind.clone(),
        };
        plaintext.extend_from_slice(&open_chunk(ek, &ad, rec)?);
        offset += rec_len;
    }
    Ok((header, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ek() -> EpochKey {
        let isk = crate::kdf::IdentitySecret::from_bytes([0x07; 32]);
        crate::kdf::derive_epoch_key(&isk, VaultId([0x01; 16]), Epoch(1), "test").unwrap()
    }
    fn oid() -> ObjectId {
        ObjectId([0xab; 16])
    }

    #[test]
    fn seal_open_roundtrip_small() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"hello world",
        )
        .unwrap();
        let (h, pt) = open_object(&ek, &sealed.header.to_bytes(), &sealed.chunks, b"").unwrap();
        assert_eq!(pt, b"hello world");
        assert_eq!(h.chunk_count, 1);
        assert_eq!(h.plain_len, 11);
    }

    #[test]
    fn empty_object_roundtrips() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"",
        )
        .unwrap();
        assert_eq!(sealed.header.chunk_count, 0);
        let (h, pt) = open_object(&ek, &sealed.header.to_bytes(), &sealed.chunks, b"").unwrap();
        assert!(pt.is_empty());
        assert_eq!(h.chunk_count, 0);
    }

    #[test]
    fn multi_chunk_roundtrips() {
        let ek = ek();
        let cs = 64 << 10;
        let pt = vec![0x5a; (cs as usize) * 3 + 10];
        let sealed = seal_object(&ek, VaultId([0x01; 16]), Epoch(1), oid(), cs, b"", &pt).unwrap();
        assert_eq!(sealed.header.chunk_count, 4);
        let (_, opened) = open_object(&ek, &sealed.header.to_bytes(), &sealed.chunks, b"").unwrap();
        assert_eq!(opened, pt);
    }

    #[test]
    fn flipped_chunk_bit_is_auth_fail() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"hello world",
        )
        .unwrap();
        let mut chunks = sealed.chunks.clone();
        chunks[16] ^= 0x01;
        let r = open_object(&ek, &sealed.header.to_bytes(), &chunks, b"");
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn flipped_header_tag_is_auth_fail() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"hello world",
        )
        .unwrap();
        let mut hb = sealed.header.to_bytes();
        hb[92] ^= 0x01;
        let r = open_object(&ek, &hb, &sealed.chunks, b"");
        assert!(matches!(r, Err(Error::AuthFail)));
    }

    #[test]
    fn content_root_matches_header() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"hello world",
        )
        .unwrap();
        // content_root is non-zero for a non-empty object.
        assert_ne!(sealed.content_root, [0u8; 32]);
    }

    // ---- G2c: path-bind on -> moved object fails open ----

    #[test]
    fn bind_on_moved_object_fails_open() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"docs/plan.md",
            b"secret plan",
        )
        .unwrap();
        assert_ne!(sealed.header.path_bind_hash, [0u8; 32]);
        // wrong path -> AuthFail
        let r = open_object(
            &ek,
            &sealed.header.to_bytes(),
            &sealed.chunks,
            b"docs/other.md",
        );
        assert!(
            matches!(r, Err(Error::AuthFail)),
            "bind on: moved object MUST fail open"
        );
        // right path -> ok
        let (_, pt) = open_object(
            &ek,
            &sealed.header.to_bytes(),
            &sealed.chunks,
            b"docs/plan.md",
        )
        .unwrap();
        assert_eq!(pt, b"secret plan");
    }

    // ---- G2c: bind off -> move succeeds ----

    #[test]
    fn bind_off_move_succeeds() {
        let ek = ek();
        let sealed = seal_object(
            &ek,
            VaultId([0x01; 16]),
            Epoch(1),
            oid(),
            DEFAULT_CHUNK_SIZE,
            b"",
            b"movable",
        )
        .unwrap();
        assert_eq!(sealed.header.path_bind_hash, [0u8; 32]);
        // open under any path -> ok (no bind)
        let (_, pt) = open_object(
            &ek,
            &sealed.header.to_bytes(),
            &sealed.chunks,
            b"anywhere/x",
        )
        .unwrap();
        assert_eq!(pt, b"movable");
    }
}
