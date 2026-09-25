//! Manifest authentication and merklization (02-cryptography 8; 03-format 5).
//!
//! G2: real JCS canonicalization (RFC 8785), BLAKE3 merkle root over entries,
//! and AEGIS-256-X2 MAC under `ManifestKey` (geode/v1/manifest).

use crate::kdf::{Epoch, ObjectId, VaultId};
use crate::{Error, Result};
use aegis::aegis256x2::{Aegis256X2, Nonce};

/// Manifest entry (03-format 5).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Entry {
    pub path: String,
    pub path_sealed: bool,
    pub object_id: ObjectId,
    pub kind: EntryKind,
    pub plain_len: u64,
    pub chunk_count: u32,
    pub mode: u32,
    pub mtime_ms: i64,
    pub content_root: [u8; 32],
    pub bind: bool,
}

/// Manifest entry kind (03-format 5; `schemas/vault.manifest.schema.json`
/// enum `file | dir | symlink`).
///
/// `Dir` carries no object body: the row names an `object_id` (the schema
/// requires one) but no `.gobj` is written, and `plain_len` / `chunk_count`
/// are 0. It exists so an empty directory survives unmount (08-mount 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    File,
    Dir,
    Symlink,
}

impl EntryKind {
    /// Is this row a directory (no object body; `plain_len` / `chunk_count` 0)?
    #[must_use]
    pub fn is_dir(self) -> bool {
        matches!(self, Self::Dir)
    }
}

/// Vault manifest header (03-format 5).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct Manifest {
    pub vault_id: VaultId,
    pub epoch: Epoch,
    pub suite: u8,
    pub flags: u16,
    pub generated_at: i64,
    pub generator: String,
    pub root: [u8; 32],
    pub entry_count: u32,
    pub total_plain_bytes: u64,
    pub total_cipher_bytes: u64,
    #[serde(default)]
    pub entries: Vec<Entry>,
}

/// Canonicalize a JSON value per RFC 8785 JCS: object keys sorted by UTF-8
/// code point, no insignificant whitespace (02-cryptography 8; 03-format 6).
pub fn canonicalize(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    write_canonical(value, &mut out);
    Ok(out)
}

fn write_canonical(value: &serde_json::Value, out: &mut Vec<u8>) {
    match value {
        serde_json::Value::Null => out.extend_from_slice(b"null"),
        serde_json::Value::Bool(b) => out.extend_from_slice(if *b { b"true" } else { b"false" }),
        serde_json::Value::Number(n) => out.extend_from_slice(n.to_string().as_bytes()),
        serde_json::Value::String(s) => write_string(s, out),
        serde_json::Value::Array(a) => {
            out.push(b'[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_canonical(v, out);
            }
            out.push(b']');
        }
        serde_json::Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write_canonical(&o[*k], out);
            }
            out.push(b'}');
        }
    }
}

fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", c as u32).as_bytes());
            }
            c => out.extend_from_slice(c.to_string().as_bytes()),
        }
    }
    out.push(b'"');
}

/// Merkle root over manifest entries (02-cryptography 8).
pub fn entries_root(entries: &[Entry]) -> Result<[u8; 32]> {
    if entries.is_empty() { return Ok([0u8; 32]); }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(entries.len());
    for e in entries {
        let val = serde_json::to_value(e).map_err(|e| Error::Format(format!("entry serialize: {e}")))?;
        let canon = canonicalize(&val)?;
        leaves.push(*blake3::hash(&canon).as_bytes());
    }
    Ok(merkle(&leaves))
}

fn merkle(leaves: &[[u8; 32]]) -> [u8; 32] {
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

fn mac_nonce(manifest_key: &[u8; 32]) -> Nonce {
    let mut h = blake3::Hasher::new_keyed(manifest_key);
    h.update(b"geode/v1/manifest-nonce");
    let mut n = [0u8; 32];
    n.copy_from_slice(h.finalize().as_bytes());
    n
}

/// Compute the manifest MAC over canonical body (02-cryptography 8).
pub fn manifest_mac(manifest_key: &[u8; 32], body: &[u8]) -> Result<[u8; 16]> {
    Ok(mac_with(manifest_key, b"geode/v1/manifest", body))
}

/// Snapshot MAC over a canonical snapshot envelope body (04-vault 7).
/// Distinct AD from `manifest_mac` so a snapshot tag cannot be replayed as a
/// manifest tag and vice versa.
#[allow(clippy::unnecessary_wraps)] // mirrors `manifest_mac`'s Result API for the `mac_fn` pointer contract
pub fn snapshot_mac(manifest_key: &[u8; 32], body: &[u8]) -> Result<[u8; 16]> {
    Ok(mac_with(manifest_key, b"geode/v1/snapshot", body))
}

/// AEGIS-256-X2 MAC of `body` under `manifest_key` with associated data `ad`.
fn mac_with(manifest_key: &[u8; 32], ad: &[u8], body: &[u8]) -> [u8; 16] {
    let nonce = mac_nonce(manifest_key);
    let ctx = Aegis256X2::<16>::new(manifest_key, &nonce);
    let (_ct, tag) = ctx.encrypt(body, ad);
    let mut t = [0u8; 16];
    t.copy_from_slice(&tag);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_sorts_keys() {
        let v: serde_json::Value = serde_json::json!({"b":1,"a":2,"c":3});
        let c = canonicalize(&v).unwrap();
        let s = String::from_utf8(c).unwrap();
        assert_eq!(s, "{\"a\":2,\"b\":1,\"c\":3}");
    }

    #[test]
    fn canonicalize_no_whitespace() {
        let v: serde_json::Value = serde_json::json!({"x":[1,2,3],"y":{"q":true}});
        let c = canonicalize(&v).unwrap();
        let s = String::from_utf8(c).unwrap();
        assert_eq!(s, "{\"x\":[1,2,3],\"y\":{\"q\":true}}");
    }

    #[test]
    fn manifest_mac_is_stable() {
        let key = [0x42; 32];
        let t1 = manifest_mac(&key, b"canonical body").unwrap();
        let t2 = manifest_mac(&key, b"canonical body").unwrap();
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 16);
    }

    #[test]
    fn manifest_mac_changes_on_body() {
        let key = [0x42; 32];
        let t1 = manifest_mac(&key, b"body1").unwrap();
        let t2 = manifest_mac(&key, b"body2").unwrap();
        assert_ne!(t1, t2);
    }

    #[test]
    fn entries_root_empty_is_zero() {
        assert_eq!(entries_root(&[]).unwrap(), [0u8; 32]);
    }

    #[test]
    fn entries_root_nonempty() {
        let e = Entry {
            path: "a".into(),
            path_sealed: false,
            object_id: ObjectId([0; 16]),
            kind: EntryKind::File,
            plain_len: 1,
            chunk_count: 1,
            mode: 0o644,
            mtime_ms: 0,
            content_root: [0u8; 32],
            bind: false,
        };
        let r = entries_root(&[e]).unwrap();
        assert_ne!(r, [0u8; 32]);
    }
}
