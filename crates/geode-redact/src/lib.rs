//! Redact secret values and known key prefixes.
//!
//! v1 needles are the raw value, base64 (standard and URL-safe, padded and
//! unpadded, three alignments), hex (lower and upper), one RFC 3986
//! percent-encoding, and the canonical JSON string. Alignment fragments
//! shorter than 8 bytes are dropped. A value shorter than 8 bytes is refused
//! and is not indexed. Prefix matches are replaced with `[REDACTED]`.

use std::collections::BTreeSet;

use aho_corasick::{AhoCorasick, MatchKind};
use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;

mod named;
pub use named::{NamedIndexError, NamedRedactor, NamedStream, Placeholder};

const MIN_VALUE: usize = 8;
const REPLACEMENT: &[u8] = b"[REDACTED]";
/// Chars of a base64 group that still depend on bytes before the secret.
const ALIGN_SKIP: [usize; 3] = [0, 2, 3];

const PREFIXES: &[&[u8]] = &[
    b"sk-",
    b"ghp_",
    b"github_pat_",
    b"xoxa-",
    b"xoxb-",
    b"xoxp-",
    b"xoxr-",
    b"AKIA",
    b"GTOK",
    b"-----BEGIN",
];

/// A value was shorter than 8 bytes, so it was not indexed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexError {
    /// Length of the rejected value. The bytes are not stored.
    pub len: usize,
}

impl std::fmt::Display for IndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "value of {} bytes is too short to index", self.len)
    }
}

impl std::error::Error for IndexError {}

/// Automaton over v1 needles and known key prefixes.
///
/// `Debug` does not print needles.
pub struct Redactor {
    ac: AhoCorasick,
    max_len: usize,
}

impl std::fmt::Debug for Redactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Redactor")
            .field("max_len", &self.max_len)
            .finish()
    }
}

impl Redactor {
    /// Index `values` plus the known prefixes.
    ///
    /// # Errors
    ///
    /// Returns [`IndexError`] when any value is shorter than 8 bytes.
    /// Nothing from that call is indexed.
    pub fn try_new<I, B>(values: I) -> Result<Self, IndexError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut needles = Vec::new();
        let mut seen = BTreeSet::new();
        for prefix in PREFIXES {
            push_needle(&mut needles, &mut seen, prefix);
        }
        for value in values {
            let value = value.as_ref();
            if value.len() < MIN_VALUE {
                return Err(IndexError { len: value.len() });
            }
            index_value(&mut needles, &mut seen, value);
        }
        let max_len = needles.iter().map(Vec::len).max().unwrap_or(1);
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&needles)
            .expect("prefix needles are non-empty");
        Ok(Self { ac, max_len })
    }

    /// Replace every needle in `input` with `[REDACTED]`.
    #[must_use]
    pub fn redact(&self, input: &[u8]) -> Vec<u8> {
        apply(&self.ac, input)
    }

    /// Stream `input` in chunks. `finish` must be called to flush the tail.
    #[must_use]
    pub fn stream(&self) -> StreamRedactor<'_> {
        StreamRedactor {
            ac: &self.ac,
            max_len: self.max_len,
            buf: Vec::new(),
        }
    }
}

/// Carry buffer so a needle split across reads still matches.
pub struct StreamRedactor<'a> {
    ac: &'a AhoCorasick,
    max_len: usize,
    buf: Vec<u8>,
}

impl StreamRedactor<'_> {
    /// Append `chunk` and return the bytes that can no longer change.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        self.take_stable()
    }

    /// Redact the uncommitted tail.
    #[must_use]
    pub fn finish(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.buf);
        apply(self.ac, &buf)
    }

    fn take_stable(&mut self) -> Vec<u8> {
        let max_len = self.max_len.max(1);
        if self.buf.len() < max_len {
            return Vec::new();
        }
        // A start is stable once `max_len` bytes have been seen from there.
        let first_unstable = self.buf.len() - max_len + 1;
        let mut out = Vec::new();
        let mut i = 0;
        for m in self.ac.find_iter(&self.buf) {
            if m.start() >= first_unstable {
                break;
            }
            out.extend_from_slice(&self.buf[i..m.start()]);
            out.extend_from_slice(REPLACEMENT);
            i = m.end();
        }
        if i < first_unstable {
            out.extend_from_slice(&self.buf[i..first_unstable]);
            self.buf.drain(..first_unstable);
        } else {
            self.buf.drain(..i);
        }
        out
    }
}

fn apply(ac: &AhoCorasick, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut last = 0;
    for m in ac.find_iter(input) {
        out.extend_from_slice(&input[last..m.start()]);
        out.extend_from_slice(REPLACEMENT);
        last = m.end();
    }
    out.extend_from_slice(&input[last..]);
    out
}

fn push_needle(needles: &mut Vec<Vec<u8>>, seen: &mut BTreeSet<Vec<u8>>, needle: &[u8]) {
    if needle.is_empty() || !seen.insert(needle.to_vec()) {
        return;
    }
    needles.push(needle.to_vec());
}

fn index_value(needles: &mut Vec<Vec<u8>>, seen: &mut BTreeSet<Vec<u8>>, value: &[u8]) {
    for needle in value_needles(value) {
        push_needle(needles, seen, &needle);
    }
}

/// Every v1 encoding of `value` that is at least 8 bytes long.
fn value_needles(value: &[u8]) -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = Vec::new();
    let mut add = |needle: &[u8]| {
        if needle.len() >= MIN_VALUE {
            out.push(needle.to_vec());
        }
    };
    add(value);
    add(&hex_encode(value, false));
    add(&hex_encode(value, true));
    add(&percent_encode(value));
    if let Some(json) = json_canonical(value) {
        add(&json);
    }
    for url_safe in [false, true] {
        let (padded, unpadded) = whole_b64(value, url_safe);
        add(&padded);
        add(&unpadded);
        for align in 0..3 {
            if let Some(frag) = stable_b64(value, align, url_safe) {
                add(&frag);
            }
        }
    }
    out
}

fn hex_encode(data: &[u8], upper: bool) -> Vec<u8> {
    const LOWER: &[u8; 16] = b"0123456789abcdef";
    const UPPER: &[u8; 16] = b"0123456789ABCDEF";
    let alphabet = if upper { UPPER } else { LOWER };
    let mut out = Vec::with_capacity(data.len() * 2);
    for byte in data {
        out.push(alphabet[usize::from(byte >> 4)]);
        out.push(alphabet[usize::from(byte & 0x0f)]);
    }
    out
}

fn percent_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    for &byte in data {
        if is_unreserved(byte) {
            out.push(byte);
        } else {
            out.push(b'%');
            out.extend_from_slice(&hex_encode(&[byte], true));
        }
    }
    out
}

fn is_unreserved(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
    )
}

fn json_canonical(data: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(data).ok()?;
    let quoted = serde_json::to_string(text).expect("str always serializes");
    Some(quoted.as_bytes()[1..quoted.len() - 1].to_vec())
}

fn whole_b64(data: &[u8], url_safe: bool) -> (Vec<u8>, Vec<u8>) {
    let engine = if url_safe { URL_SAFE } else { STANDARD };
    let padded = engine.encode(data);
    let unpadded = padded.trim_end_matches('=').as_bytes().to_vec();
    (padded.into_bytes(), unpadded)
}

/// Base64 chars that depend only on `secret` when it starts at `align` mod 3.
fn stable_b64(secret: &[u8], align: usize, url_safe: bool) -> Option<Vec<u8>> {
    let engine = if url_safe { URL_SAFE } else { STANDARD };
    let mut buf = vec![0u8; align];
    buf.extend_from_slice(secret);
    let enc = engine.encode(&buf);
    let complete = (buf.len() / 3) * 4;
    let skip = ALIGN_SKIP[align];
    if complete <= skip || enc.len() < complete {
        return None;
    }
    let frag = &enc.as_bytes()[skip..complete];
    if frag.len() < MIN_VALUE {
        None
    } else {
        Some(frag.to_vec())
    }
}

/// Scrub a formatted log line with the prefix needles.
#[cfg(feature = "layer")]
pub struct RedactLayer {
    inner: Redactor,
}

#[cfg(feature = "layer")]
impl RedactLayer {
    /// Prefix rules only. No caller-supplied value is indexed.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Redactor::try_new(std::iter::empty::<&[u8]>()).expect("prefixes index"),
        }
    }

    /// Replace prefix hits in `line`.
    #[must_use]
    pub fn redact_line(&self, line: &str) -> String {
        let bytes = self.inner.redact(line.as_bytes());
        String::from_utf8(bytes)
            .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned())
    }
}

#[cfg(feature = "layer")]
impl Default for RedactLayer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty() && hay.windows(needle.len()).any(|w| w == needle)
    }

    fn assert_absent(redactor: &Redactor, needle: &[u8]) {
        if needle.len() < MIN_VALUE {
            return;
        }
        let out = redactor.redact(needle);
        assert!(!contains(&out, needle), "still present: {needle:?}");
    }

    fn assert_splits(redactor: &Redactor, payload: &[u8]) {
        let once = redactor.redact(payload);
        for i in 0..=payload.len() {
            let mut stream = redactor.stream();
            let mut got = stream.push(&payload[..i]);
            got.extend(stream.push(&payload[i..]));
            got.extend(stream.finish());
            assert_eq!(got, once, "split at {i}");
        }
    }

    #[test]
    fn short_value_is_refused_and_not_indexed() {
        let short = b"1234567";
        assert_eq!(
            Redactor::try_new([short.as_slice()]).unwrap_err(),
            IndexError { len: 7 }
        );
        let redactor = Redactor::try_new(std::iter::empty::<&[u8]>()).unwrap();
        assert!(contains(&redactor.redact(short), short));
    }

    #[test]
    fn eight_bytes_is_indexed() {
        let value = b"12345678";
        let redactor = Redactor::try_new([value.as_slice()]).unwrap();
        assert_absent(&redactor, value);
        assert_splits(&redactor, value);
    }

    #[test]
    fn fixed_encodings_and_splits() {
        let secret = br#"abcd"ef\ghij"#;
        assert!(secret.len() >= MIN_VALUE);
        let redactor = Redactor::try_new([secret.as_slice()]).unwrap();
        for needle in independent_needles(secret) {
            assert_absent(&redactor, &needle);
            assert_splits(&redactor, &needle);
        }
        for align in 0..3 {
            let mut raw = vec![0xABu8; align];
            raw.extend_from_slice(secret);
            raw.extend_from_slice(&[0xCD, 0xCE]);
            for url_safe in [false, true] {
                let engine = if url_safe { URL_SAFE } else { STANDARD };
                let embedded = engine.encode(&raw);
                if let Some(frag) = stable_b64(secret, align, url_safe) {
                    let out = redactor.redact(embedded.as_bytes());
                    assert!(
                        !contains(&out, &frag),
                        "align {align} url {url_safe} fragment survived in {embedded}"
                    );
                    assert_splits(&redactor, embedded.as_bytes());
                }
            }
        }
    }

    #[test]
    fn alignment_fragment_ignores_the_preceding_byte() {
        let secret = b"0123456789abcdef";
        for (align, skip) in [(1usize, 2usize), (2, 3)] {
            for url_safe in [false, true] {
                let got = stable_b64(secret, align, url_safe).expect("fragment");
                let engine = if url_safe { URL_SAFE } else { STANDARD };
                let mut buf = vec![0xFFu8; align];
                buf.extend_from_slice(secret);
                let enc = engine.encode(&buf);
                let complete = (buf.len() / 3) * 4;
                let expect = &enc.as_bytes()[skip..complete];
                assert_eq!(got, expect, "align {align} url {url_safe}");
            }
        }
    }

    #[test]
    fn form_plus_and_unicode_escape_are_not_needles() {
        let spaced = b"abcd efgh";
        let redactor = Redactor::try_new([spaced.as_slice()]).unwrap();
        let form = b"abcd+efgh";
        assert!(contains(&redactor.redact(form), form));

        let plain = b"abcdefgh";
        let redactor = Redactor::try_new([plain.as_slice()]).unwrap();
        let unicode = br"\u0061bcdefgh";
        assert!(contains(&redactor.redact(unicode), unicode));
    }

    #[test]
    fn manifest_has_no_vault_or_http_stack() {
        let manifest = include_str!("../Cargo.toml");
        assert!(!manifest.contains("geode-core"));
        assert!(!manifest.contains("geode-grotto"));
        assert!(!manifest.contains("tower"));
        assert!(!manifest.contains("axum"));
    }

    fn independent_needles(secret: &[u8]) -> Vec<Vec<u8>> {
        let mut out = vec![
            secret.to_vec(),
            hex_encode(secret, false),
            hex_encode(secret, true),
            percent_encode(secret),
        ];
        if let Some(json) = json_canonical(secret) {
            out.push(json);
        }
        for url_safe in [false, true] {
            let engine = if url_safe { URL_SAFE } else { STANDARD };
            let padded = engine.encode(secret);
            out.push(padded.clone().into_bytes());
            out.push(padded.trim_end_matches('=').as_bytes().to_vec());
            for align in 0..3 {
                if let Some(frag) = stable_b64(secret, align, url_safe) {
                    out.push(frag);
                }
            }
        }
        out.retain(|n| n.len() >= MIN_VALUE);
        out
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]
        #[test]
        fn every_encoding_and_every_split(secret in prop::collection::vec(any::<u8>(), 8..=16)) {
            let redactor = Redactor::try_new([&secret[..]]).unwrap();
            for needle in independent_needles(&secret) {
                let out = redactor.redact(&needle);
                prop_assert!(!contains(&out, &needle), "needle survived: {needle:?}");
                let once = redactor.redact(&needle);
                for i in 0..=needle.len() {
                    let mut stream = redactor.stream();
                    let mut got = stream.push(&needle[..i]);
                    got.extend(stream.push(&needle[i..]));
                    got.extend(stream.finish());
                    prop_assert!(got == once, "split mismatch at {}", i);
                }
            }
        }
    }

    #[cfg(feature = "layer")]
    #[test]
    fn layer_redacts_sk_prefix_in_log_line() {
        let layer = RedactLayer::new();
        let line = "level=info authorization=Bearer sk-dummy-0000QA";
        let out = layer.redact_line(line);
        assert!(out.contains("[REDACTED]"), "{out}");
        assert!(!out.contains("sk-dummy-0000QA"), "{out}");
    }
}
