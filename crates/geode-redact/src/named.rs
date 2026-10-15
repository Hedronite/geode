//! Named redaction for injected bindings (SPEC-v034 G6).
//!
//! Same v1 needles and prefixes as [`crate::Redactor`]. A bound value is
//! replaced with `[REDACTED:NAME]`, or `[REDACTED]` under
//! [`Placeholder::Hidden`]. A prefix match is always `[REDACTED]`. Hits are
//! counted per binding name; prefix hits are not counted. Additive: the
//! unnamed [`crate::Redactor`] is unchanged.

use std::collections::{BTreeMap, BTreeSet};

use aho_corasick::{AhoCorasick, MatchKind};

use super::{push_needle, value_needles, MIN_VALUE, PREFIXES, REPLACEMENT};

/// How a bound value hit is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placeholder {
    /// `[REDACTED:NAME]`.
    Named,
    /// `[REDACTED]`, no binding name.
    Hidden,
}

/// A binding value was shorter than 8 bytes, so nothing was indexed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NamedIndexError {
    /// Binding name. The value is not stored.
    pub name: String,
}

impl std::fmt::Display for NamedIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "binding {}: too short to redact safely", self.name)
    }
}

impl std::error::Error for NamedIndexError {}

#[derive(Clone, Copy)]
enum Label {
    Prefix,
    Binding(usize),
}

/// Automaton over binding needles (labelled by name) plus the known prefixes.
///
/// `Debug` does not print needles.
pub struct NamedRedactor {
    ac: AhoCorasick,
    labels: Vec<Label>,
    /// Binding needles only, for the argv check.
    bindings_ac: AhoCorasick,
    names: Vec<String>,
    max_len: usize,
    placeholder: Placeholder,
}

impl std::fmt::Debug for NamedRedactor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NamedRedactor")
            .field("names", &self.names)
            .field("max_len", &self.max_len)
            .finish_non_exhaustive()
    }
}

impl NamedRedactor {
    /// Index each `(name, value)` binding plus the known prefixes. When two
    /// bindings share a needle, the first binding names it.
    ///
    /// # Errors
    ///
    /// Returns [`NamedIndexError`] naming the first binding shorter than 8
    /// bytes. Nothing from that call is indexed.
    pub fn try_new<N, B>(
        bindings: &[(N, B)],
        placeholder: Placeholder,
    ) -> Result<Self, NamedIndexError>
    where
        N: AsRef<str>,
        B: AsRef<[u8]>,
    {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut labels = Vec::new();
        let mut seen = BTreeSet::new();
        let mut binding_needles: Vec<Vec<u8>> = Vec::new();
        let mut names = Vec::with_capacity(bindings.len());
        for (idx, (name, value)) in bindings.iter().enumerate() {
            let value = value.as_ref();
            if value.len() < MIN_VALUE {
                return Err(NamedIndexError {
                    name: name.as_ref().to_owned(),
                });
            }
            names.push(name.as_ref().to_owned());
            for needle in value_needles(value) {
                let before = needles.len();
                push_needle(&mut needles, &mut seen, &needle);
                if needles.len() > before {
                    labels.push(Label::Binding(idx));
                    binding_needles.push(needle);
                }
            }
        }
        for prefix in PREFIXES {
            let before = needles.len();
            push_needle(&mut needles, &mut seen, prefix);
            if needles.len() > before {
                labels.push(Label::Prefix);
            }
        }
        let max_len = needles.iter().map(Vec::len).max().unwrap_or(1);
        let ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&needles)
            .expect("prefix needles are non-empty");
        let bindings_ac = AhoCorasick::builder()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&binding_needles)
            .expect("needles build");
        Ok(Self {
            ac,
            labels,
            bindings_ac,
            names,
            max_len,
            placeholder,
        })
    }

    /// True when any v1 encoding of any bound value occurs in `input`.
    /// Prefix needles do not count here.
    #[must_use]
    pub fn contains_binding(&self, input: &[u8]) -> bool {
        self.bindings_ac.is_match(input)
    }

    /// Binding names in index order.
    #[must_use]
    pub fn names(&self) -> &[String] {
        &self.names
    }

    /// Stream `input` in chunks. `finish` must be called to flush the tail.
    #[must_use]
    pub fn stream(&self) -> NamedStream<'_> {
        NamedStream {
            r: self,
            buf: Vec::new(),
            hits: vec![0; self.names.len()],
        }
    }

    fn replacement(&self, label: Label, out: &mut Vec<u8>, hits: &mut [u64]) {
        match label {
            Label::Prefix => out.extend_from_slice(REPLACEMENT),
            Label::Binding(idx) => {
                hits[idx] += 1;
                match self.placeholder {
                    Placeholder::Hidden => out.extend_from_slice(REPLACEMENT),
                    Placeholder::Named => {
                        out.extend_from_slice(b"[REDACTED:");
                        out.extend_from_slice(self.names[idx].as_bytes());
                        out.push(b']');
                    }
                }
            }
        }
    }
}

/// Carry buffer so a needle split across reads still matches, with
/// per-binding hit counts.
pub struct NamedStream<'a> {
    r: &'a NamedRedactor,
    buf: Vec<u8>,
    hits: Vec<u64>,
}

impl NamedStream<'_> {
    /// Append `chunk` and return the bytes that can no longer change.
    #[must_use]
    pub fn push(&mut self, chunk: &[u8]) -> Vec<u8> {
        self.buf.extend_from_slice(chunk);
        let max_len = self.r.max_len.max(1);
        if self.buf.len() < max_len {
            return Vec::new();
        }
        // A start is stable once `max_len` bytes have been seen from there.
        let first_unstable = self.buf.len() - max_len + 1;
        let mut out = Vec::new();
        let mut i = 0;
        for m in self.r.ac.find_iter(&self.buf) {
            if m.start() >= first_unstable {
                break;
            }
            out.extend_from_slice(&self.buf[i..m.start()]);
            self.r.replacement(
                self.r.labels[m.pattern().as_usize()],
                &mut out,
                &mut self.hits,
            );
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

    /// Redact the uncommitted tail.
    #[must_use]
    pub fn finish(&mut self) -> Vec<u8> {
        let buf = std::mem::take(&mut self.buf);
        let mut out = Vec::with_capacity(buf.len());
        let mut last = 0;
        for m in self.r.ac.find_iter(&buf) {
            out.extend_from_slice(&buf[last..m.start()]);
            self.r.replacement(
                self.r.labels[m.pattern().as_usize()],
                &mut out,
                &mut self.hits,
            );
            last = m.end();
        }
        out.extend_from_slice(&buf[last..]);
        out
    }

    /// Hits per binding name so far. Names with zero hits are omitted.
    #[must_use]
    pub fn hits(&self) -> BTreeMap<String, u64> {
        self.r
            .names
            .iter()
            .zip(&self.hits)
            .filter(|(_, n)| **n > 0)
            .map(|(name, n)| (name.clone(), *n))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V: &[u8] = b"sk-dummy-0000QA";

    fn run(r: &NamedRedactor, input: &[u8], split: usize) -> (Vec<u8>, BTreeMap<String, u64>) {
        let mut s = r.stream();
        let mut out = s.push(&input[..split]);
        out.extend(s.push(&input[split..]));
        out.extend(s.finish());
        (out, s.hits())
    }

    #[test]
    fn value_wins_over_prefix_and_is_named() {
        let r = NamedRedactor::try_new(&[("KEY", V)], Placeholder::Named).unwrap();
        let input = b"echo sk-dummy-0000QA then sk-other\n";
        for split in 0..=input.len() {
            let (out, hits) = run(&r, input, split);
            assert_eq!(
                out, b"echo [REDACTED:KEY] then [REDACTED]other\n",
                "split {split}"
            );
            assert_eq!(hits.get("KEY"), Some(&1));
            assert_eq!(hits.len(), 1);
        }
    }

    #[test]
    fn encodings_are_named() {
        use base64::Engine as _;
        let r = NamedRedactor::try_new(&[("KEY", V)], Placeholder::Named).unwrap();
        let b64 = base64::engine::general_purpose::STANDARD.encode(V);
        let hex: String = V.iter().map(|b| format!("{b:02x}")).collect();
        let input = format!("{b64}\n{hex}\n");
        let (out, hits) = run(&r, input.as_bytes(), 3);
        assert_eq!(out, b"[REDACTED:KEY]\n[REDACTED:KEY]\n");
        assert_eq!(hits.get("KEY"), Some(&2));
    }

    #[test]
    fn hidden_omits_name_and_still_counts() {
        let r = NamedRedactor::try_new(&[("KEY", V)], Placeholder::Hidden).unwrap();
        let (out, hits) = run(&r, b"x sk-dummy-0000QA y", 5);
        assert_eq!(out, b"x [REDACTED] y");
        assert_eq!(hits.get("KEY"), Some(&1));
    }

    #[test]
    fn short_binding_is_refused_by_name() {
        let err = NamedRedactor::try_new(
            &[("A", &b"long-enough-1"[..]), ("PIN", &b"1234"[..])],
            Placeholder::Named,
        )
        .unwrap_err();
        assert_eq!(err.name, "PIN");
        assert!(!err.to_string().contains("1234"));
    }

    #[test]
    fn contains_binding_ignores_prefixes() {
        let r = NamedRedactor::try_new(&[("KEY", V)], Placeholder::Named).unwrap();
        assert!(r.contains_binding(b"--arg=sk-dummy-0000QA"));
        assert!(r.contains_binding(b"736b2d64756d6d792d303030305141"));
        assert!(!r.contains_binding(b"sk-unrelated AKIA"));
    }

    #[test]
    fn debug_has_no_needles() {
        let r = NamedRedactor::try_new(&[("KEY", V)], Placeholder::Named).unwrap();
        let d = format!("{r:?}");
        assert!(!d.contains("dummy"), "{d}");
    }
}
