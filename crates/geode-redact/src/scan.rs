//! Unknown-secret scanner: pattern, entropy and known-value detectors over
//! raw bytes.
//!
//! This module is pure: it never touches the filesystem. The caller reads
//! files, decides which paths are always findings (key files), and applies
//! an allowlist.
//!
//! A [`Finding`] carries a rule, a 1-based line and byte column, and a keyed
//! fingerprint. It never carries the matched bytes. The fingerprint is
//! `BLAKE3-keyed(K, value)` truncated to 128 bits, so a reader of the output
//! who lacks `K` cannot test guesses of a low-entropy value against it.
//! Fingerprints made under one key do not match those made under another.
//!
//! Detectors:
//! - structured patterns seeded from the redaction prefixes: `AKIA` + 16,
//!   `gh[pousr]_` + 36 or more, `github_pat_` + 60 or more, `xox[abpr]-` +
//!   10 or more, and PEM private-key blocks;
//! - Shannon entropy over runs of base64 or hex alphabet of at least 20
//!   bytes (defaults 4.0 bits/char base64, 3.0 bits/char hex);
//! - optional known values, matched raw.
//!
//! Pattern and entropy rules miss low-entropy secrets such as short
//! passwords. The scan is a backstop, not an allowlist.

use std::fmt;
use std::str::FromStr;

use aho_corasick::{AhoCorasick, MatchKind};
use zeroize::Zeroize;

use crate::{IndexError, MIN_VALUE};

/// BLAKE3 `derive_key` context for a scan key derived from an identity key.
pub const SCAN_FP_DOMAIN: &str = "geode/v1/scan-fp";

/// Fingerprint length in bytes (128 bits, 32 hex chars).
pub const FINGERPRINT_LEN: usize = 16;

/// Key for fingerprints. Zeroed on drop; `Debug` does not print it.
pub struct ScanKey([u8; 32]);

impl ScanKey {
    /// Use 32 raw bytes (the per-user random scan key).
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Derive the scan key from identity key bytes under [`SCAN_FP_DOMAIN`].
    #[must_use]
    pub fn from_isk(isk: &[u8; 32]) -> Self {
        Self(blake3::derive_key(SCAN_FP_DOMAIN, isk))
    }
}

impl Drop for ScanKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for ScanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScanKey(**redacted**)")
    }
}

/// Keyed, truncated fingerprint of a matched value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fingerprint(pub [u8; FINGERPRINT_LEN]);

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A string that is not 32 lowercase hex characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FingerprintParseError;

impl fmt::Display for FingerprintParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a fingerprint (32 lowercase hex characters)")
    }
}

impl std::error::Error for FingerprintParseError {}

impl FromStr for Fingerprint {
    type Err = FingerprintParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b = s.as_bytes();
        if b.len() != FINGERPRINT_LEN * 2 {
            return Err(FingerprintParseError);
        }
        let nib = |c: u8| match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(FingerprintParseError),
        };
        let mut out = [0u8; FINGERPRINT_LEN];
        for (i, o) in out.iter_mut().enumerate() {
            *o = (nib(b[2 * i])? << 4) | nib(b[2 * i + 1])?;
        }
        Ok(Self(out))
    }
}

/// What matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Rule {
    /// `AKIA` followed by 16 of `[0-9A-Z]`.
    AwsAccessKey,
    /// `gh[pousr]_` followed by 36 or more of `[A-Za-z0-9]`.
    GithubToken,
    /// `github_pat_` followed by 60 or more of `[A-Za-z0-9_]`.
    GithubPat,
    /// `xox[abpr]-` followed by 10 or more of `[A-Za-z0-9-]`.
    SlackToken,
    /// A PEM `-----BEGIN ... PRIVATE KEY-----` block.
    PrivateKey,
    /// A high-entropy run of base64 alphabet.
    EntropyBase64,
    /// A high-entropy run of hex digits.
    EntropyHex,
    /// A known secret value.
    KnownValue,
    /// A Geode key file inside a scan root. Set by the caller, never
    /// suppressed.
    GeodeKeyFile,
}

impl Rule {
    /// Stable id used in output.
    #[must_use]
    pub fn id(self) -> &'static str {
        match self {
            Self::AwsAccessKey => "aws-access-key",
            Self::GithubToken => "github-token",
            Self::GithubPat => "github-pat",
            Self::SlackToken => "slack-token",
            Self::PrivateKey => "private-key",
            Self::EntropyBase64 => "entropy-base64",
            Self::EntropyHex => "entropy-hex",
            Self::KnownValue => "known-value",
            Self::GeodeKeyFile => "geode-key-file",
        }
    }
}

/// One finding. Holds no matched bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Finding {
    /// 1-based line; 0 for a whole-file finding.
    pub line: u64,
    /// 1-based byte column; 0 for a whole-file finding.
    pub col: u64,
    /// Rule that matched.
    pub rule: Rule,
    /// Keyed fingerprint of the matched bytes.
    pub fingerprint: Fingerprint,
}

/// Entropy settings.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Thresholds {
    /// Shortest run considered, in bytes.
    pub min_len: usize,
    /// Minimum Shannon entropy, bits per char, for a base64 run.
    pub base64_bits: f64,
    /// Minimum Shannon entropy, bits per char, for a hex run.
    pub hex_bits: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            min_len: 20,
            base64_bits: 4.0,
            hex_bits: 3.0,
        }
    }
}

/// The scanner. `Debug` prints neither the key nor known values.
pub struct Scanner {
    key: ScanKey,
    thresholds: Thresholds,
    known: Option<AhoCorasick>,
}

impl fmt::Debug for Scanner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Scanner")
            .field("thresholds", &self.thresholds)
            .field("known_values", &self.known.is_some())
            .finish_non_exhaustive()
    }
}

impl Scanner {
    /// A scanner with default thresholds and no known values.
    #[must_use]
    pub fn new(key: ScanKey) -> Self {
        Self {
            key,
            thresholds: Thresholds::default(),
            known: None,
        }
    }

    /// Replace the entropy thresholds.
    #[must_use]
    pub fn with_thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Also flag these exact values (rule `known-value`).
    ///
    /// # Errors
    ///
    /// [`IndexError`] when a value is shorter than 8 bytes. Nothing from
    /// that call is indexed.
    pub fn with_known_values<I, B>(mut self, values: I) -> Result<Self, IndexError>
    where
        I: IntoIterator<Item = B>,
        B: AsRef<[u8]>,
    {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        for v in values {
            let v = v.as_ref();
            if v.len() < MIN_VALUE {
                for n in &mut needles {
                    n.zeroize();
                }
                return Err(IndexError { len: v.len() });
            }
            needles.push(v.to_vec());
        }
        self.known = if needles.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .match_kind(MatchKind::LeftmostLongest)
                    .build(&needles)
                    .expect("known values are non-empty"),
            )
        };
        for n in &mut needles {
            n.zeroize();
        }
        Ok(self)
    }

    /// Keyed fingerprint of `value`.
    #[must_use]
    pub fn fingerprint(&self, value: &[u8]) -> Fingerprint {
        let full = blake3::keyed_hash(&self.key.0, value);
        let mut fp = [0u8; FINGERPRINT_LEN];
        fp.copy_from_slice(&full.as_bytes()[..FINGERPRINT_LEN]);
        Fingerprint(fp)
    }

    /// A whole-file finding (line 0, column 0) for `rule`, fingerprinted
    /// over `contents`.
    #[must_use]
    pub fn whole_file(&self, rule: Rule, contents: &[u8]) -> Finding {
        Finding {
            line: 0,
            col: 0,
            rule,
            fingerprint: self.fingerprint(contents),
        }
    }

    /// Scan `data`. Findings are in byte order; a match inside another
    /// match's span is reported once.
    #[must_use]
    pub fn scan(&self, data: &[u8]) -> Vec<Finding> {
        let mut spans: Vec<(usize, usize, Rule)> = Vec::new();
        if let Some(ac) = &self.known {
            for m in ac.find_iter(data) {
                spans.push((m.start(), m.end(), Rule::KnownValue));
            }
        }
        structured(data, &mut spans);
        self.entropy(data, &mut spans);

        spans.sort_by_key(|&(s, e, _)| (s, std::cmp::Reverse(e)));
        let mut kept: Vec<(usize, usize, Rule)> = Vec::new();
        for span in spans {
            if kept.last().is_some_and(|&(_, end, _)| span.0 < end) {
                continue;
            }
            kept.push(span);
        }

        let mut out = Vec::with_capacity(kept.len());
        let (mut line, mut line_start, mut pos) = (1u64, 0usize, 0usize);
        for (start, end, rule) in kept {
            for (i, &b) in data[pos..start].iter().enumerate() {
                if b == b'\n' {
                    line += 1;
                    line_start = pos + i + 1;
                }
            }
            pos = start;
            out.push(Finding {
                line,
                col: (start - line_start + 1) as u64,
                rule,
                fingerprint: self.fingerprint(&data[start..end]),
            });
        }
        out
    }

    fn entropy(&self, data: &[u8], spans: &mut Vec<(usize, usize, Rule)>) {
        let t = self.thresholds;
        let mut i = 0;
        while i < data.len() {
            if !is_b64(data[i]) {
                i += 1;
                continue;
            }
            let start = i;
            while i < data.len() && is_b64(data[i]) {
                i += 1;
            }
            let run = &data[start..i];
            if run.len() < t.min_len {
                continue;
            }
            if spans.iter().any(|&(s, e, _)| s < i && start < e) {
                continue;
            }
            let hex = run.iter().all(u8::is_ascii_hexdigit);
            if hex {
                let digits = run.iter().any(u8::is_ascii_digit);
                let letters = run.iter().any(u8::is_ascii_alphabetic);
                if digits && letters && shannon(run) >= t.hex_bits {
                    spans.push((start, i, Rule::EntropyHex));
                }
            } else if classes(run) >= 3 && shannon(run) >= t.base64_bits {
                spans.push((start, i, Rule::EntropyBase64));
            }
        }
    }
}

/// Structured pattern spans.
fn structured(data: &[u8], spans: &mut Vec<(usize, usize, Rule)>) {
    let mut i = 0;
    while i < data.len() {
        let before_ok = i == 0 || !data[i - 1].is_ascii_alphanumeric();
        let found = if before_ok { match_at(data, i) } else { None };
        match found {
            Some((end, rule)) => {
                spans.push((i, end, rule));
                i = end;
            }
            None => i += 1,
        }
    }
}

/// A structured match starting at `i`: its end and rule.
fn match_at(data: &[u8], i: usize) -> Option<(usize, Rule)> {
    let rest = &data[i..];
    if rest.starts_with(b"AKIA") {
        let body = rest.get(4..20)?;
        let upper_digit = |b: &u8| b.is_ascii_uppercase() || b.is_ascii_digit();
        if body.iter().all(upper_digit) && !rest.get(20).is_some_and(u8::is_ascii_alphanumeric) {
            return Some((i + 20, Rule::AwsAccessKey));
        }
        return None;
    }
    if rest.starts_with(b"github_pat_") {
        let n = run_len(&rest[11..], |b| b.is_ascii_alphanumeric() || b == b'_');
        return (n >= 60).then_some((i + 11 + n, Rule::GithubPat));
    }
    if rest.len() > 4 && rest.starts_with(b"gh") && b"pousr".contains(&rest[2]) && rest[3] == b'_' {
        let n = run_len(&rest[4..], |b| b.is_ascii_alphanumeric());
        return (n >= 36).then_some((i + 4 + n, Rule::GithubToken));
    }
    if rest.len() > 5 && rest.starts_with(b"xox") && b"abpr".contains(&rest[3]) && rest[4] == b'-' {
        let n = run_len(&rest[5..], |b| b.is_ascii_alphanumeric() || b == b'-');
        return (n >= 10).then_some((i + 5 + n, Rule::SlackToken));
    }
    if rest.starts_with(b"-----BEGIN ") {
        let header_end = find(&rest[11..], b"-----")? + 11;
        find(&rest[11..header_end], b"PRIVATE KEY")?;
        let end = match find(&rest[header_end..], b"-----END ") {
            Some(e) => {
                let tail = header_end + e + 9;
                find(&rest[tail..], b"-----").map_or(rest.len(), |c| tail + c + 5)
            }
            None => rest.len(),
        };
        return Some((i + end, Rule::PrivateKey));
    }
    None
}

fn run_len(data: &[u8], ok: impl Fn(u8) -> bool) -> usize {
    data.iter().take_while(|&&b| ok(b)).count()
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn is_b64(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
}

/// Character classes present: upper, lower, digit, symbol.
fn classes(run: &[u8]) -> usize {
    [
        run.iter().any(u8::is_ascii_uppercase),
        run.iter().any(u8::is_ascii_lowercase),
        run.iter().any(u8::is_ascii_digit),
        run.iter().any(|b| !b.is_ascii_alphanumeric()),
    ]
    .iter()
    .filter(|&&c| c)
    .count()
}

/// Shannon entropy in bits per byte.
#[allow(clippy::cast_precision_loss)]
fn shannon(run: &[u8]) -> f64 {
    let mut counts = [0u32; 256];
    for &b in run {
        counts[usize::from(b)] += 1;
    }
    let n = run.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> Scanner {
        Scanner::new(ScanKey::from_bytes([7u8; 32]))
    }

    fn rules(data: &[u8]) -> Vec<Rule> {
        scanner().scan(data).iter().map(|f| f.rule).collect()
    }

    /// Deterministic pseudo-random bytes for fixtures (not real tokens).
    fn noise(seed: &str, n: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut ctr = 0u32;
        while out.len() < n {
            let h = blake3::hash(format!("{seed}/{ctr}").as_bytes());
            out.extend_from_slice(h.as_bytes());
            ctr += 1;
        }
        out.truncate(n);
        out
    }

    fn pick(seed: &str, alphabet: &[u8], n: usize) -> String {
        noise(seed, n)
            .iter()
            .map(|b| alphabet[usize::from(*b) % alphabet.len()] as char)
            .collect()
    }

    const UPPER_DIGIT: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    #[test]
    fn aws_key() {
        let k = format!("AKIA{}", pick("aws", UPPER_DIGIT, 16));
        assert_eq!(rules(format!("id={k}\n").as_bytes()), [Rule::AwsAccessKey]);
        // near misses: 15 chars, a 17th char, lowercase, glued prefix
        let short = format!("AKIA{}", pick("aws", UPPER_DIGIT, 15));
        assert!(rules(short.as_bytes()).is_empty());
        assert!(rules(format!("{k}Z").as_bytes()).is_empty());
        assert!(rules(format!("AKIA{}", pick("aws", b"abcdefghij", 16)).as_bytes()).is_empty());
        assert!(rules(format!("X{k}").as_bytes()).is_empty());
    }

    #[test]
    fn github_tokens() {
        for p in ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] {
            let t = format!("{p}{}", pick(p, ALNUM, 36));
            assert_eq!(rules(t.as_bytes()), [Rule::GithubToken], "{p}");
        }
        // 35 chars is not a token (it may still be high-entropy).
        let short = format!("ghp_{}", pick("x", ALNUM, 35));
        assert!(!rules(short.as_bytes()).contains(&Rule::GithubToken));
        assert!(rules(format!("ghx_{}", pick("x", b"abc", 36)).as_bytes()).is_empty());
        let pat = format!("github_pat_{}", pick("pat", ALNUM, 60));
        assert_eq!(rules(pat.as_bytes()), [Rule::GithubPat]);
        assert!(rules(format!("github_pat_{}", pick("pat", b"ab", 59)).as_bytes()).is_empty());
    }

    #[test]
    fn slack_token() {
        let t = format!("xoxb-{}", pick("slack", b"0123456789", 12));
        assert_eq!(rules(t.as_bytes()), [Rule::SlackToken]);
        assert!(rules(b"xoxb-12345").is_empty());
        assert!(rules(b"xoxz-123456789012").is_empty());
    }

    #[test]
    fn pem_private_key() {
        let body = "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n";
        let f = scanner().scan(format!("x\n{body}").as_bytes());
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].rule, f[0].line, f[0].col), (Rule::PrivateKey, 2, 1));
        assert!(rules(b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----").is_empty());
        assert!(rules(b"-----BEGIN PUBLIC KEY-----").is_empty());
    }

    #[test]
    fn entropy_rules() {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD.encode(noise("blob", 40));
        assert_eq!(
            rules(format!("v = {b64}\n").as_bytes()),
            [Rule::EntropyBase64]
        );
        let hex: String = noise("hex", 20)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(rules(hex.as_bytes()), [Rule::EntropyHex]);
        // near misses: short, low entropy, one class, prose
        assert!(rules(&b64.as_bytes()[..19]).is_empty());
        assert!(rules(b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_empty());
        assert!(rules(b"abababababababababab12121212").is_empty());
        assert!(rules(b"this-is-a-long-kebab-case-identifier").is_empty());
        assert!(rules(b"The quick brown fox jumps over the lazy dog.\n").is_empty());
        let strict = scanner().with_thresholds(Thresholds {
            base64_bits: 6.5,
            ..Thresholds::default()
        });
        assert!(
            strict.scan(b64.as_bytes()).is_empty(),
            "threshold is tunable"
        );
    }

    #[test]
    fn known_values_and_binary() {
        let s = scanner().with_known_values(["hunter2-but-longer"]).unwrap();
        let mut data = vec![0u8, 159, 146, 150, b'\n'];
        data.extend_from_slice(b"\x00hunter2-but-longer\x00");
        let f = s.scan(&data);
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].rule, f[0].line, f[0].col), (Rule::KnownValue, 2, 2));
        assert_eq!(
            scanner().with_known_values(["short"]).unwrap_err(),
            IndexError { len: 5 }
        );

        let k = format!("AKIA{}", pick("bin", UPPER_DIGIT, 16));
        let mut bin = noise("bin-pad", 64);
        bin.push(0);
        bin.extend_from_slice(k.as_bytes());
        bin.push(0xff);
        assert!(rules(&bin).contains(&Rule::AwsAccessKey));
    }

    #[test]
    fn line_and_column() {
        let k = format!("AKIA{}", pick("pos", UPPER_DIGIT, 16));
        let f = scanner().scan(format!("a\nbb\n  key: {k}\n").as_bytes());
        assert_eq!((f[0].line, f[0].col), (3, 8));
    }

    #[test]
    fn fingerprints_are_keyed() {
        let value = b"AKIAABCDEFGHIJKLMNOP";
        let a = Scanner::new(ScanKey::from_bytes([1u8; 32]));
        let b = Scanner::new(ScanKey::from_bytes([2u8; 32]));
        let c = Scanner::new(ScanKey::from_isk(&[1u8; 32]));
        assert_eq!(a.fingerprint(value), a.fingerprint(value));
        assert_ne!(a.fingerprint(value), b.fingerprint(value));
        assert_ne!(
            a.fingerprint(value),
            c.fingerprint(value),
            "ISK path is domain-separated"
        );
        let unkeyed = blake3::hash(value).to_hex().to_string();
        for s in [&a, &b, &c] {
            let fp = s.fingerprint(value).to_string();
            assert_eq!(fp.len(), 32);
            assert!(!unkeyed.contains(&fp));
            assert_eq!(fp.parse::<Fingerprint>().unwrap(), s.fingerprint(value));
        }
        assert!("ABCD".parse::<Fingerprint>().is_err());
        assert!("0123456789ABCDEF0123456789abcdef"
            .parse::<Fingerprint>()
            .is_err());
        assert_eq!(
            format!("{:?}", ScanKey::from_bytes([9u8; 32])),
            "ScanKey(**redacted**)"
        );
    }
}
