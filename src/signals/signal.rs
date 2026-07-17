//! Response signal classification.
//!
//! Given a baseline response and a probe response, classify what changed.
//! Modelled on nuclei's matcher taxonomy: each [`Classifier`] looks for one
//! kind of signal and returns it if found. The [`SignalSet`] composes them.
//!
//! Adding a new signal type = one variant on [`Signal`] + one struct impl.

use std::time::Duration;

/// A minimal view of an HTTP response, enough for signal classification.
///
/// Intentionally narrow so the loop is independent of the gRPC tool plumbing
/// and trivially mockable in tests.
#[derive(Debug, Clone)]
pub struct ProbeResponse {
    /// HTTP status code.
    pub status: u16,
    /// Response body as bytes (kept as bytes so binary classifiers don't pay UTF-8 cost).
    pub body: Vec<u8>,
    /// Wall-clock duration of the request.
    pub duration: Duration,
}

impl ProbeResponse {
    /// Lossy UTF-8 view of the body — for word/regex matchers.
    pub fn body_text(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.body)
    }
}

/// Typed signal extracted from a `(baseline, probe)` pair.
///
/// Intentionally flat — each variant is what a future mutator dispatches on.
/// Add a variant when a new classifier needs to surface a distinct case.
#[derive(Debug, Clone, PartialEq)]
pub enum Signal {
    /// No interesting change vs baseline.
    NoEffect,
    /// HTTP status changed.
    StatusDelta { from: u16, to: u16 },
    /// Body length changed by more than the threshold.
    SizeDelta { baseline_bytes: usize, probe_bytes: usize, ratio: f64 },
    /// The injected payload appears in the response body.
    Reflected {
        /// How the payload appears (literal, percent-encoded, html-encoded, …).
        encoding: ReflectionEncoding,
    },
    /// A regex from the error library matched.
    Error {
        /// Which error family the regex came from (e.g. "mysql", "postgres", "java_stack").
        family: String,
        /// The matched substring.
        snippet: String,
    },
    /// A known dangerous-content signature appeared in the body that was NOT in
    /// the baseline — e.g. leaked file bytes (`root:x:0:0`) or cloud metadata
    /// (`AccessKeyId`). Direct evidence of a successful file read / SSRF, so it
    /// confirms a hit on its own (unlike the deliberately-noisy `SizeDelta`).
    LeakSignature {
        /// Which signature family matched (e.g. "unix_passwd", "aws_credentials").
        label: String,
        /// The matched substring.
        snippet: String,
    },
    /// Probe duration crossed the time-based threshold.
    TimeDelay {
        baseline_ms: u128,
        probe_ms: u128,
    },
    /// Body bytes differ from baseline despite identical size.
    /// Signals ORDER BY / structural injection where ordering changes content
    /// but not byte count — invisible to SizeDelta.
    BodyDiff,
    /// The response is unlike anything in the calibrated "boring set" — a
    /// recall-first novelty flag (see ANOMALY.md). Not a confirmation; a
    /// "this is different, look at it" report. `detail` names what deviated.
    Anomaly { detail: String },
    /// A server-side prototype-pollution detection gadget fired — the response
    /// changed in a way only pollution explains (e.g. the `json spaces` gadget
    /// reformatting the JSON body). Confirms on its own. `gadget` names which.
    PrototypePollution { gadget: String },
}

/// How a reflected payload appears in the response.
#[derive(Debug, Clone, PartialEq)]
pub enum ReflectionEncoding {
    /// Payload appears verbatim.
    Literal,
    /// Payload appears percent-encoded (`<` → `%3C`).
    PercentEncoded,
    /// Payload appears HTML-encoded (`<` → `&lt;`).
    HtmlEncoded,
}

impl Signal {
    /// Short discriminator suitable for mutation-table lookup.
    pub fn kind(&self) -> &'static str {
        match self {
            Signal::NoEffect => "no_effect",
            Signal::StatusDelta { .. } => "status_delta",
            Signal::SizeDelta { ratio, .. } => {
                if *ratio >= 3.0 { "size_delta_large" }
                else if *ratio <= 0.33 { "size_delta_small" }
                else { "size_delta" }
            },
            Signal::Reflected { .. } => "reflected",
            Signal::Error { .. } => "error",
            Signal::LeakSignature { .. } => "leak_signature",
            Signal::TimeDelay { .. } => "time_delay",
            Signal::BodyDiff => "body_diff",
            Signal::Anomaly { .. } => "anomaly",
            Signal::PrototypePollution { .. } => "proto_pollution",
        }
    }
}

/// One thing that can detect one kind of signal.
///
/// Returns `None` if it sees nothing of its kind; this lets the [`SignalSet`]
/// collect all detected signals rather than stopping at the first hit.
pub trait Classifier: Send + Sync {
    /// Inspect the baseline / probe pair and emit a signal if one is present.
    fn classify(&self, payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal>;
}

/// A composed collection of classifiers.
///
/// Runs every classifier and returns all detected signals.
/// The mutator decides which one to act on; signal *ranking* is policy,
/// not classification.
pub struct SignalSet {
    classifiers: Vec<Box<dyn Classifier>>,
}

impl SignalSet {
    /// Empty set — add classifiers via [`with`].
    pub fn new() -> Self {
        Self { classifiers: Vec::new() }
    }

    /// Builder add.
    pub fn with(mut self, classifier: Box<dyn Classifier>) -> Self {
        self.classifiers.push(classifier);
        self
    }

    /// Append a classifier in place (e.g. bolt on the `NoveltyClassifier` for
    /// `--hunt` after the set is already built).
    pub fn push(&mut self, classifier: Box<dyn Classifier>) {
        self.classifiers.push(classifier);
    }

    /// A starter set: status, size, body-diff, reflection, time-delay, and one error library.
    /// Add classifiers to dial in.
    pub fn defaults() -> Self {
        Self::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(BodyDiffClassifier))
            .with(Box::new(ReflectionClassifier))
            .with(Box::new(TimeDelayClassifier::default()))
            .with(Box::new(ErrorClassifier::dbms_starter()))
    }

    /// Run every classifier; collect any signals.
    pub fn run(&self, payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Vec<Signal> {
        self.classifiers
            .iter()
            .filter_map(|c| c.classify(payload, baseline, probe))
            .collect()
    }
}

impl Default for SignalSet {
    fn default() -> Self { Self::defaults() }
}

// ── concrete classifiers ────────────────────────────────────────────────────

/// Status code changed.
pub struct StatusClassifier;
impl Classifier for StatusClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        if probe.status != baseline.status {
            Some(Signal::StatusDelta { from: baseline.status, to: probe.status })
        } else { None }
    }
}

/// Body size changed by more than a threshold (absolute or relative).
pub struct SizeClassifier {
    /// Minimum absolute byte delta to flag.
    pub min_abs: usize,
    /// Minimum relative delta to flag (0.0..1.0).
    pub min_rel: f64,
}
impl Default for SizeClassifier {
    fn default() -> Self { Self { min_abs: 50, min_rel: 0.05 } }
}
impl Classifier for SizeClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        let b = baseline.body.len();
        let p = probe.body.len();
        let abs = if b > p { b - p } else { p - b };
        let rel = if b == 0 { 1.0 } else { (abs as f64) / (b as f64) };
        // recall-first (see ANOMALY.md): this ANDs abs+rel for precision. A
        // `sensitive()`/`--hunt` mode should OR them and lower both — a 40-byte
        // delta on a 2 KB page is exactly the outlier we don't want to drop.
        if abs >= self.min_abs && rel >= self.min_rel {
            let ratio = (p as f64) / (b as f64).max(1.0);
            Some(Signal::SizeDelta { baseline_bytes: b, probe_bytes: p, ratio })
        } else { None }
    }
}

/// Payload appears in the probe body, possibly encoded.
pub struct ReflectionClassifier;
impl Classifier for ReflectionClassifier {
    fn classify(&self, payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        // Single chars like `"`, `'`, `<` appear in every HTML page — skip.
        // Payloads shorter than 3 bytes are not checked for reflection.
        // This suppresses single-char noise (e.g. "'", "<" appearing in benign
        // JSON/HTML contexts), at the cost of missing short-but-real reflections.
        // Trade-off: fewer false positives vs. blind spot for 1-2 char XSS probes.
        // recall-first (see ANOMALY.md): this `< 3` skip is a deliberate blind
        // spot; a `sensitive()`/`--hunt` mode should drop it and eat the noise.
        if payload.len() < 3 { return None; }
        let body = probe.body_text();
        let baseline_body = baseline.body_text();

        // Literal — only signal if NOT already in baseline.
        if body.contains(payload) && !baseline_body.contains(payload) {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::Literal });
        }

        // Percent-encoded (RFC 3986 — only encode non-unreserved bytes).
        // Both uppercase (%3C) and lowercase (%3c) appear in the wild.
        let percent_upper = percent_encode(payload, true);
        let percent_lower = percent_encode(payload, false);
        if (body.contains(&percent_upper) || body.contains(&percent_lower))
            && !baseline_body.contains(&percent_upper)
            && !baseline_body.contains(&percent_lower)
        {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::PercentEncoded });
        }

        // HTML-encoded — only the dangerous characters.
        let html_encoded = html_encode(payload);
        if !html_encoded.is_empty()
            && body.contains(&html_encoded)
            && !baseline_body.contains(&html_encoded)
        {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::HtmlEncoded });
        }
        None
    }
}

/// Percent-encode a string per RFC 3986. Only encodes bytes outside the
/// unreserved set (A-Z, a-z, 0-9, -, _, ., ~). Upper/lower case on hex digits
/// is caller-selectable.
fn percent_encode(s: &str, upper: bool) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                String::from_utf8(vec![b]).unwrap()
            } else if upper {
                format!("%{:02X}", b)
            } else {
                format!("%{:02x}", b)
            }
        })
        .collect()
}

/// HTML-encode the dangerous characters. Returns an empty string if no
/// encoding was applied (payload contained no dangerous chars).
fn html_encode(s: &str) -> String {
    let result = s
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;");
    if result == s { String::new() } else { result }
}

/// Time-delay signal: probe took noticeably longer than baseline.
pub struct TimeDelayClassifier {
    /// Probe duration must exceed baseline by this factor (e.g. 3.0 = 3× slower).
    pub min_factor: f64,
    /// Floor so noise on fast endpoints doesn't trigger ("10ms vs 30ms" is not a signal).
    /// recall-first (see ANOMALY.md): this floor is a precision gate. It's the
    /// right call for *confirmation*, but too coarse for anomaly flagging — a
    /// `sensitive()`/`--hunt` mode wants a much lower floor (and eats the noise).
    /// Lowering it 500→200 halved ssrf's hits/1k via the timing re-probe; see git log.
    pub min_abs_ms: u128,
}
impl Default for TimeDelayClassifier {
    fn default() -> Self { Self { min_factor: 3.0, min_abs_ms: 500 } }
}
impl Classifier for TimeDelayClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        let b = baseline.duration.as_millis();
        let p = probe.duration.as_millis();
        if p < self.min_abs_ms { return None; }
        let b_safe = b.max(1);
        let factor = (p as f64) / (b_safe as f64);
        if factor >= self.min_factor {
            Some(Signal::TimeDelay { baseline_ms: b, probe_ms: p })
        } else { None }
    }
}

/// Response body changed structurally despite the same byte length.
///
/// Fires when `baseline.body != probe.body` but `baseline.body.len() == probe.body.len()`.
/// Catches ORDER BY injection, content shuffle, and any mutation that rearranges
/// rather than grows or shrinks the response.
pub struct BodyDiffClassifier;
impl Classifier for BodyDiffClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        if baseline.body.len() == probe.body.len() && baseline.body != probe.body {
            Some(Signal::BodyDiff)
        } else {
            None
        }
    }
}

/// Confirms server-side **prototype pollution** via the canonical `json spaces`
/// detection gadget: once `res.json`'s indentation setting is polluted, the
/// response body is the same content re-serialised with extra whitespace. So if
/// the probe body equals the baseline body after whitespace is stripped, but the
/// raw bytes differ and the probe is larger, only a formatting-config pollution
/// explains it — a normal endpoint never re-indents identical content on its own.
/// High precision (near-zero false positives), so it confirms.
pub struct ProtoPollutionClassifier;
impl Classifier for ProtoPollutionClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        // Only meaningful when both bodies carry JSON structure.
        if !baseline.body.contains(&b'{') || probe.body.len() <= baseline.body.len() {
            return None;
        }
        let strip_ws = |b: &[u8]| -> Vec<u8> {
            b.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect()
        };
        if baseline.body != probe.body && strip_ws(&baseline.body) == strip_ws(&probe.body) {
            Some(Signal::PrototypePollution { gadget: "json-spaces-reformat".to_string() })
        } else {
            None
        }
    }
}

/// Regex against a library of error patterns, keyed by family.
///
/// Each entry: `(family, compiled regex)`. Add to the table to dial in.
pub struct ErrorClassifier {
    patterns: Vec<(String, regex::Regex)>,
}

impl ErrorClassifier {
    /// Build from `(family, pattern)` pairs. Invalid regexes are skipped.
    pub fn new(entries: &[(&str, &str)]) -> Self {
        let patterns = entries
            .iter()
            .filter_map(|(family, pat)| {
                regex::Regex::new(pat).ok().map(|re| (family.to_string(), re))
            })
            .collect();
        Self { patterns }
    }

    /// A tiny starter library — DBMS errors only. Expand as needed.
    pub fn dbms_starter() -> Self {
        Self::new(&[
            ("mysql",    r"(?i)you have an error in your sql syntax"),
            ("mysql",    r"(?i)mysql_fetch"),
            ("postgres", r"(?i)pg_query\(\)|pgsql_query\(\)|postgresql.*error"),
            ("mssql",    r"(?i)microsoft sql native client|sql server"),
            ("sqlite",   r"(?i)sqlite3?::?(?:exception|error)|sqlite_master"),
            ("oracle",   r"(?i)ora-\d{5}"),
            ("generic",  r"(?i)sql syntax|unclosed quotation mark"),
        ])
    }

    /// Node.js / V8 runtime error signatures useful for detecting JS sink hits.
    pub fn nodejs_starter() -> Self {
        Self::new(&[
            ("node", r"(?i)ReferenceError"),
            ("node", r"(?i)SyntaxError"),
            ("node", r"(?i)TypeError"),
            ("node", r"(?i)EvalError"),
            ("node", r"(?i)RangeError"),
            ("node", r"(?i)URIError"),
            ("node", r"(?i)at .* \(.*:\d+:\d+\)"),
            ("node", r"(?i)Cannot find module"),
            ("node", r"(?i)Module not found"),
            ("node", r"(?i)process\.binding is not supported"),
        ])
    }
}

impl Classifier for ErrorClassifier {
    fn classify(&self, _payload: &str, _baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        let body = probe.body_text();
        for (family, re) in &self.patterns {
            if let Some(m) = re.find(&body) {
                return Some(Signal::Error {
                    family: family.clone(),
                    snippet: m.as_str().to_string(),
                });
            }
        }
        None
    }
}

/// Literal-substring match against a library of "leak signatures" — content
/// that only appears when an injection actually succeeded (leaked file bytes,
/// cloud metadata, etc.). Unlike [`ErrorClassifier`] (DBMS error regexes),
/// these are per-vulnerability-class and confirm a hit directly.
///
/// Only fires when the signature is in the probe body but NOT the baseline, so
/// content the target always serves is never mistaken for a fresh leak.
pub struct BodySignatureClassifier {
    /// `(label, needle)` pairs; the needle is matched as a literal substring.
    signatures: Vec<(String, String)>,
}

impl BodySignatureClassifier {
    /// Build from labelled `(label, needle)` pairs.
    pub fn new(entries: &[(&str, &str)]) -> Self {
        let signatures = entries
            .iter()
            .map(|(label, needle)| (label.to_string(), needle.to_string()))
            .collect();
        Self { signatures }
    }

    /// Build from bare needles, using each needle as its own label. Handy when
    /// signatures come from config (e.g. a mock target's `confirm_signatures`).
    pub fn from_needles<I, S>(needles: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let signatures = needles
            .into_iter()
            .map(|n| (n.as_ref().to_string(), n.as_ref().to_string()))
            .collect();
        Self { signatures }
    }

    /// File-read / path-traversal leak signatures (unix + windows).
    pub fn file_read() -> Self {
        Self::new(&[
            ("unix_passwd", "root:x:0:0"),
            ("win_ini",     "[extensions]"),
            ("win_boot",    "[boot loader]"),
        ])
    }

    /// SSRF / cloud-metadata leak signatures.
    pub fn cloud_metadata() -> Self {
        Self::new(&[
            ("aws_credentials", "AccessKeyId"),
            ("aws_ami",         "ami-id"),
            ("gcp_metadata",    "Metadata-Flavor"),
        ])
    }
}

impl Classifier for BodySignatureClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        let body = probe.body_text();
        let baseline_body = baseline.body_text();
        for (label, needle) in &self.signatures {
            if body.contains(needle.as_str()) && !baseline_body.contains(needle.as_str()) {
                return Some(Signal::LeakSignature {
                    label: label.clone(),
                    snippet: needle.clone(),
                });
            }
        }
        None
    }
}

/// A cheap response fingerprint: the four features every content-discovery
/// fuzzer keys on (status, size, word count, line count). No stats, no ML.
#[derive(Debug, Clone, PartialEq)]
struct Fingerprint {
    status: u16,
    size: usize,
    words: usize,
    lines: usize,
}

impl Fingerprint {
    fn of(r: &ProbeResponse) -> Self {
        let text = r.body_text();
        Self {
            status: r.status,
            size: r.body.len(),
            words: text.split_whitespace().count(),
            lines: text.lines().count(),
        }
    }
}

/// Recall-first novelty detector (see ANOMALY.md). Learns a "boring set" of
/// response fingerprints (seeded from the baseline; extensible to ffuf-style
/// autocalibration) and flags any probe whose fingerprint is unlike *all* of
/// them — status differs, OR size/word/line counts fall outside tolerance.
///
/// This is the greedy, OR-combined counterpart to the precision-gated
/// classifiers: it exists to surface the rare unusual response for human
/// review, accepting false positives as the cost of not missing a hit.
pub struct NoveltyClassifier {
    boring: std::sync::Mutex<Vec<Fingerprint>>,
    /// Tolerances — how far a feature may drift and still count as "boring".
    /// Small, non-zero to absorb minor dynamic wobble without going blind.
    size_tol: usize,
    word_tol: usize,
    line_tol: usize,
}

impl NoveltyClassifier {
    /// Sensitive defaults: tiny tolerances so almost any deviation flags.
    pub fn new() -> Self {
        Self {
            boring: std::sync::Mutex::new(Vec::new()),
            size_tol: 16,
            word_tol: 2,
            line_tol: 1,
        }
    }

    /// Pre-seed the boring set with a known-normal response (autocalibration).
    pub fn calibrate(&self, normal: &ProbeResponse) {
        let fp = Fingerprint::of(normal);
        let mut boring = self.boring.lock().unwrap();
        if !boring.iter().any(|f| *f == fp) {
            boring.push(fp);
        }
    }

    fn is_boring(&self, boring: &[Fingerprint], p: &Fingerprint) -> bool {
        boring.iter().any(|b| {
            b.status == p.status
                && p.size.abs_diff(b.size) <= self.size_tol
                && p.words.abs_diff(b.words) <= self.word_tol
                && p.lines.abs_diff(b.lines) <= self.line_tol
        })
    }
}

impl Default for NoveltyClassifier {
    fn default() -> Self { Self::new() }
}

impl Classifier for NoveltyClassifier {
    fn classify(&self, _payload: &str, baseline: &ProbeResponse, probe: &ProbeResponse) -> Option<Signal> {
        // Learn the baseline into the boring set (idempotent). During
        // BaselineProfile::capture the probe *is* the baseline, so this both
        // seeds the set and correctly flags nothing.
        self.calibrate(baseline);

        let p = Fingerprint::of(probe);
        let boring = self.boring.lock().unwrap();
        if self.is_boring(&boring, &p) {
            return None;
        }
        let b = Fingerprint::of(baseline);
        let mut parts = Vec::new();
        if p.status != b.status { parts.push(format!("status {}→{}", b.status, p.status)); }
        if p.size != b.size { parts.push(format!("size {}→{}", b.size, p.size)); }
        if p.words != b.words { parts.push(format!("words {}→{}", b.words, p.words)); }
        if p.lines != b.lines { parts.push(format!("lines {}→{}", b.lines, p.lines)); }
        Some(Signal::Anomaly { detail: parts.join(", ") })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str, ms: u64) -> ProbeResponse {
        ProbeResponse { status, body: body.as_bytes().to_vec(), duration: Duration::from_millis(ms) }
    }

    #[test]
    fn novelty_flags_deviation_but_not_the_boring_set() {
        let c = NoveltyClassifier::new();
        let base = resp(200, "the quick brown fox jumps", 5);
        // baseline-vs-baseline (capture): seeds the boring set, flags nothing.
        assert!(c.classify("", &base, &base).is_none());
        // A near-identical response within tolerance stays boring.
        assert!(c.classify("x", &base, &resp(200, "the quick brown fox jump", 5)).is_none());
        // Status change → anomaly.
        assert!(matches!(
            c.classify("x", &base, &resp(500, "the quick brown fox jumps", 5)),
            Some(Signal::Anomaly { .. })
        ));
        // Big size/word/line change → anomaly.
        assert!(matches!(
            c.classify("x", &base, &resp(200, "totally different and much much longer body here now", 5)),
            Some(Signal::Anomaly { .. })
        ));
    }

    #[test]
    fn body_signature_confirms_leak_but_not_ambient() {
        let c = BodySignatureClassifier::file_read();
        let clean = resp(200, "ok", 5);
        // Leaked passwd content the baseline never showed → signal.
        let leak = resp(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:", 5);
        assert!(matches!(
            c.classify("../etc/passwd", &clean, &leak),
            Some(Signal::LeakSignature { .. })
        ));
        // Same content already in baseline → ambient, not a fresh leak.
        assert!(c.classify("../etc/passwd", &leak, &leak).is_none());
        // Body without any signature → nothing.
        assert!(c.classify("../etc/passwd", &clean, &resp(200, "not found", 5)).is_none());
    }

    #[test]
    fn status_delta_detects_change() {
        let s = StatusClassifier;
        assert_eq!(s.classify("'", &resp(200, "", 10), &resp(500, "", 10)),
            Some(Signal::StatusDelta { from: 200, to: 500 }));
        assert!(s.classify("'", &resp(200, "", 10), &resp(200, "", 10)).is_none());
    }

    #[test]
    fn size_delta_respects_threshold() {
        let s = SizeClassifier::default();
        // ~5% change below 50 byte floor: not a signal.
        let baseline = resp(200, &"a".repeat(100), 10);
        let probe = resp(200, &"a".repeat(110), 10);
        assert!(s.classify("'", &baseline, &probe).is_none());
        // Large change (5×): signal with ratio >= 3.0 → kind = "size_delta_large".
        let bigger = resp(200, &"a".repeat(500), 10);
        let sig = s.classify("'", &baseline, &bigger);
        assert!(matches!(sig, Some(Signal::SizeDelta { .. })));
        if let Some(Signal::SizeDelta { ratio, .. }) = sig {
            assert!(ratio >= 3.0, "expected ratio >= 3.0 for 5x size increase, got {ratio}");
            assert_eq!(Signal::SizeDelta { baseline_bytes: 100, probe_bytes: 500, ratio }.kind(), "size_delta_large");
        }
    }

    #[test]
    fn size_delta_small_ratio_is_not_large() {
        let s = SizeClassifier::default();
        let baseline = resp(200, &"a".repeat(200), 10);
        // 300 bytes: 1.5× — above threshold but below 3.0 → "size_delta"
        let probe = resp(200, &"a".repeat(300), 10);
        let sig = s.classify("'", &baseline, &probe);
        assert!(matches!(sig, Some(Signal::SizeDelta { .. })));
        if let Some(Signal::SizeDelta { ratio, .. }) = sig {
            assert!(ratio < 3.0, "expected ratio < 3.0 for 1.5x size increase, got {ratio}");
            assert_eq!(Signal::SizeDelta { baseline_bytes: 200, probe_bytes: 300, ratio }.kind(), "size_delta");
        }
    }

    #[test]
    fn reflection_detects_literal_and_encoded() {
        let c = ReflectionClassifier;
        let empty = resp(200, "", 10);
        assert!(matches!(
            c.classify("<svg>", &empty, &resp(200, "hi <svg> there", 10)),
            Some(Signal::Reflected { encoding: ReflectionEncoding::Literal })
        ));
        assert!(matches!(
            c.classify("<svg>", &empty, &resp(200, "hi &lt;svg&gt; there", 10)),
            Some(Signal::Reflected { encoding: ReflectionEncoding::HtmlEncoded })
        ));
        assert!(c.classify("<svg>", &empty, &resp(200, "no payload here", 10)).is_none());
    }

    #[test]
    fn percent_encoding_only_encodes_special_chars() {
        // <svg> → %3Csvg%3E, NOT %3C%73%76%67%3E
        assert_eq!(percent_encode("<svg>", true), "%3Csvg%3E");
        assert_eq!(percent_encode("abc123", true), "abc123");
        assert_eq!(percent_encode("hello world", true), "hello%20world");
        assert_eq!(percent_encode("' OR 1=1--", true), "%27%20OR%201%3D1--");
    }

    #[test]
    fn encoded_in_baseline_suppresses_reflection() {
        let c = ReflectionClassifier;
        // Baseline already contains the percent-encoded form
        let baseline = resp(200, "%3Csvg%3E", 10);
        let probe = resp(200, "%3Csvg%3E more", 10);
        assert!(c.classify("<svg>", &baseline, &probe).is_none(),
            "percent-encoded form in baseline should suppress reflection");

        // Baseline contains the HTML-encoded form
        let baseline2 = resp(200, "&lt;svg&gt;", 10);
        let probe2 = resp(200, "&lt;svg&gt; more", 10);
        assert!(c.classify("<svg>", &baseline2, &probe2).is_none(),
            "HTML-encoded form in baseline should suppress reflection");
    }

    #[test]
    fn literal_in_baseline_suppresses_reflection() {
        let c = ReflectionClassifier;
        let baseline = resp(200, "<svg> already here", 10);
        let probe = resp(200, "<svg> already here and more", 10);
        assert!(c.classify("<svg>", &baseline, &probe).is_none(),
            "literal in baseline should suppress reflection");
    }

    #[test]
    fn time_delay_needs_floor_and_factor() {
        let c = TimeDelayClassifier::default();
        // Fast vs fast: no signal (below 500ms floor).
        assert!(c.classify("", &resp(200, "", 10), &resp(200, "", 100)).is_none());
        // 100ms → 600ms: 6×, above floor, signal.
        assert!(matches!(
            c.classify("", &resp(200, "", 100), &resp(200, "", 600)),
            Some(Signal::TimeDelay { .. })
        ));
    }

    #[test]
    fn error_classifier_matches_known_dbms() {
        let c = ErrorClassifier::dbms_starter();
        let probe = resp(500, "Error: You have an error in your SQL syntax near 'foo'", 10);
        match c.classify("'", &resp(200, "", 10), &probe) {
            Some(Signal::Error { family, .. }) => assert_eq!(family, "mysql"),
            other => panic!("expected mysql error, got {:?}", other),
        }
    }

    #[test]
    fn signal_set_collects_multiple_signals() {
        let set = SignalSet::defaults();
        let baseline = resp(200, "ok", 10);
        let probe = resp(500, "Error: You have an error in your SQL syntax", 10);
        let signals = set.run("'", &baseline, &probe);
        // Status delta + error at least.
        assert!(signals.iter().any(|s| matches!(s, Signal::StatusDelta { .. })));
        assert!(signals.iter().any(|s| matches!(s, Signal::Error { .. })));
    }
}
