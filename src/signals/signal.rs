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
    /// Probe duration crossed the time-based threshold.
    TimeDelay {
        baseline_ms: u128,
        probe_ms: u128,
    },
    /// Body bytes differ from baseline despite identical size.
    /// Signals ORDER BY / structural injection where ordering changes content
    /// but not byte count — invisible to SizeDelta.
    BodyDiff,
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
            Signal::TimeDelay { .. } => "time_delay",
            Signal::BodyDiff => "body_diff",
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
        if payload.len() < 3 { return None; }
        let body = probe.body_text();
        let baseline_body = baseline.body_text();
        // Literal first — cheapest. Only signal if not already present in baseline.
        if body.contains(payload) && !baseline_body.contains(payload) {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::Literal });
        }
        // Percent-encoded — check both cases (%3C and %3c both appear in the wild).
        let percent_upper: String = payload.bytes().map(|b| format!("%{:02X}", b)).collect();
        let percent_lower: String = payload.bytes().map(|b| format!("%{:02x}", b)).collect();
        if body.contains(&percent_upper) || body.contains(&percent_lower) {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::PercentEncoded });
        }
        // HTML-encoded (just the dangerous chars).
        let html_encoded = payload
            .replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#x27;");
        if html_encoded != payload && body.contains(&html_encoded) {
            return Some(Signal::Reflected { encoding: ReflectionEncoding::HtmlEncoded });
        }
        None
    }
}

/// Time-delay signal: probe took noticeably longer than baseline.
pub struct TimeDelayClassifier {
    /// Probe duration must exceed baseline by this factor (e.g. 3.0 = 3× slower).
    pub min_factor: f64,
    /// Floor so noise on fast endpoints doesn't trigger ("10ms vs 30ms" is not a signal).
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

#[cfg(test)]
mod tests {
    use super::*;

    fn resp(status: u16, body: &str, ms: u64) -> ProbeResponse {
        ProbeResponse { status, body: body.as_bytes().to_vec(), duration: Duration::from_millis(ms) }
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
        let baseline = resp(200, "", 10);
        assert!(matches!(
            c.classify("<svg>", &baseline, &resp(200, "hi <svg> there", 10)),
            Some(Signal::Reflected { encoding: ReflectionEncoding::Literal })
        ));
        assert!(matches!(
            c.classify("<svg>", &baseline, &resp(200, "hi &lt;svg&gt; there", 10)),
            Some(Signal::Reflected { encoding: ReflectionEncoding::HtmlEncoded })
        ));
        assert!(c.classify("<svg>", &baseline, &resp(200, "no payload here", 10)).is_none());
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
