//! Null-hypothesis filtering for signal classification.
//!
//! Not every signal is a real signal. A 500 status might be server instability.
//! A time delay might be network jitter. A size delta might be dynamic content.
//!
//! `BaselineProfile` runs the baseline response through the same classifiers,
//! records the full signal details, then compares each probe signal against
//! the ambient fingerprint. A probe signal is suppressed only if it matches
//! the ambient signal in meaningful detail — same error family, same status
//! direction, same reflection encoding, etc. Simple kind() matching is too blunt.

use crate::signals::signal::*;

// ── BaselineProfile ────────────────────────────────────────────────────────

/// A pre-computed fingerprint of the target's normal behavior.
///
/// Stores full signal details, not just kind labels. Every probe signal is
/// compared against this profile with variant-specific matching — a different
/// SQL error family, a different status delta direction, or a different
/// reflection encoding survive even if the same signal *kind* appears in the
/// baseline.
#[derive(Debug, Clone)]
pub struct BaselineProfile {
    /// Full ambient signals recorded from baseline vs baseline.
    ambient: Vec<Signal>,
    /// Baseline status code.
    baseline_status: u16,
    /// Baseline body length in bytes.
    baseline_body_len: usize,
    /// Baseline duration in ms.
    baseline_duration_ms: u128,
}

impl BaselineProfile {
    pub fn capture(baseline: &ProbeResponse, signal_set: &SignalSet) -> Self {
        let ambient = signal_set.run("", baseline, baseline);
        Self {
            ambient,
            baseline_status: baseline.status,
            baseline_body_len: baseline.body.len(),
            baseline_duration_ms: baseline.duration.as_millis(),
        }
    }

    /// Filter probe signals: remove any that are explained by the baseline.
    pub fn filter(&self, signals: &[Signal]) -> Vec<Signal> {
        signals
            .iter()
            .filter(|s| !self.is_ambient(s))
            .cloned()
            .collect()
    }

    /// True if this probe signal is explained by baseline behavior alone.
    fn is_ambient(&self, s: &Signal) -> bool {
        // Variant-specific matching against recorded ambient signals.
        if self.ambient.iter().any(|a| signals_match(a, s)) {
            return true;
        }

        // Numerical thresholds for signals not caught by matching.
        match s {
            // Baseline itself is broken — any status delta is noise.
            Signal::StatusDelta { .. } if self.baseline_status >= 500 => true,

            // Time delay below 2× baseline is network jitter.
            Signal::TimeDelay { probe_ms, .. } => {
                let safe = self.baseline_duration_ms.max(1);
                (*probe_ms as f64) < (safe as f64) * 2.0
            }

            // Size delta below 5% of baseline body is dynamic content.
            Signal::SizeDelta { baseline_bytes, probe_bytes, .. } => {
                let safe = self.baseline_body_len.max(1);
                let delta = if probe_bytes > baseline_bytes {
                    probe_bytes - baseline_bytes
                } else {
                    baseline_bytes - probe_bytes
                };
                (delta as f64) < (safe as f64 * 0.05)
            }

            // Body diff on tiny responses is formatting noise.
            Signal::BodyDiff if self.baseline_body_len < 50 => true,

            _ => false,
        }
    }

    /// Confidence: 0.0 = unreliable target, 1.0 = clean.
    pub fn confidence(&self) -> f32 {
        let mut c = 1.0f32;

        if self.baseline_status >= 500 { c *= 0.3; }
        else if self.baseline_status >= 400 { c *= 0.6; }

        let count = self.ambient.len();
        if count >= 3 { c *= 0.4; }
        else if count >= 1 { c *= 0.7; }

        if self.baseline_body_len < 100 { c *= 0.8; }

        c.clamp(0.0, 1.0)
    }

    pub fn summary(&self) -> String {
        let health = if self.baseline_status < 400 { "stable" }
            else if self.baseline_status < 500 { "client-error" }
            else { "unstable" };
        let kinds: Vec<&str> = self.ambient.iter().map(|s| s.kind()).collect();
        format!(
            "status={} ({}), body={}B, dur={}ms, ambient={:?}, confidence={:.0}%",
            self.baseline_status, health, self.baseline_body_len,
            self.baseline_duration_ms, kinds, self.confidence() * 100.0,
        )
    }
}

// ── Variant-specific signal matching ───────────────────────────────────────

/// Do two signals represent the same underlying phenomenon?
/// More precise than `kind()` match — compares variant-specific details.
fn signals_match(ambient: &Signal, probe: &Signal) -> bool {
    match (ambient, probe) {
        // Error: same family, overlapping snippet.
        (
            Signal::Error { family: af, snippet: asn },
            Signal::Error { family: pf, snippet: psn },
        ) => {
            af == pf && (asn.contains(psn.as_str()) || psn.contains(asn.as_str()))
        }

        // StatusDelta: same class and same direction.
        // 500→200 is NOT ambient if baseline was 500→500.
        (
            Signal::StatusDelta { from: af, to: at },
            Signal::StatusDelta { from: pf, to: pt },
        ) => {
            status_class(*af) == status_class(*pf)
                && status_class(*at) == status_class(*pt)
                && status_direction(*af, *at) == status_direction(*pf, *pt)
        }

        // Reflected: same encoding. Content overlap is checked separately.
        (
            Signal::Reflected { encoding: ae },
            Signal::Reflected { encoding: pe },
        ) => ae == pe,

        // SizeDelta: similar magnitude (within 2×).
        (
            Signal::SizeDelta { ratio: ar, .. },
            Signal::SizeDelta { ratio: pr, .. },
        ) => {
            let (a, p) = (ar.max(1.0 / ar), pr.max(1.0 / pr));
            (a / p).max(p / a) < 2.0
        }

        // BodyDiff: always match (baseline body diff = target has dynamic content).
        (Signal::BodyDiff, Signal::BodyDiff) => true,

        // TimeDelay: within 2× of ambient duration.
        (
            Signal::TimeDelay { probe_ms: ap, .. },
            Signal::TimeDelay { probe_ms: pp, .. },
        ) => {
            let (a, p) = (*ap as f64, *pp as f64);
            (a / p.max(1.0)).max(p / a.max(1.0)) < 2.0
        }

        // NoEffect never matches anything (it's not a signal).
        (Signal::NoEffect, _) | (_, Signal::NoEffect) => false,

        // Different variants — can't match.
        _ => false,
    }
}

fn status_class(s: u16) -> u8 {
    match s / 100 {
        2 => 2, // success
        3 => 3, // redirect
        4 => 4, // client error
        5 => 5, // server error
        _ => 0,
    }
}

fn status_direction(from: u16, to: u16) -> i8 {
    if to > from { 1 } else if to < from { -1 } else { 0 }
}

// ── WeightedSignal ─────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct WeightedSignal {
    pub signal: Signal,
    pub raw_score: u8,
    pub confidence: f32,
    pub adjusted_score: f32,
}

pub fn weigh(
    signals: &[Signal],
    profile: &BaselineProfile,
    raw_score: u8,
) -> Vec<WeightedSignal> {
    let filtered = profile.filter(signals);
    let confidence = profile.confidence();
    filtered
        .into_iter()
        .map(|s| {
            let adjusted_score = raw_score as f32 * confidence;
            WeightedSignal { signal: s, raw_score, confidence, adjusted_score }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn resp(status: u16, body: &str, ms: u64) -> ProbeResponse {
        ProbeResponse { status, body: body.as_bytes().to_vec(), duration: Duration::from_millis(ms) }
    }

    // ── Variant-specific matching ───────────────────────────────────────

    #[test]
    fn different_error_family_does_not_match() {
        let ambient = Signal::Error { family: "mysql".into(), snippet: "syntax".into() };
        let probe = Signal::Error { family: "postgres".into(), snippet: "pg_query".into() };
        assert!(!signals_match(&ambient, &probe),
            "different error families should not match");
    }

    #[test]
    fn same_error_family_overlapping_snippet_matches() {
        let ambient = Signal::Error { family: "mysql".into(), snippet: "SQL syntax near".into() };
        let probe = Signal::Error { family: "mysql".into(), snippet: "SQL syntax near 'foo'".into() };
        assert!(signals_match(&ambient, &probe),
            "same family with overlapping snippet should match");
    }

    #[test]
    fn status_200_to_500_not_ambient_from_500_to_500() {
        // Baseline: 500→500 has no delta. An ambient 500→??? doesn't exist.
        // But if baseline is unstable (500), ALL status deltas are suppressed
        // via the numerical threshold, not via signal matching.
        let baseline = resp(500, "err", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        let probe = resp(200, "ok", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        let has_status = filtered.iter().any(|s| matches!(s, Signal::StatusDelta { .. }));
        assert!(!has_status, "status delta suppressed on unstable baseline");
    }

    #[test]
    fn different_status_direction_survives() {
        // Baseline: 200→500 triggers a status delta.
        // Probe: 500→200 is a DIFFERENT status delta — different direction.
        let baseline = resp(500, "err", 10);
        // We need an ambient StatusDelta. Let's craft it manually.
        let ambient = Signal::StatusDelta { from: 200, to: 500 };
        let probe_sig = Signal::StatusDelta { from: 500, to: 200 };
        assert!(!signals_match(&ambient, &probe_sig),
            "200→500 ambient should not match 500→200 probe — different direction");
    }

    // ── Integration tests ───────────────────────────────────────────────

    #[test]
    fn clean_baseline_preserves_signals() {
        let baseline = resp(200, "ok", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.ambient.is_empty());
        let probe = resp(500, "error", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        assert!(!filtered.is_empty());
    }

    #[test]
    fn ambient_error_suppresses_same_error() {
        let baseline = resp(200, "You have an error in your SQL syntax", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        let probe = resp(200, "You have an error in your SQL syntax near 'foo'", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        let has_error = filtered.iter().any(|s| matches!(s, Signal::Error { .. }));
        assert!(!has_error, "same error should be suppressed");
    }

    #[test]
    fn confidence_penalizes_unstable_target() {
        let baseline = resp(500, "error", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.confidence() < 0.5);
    }

    #[test]
    fn confidence_high_on_clean_target() {
        let baseline = resp(200, &"a".repeat(1000), 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.confidence() > 0.8);
    }
}
