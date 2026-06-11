//! Null-hypothesis filtering for signal classification.
//!
//! Not every signal is a real signal. A 500 status might be server instability.
//! A time delay might be network jitter. A size delta might be dynamic content.
//!
//! `BaselineProfile` runs the baseline response through the same classifiers,
//! then subtracts those "ambient" signals from every probe result. Only
//! payload-specific signals survive.

use crate::signals::signal::*;
use std::collections::HashSet;

// ── BaselineProfile ────────────────────────────────────────────────────────

/// A pre-computed fingerprint of the target's normal behavior.
///
/// Built once before the fuzz loop starts. Every probe signal is compared
/// against this profile — any signal that matches the baseline fingerprint
/// is suppressed (it was not caused by the payload).
#[derive(Debug, Clone)]
pub struct BaselineProfile {
    /// Signal kinds that the baseline response itself triggers.
    ambient_kinds: HashSet<&'static str>,
    /// Baseline status code. If baseline already returns 5xx, the target is
    /// unstable — status deltas are unreliable.
    baseline_status: u16,
    /// Baseline body length. Size deltas smaller than 5% of baseline are
    /// likely dynamic content, not payload-induced.
    baseline_body_len: usize,
    /// Baseline duration in ms. Time-delay signals below 2× baseline
    /// are likely normal jitter.
    baseline_duration_ms: u128,
}

impl BaselineProfile {
    /// Profile a target by running its baseline response through the given
    /// signal set. The ambient signals are recorded and subtracted from all
    /// future probe classifications.
    ///
    /// Also captures raw metrics (status, body length, duration) for
    /// threshold-based filtering.
    pub fn capture(baseline: &ProbeResponse, signal_set: &SignalSet) -> Self {
        // Run the baseline against itself — what signals does the target
        // produce even without a payload?
        let ambient_signals = signal_set.run("", baseline, baseline);
        let ambient_kinds: HashSet<&'static str> = ambient_signals
            .iter()
            .map(|s| s.kind())
            .collect();

        Self {
            ambient_kinds,
            baseline_status: baseline.status,
            baseline_body_len: baseline.body.len(),
            baseline_duration_ms: baseline.duration.as_millis(),
        }
    }

    /// Filter probe signals: remove any that match ambient baseline behavior.
    /// Returns only payload-specific signals.
    pub fn filter(&self, signals: &[Signal]) -> Vec<Signal> {
        signals
            .iter()
            .filter(|s| !self.is_ambient(s))
            .cloned()
            .collect()
    }

    /// True if this signal is explained by the baseline alone — not
    /// payload-induced.
    fn is_ambient(&self, s: &Signal) -> bool {
        // 1. Direct match: the baseline itself triggered this signal kind
        if self.ambient_kinds.contains(s.kind()) {
            return true;
        }

        // 2. Baseline is already broken: status deltas from unstable servers
        //    are meaningless
        match s {
            Signal::StatusDelta { .. } if self.baseline_status >= 500 => true,

            // 3. Time delays below 2× baseline are normal jitter, not injection
            Signal::TimeDelay { baseline_ms, probe_ms } => {
                let safe_baseline = self.baseline_duration_ms.max(1);
                (*probe_ms as f64) < (safe_baseline as f64) * 2.0
            }

            // 4. Size deltas below 5% of baseline body are dynamic content
            Signal::SizeDelta { baseline_bytes, probe_bytes, .. } => {
                let safe_baseline = self.baseline_body_len.max(1);
                let delta = if probe_bytes > baseline_bytes {
                    probe_bytes - baseline_bytes
                } else {
                    baseline_bytes - probe_bytes
                };
                (delta as f64) < (safe_baseline as f64 * 0.05)
            }

            // 5. Body diff on tiny responses (<50 bytes) is formatting noise
            Signal::BodyDiff if self.baseline_body_len < 50 => true,

            _ => false,
        }
    }

    /// Confidence adjustment: 0.0 = completely unreliable, 1.0 = clean.
    /// Multiplied into the signal score to produce a confidence-weighted
    /// result for the agent.
    pub fn confidence(&self) -> f32 {
        let mut c = 1.0f32;

        // Unstable baseline reduces confidence on everything
        if self.baseline_status >= 500 {
            c *= 0.3;
        } else if self.baseline_status >= 400 {
            c *= 0.6;
        }

        // Many ambient signals = noisy target
        let ambient_count = self.ambient_kinds.len();
        if ambient_count >= 3 {
            c *= 0.4;
        } else if ambient_count >= 1 {
            c *= 0.7;
        }

        // Tiny baseline = hard to classify
        if self.baseline_body_len < 100 {
            c *= 0.8;
        }

        c.clamp(0.0, 1.0)
    }

    /// Human-readable summary of what the baseline looks like.
    pub fn summary(&self) -> String {
        let status_health = if self.baseline_status < 400 {
            "stable"
        } else if self.baseline_status < 500 {
            "client-error"
        } else {
            "unstable"
        };
        let ambient_list: Vec<&str> = self.ambient_kinds.iter().copied().collect();
        format!(
            "status={} ({}), body={}B, baseline_ms={}, ambient_signals={:?}, confidence={:.0}%",
            self.baseline_status,
            status_health,
            self.baseline_body_len,
            self.baseline_duration_ms,
            ambient_list,
            self.confidence() * 100.0,
        )
    }
}

// ── WeightedSignal ─────────────────────────────────────────────────────────

/// A signal with confidence applied. The raw signal score is multiplied
/// by baseline confidence to get the adjusted score.
#[derive(Debug, Clone)]
pub struct WeightedSignal {
    pub signal: Signal,
    pub raw_score: u8,
    pub confidence: f32,
    pub adjusted_score: f32,
}

/// Apply baseline profile filtering and confidence weighting to a set of
/// raw signals. Returns only payload-specific signals with adjusted scores.
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
            WeightedSignal {
                signal: s,
                raw_score,
                confidence,
                adjusted_score,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn resp(status: u16, body: &str, ms: u64) -> ProbeResponse {
        ProbeResponse {
            status,
            body: body.as_bytes().to_vec(),
            duration: Duration::from_millis(ms),
        }
    }

    #[test]
    fn unstable_baseline_suppresses_status_delta() {
        let baseline = resp(500, "error", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());

        // 500→500 has no delta, so status_delta won't be in ambient_kinds.
        // But baseline_status=500 triggers the is_ambient rule directly.
        // A probe returning 200 should have its status delta suppressed
        // because the target is unstable.
        let probe = resp(200, "ok", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        let has_status = filtered.iter().any(|s| matches!(s, Signal::StatusDelta { .. }));
        assert!(!has_status, "status delta should be suppressed on unstable baseline");
    }

    #[test]
    fn clean_baseline_preserves_signals() {
        let baseline = resp(200, "ok", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());

        // 200 "ok" should have no ambient signals
        assert!(profile.ambient_kinds.is_empty());

        let probe = resp(500, "error", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        assert!(!filtered.is_empty(), "clean baseline should preserve probe signals");
    }

    #[test]
    fn ambient_error_suppresses_error_signal() {
        // Target that already leaks DBMS errors on normal pages
        let baseline = resp(200, "You have an error in your SQL syntax", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.ambient_kinds.contains("error"));

        let probe = resp(200, "You have an error in your SQL syntax near 'foo'", 10);
        let signals = SignalSet::defaults().run("'", &baseline, &probe);
        let filtered = profile.filter(&signals);
        let has_error = filtered.iter().any(|s| matches!(s, Signal::Error { .. }));
        assert!(!has_error, "ambient error should suppress probe error signal");
    }

    #[test]
    fn confidence_penalizes_unstable_target() {
        let baseline = resp(500, "error", 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.confidence() < 0.5, "unstable baseline should lower confidence");
    }

    #[test]
    fn confidence_high_on_clean_target() {
        let baseline = resp(200, &"a".repeat(1000), 10);
        let profile = BaselineProfile::capture(&baseline, &SignalSet::defaults());
        assert!(profile.confidence() > 0.8, "clean baseline should have high confidence");
    }
}
