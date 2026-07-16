//! Payload mutators.
//!
//! Given the current payload and the signals from the last probe, a [`Mutator`]
//! decides what to try next, or returns `None` to terminate the loop.
//!
//! Three starter strategies:
//! - [`StaticListMutator`] — walks a fixed payload list, ignoring signal.
//!   Useful as a baseline + for the "batch" tools that just want to sweep.
//! - [`SignalGuidedMutator`] — looks up the next payload by `Signal::kind()`.
//!   The lookup table is the policy surface; add an entry to dial in.
//! - [`StopOn`] — wrapper that terminates when a target signal fires.
//!   Lets a caller compose "sweep until confirmed" without writing a loop.
//!
//! Adding a new strategy = one struct + one `impl Mutator`.

use super::signal::Signal;

/// Decides the next payload to try, or `None` to stop mutating.
///
/// The loop will keep calling this until it returns `None` or hits its budget.
pub trait Mutator: Send + Sync {
    /// Given the current payload and signals observed from it, return the next
    /// payload to probe, or `None` to terminate.
    fn next_payload(&mut self, current: &str, signals: &[Signal]) -> Option<String>;
}

// ── concrete starter strategies ─────────────────────────────────────────────

/// Walks a fixed list of payloads, returning each one in order. Ignores
/// signals — this is the "batch sweep" mutator that the existing test_X tools
/// are conceptually using today.
pub struct StaticListMutator {
    payloads: std::vec::IntoIter<String>,
}

impl StaticListMutator {
    pub fn new<I, S>(payloads: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let v: Vec<String> = payloads.into_iter().map(Into::into).collect();
        Self { payloads: v.into_iter() }
    }
}

impl Mutator for StaticListMutator {
    fn next_payload(&mut self, _current: &str, _signals: &[Signal]) -> Option<String> {
        self.payloads.next()
    }
}

/// Looks up the next payload by the kind of the strongest signal seen.
///
/// The table maps `Signal::kind()` → ordered list of follow-up payloads. The
/// mutator walks the list one at a time per signal, so after several probes
/// against the same signal the list is exhausted and `None` is returned.
///
/// This is the "response-aware" core. The table is the dial; adding a new
/// `(signal_kind, payloads)` entry teaches the loop a new response.
pub struct SignalGuidedMutator {
    // TODO(SignalKind enum): replace &'static str dispatch with a typed enum so the
    // compiler catches typos in table keys.
    table: std::collections::HashMap<&'static str, std::collections::VecDeque<String>>,
    /// What to do when no signal is observed. Defaults to the "no_effect" entry.
    no_signal_fallback_kind: &'static str,
}

impl SignalGuidedMutator {
    /// Build from a table of `(signal_kind, payloads)`. Each `signal_kind`
    /// should match a value from [`Signal::kind()`].
    pub fn new<I, P>(entries: I) -> Self
    where
        I: IntoIterator<Item = (&'static str, P)>,
        P: IntoIterator<Item = String>,
    {
        let mut table = std::collections::HashMap::new();
        for (kind, payloads) in entries {
            let dq: std::collections::VecDeque<String> = payloads.into_iter().collect();
            table.insert(kind, dq);
        }
        Self { table, no_signal_fallback_kind: "no_effect" }
    }

    /// Override which key to use when no signals are observed.
    pub fn with_no_signal_fallback(mut self, kind: &'static str) -> Self {
        self.no_signal_fallback_kind = kind;
        self
    }

    /// Pick the strongest signal — policy decision. Today: prefer Error >
    /// TimeDelay > Reflected > StatusDelta > SizeDelta > NoEffect.
    /// Change the order here to re-rank what the mutator reacts to first.
    fn strongest(signals: &[Signal]) -> &'static str {
        let mut best_rank: u8 = 0;
        let mut best_kind: &'static str = "no_effect";
        for s in signals {
            let (rank, kind) = match s {
                Signal::Error { .. }       => (6, s.kind()),
                Signal::LeakSignature { .. } => (5, s.kind()),
                Signal::TimeDelay { .. }   => (5, s.kind()),
                Signal::Reflected { .. }   => (4, s.kind()),
                Signal::StatusDelta { .. } => (3, s.kind()),
                Signal::SizeDelta { ratio, .. } => {
                    if *ratio >= 3.0 || *ratio <= 0.33 { (3, s.kind()) } else { (2, s.kind()) }
                },
                Signal::BodyDiff           => (3, s.kind()),
                Signal::Anomaly { .. }     => (2, s.kind()),
                Signal::PrototypePollution { .. } => (5, s.kind()),
                Signal::NoEffect           => (1, s.kind()),
            };
            if rank > best_rank { best_rank = rank; best_kind = kind; }
        }
        best_kind
    }
}

impl Mutator for SignalGuidedMutator {
    fn next_payload(&mut self, _current: &str, signals: &[Signal]) -> Option<String> {
        let kind = if signals.is_empty() {
            self.no_signal_fallback_kind
        } else {
            Self::strongest(signals)
        };
        // Try the matched bucket first.
        if let Some(queue) = self.table.get_mut(kind) {
            if let Some(payload) = queue.pop_front() {
                return Some(payload);
            }
        }
        // Matched bucket empty or missing — fall back to the no_effect bucket,
        // but only if it's a different key (avoids double-draining when kind IS
        // the fallback).
        if kind != self.no_signal_fallback_kind {
            if let Some(queue) = self.table.get_mut(self.no_signal_fallback_kind) {
                return queue.pop_front();
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signals::signal::*;

    #[test]
    fn static_list_walks_in_order() {
        let mut m = StaticListMutator::new(vec!["a", "b", "c"]);
        assert_eq!(m.next_payload("", &[]).as_deref(), Some("a"));
        assert_eq!(m.next_payload("", &[]).as_deref(), Some("b"));
        assert_eq!(m.next_payload("", &[]).as_deref(), Some("c"));
        assert_eq!(m.next_payload("", &[]), None);
    }

    #[test]
    fn signal_guided_dispatches_on_strongest() {
        let mut m = SignalGuidedMutator::new(vec![
            ("error",     vec!["err_followup_1".to_string(), "err_followup_2".to_string()]),
            ("reflected", vec!["xss_followup".to_string()]),
            ("no_effect", vec!["next_strategy".to_string()]),
        ]);

        // Error signal: pulls from the "error" bucket.
        let next = m.next_payload("'", &[Signal::Error { family: "mysql".into(), snippet: "syntax".into() }]);
        assert_eq!(next.as_deref(), Some("err_followup_1"));
        // Error again: pulls the second entry.
        let next = m.next_payload("''", &[Signal::Error { family: "mysql".into(), snippet: "syntax".into() }]);
        assert_eq!(next.as_deref(), Some("err_followup_2"));
        // Error a third time: bucket exhausted, falls back to no_effect bucket.
        let next = m.next_payload("'''", &[Signal::Error { family: "mysql".into(), snippet: "syntax".into() }]);
        assert_eq!(next.as_deref(), Some("next_strategy"));
    }

    #[test]
    fn signal_guided_strongest_prefers_error_over_status() {
        let m = SignalGuidedMutator::new(vec![
            ("error",        vec!["chose_error".to_string()]),
            ("status_delta", vec!["chose_status".to_string()]),
        ]);
        // Both signals present — error wins.
        let mut m = m;
        let next = m.next_payload(
            "'",
            &[
                Signal::StatusDelta { from: 200, to: 500 },
                Signal::Error { family: "mysql".into(), snippet: "syntax".into() },
            ],
        );
        assert_eq!(next.as_deref(), Some("chose_error"));
    }
}
