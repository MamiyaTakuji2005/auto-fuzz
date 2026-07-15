//! Evolutionary corpus — the LibAFL-inspired state that replaces static payload tables.
//!
//! Three concepts:
//! - `CorpusEntry`  — a payload + how promising it turned out to be
//! - `SeedCorpus`   — the living collection; starts with seeds, grows as interesting
//!                    payloads are discovered
//! - `Feedback`     — decides if a probe result is interesting enough to add to
//!                    the corpus, and how much energy to assign
//!
//! The scheduler (power schedule) is built into `SeedCorpus::schedule`: entries
//! are drawn at random proportional to their energy, so high-signal payloads
//! receive more mutations than low-signal ones — the same core insight as AFL's
//! power schedule.

use rand::Rng;
use crate::signals::signal::{Signal, ReflectionEncoding, ProbeResponse};
use crate::signals::Request;
use std::collections::HashMap;

// ── CorpusEntry ───────────────────────────────────────────────────────────────

/// A single item in the corpus: a payload string and everything we know about it.
#[derive(Debug, Clone)]
pub struct CorpusEntry {
    /// The payload string.
    pub payload: String,
    /// Strongest signal seen when probing this payload. `None` for unprobed seeds.
    pub best_signal: Option<Signal>,
    /// Energy score (1–12). Higher = more mutations scheduled from this entry.
    pub energy: u8,
    /// How many mutation children have been spawned from this entry.
    pub fuzz_count: u32,
    /// Index of the parent entry this was derived from. `None` for original seeds.
    pub parent_idx: Option<usize>,
}

impl CorpusEntry {
    /// A fresh, unprobed seed with base energy.
    pub fn seed(payload: impl Into<String>) -> Self {
        Self { payload: payload.into(), best_signal: None, energy: 1, fuzz_count: 0, parent_idx: None }
    }

    /// A discovered entry produced by the evolutionary loop.
    pub fn discovered(payload: impl Into<String>, signal: Signal, energy: u8, parent_idx: usize) -> Self {
        Self {
            payload: payload.into(),
            best_signal: Some(signal),
            energy,
            fuzz_count: 0,
            parent_idx: Some(parent_idx),
        }
    }

    pub fn is_interesting(&self) -> bool {
        matches!(self.best_signal, Some(ref s) if !matches!(s, Signal::NoEffect))
    }
}

// ── BoostPolicy ─────────────────────────────────────────────────────────────

/// How parent energy grows when a child discovers something interesting.
/// This is the core explore/exploit dial — it determines how aggressively
/// the scheduler concentrates on signal-rich lineages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoostMode {
    /// No boost — parent energy stays at its initial value. Pure exploration:
    /// every entry is equally likely regardless of how many hits it produced.
    None,
    /// Additive: `energy += score` (current default behavior). Linear growth.
    Additive,
    /// Flat: `energy += 1` regardless of signal strength. All interesting
    /// children boost the parent equally.
    Flat,
    /// Multiplicative: `energy = energy * (6 + score) / 6`. Faster growth for
    /// high-score signals, slower for low-score ones. Exponential exploitation.
    Multiplicative,
}

impl Default for BoostMode {
    fn default() -> Self { Self::Additive }
}

impl BoostMode {
    /// Compute the new energy given the old energy, the signal score, and cap.
    fn apply(self, old_energy: u8, score: u8, cap: u8) -> u8 {
        match self {
            BoostMode::None => old_energy,
            BoostMode::Additive => old_energy.saturating_add(score).min(cap),
            BoostMode::Flat => old_energy.saturating_add(1).min(cap),
            BoostMode::Multiplicative => {
                // energy * (6 + score) / 6 — grows ~1x to ~2x per boost
                let factor = (6 + score.min(6)) as u16;
                let scaled = (old_energy as u16 * factor) / 6;
                scaled.min(cap as u16) as u8
            }
        }
    }
}

// ── SeedCorpus ────────────────────────────────────────────────────────────────

/// Maximum possible energy cap — bucket arrays are sized to this.
/// Supports any cap up to 255 (u8::MAX).
const BUCKET_CAP: usize = 256;

/// The living corpus. Starts with seeds; grows as the evolutionary loop finds
/// interesting payloads. Entries are never removed (AFL-style: removals introduce
/// non-determinism and rarely help). Duplicate payloads are rejected — if a
/// payload is rediscovered with a stronger signal, its energy is updated.
pub struct SeedCorpus {
    entries: Vec<CorpusEntry>,
    total_energy: u32,
    index_by_payload: HashMap<String, usize>,
    /// Buckets by energy level (0..BUCKET_CAP-1). Bucket 0 is unused.
    buckets: [Vec<usize>; BUCKET_CAP],
    /// Precomputed per-bucket weight = bucket.len() * energy.
    bucket_weights: [u32; BUCKET_CAP],
    /// How parent energy grows on interesting children.
    pub boost_mode: BoostMode,
    /// Maximum energy any entry can reach. Default 64.
    pub max_energy: u8,
}

impl SeedCorpus {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            total_energy: 0,
            index_by_payload: HashMap::new(),
            buckets: [(); BUCKET_CAP].map(|_| Vec::new()),
            bucket_weights: [0; BUCKET_CAP],
            boost_mode: BoostMode::default(),
            max_energy: 64,
        }
    }

    /// Set the boost mode (how parent energy grows on interesting children).
    pub fn with_boost_mode(mut self, mode: BoostMode) -> Self {
        self.boost_mode = mode;
        self
    }

    /// Set the maximum energy cap. Valid range: 1–255.
    pub fn with_max_energy(mut self, cap: u8) -> Self {
        self.max_energy = cap.max(1);
        self
    }

    /// Build from a list of seed strings. All get base energy = 1.
    pub fn from_seeds<I, S>(seeds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut c = Self::new();
        for s in seeds { c.push_seed(s.into()); }
        c
    }

    // ── bucket bookkeeping ──────────────────────────────────────────────────

    fn add_to_bucket(&mut self, idx: usize, energy: u8) {
        let e = energy as usize;
        self.buckets[e].push(idx);
        self.bucket_weights[e] = self.buckets[e].len() as u32 * e as u32;
    }

    fn remove_from_bucket(&mut self, idx: usize, energy: u8) {
        let e = energy as usize;
        let bucket = &mut self.buckets[e];
        if let Some(pos) = bucket.iter().position(|&i| i == idx) {
            bucket.swap_remove(pos);
            self.bucket_weights[e] = bucket.len() as u32 * e as u32;
        }
    }

    fn move_bucket(&mut self, idx: usize, old_energy: u8, new_energy: u8) {
        self.remove_from_bucket(idx, old_energy);
        self.add_to_bucket(idx, new_energy);
    }

    // ── public mutation ────────────────────────────────────────────────────

    pub fn push_seed(&mut self, payload: String) {
        // Deduplicate seeds — same payload only added once.
        if self.index_by_payload.contains_key(&payload) {
            return;
        }
        let idx = self.entries.len();
        self.index_by_payload.insert(payload.clone(), idx);
        self.total_energy += 1;
        self.entries.push(CorpusEntry::seed(payload));
        self.add_to_bucket(idx, 1);
    }

    /// Add a discovered entry. Returns its index (new or existing).
    /// If the payload was already seen:
    ///   - If the new signal is stronger, update the existing entry's energy.
    ///   - Otherwise, skip (no duplicate added).
    pub fn push_discovered(&mut self, entry: CorpusEntry) -> usize {
        if let Some(&idx) = self.index_by_payload.get(&entry.payload) {
            // Already in corpus — only upgrade if signal is better.
            let old_energy = self.entries[idx].energy;
            if entry.energy > old_energy {
                let delta = (entry.energy - old_energy) as u32;
                self.entries[idx].energy = entry.energy;
                self.entries[idx].best_signal = entry.best_signal;
                self.total_energy += delta;
                self.move_bucket(idx, old_energy, entry.energy);
            }
            idx
        } else {
            let idx = self.entries.len();
            let energy = entry.energy;
            self.index_by_payload.insert(entry.payload.clone(), idx);
            self.total_energy += energy as u32;
            self.entries.push(entry);
            self.add_to_bucket(idx, energy);
            idx
        }
    }

    /// Boost the energy of an existing entry (reward a parent whose child found something).
    pub fn boost_energy(&mut self, idx: usize, by: u8) {
        let (old, new) = {
            if let Some(e) = self.entries.get_mut(idx) {
                let old = e.energy;
                e.energy = self.boost_mode.apply(old, by, self.max_energy);
                (old, e.energy)
            } else {
                return;
            }
        };
        self.total_energy += (new - old) as u32;
        if new != old {
            self.move_bucket(idx, old, new);
        }
    }

    /// Power schedule: select the next entry to mutate, weighted by energy.
    /// O(n) via energy buckets — walks buckets instead of the full corpus.
    /// Returns the index; caller uses `entry()` to read the payload.
    pub fn schedule<R: Rng>(&mut self, rng: &mut R) -> Option<usize> {
        if self.entries.is_empty() { return None; }
        if self.total_energy == 0 {
            self.entries[0].fuzz_count += 1;
            return Some(0);
        }
        let cap = self.max_energy as usize;
        let mut pick = rng.gen_range(0..self.total_energy);
        for energy in 1..=cap {
            let w = self.bucket_weights[energy];
            if pick < w {
                let bucket = &self.buckets[energy];
                let idx = bucket[rng.gen_range(0..bucket.len())];
                self.entries[idx].fuzz_count += 1;
                return Some(idx);
            }
            pick -= w;
        }
        // Fallback (should never reach here unless weights are inconsistent).
        let last = self.entries.len() - 1;
        self.entries[last].fuzz_count += 1;
        Some(last)
    }

    pub fn entry(&self, idx: usize) -> Option<&CorpusEntry> {
        self.entries.get(idx)
    }

    pub fn entry_mut(&mut self, idx: usize) -> Option<&mut CorpusEntry> {
        self.entries.get_mut(idx)
    }

    pub fn entries(&self) -> &[CorpusEntry] { &self.entries }
    pub fn len(&self) -> usize { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }

    /// Count of entries that have seen at least one interesting signal.
    pub fn interesting_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_interesting()).count()
    }

    /// Collect all payload strings for use in splice mutations.
    pub fn all_payloads(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.payload.clone()).collect()
    }
}

impl Default for SeedCorpus {
    fn default() -> Self { Self::new() }
}

// ── Feedback ──────────────────────────────────────────────────────────────────

/// Full evaluation context passed to feedback.
///
/// Feedback implementors can inspect anything — payload, request, baseline,
/// response, raw vs filtered signals, timing, transport errors — not just
/// the post-filtered signal list. This makes the fuzzer truly universal.
pub struct EvaluationContext<'a> {
    /// The candidate payload being probed.
    pub payload: &'a str,
    /// The HTTP request that was sent.
    pub request: &'a Request,
    /// Baseline response (same-shape, empty payload).
    pub baseline: &'a ProbeResponse,
    /// Probe response.
    pub response: &'a ProbeResponse,
    /// Transport error (if the probe failed).
    pub probe_error: Option<&'a str>,
    /// All signals before baseline filtering.
    pub raw_signals: &'a [Signal],
    /// Signals after baseline filtering (payload-specific).
    pub filtered_signals: &'a [Signal],
}

/// Result of evaluating a probe. Produced by a single pass through the
/// evaluation context — no repeated iteration over signals.
#[derive(Debug, Clone)]
pub struct FeedbackEval {
    /// Energy to assign (0 = discard, 1–12 = keep with this weight).
    pub score: u8,
    /// Should this payload be added to the corpus?
    pub interesting: bool,
    /// High-value confirmation: stop the loop early and report.
    pub confirmed: bool,
    /// The strongest signal in the set (for corpus entry tracking).
    pub best_signal: Signal,
}

impl FeedbackEval {
    /// Empty eval — no signals, no effect.
    pub fn none() -> Self {
        Self { score: 0, interesting: false, confirmed: false, best_signal: Signal::NoEffect }
    }
}

/// Decides if a probe result is interesting enough to add to the corpus, and
/// how much energy to assign. This is the LibAFL `Feedback` concept.
///
/// Receives the full `EvaluationContext` — not just signals. This lets
/// implementations inspect payloads, requests, baseline vs response, timing,
/// transport errors, and raw vs filtered signals. Old signal-only eval is
/// just `ctx.filtered_signals`.
pub trait Feedback: Send + Sync {
    /// Evaluate the probe in context. Returns all decisions at once.
    fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FeedbackEval;
}

/// Signal-strength feedback. Uses the same ranking as the existing
/// `SignalGuidedMutator` but as an explicit, replaceable policy object.
#[derive(Debug, Clone)]
pub struct HttpFeedback {
    /// Minimum score to add to corpus (default: 2 — any real signal).
    ///
    /// recall-first (see ANOMALY.md): this gate controls *corpus energy*, which
    /// is a separate dial from *reporting*. A recall-first anomaly detector flags
    /// everything unusual to the human, but feeding every mild anomaly back here
    /// as high energy makes heavy havoc chase noise. Keep this selective even if
    /// the report is greedy — detection recall and exploration guidance differ.
    pub min_corpus_score: u8,
}

impl Default for HttpFeedback {
    fn default() -> Self { Self { min_corpus_score: 2 } }
}

impl Feedback for HttpFeedback {
    fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FeedbackEval {
        let mut best = Signal::NoEffect;
        let mut best_rank: u8 = 0;
        let mut confirmed = false;

        for s in ctx.filtered_signals {
            let rank = match s {
                Signal::Error { .. } => { confirmed = true; 6 }
                Signal::LeakSignature { .. } => { confirmed = true; 5 }
                Signal::TimeDelay { .. } => { confirmed = true; 5 }
                Signal::Reflected { encoding } => {
                    if matches!(encoding, ReflectionEncoding::Literal) { confirmed = true; }
                    4
                }
                Signal::StatusDelta { to, .. } => {
                    if *to >= 500 { confirmed = true; 4 } else { 3 }
                }
                Signal::SizeDelta { ratio, .. } => {
                    if *ratio >= 3.0 || *ratio <= 0.33 { 3 } else { 2 }
                }
                Signal::BodyDiff => 2,
                // recall-first (see ANOMALY.md): report it (>= min_corpus_score)
                // but keep it low so heavy havoc doesn't chase every wobble.
                Signal::Anomaly { .. } => 2,
                Signal::NoEffect => 0,
            };
            if rank > best_rank {
                best_rank = rank;
                best = s.clone();
            }
        }

        let interesting = best_rank >= self.min_corpus_score;
        FeedbackEval { score: best_rank, interesting, confirmed, best_signal: best }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn corpus_power_schedule_favors_high_energy() {
        let mut corpus = SeedCorpus::new();
        corpus.push_seed("low".into());  // energy 1
        corpus.push_discovered(CorpusEntry::discovered(
            "high".to_string(),
            Signal::Error { family: "sql".to_string(), snippet: String::new() }, 6, 0));

        let mut rng = rand::thread_rng();
        let mut high_count = 0u32;
        for _ in 0..1000 {
            if corpus.schedule(&mut rng) == Some(1) { high_count += 1; }
        }
        // With energy 1 vs 6, entry 1 should be picked ~6/7 ≈ 85% of the time.
        assert!(high_count > 700, "high-energy entry picked {high_count}/1000, expected >700");
    }

    #[test]
    fn boost_energy_updates_total() {
        let mut c = SeedCorpus::new();
        c.push_seed("a".into());
        let total_before = c.total_energy;
        c.boost_energy(0, 3);
        assert_eq!(c.total_energy, total_before + 3);
        assert_eq!(c.entry(0).unwrap().energy, 4);
    }

    #[test]
    fn http_feedback_scores_correctly() {
        let fb = HttpFeedback::default();
        let error_signals = vec![Signal::Error { family: "mysql".into(), snippet: "syntax".into() }];
        let ctx = EvaluationContext {
            payload: "'",
            request: &crate::signals::Request { url: "".into(), method: "GET".into(), headers: std::collections::HashMap::new(), body: "".into() },
            baseline: &crate::signals::signal::ProbeResponse { status: 200, body: vec![], duration: Duration::from_millis(1) },
            response: &crate::signals::signal::ProbeResponse { status: 500, body: vec![], duration: Duration::from_millis(10) },
            probe_error: None,
            raw_signals: &error_signals,
            filtered_signals: &error_signals,
        };
        let eval = fb.evaluate(&ctx);
        assert_eq!(eval.score, 6);
        assert!(eval.interesting);
        assert!(eval.confirmed);

        let no_effect = vec![Signal::NoEffect];
        let ctx = EvaluationContext {
            payload: "x",
            request: &crate::signals::Request { url: "".into(), method: "GET".into(), headers: std::collections::HashMap::new(), body: "".into() },
            baseline: &crate::signals::signal::ProbeResponse { status: 200, body: vec![], duration: Duration::from_millis(1) },
            response: &crate::signals::signal::ProbeResponse { status: 200, body: vec![], duration: Duration::from_millis(1) },
            probe_error: None,
            raw_signals: &no_effect,
            filtered_signals: &no_effect,
        };
        let eval = fb.evaluate(&ctx);
        assert_eq!(eval.score, 0);
        assert!(!eval.interesting);
    }

    #[test]
    fn corpus_is_empty_guard() {
        let mut c = SeedCorpus::new();
        let mut rng = rand::thread_rng();
        assert!(c.schedule(&mut rng).is_none());
    }

    #[test]
    fn deduplicates_seeds() {
        let c = SeedCorpus::from_seeds(["a", "b", "a"]);
        assert_eq!(c.len(), 2, "duplicate seed should be rejected");
    }

    #[test]
    fn deduplicates_discovered() {
        let mut c = SeedCorpus::from_seeds(["x"]);
        let e1 = CorpusEntry::discovered("dup".to_string(),
            Signal::StatusDelta { from: 200, to: 500 }, 4, 0);
        let idx1 = c.push_discovered(e1);
        assert_eq!(c.len(), 2);

        // Same payload, lower energy — should be rejected
        let e2 = CorpusEntry::discovered("dup".to_string(),
            Signal::StatusDelta { from: 200, to: 302 }, 3, 1);
        let idx2 = c.push_discovered(e2);
        assert_eq!(c.len(), 2, "duplicate with lower energy should not add entry");
        assert_eq!(idx1, idx2, "should return existing index");
    }

    #[test]
    fn upgrade_existing_on_stronger_signal() {
        let mut c = SeedCorpus::from_seeds(["x"]);
        let e1 = CorpusEntry::discovered("dup".to_string(),
            Signal::StatusDelta { from: 200, to: 500 }, 4, 0);
        c.push_discovered(e1);

        // Same payload, HIGHER energy — should upgrade
        let e2 = CorpusEntry::discovered("dup".to_string(),
            Signal::Error { family: "sql".into(), snippet: "e".into() }, 6, 1);
        c.push_discovered(e2);
        assert_eq!(c.len(), 2, "upgrade should not add duplicate entry");
        assert_eq!(c.entry(1).unwrap().energy, 6, "energy should be upgraded");
    }
}
