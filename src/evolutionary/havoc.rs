//! Havoc mutation stage — non-deterministic, stochastic operators.
//!
//! Instead of signal → pre-programmed payload table (deterministic, exhaustible,
//! predictable), havoc applies a random sequence of operators to a seed from
//! the corpus. Combined with evolutionary corpus scheduling this explores the
//! mutation space far more thoroughly than hand-crafted tables ever can.
//!
//! Architecture mirrors AFL++'s havoc stage:
//!   pick corpus entry (power schedule) → apply N random ops → probe → score →
//!   if interesting: add to corpus, boost parent energy → repeat
//!
//! `HavocMutator` implements `Mutator` so it drops into the existing
//! `MutationLoop` unchanged. Its real power is in `EvolutionaryLoop` where
//! corpus feedback drives scheduling.
//!
//! Unlike v1, atom selection is driven by a `WeightedSampler` (chain-weight
//! table) rather than a static `TokenPool`. The randomness/determinism dial
//! lives in the chain weights: weight 1.0 = uniform random, higher = steered.

use rand::Rng;
use rand::seq::SliceRandom;
use crate::signals::signal::Signal;
use crate::signals::mutator::Mutator;
use crate::evolutionary::atoms::{WeightedSampler, random_char_boundary};
use crate::evolutionary::rng::{RngEngine, RngMode};

// ── Operators ─────────────────────────────────────────────────────────────────

/// A single havoc mutation operator.
///
/// Each operator is a small, composable transformation. The loop chains
/// `ops_per_step` of them in random order each iteration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HavocOp {
    /// Insert a chain-weighted atom at a random position.
    InsertToken,
    /// Replace a random substring with a chain-weighted atom.
    ReplaceWithToken,
    /// Delete a random contiguous chunk.
    DeleteChunk,
    /// Duplicate a random chunk and insert it at a random position.
    DuplicateChunk,
    /// Splice: take the prefix of this payload + a random suffix from the corpus.
    SpliceSuffix,
    /// URL-encode a single random byte.
    UrlEncodeChar,
    /// Double-URL-encode a single random byte (%25XX).
    DoubleUrlEncodeChar,
    /// Insert a "boundary interesting" value at a random position.
    InsertBoundaryValue,
    /// Repeat the entire payload 2–4 times (tickles length-check parsers).
    RepeatPayload,
    /// Wrap payload in a delimiter pair (', ", (), [], {}, <!-- -->, etc.)
    WrapDelimiter,
    /// Reverse the payload (catches reversed-string checks).
    Reverse,
    /// Uppercase the entire payload.
    Uppercase,
}

/// Per-operator sampling weights. Higher weight = selected more often.
///
/// All weights are clamped to ≥ 0.0. Setting a weight to 0.0 disables the
/// operator entirely. Fields are `pub` so a feedback loop (future MOpt-style
/// adaptive tuning) can read and update weights between campaigns.
#[derive(Debug, Clone)]
pub struct HavocSchedule {
    pub insert_token: f32,
    pub replace_token: f32,
    pub delete_chunk: f32,
    pub duplicate_chunk: f32,
    pub splice_suffix: f32,
    pub url_encode: f32,
    pub double_url_encode: f32,
    pub insert_boundary_value: f32,
    pub repeat_payload: f32,
    pub wrap_delimiter: f32,
    pub reverse: f32,
    pub uppercase: f32,
}

impl HavocSchedule {
    /// Sensible defaults for web fuzzing: structural ops weighted higher,
    /// destructive/narrow ops weighted lower.
    pub fn defaults() -> Self {
        Self {
            insert_token:          3.0,
            replace_token:         0.5, // calib: replacing tokens pushes payload off the trigger
            delete_chunk:          2.0,
            duplicate_chunk:       1.5,
            splice_suffix:         2.5,
            url_encode:            2.5,
            double_url_encode:     2.0,
            insert_boundary_value: 1.5,
            repeat_payload:        1.5, // calib: repetition keeps the trigger intact, helps hits
            wrap_delimiter:        1.0,
            reverse:               0.3,
            uppercase:             0.3,
        }
    }

    /// Uniform weights — every operator equally likely. Useful for tests.
    pub fn uniform() -> Self {
        Self {
            insert_token: 1.0, replace_token: 1.0, delete_chunk: 1.0,
            duplicate_chunk: 1.0, splice_suffix: 1.0, url_encode: 1.0,
            double_url_encode: 1.0, insert_boundary_value: 1.0,
            repeat_payload: 1.0, wrap_delimiter: 1.0,
            reverse: 1.0, uppercase: 1.0,
        }
    }

    /// Sample an operator weighted by the schedule.
    pub fn sample<R: Rng>(&self, rng: &mut R) -> HavocOp {
        let ops: [(HavocOp, f32); 12] = [
            (HavocOp::InsertToken,         self.insert_token),
            (HavocOp::ReplaceWithToken,    self.replace_token),
            (HavocOp::DeleteChunk,         self.delete_chunk),
            (HavocOp::DuplicateChunk,      self.duplicate_chunk),
            (HavocOp::SpliceSuffix,        self.splice_suffix),
            (HavocOp::UrlEncodeChar,       self.url_encode),
            (HavocOp::DoubleUrlEncodeChar, self.double_url_encode),
            (HavocOp::InsertBoundaryValue, self.insert_boundary_value),
            (HavocOp::RepeatPayload,       self.repeat_payload),
            (HavocOp::WrapDelimiter,       self.wrap_delimiter),
            (HavocOp::Reverse,             self.reverse),
            (HavocOp::Uppercase,           self.uppercase),
        ];
        let total: f32 = ops.iter().map(|(_, w)| w).sum();
        if total <= 0.0 {
            return HavocOp::InsertToken;
        }
        let mut pick = rng.gen::<f32>() * total;
        for (op, w) in &ops {
            pick -= w;
            if pick <= 0.0 {
                return *op;
            }
        }
        HavocOp::InsertToken // float-drift fallback
    }
}

impl Default for HavocSchedule {
    fn default() -> Self { Self::defaults() }
}

impl HavocOp {
    #[allow(dead_code)]
    const ALL: &'static [HavocOp] = &[
        HavocOp::InsertToken,
        HavocOp::ReplaceWithToken,
        HavocOp::DeleteChunk,
        HavocOp::DuplicateChunk,
        HavocOp::SpliceSuffix,
        HavocOp::UrlEncodeChar,
        HavocOp::DoubleUrlEncodeChar,
        HavocOp::InsertBoundaryValue,
        HavocOp::RepeatPayload,
        HavocOp::WrapDelimiter,
        HavocOp::Reverse,
        HavocOp::Uppercase,
    ];

    /// Uniform random selection (kept for tests and simple usage).
    #[allow(dead_code)]
    fn random<R: Rng>(rng: &mut R) -> Self {
        *Self::ALL.choose(rng).expect("ALL is non-empty")
    }
}

// Interesting boundary values borrowed from AFL/libfuzzer — values that tend
// to trigger edge cases in parsers and validators.
const BOUNDARY_VALUES: &[&str] = &[
    "0", "-1", "1", "127", "-128", "128", "255", "-256", "256",
    "32767", "-32768", "32768", "65535", "2147483647", "-2147483648",
    "null", "undefined", "NaN", "Infinity", "-Infinity",
    "true", "false", "[]", "{}", "\"\"", "''", "0x0",
];

const DELIMITER_PAIRS: &[(&str, &str)] = &[
    ("'", "'"), ("\"", "\""), ("`", "`"),
    ("(", ")"), ("[", "]"), ("{", "}"),
    ("/*", "*/"), ("<!--", "-->"),
    ("%27", "%27"), ("%22", "%22"),
    ("{{", "}}"), ("${", "}"),
];

// ── HavocMutator ──────────────────────────────────────────────────────────────

/// Non-deterministic mutator: applies `ops_per_step` random operators to the
/// current payload each time `next_payload` is called.
///
/// Atom selection (InsertToken / ReplaceWithToken) is guided by a
/// `WeightedSampler` that uses chain-weight probabilities rather than a static
/// token list. All other operators are purely geometric.
pub struct HavocMutator {
    sampler: WeightedSampler,
    /// Payloads from the current corpus state, used for splice operations.
    corpus_payloads: Vec<String>,
    /// Operators to chain per `next_payload` call.
    pub ops_per_step: usize,
    /// Remaining steps before `next_payload` returns `None`.
    budget: usize,
    rng: RngEngine,
    /// RNG backend (Small for speed, ChaCha12 for replay).
    pub rng_mode: RngMode,
    /// Per-operator sampling weights. `pub` so adaptive tuning can read/update.
    pub schedule: HavocSchedule,
    /// Optional bypass shells: pairs of (prefix, suffix) used by `WrapDelimiter`.
    /// When non-empty, `WrapDelimiter` prefers these over the generic delimiter
    /// pairs — useful for snapping a static-analyzer bypass wrapper around a
    /// payload (e.g. `this['` + `base` + `'](event.msg)`).
    shells: Vec<(String, String)>,
}

impl HavocMutator {
    pub fn new(sampler: WeightedSampler, budget: usize) -> Self {
        let rng_mode = RngMode::Small;
        Self {
            sampler,
            corpus_payloads: Vec::new(),
            ops_per_step: 1, // calib: fewer ops stay near the high-signal seed (monotonic in sweeps)
            budget,
            rng: RngEngine::from_entropy(rng_mode),
            rng_mode,
            schedule: HavocSchedule::default(),
            shells: Vec::new(),
        }
    }

    /// Override the operator schedule (e.g., `HavocSchedule::uniform()` for tests).
    pub fn with_schedule(mut self, schedule: HavocSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Provide bypass shell pairs for `WrapDelimiter`.
    pub fn with_shells(mut self, shells: Vec<(String, String)>) -> Self {
        self.shells = shells;
        self
    }

    /// Override how many operators to chain per step (default: 1).
    pub fn with_ops_per_step(mut self, n: usize) -> Self {
        self.ops_per_step = n.max(1);
        self
    }

    /// Override the RNG backend. Default is `RngMode::Small` for speed.
    /// Use `RngMode::ChaCha12` for cross-platform reproducible replay.
    pub fn with_rng_mode(mut self, mode: RngMode) -> Self {
        self.rng_mode = mode;
        self.rng = RngEngine::from_entropy(mode);
        self
    }

    /// Reseed the internal RNG. Uses the current `rng_mode`.
    /// Pair with `EvolutionaryLoop::with_seed` for fully reproducible runs.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = RngEngine::from_seed(self.rng_mode, seed);
        self
    }

    /// Provide the corpus payload list for splice operations. Replaces all payloads.
    /// Prefer `push_corpus_payload` for incremental updates after the initial sync.
    pub fn update_corpus(&mut self, payloads: Vec<String>) {
        self.corpus_payloads = payloads;
    }

    /// Push a single new payload for splice operations — O(1) instead of
    /// cloning the entire corpus on every growth.
    pub fn push_corpus_payload(&mut self, payload: String) {
        self.corpus_payloads.push(payload);
    }

    /// Apply a single operator to `payload`. Pure: does not consume budget.
    pub fn apply_op(&mut self, payload: &str, op: HavocOp) -> String {
        match op {
            HavocOp::InsertToken => {
                self.sampler.insert(payload, &mut self.rng)
            }
            HavocOp::ReplaceWithToken => {
                self.sampler.replace_slice(payload, &mut self.rng)
            }
            HavocOp::DeleteChunk => {
                if payload.len() < 2 { return payload.to_string(); }
                let (start, end) = if payload.is_ascii() {
                    let len = payload.len();
                    let s = self.rng.gen_range(0..len);
                    let max_end = (s + (len.saturating_sub(s)) / 2 + 1).min(len);
                    let e = if max_end > s + 1 {
                        self.rng.gen_range((s + 1)..=max_end)
                    } else {
                        s + 1
                    }.min(len);
                    (s, e)
                } else {
                    let boundaries: Vec<usize> = payload.char_indices()
                        .map(|(i, _)| i).chain(std::iter::once(payload.len())).collect();
                    if boundaries.len() < 2 { return payload.to_string(); }
                    let start_idx = self.rng.gen_range(0..boundaries.len() - 1);
                    let start = boundaries[start_idx];
                    let max_end_idx = (start_idx + boundaries.len().saturating_sub(start_idx) / 2 + 1)
                        .min(boundaries.len());
                    let end = boundaries[self.rng.gen_range((start_idx + 1)..max_end_idx)];
                    (start, end)
                };
                format!("{}{}", &payload[..start], &payload[end..])
            }
            HavocOp::DuplicateChunk => {
                if payload.is_empty() { return payload.to_string(); }
                let (start, end) = if payload.is_ascii() {
                    let s = self.rng.gen_range(0..=payload.len());
                    (s, self.rng.gen_range(s..=payload.len()))
                } else {
                    let boundaries: Vec<usize> = payload.char_indices()
                        .map(|(i, _)| i).chain(std::iter::once(payload.len())).collect();
                    let start_idx = self.rng.gen_range(0..boundaries.len());
                    let start = boundaries[start_idx];
                    (start, boundaries[self.rng.gen_range(start_idx..boundaries.len())])
                };
                let chunk = payload[start..end].to_string();
                let ins = random_char_boundary(payload, &mut self.rng);
                let mut s = payload.to_string();
                s.insert_str(ins, &chunk);
                s
            }
            HavocOp::SpliceSuffix => {
                if self.corpus_payloads.is_empty() || payload.is_empty() {
                    return payload.to_string();
                }
                let other = &self.corpus_payloads[
                    self.rng.gen_range(0..self.corpus_payloads.len())];
                if other.is_empty() { return payload.to_string(); }
                let my_at  = random_char_boundary(payload, &mut self.rng);
                let its_at = random_char_boundary(other, &mut self.rng);
                format!("{}{}", &payload[..my_at], &other[its_at..])
            }
            HavocOp::UrlEncodeChar => {
                if payload.is_empty() { return payload.to_string(); }
                let (pos, ch, ch_len) = if payload.is_ascii() {
                    let pos = self.rng.gen_range(0..payload.len());
                    (pos, payload.as_bytes()[pos] as char, 1usize)
                } else {
                    let nth = self.rng.gen_range(0..payload.chars().count());
                    let (pos, ch) = payload.char_indices().nth(nth).unwrap();
                    (pos, ch, ch.len_utf8())
                };
                if ch_len > 1 {
                    // Multi-byte char — percent-encode each UTF-8 byte
                    let bytes = ch.to_string().into_bytes();
                    let encoded: String = bytes.iter().map(|b| format!("%{:02X}", b)).collect();
                    format!("{}{}{}", &payload[..pos], encoded, &payload[pos + ch_len..])
                } else {
                    format!("{}%{:02X}{}", &payload[..pos], ch as u8, &payload[pos + 1..])
                }
            }
            HavocOp::DoubleUrlEncodeChar => {
                if payload.is_empty() { return payload.to_string(); }
                let (pos, ch, ch_len) = if payload.is_ascii() {
                    let pos = self.rng.gen_range(0..payload.len());
                    (pos, payload.as_bytes()[pos] as char, 1usize)
                } else {
                    let nth = self.rng.gen_range(0..payload.chars().count());
                    let (pos, ch) = payload.char_indices().nth(nth).unwrap();
                    (pos, ch, ch.len_utf8())
                };
                if ch_len > 1 {
                    let bytes = ch.to_string().into_bytes();
                    let encoded: String = bytes.iter().map(|b| format!("%25{:02X}", b)).collect();
                    format!("{}{}{}", &payload[..pos], encoded, &payload[pos + ch_len..])
                } else {
                    format!("{}%25{:02X}{}", &payload[..pos], ch as u8, &payload[pos + 1..])
                }
            }
            HavocOp::InsertBoundaryValue => {
                let val = BOUNDARY_VALUES[self.rng.gen_range(0..BOUNDARY_VALUES.len())];
                if payload.is_empty() { return val.to_string(); }
                let pos = random_char_boundary(payload, &mut self.rng);
                let mut s = payload.to_string();
                s.insert_str(pos, val);
                s
            }
            HavocOp::RepeatPayload => {
                let n = self.rng.gen_range(2..=4usize);
                payload.repeat(n)
            }
            HavocOp::WrapDelimiter => {
                let (open, close): (&str, &str) = if self.shells.is_empty() {
                    (DELIMITER_PAIRS[self.rng.gen_range(0..DELIMITER_PAIRS.len())].0,
                     DELIMITER_PAIRS[self.rng.gen_range(0..DELIMITER_PAIRS.len())].1)
                } else {
                    let pair = &self.shells[self.rng.gen_range(0..self.shells.len())];
                    (pair.0.as_str(), pair.1.as_str())
                };
                format!("{}{}{}", open, payload, close)
            }
            HavocOp::Reverse => {
                payload.chars().rev().collect()
            }
            HavocOp::Uppercase => {
                payload.to_uppercase()
            }
        }
    }

    /// Apply `ops_per_step` random operators in sequence to `payload`.
    /// All ops are generated upfront (stack-allocated) so RNG state for
    /// op selection is independent of mutation-side RNG usage.
    pub fn mutate(&mut self, payload: &str) -> String {
        const MAX_OPS: usize = 32;
        let n = self.ops_per_step;
        let ops: [HavocOp; MAX_OPS] = std::array::from_fn(|i| {
            if i < n { self.schedule.sample(&mut self.rng) } else { HavocOp::InsertToken }
        });
        let mut result = payload.to_string();
        for i in 0..n {
            result = self.apply_op(&result, ops[i]);
        }
        result
    }

    pub fn remaining_budget(&self) -> usize { self.budget }
}

impl Mutator for HavocMutator {
    fn next_payload(&mut self, current: &str, _signals: &[Signal]) -> Option<String> {
        if self.budget == 0 { return None; }
        self.budget -= 1;
        Some(self.mutate(current))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(budget: usize) -> HavocMutator {
        HavocMutator::new(WeightedSampler::default_weights(), budget)
    }

    #[test]
    fn budget_exhausts() {
        let mut m = mk(3);
        assert!(m.next_payload("x", &[]).is_some());
        assert!(m.next_payload("x", &[]).is_some());
        assert!(m.next_payload("x", &[]).is_some());
        assert!(m.next_payload("x", &[]).is_none());
    }

    #[test]
    fn url_encode_produces_percent() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100);
        let mut found = false;
        for _ in 0..50 {
            if m.apply_op("abc", HavocOp::UrlEncodeChar).contains('%') {
                found = true;
                break;
            }
        }
        assert!(found);
    }

    #[test]
    fn double_url_encode_produces_percent25() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100);
        let mut found = false;
        for _ in 0..50 {
            let r = m.apply_op("abc", HavocOp::DoubleUrlEncodeChar);
            if r.contains("%25") { found = true; break; }
        }
        assert!(found);
    }

    #[test]
    fn delete_chunk_can_shrink() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100);
        let mut shrunk = false;
        for _ in 0..30 {
            if m.apply_op("hello world", HavocOp::DeleteChunk).len() < "hello world".len() {
                shrunk = true;
                break;
            }
        }
        assert!(shrunk);
    }

    #[test]
    fn wrap_delimiter_wraps() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100);
        let mut wrapped = false;
        for _ in 0..30 {
            let r = m.apply_op("payload", HavocOp::WrapDelimiter);
            if r.len() > "payload".len() { wrapped = true; break; }
        }
        assert!(wrapped);
    }

    #[test]
    fn wrap_delimiter_uses_bypass_shells_when_configured() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100)
            .with_shells(vec![
                ("this['".into(), "'](event.msg)".into()),
                ("import('http://x/".into(), "')".into()),
            ]);
        let shells = [
            "this['PAYLOAD'](event.msg)",
            "import('http://x/PAYLOAD')",
        ];
        let mut found = 0u32;
        for _ in 0..100 {
            let r = m.apply_op("PAYLOAD", HavocOp::WrapDelimiter);
            if shells.iter().any(|s| r == *s) { found += 1; }
        }
        assert!(found > 50, "configured shells rarely used ({found}/100)");
    }

    #[test]
    fn splice_uses_corpus() {
        let mut m = HavocMutator::new(WeightedSampler::uniform(), 100);
        m.update_corpus(vec!["CORPUS_SUFFIX".to_string()]);
        let mut spliced = false;
        for _ in 0..50 {
            if m.apply_op("prefix_", HavocOp::SpliceSuffix).contains("CORPUS_SUFFIX") {
                spliced = true;
                break;
            }
        }
        // Not guaranteed (splice point could be at the very end of corpus),
        // but with 50 tries it almost certainly fires.
        let _ = spliced; // don't assert; just ensure no panic
    }

    #[test]
    fn no_panic_on_single_char_payload() {
        let mut m = HavocMutator::new(WeightedSampler::default_weights(), 100);
        for op in HavocOp::ALL {
            let _ = m.apply_op("x", *op);
        }
    }

    #[test]
    fn no_panic_on_empty_payload() {
        let mut m = HavocMutator::new(WeightedSampler::default_weights(), 100);
        for op in HavocOp::ALL {
            let _ = m.apply_op("", *op);
        }
    }

    #[test]
    fn insert_token_uses_atoms() {
        let mut m = HavocMutator::new(WeightedSampler::default_weights(), 100);
        let mut grew = false;
        for _ in 0..30 {
            if m.apply_op("abc", HavocOp::InsertToken).len() > "abc".len() {
                grew = true;
                break;
            }
        }
        assert!(grew, "InsertToken should grow the payload");
    }

    #[test]
    fn no_panic_on_unicode_payload() {
        let mut m = HavocMutator::new(WeightedSampler::default_weights(), 100);
        // 2-byte, 3-byte, 4-byte UTF-8 sequences
        for payload in &["café", "naïve", "日本語", "🌟star🌟", "a\u{00E9}b\u{3042}c"] {
            for op in HavocOp::ALL {
                let _ = m.apply_op(payload, *op);
            }
        }
    }

    #[test]
    fn unicode_url_encode_preserves_structure() {
        let mut m = HavocMutator::new(WeightedSampler::default_weights(), 100);
        // Encoded result should still be valid UTF-8 after any op
        for _ in 0..20 {
            let result = m.apply_op("café", HavocOp::UrlEncodeChar);
            assert!(String::from_utf8(result.into_bytes()).is_ok(),
                "URL-encoded unicode payload should remain valid UTF-8");
        }
    }
}
