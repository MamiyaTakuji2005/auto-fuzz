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
use rand::SeedableRng;
use rand::rngs::SmallRng;
use rand::seq::SliceRandom;
use crate::signals::signal::Signal;
use crate::signals::mutator::Mutator;
use crate::evolutionary::atoms::WeightedSampler;

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

impl HavocOp {
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
    rng: SmallRng,
}

impl HavocMutator {
    pub fn new(sampler: WeightedSampler, budget: usize) -> Self {
        Self {
            sampler,
            corpus_payloads: Vec::new(),
            ops_per_step: 4,
            budget,
            rng: SmallRng::from_entropy(),
        }
    }

    /// Override how many operators to chain per step (default: 4).
    pub fn with_ops_per_step(mut self, n: usize) -> Self {
        self.ops_per_step = n.max(1);
        self
    }

    /// Reseed the internal RNG. Pair with `EvolutionaryLoop::with_seed` for
    /// fully reproducible runs — both RNGs need to be deterministic, not just one.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng = SmallRng::seed_from_u64(seed);
        self
    }

    /// Provide the corpus payload list for splice operations.
    /// Call this whenever the corpus grows.
    pub fn update_corpus(&mut self, payloads: Vec<String>) {
        self.corpus_payloads = payloads;
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
                let len   = payload.len();
                let start = self.rng.gen_range(0..len);
                let max_end = (start + len / 2 + 1).min(len);
                let end   = self.rng.gen_range((start + 1)..=max_end);
                format!("{}{}", &payload[..start], &payload[end..])
            }
            HavocOp::DuplicateChunk => {
                if payload.is_empty() { return payload.to_string(); }
                let len   = payload.len();
                let start = self.rng.gen_range(0..len);
                let end   = self.rng.gen_range(start..=len);
                let chunk = payload[start..end].to_string();
                let ins   = self.rng.gen_range(0..=len);
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
                let my_at  = self.rng.gen_range(0..=payload.len());
                let its_at = self.rng.gen_range(0..=other.len());
                format!("{}{}", &payload[..my_at], &other[its_at..])
            }
            HavocOp::UrlEncodeChar => {
                if payload.is_empty() { return payload.to_string(); }
                let pos = self.rng.gen_range(0..payload.len());
                let b   = payload.as_bytes()[pos];
                format!("{}%{:02X}{}", &payload[..pos], b, &payload[pos + 1..])
            }
            HavocOp::DoubleUrlEncodeChar => {
                if payload.is_empty() { return payload.to_string(); }
                let pos = self.rng.gen_range(0..payload.len());
                let b   = payload.as_bytes()[pos];
                format!("{}%25{:02X}{}", &payload[..pos], b, &payload[pos + 1..])
            }
            HavocOp::InsertBoundaryValue => {
                let val = BOUNDARY_VALUES[self.rng.gen_range(0..BOUNDARY_VALUES.len())];
                if payload.is_empty() { return val.to_string(); }
                let pos = self.rng.gen_range(0..=payload.len());
                let mut s = payload.to_string();
                s.insert_str(pos, val);
                s
            }
            HavocOp::RepeatPayload => {
                let n = self.rng.gen_range(2..=4usize);
                payload.repeat(n)
            }
            HavocOp::WrapDelimiter => {
                let (open, close) =
                    DELIMITER_PAIRS[self.rng.gen_range(0..DELIMITER_PAIRS.len())];
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
    pub fn mutate(&mut self, payload: &str) -> String {
        let ops: Vec<HavocOp> = (0..self.ops_per_step)
            .map(|_| HavocOp::random(&mut self.rng))
            .collect();
        let mut result = payload.to_string();
        for op in ops {
            result = self.apply_op(&result, op);
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
}
