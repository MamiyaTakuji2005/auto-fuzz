//! Atom tables, chain-weight table, placement policy, and length policy.
//!
//! Four decoupled primitives compose the generation engine:
//!
//! - `ATOMS` / `NUMERIC_ATOMS` — the vocabulary. Atoms range from single
//!   bytes (`'`, `<`) to space-padded keywords (` OR `, ` UNION `).
//!
//! - `ChainTable` — sparse weight map `(from, to) → f32` using owned strings.
//!   Unlisted pairs default to 1.0. Weight bands:
//!   ```text
//!   0.0  = never
//!   0.2  = unlikely
//!   1.0  = default random
//!   2.0  = mild preference
//!   5.0  = strong preference
//!   20.0 = near-deterministic
//!   ```
//!   Stored as nested `HashMap<String, HashMap<String, f32>>` so both built-in
//!   (`&'static str`) and proto-provided runtime weights share the same table type.
//!
//! - `PlacementPolicy` — three-weight sampler: append, prepend, wrap.
//!   Replace/InsertMiddle are mutation operations in `HavocMutator`, not here.
//!
//! - `LengthPolicy` — geometric stop probability, fully decoupled from chain weights.
//!
//! `WeightedSampler` ties all four together. `atoms` is `Vec<String>` so that
//! both the built-in tables and proto-dispatched runtime tables use the same type.
//! Use `WeightedSampler::default_weights()` for the standard web-attack vocabulary,
//! or `WeightedSampler::from_proto_config()` to wire in per-task proto dispatch.

use rand::Rng;
use std::collections::HashMap;

// ── Atom tables ───────────────────────────────────────────────────────────────

/// Web-attack atoms: SQL / XSS / template / command / path / encoding.
pub const ATOMS: &[&str] = &[
    // SQL syntax
    "'", "\"", ";", "--", "#", "/*", "*/", "(", ")",
    // SQL keywords (space-padded so they read correctly when injected mid-word)
    " OR ", " AND ", " UNION ", " SELECT ", "NULL", "SLEEP", "BENCHMARK",
    // XSS syntax
    "<", ">", "/", "=", "onerror=", "onload=",
    // Template / expression delimiters
    "{{", "}}", "${", "}", "<%=", "%>", "{", "7*7", "*",
    // Command injection
    "|", "&", "$(", "`", "%0a", "%0d",
    // Path traversal
    "..", "%2f", "%252f", "\\",
    // Encoding primitives
    "%", "%25", "\\u", "\\x", "0x",
];

/// Numeric probe atoms — for parameter fuzzing (id, page, limit, price, etc.).
pub const NUMERIC_ATOMS: &[&str] = &[
    "0", "1", "-1", "2", "9", "10", "99", "100", "999", "1000",
    "2147483647", "2147483648", "-2147483648", "9999999999",
    "1e3", "1e309", "NaN", "Infinity", "00", "0001",
];

/// Find the longest atom from `atoms` that is a suffix of `s`.
pub fn tail_atom_from(s: &str, atoms: &'static [&'static str]) -> Option<&'static str> {
    atoms.iter()
        .copied()
        .filter(|a| s.ends_with(a))
        .max_by_key(|a| a.len())
}

/// `tail_atom_from` with the default `ATOMS` table.
pub fn tail_atom(s: &str) -> Option<&'static str> {
    tail_atom_from(s, ATOMS)
}

// ── ChainTable ────────────────────────────────────────────────────────────────

/// Sparse weight map `(from_atom, to_atom) → f32` using owned strings.
///
/// Stored as nested HashMap for construction. Missing pairs default to 1.0.
/// Weights are clamped to ≥ 0.0. For the hot sampling path, `compile()`
/// precomputes cumulative transition tables — zero allocations per sample.
#[derive(Debug, Clone)]
pub struct ChainTable {
    weights: HashMap<String, HashMap<String, f32>>,
}

/// Precomputed transition table for a single source atom.
#[derive(Debug, Clone)]
struct CompiledTransitions {
    /// Monotonically increasing cumulative weights: `(target_idx, cum_weight)`.
    cumulative: Vec<(usize, f32)>,
    total: f32,
}

impl ChainTable {
    pub fn new() -> Self {
        Self { weights: HashMap::new() }
    }

    pub fn set(&mut self, from: impl Into<String>, to: impl Into<String>, weight: f32) -> &mut Self {
        self.weights
            .entry(from.into())
            .or_default()
            .insert(to.into(), weight.max(0.0));
        self
    }

    pub fn weight(&self, from: &str, to: &str) -> f32 {
        self.weights
            .get(from)
            .and_then(|inner| inner.get(to))
            .copied()
            .unwrap_or(1.0)
    }

    /// Precompute cumulative transition tables for all source atoms.
    /// After this, sampling is a single O(atoms) linear scan with zero allocations.
    fn compile(&self, atoms: &[String]) -> Vec<CompiledTransitions> {
        atoms.iter().map(|from| {
            let explicit = self.weights.get(from.as_str());
            let mut cumulative = Vec::with_capacity(atoms.len());
            let mut running = 0.0f32;
            for (j, to) in atoms.iter().enumerate() {
                let w = explicit
                    .and_then(|inner| inner.get(to.as_str()))
                    .copied()
                    .unwrap_or(1.0);
                running += w;
                cumulative.push((j, running));
            }
            CompiledTransitions { cumulative, total: running }
        }).collect()
    }

    /// Pre-seeded weights using meaningful bands (5.0 = strong, 20.0 = near-deterministic).
    pub fn defaults() -> Self {
        let mut t = Self::new();
        // SQL injection chains
        t.set("'",       " OR ",     5.0)
         .set("'",       " AND ",    3.0)
         .set("'",       "--",       5.0)
         .set(";",       " OR ",     3.0)
         .set(";",       "|",        2.0)
         .set(";",       "&",        2.0)
         .set(" OR ",    "NULL",     3.0)
         .set(" UNION ", " SELECT ", 20.0)
         .set("/*",      "*/",       10.0);
        // XSS chains
        t.set("<",        "/",        3.0)
         .set("<",        ">",        2.0)
         .set("onerror=", "'",        5.0)
         .set("onerror=", "\"",       5.0)
         .set("onload=",  "'",        5.0)
         .set("onload=",  "\"",       5.0);
        // Template chains — near-deterministic for known SSTI probes
        t.set("{{",  "7*7",  20.0)
         .set("{{",  "}}",    5.0)
         .set("${",  "}",    20.0)
         .set("${",  "7*7",  10.0)
         .set("<%=", "%>",   20.0)
         .set("{",   "}",     3.0);
        // Command chains
        t.set("$(", ")",  10.0)
         .set("|",  "&",   2.0);
        // Path traversal chains
        t.set("..",  "/",    10.0)
         .set("..",  "%2f",   5.0)
         .set("%2f", "..",    5.0);
        // Encoding chains
        t.set("%",   "%25",  2.0)
         .set("\\x", "0x",   2.0);
        t
    }
}

impl Default for ChainTable {
    fn default() -> Self { Self::defaults() }
}

// ── PlacementPolicy ───────────────────────────────────────────────────────────

/// Where the generated chain lands relative to the base payload.
///
/// Only three cases: left, right, or both sides at once. Replace/InsertMiddle
/// are mutation operations and live in `HavocMutator`, not here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// `base + chain`
    Append,
    /// `chain + base`
    Prepend,
    /// `chain + base + chain`
    Wrap,
}

/// Three-weight placement sampler: right / left / both.
///
/// Set any weight to 0.0 to disable that direction entirely.
#[derive(Debug, Clone)]
pub struct PlacementPolicy {
    pub append: f32,
    pub prepend: f32,
    pub wrap: f32,
}

impl PlacementPolicy {
    pub fn new(append: f32, prepend: f32, wrap: f32) -> Self {
        Self { append: append.max(0.0), prepend: prepend.max(0.0), wrap: wrap.max(0.0) }
    }

    pub fn append_only()  -> Self { Self::new(1.0, 0.0, 0.0) }
    pub fn prepend_only() -> Self { Self::new(0.0, 1.0, 0.0) }
    pub fn wrap_only()    -> Self { Self::new(0.0, 0.0, 1.0) }

    pub fn sample<R: Rng>(&self, rng: &mut R) -> Placement {
        let total = self.append + self.prepend + self.wrap;
        if total == 0.0 { return Placement::Append; }
        let mut pick = rng.gen::<f32>() * total;
        pick -= self.append;  if pick <= 0.0 { return Placement::Append; }
        pick -= self.prepend; if pick <= 0.0 { return Placement::Prepend; }
        Placement::Wrap
    }
}

impl Default for PlacementPolicy {
    fn default() -> Self { Self::new(1.5, 1.0, 0.5) }
}

// ── LengthPolicy ──────────────────────────────────────────────────────────────

/// How many atoms to emit per chain.
///
/// Geometric distribution: after each atom past `min_atoms`, `stop_prob` chance
/// of stopping. Tune `stop_prob` to control average chain length; do NOT use
/// high chaining weights for this — they steer WHICH atom, not when to stop.
#[derive(Debug, Clone)]
pub struct LengthPolicy {
    pub min_atoms: usize,
    pub max_atoms: usize,
    pub stop_prob: f32,
}

impl LengthPolicy {
    pub fn new(min_atoms: usize, max_atoms: usize, stop_prob: f32) -> Self {
        Self {
            min_atoms,
            max_atoms: max_atoms.max(min_atoms),
            stop_prob: stop_prob.clamp(0.0, 1.0),
        }
    }

    pub fn fixed(n: usize) -> Self  { Self::new(n, n, 1.0) }
    // calib: shorter chains win monotonically, and min_atoms=1 always beats higher
    // floors. Presets keep their short<medium<long ordering but all bias short.
    pub fn short() -> Self          { Self::new(1, 6,  0.75) }
    pub fn medium() -> Self         { Self::new(1, 12, 0.5) }
    pub fn long() -> Self           { Self::new(1, 24, 0.25) }

    pub fn sample_count<R: Rng>(&self, rng: &mut R) -> usize {
        let mut n = self.min_atoms;
        while n < self.max_atoms {
            if rng.gen::<f32>() < self.stop_prob { break; }
            n += 1;
        }
        n
    }
}

impl Default for LengthPolicy {
    fn default() -> Self { Self::medium() }
}

// ── WeightedSampler ───────────────────────────────────────────────────────────

/// Combines atom table, chain weights, placement, and length into one sampler.
///
/// Atom table is `Vec<String>` so both static tables (converted on construction)
/// and proto-dispatched runtime tables share the same representation.
///
/// **Mutation mode** (`insert`, `replace_slice`): picks one atom via chain
/// weights and inserts/replaces it in an existing payload.
///
/// **Generation mode** (`apply_chain`): builds a complete atom chain from
/// scratch using chain weights + length policy, then applies via placement.
#[derive(Debug, Clone)]
pub struct WeightedSampler {
    pub atoms: Vec<String>,
    pub chain_table: ChainTable,
    pub placement: PlacementPolicy,
    pub length: LengthPolicy,
    /// Precomputed transition tables — zero-allocation sampling on the hot path.
    transitions: Vec<CompiledTransitions>,
    /// Atom string → index for O(1) tail-hint lookups.
    atom_ids: HashMap<String, usize>,
}

impl WeightedSampler {
    pub fn new(
        atoms: Vec<String>,
        chain_table: ChainTable,
        placement: PlacementPolicy,
        length: LengthPolicy,
    ) -> Self {
        let transitions = chain_table.compile(&atoms);
        let atom_ids: HashMap<String, usize> = atoms.iter()
            .enumerate()
            .map(|(i, a)| (a.clone(), i))
            .collect();
        Self { atoms, chain_table, placement, length, transitions, atom_ids }
    }

    /// Default web-attack sampler (ATOMS table, seeded weights, balanced placement, medium length).
    pub fn default_weights() -> Self {
        Self::new(
            ATOMS.iter().map(|s| s.to_string()).collect(),
            ChainTable::defaults(),
            PlacementPolicy::default(),
            LengthPolicy::medium(),
        )
    }

    /// Uniform sampler — all pair weights 1.0, balanced placement, medium length.
    pub fn uniform() -> Self {
        Self::new(
            ATOMS.iter().map(|s| s.to_string()).collect(),
            ChainTable::new(),
            PlacementPolicy::default(),
            LengthPolicy::medium(),
        )
    }

    /// Numeric parameter fuzzer: NUMERIC_ATOMS, append-only, short uniform chains.
    pub fn numeric() -> Self {
        Self::new(
            NUMERIC_ATOMS.iter().map(|s| s.to_string()).collect(),
            ChainTable::new(),
            PlacementPolicy::append_only(),
            LengthPolicy::short(),
        )
    }

    /// Construct from proto-dispatched configuration.
    ///
    /// If `atoms` is empty, falls back to `ATOMS`. If `chain_weights` is empty,
    /// uses `ChainTable::defaults()` when the atoms slice is also empty (i.e. full
    /// defaults), or a blank table otherwise (uniform random across custom atoms).
    pub fn from_proto_config(
        atoms: Vec<String>,
        chain_weights: impl IntoIterator<Item = (String, String, f32)>,
        placement: PlacementPolicy,
        length: LengthPolicy,
    ) -> Self {
        let (atoms, default_table) = if atoms.is_empty() {
            (ATOMS.iter().map(|s| s.to_string()).collect::<Vec<_>>(), true)
        } else {
            (atoms, false)
        };

        let mut chain_table = if default_table { ChainTable::defaults() } else { ChainTable::new() };
        let mut has_weights = false;
        for (from, to, w) in chain_weights {
            chain_table.set(from, to, w);
            has_weights = true;
        }
        // If no custom weights were provided AND we're using default atoms, keep defaults.
        // If custom atoms with no weights: uniform (blank table is already uniform).
        let _ = has_weights;

        Self::new(atoms, chain_table, placement, length)
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /// Find the longest atom suffix in `s`, returning its index and string.
    fn tail_hint_idx(&self, s: &str) -> Option<(usize, &str)> {
        self.atoms.iter()
            .enumerate()
            .filter(|(_, a)| s.ends_with(a.as_str()))
            .max_by_key(|(_, a)| a.len())
            .map(|(i, a)| (i, a.as_str()))
    }

    /// Sample the next atom given a source atom index. Uses precomputed
    /// cumulative transition table — zero allocations, no HashMap lookups.
    fn sample_next_idx<R: Rng>(&self, from_idx: usize, rng: &mut R) -> (usize, &str) {
        let trans = &self.transitions[from_idx];
        if trans.total <= 0.0 {
            let i = rng.gen_range(0..self.atoms.len());
            return (i, self.atoms[i].as_str());
        }
        let pick = rng.gen::<f32>() * trans.total;
        for &(idx, cum_w) in &trans.cumulative {
            if pick <= cum_w {
                return (idx, self.atoms[idx].as_str());
            }
        }
        let last = self.atoms.len() - 1;
        (last, self.atoms[last].as_str())
    }

    // ── Mutation mode (used by HavocMutator) ─────────────────────────────────

    /// Sample the next atom from `self.atoms` given the current chain tail hint.
    /// If no hint, picks uniformly. Uses compiled transitions when hint is present.
    pub fn sample_next<'a, R: Rng>(&'a self, hint: Option<&str>, rng: &mut R) -> &'a str {
        if let Some(h) = hint {
            if let Some(from_idx) = self.atom_ids.get(h) {
                return self.sample_next_idx(*from_idx, rng).1;
            }
        }
        self.atoms[rng.gen_range(0..self.atoms.len())].as_str()
    }

    /// Insert a chain-weighted atom at a random char boundary in `payload`.
    pub fn insert<R: Rng>(&self, payload: &str, rng: &mut R) -> String {
        let atom = if let Some((from_idx, _)) = self.tail_hint_idx(payload) {
            self.sample_next_idx(from_idx, rng).1
        } else {
            self.atoms[rng.gen_range(0..self.atoms.len())].as_str()
        };
        if payload.is_empty() { return atom.to_string(); }
        let pos = random_char_boundary(payload, rng);
        let mut s = payload.to_string();
        s.insert_str(pos, atom);
        s
    }

    /// Replace a random slice of `payload` (at char boundaries) with an atom.
    pub fn replace_slice<R: Rng>(&self, payload: &str, rng: &mut R) -> String {
        let atom = if let Some((from_idx, _)) = self.tail_hint_idx(payload) {
            self.sample_next_idx(from_idx, rng).1
        } else {
            self.atoms[rng.gen_range(0..self.atoms.len())].as_str()
        };
        if payload.is_empty() { return atom.to_string(); }
        // ASCII fast path: every byte is a char boundary — no Vec allocation.
        let (start, end) = if payload.is_ascii() {
            let s = rng.gen_range(0..=payload.len());
            (s, rng.gen_range(s..=payload.len()))
        } else {
            let boundaries: Vec<usize> = payload.char_indices()
                .map(|(i, _)| i).chain(std::iter::once(payload.len())).collect();
            let start_idx = rng.gen_range(0..boundaries.len());
            let start = boundaries[start_idx];
            (start, boundaries[rng.gen_range(start_idx..boundaries.len())])
        };
        format!("{}{}{}", &payload[..start], atom, &payload[end..])
    }

    // ── Generation mode ───────────────────────────────────────────────────────

    /// Build an atom chain and apply it to `base` using the placement policy.
    ///
    /// Chain length is drawn from `self.length`. Each atom is selected from
    /// `self.atoms` weighted by the precomputed transition tables.
    pub fn apply_chain<R: Rng>(&self, base: &str, rng: &mut R) -> String {
        let n = self.length.sample_count(rng);
        let mut from_idx: Option<usize> = self.tail_hint_idx(base).map(|(i, _)| i);
        let mut chain = String::new();
        for _ in 0..n {
            let from = from_idx.unwrap_or_else(|| rng.gen_range(0..self.atoms.len()));
            let (_next_idx, atom) = self.sample_next_idx(from, rng);
            chain.push_str(atom);
            from_idx = self.tail_hint_idx(&chain).map(|(i, _)| i);
        }
        match self.placement.sample(rng) {
            Placement::Append  => format!("{}{}", base, chain),
            Placement::Prepend => format!("{}{}", chain, base),
            Placement::Wrap    => format!("{}{}{}", chain, base, chain),
        }
    }
}

/// Pick a random valid char boundary index in `s` (0..=len).
/// Safe for `insert_str`, `split_at`, and `&s[..idx]` on UTF-8 strings.
pub(crate) fn random_char_boundary<R: Rng>(s: &str, rng: &mut R) -> usize {
    if s.is_empty() { return 0; }
    // ASCII fast path: every byte is a valid char boundary.
    if s.is_ascii() {
        return rng.gen_range(0..=s.len());
    }
    let count = s.chars().count();
    let nth = rng.gen_range(0..=count);
    if nth == count {
        s.len()
    } else {
        s.char_indices().nth(nth).map(|(i, _)| i).unwrap_or(s.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn atoms_vec() -> Vec<String> {
        ATOMS.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn tail_atom_finds_suffix() {
        assert_eq!(tail_atom("foo'"), Some("'"));
        assert_eq!(tail_atom("foo UNION "), Some(" UNION "));
        assert_eq!(tail_atom("nothing"), None);
        assert_eq!(tail_atom(""), None);
    }

    #[test]
    fn tail_atom_longest_wins() {
        assert_eq!(tail_atom("foo UNION "), Some(" UNION "));
    }

    #[test]
    fn numeric_tail_atom() {
        assert_eq!(tail_atom_from("id=100", NUMERIC_ATOMS), Some("100"));
        assert_eq!(tail_atom_from("id=NaN", NUMERIC_ATOMS), Some("NaN"));
    }

    #[test]
    fn chain_table_strong_weights() {
        let t = ChainTable::defaults();
        assert!(t.weight(" UNION ", " SELECT ") >= 20.0);
        assert!(t.weight("{{", "7*7") >= 20.0);
        assert!(t.weight("${", "}") >= 20.0);
    }

    #[test]
    fn chain_table_owned_set() {
        let mut t = ChainTable::new();
        t.set("foo".to_string(), "bar".to_string(), 5.0);
        assert_eq!(t.weight("foo", "bar"), 5.0);
        assert_eq!(t.weight("foo", "baz"), 1.0);
    }

    #[test]
    fn weighted_sampler_no_panic_no_hint() {
        let s = WeightedSampler::default_weights();
        let mut rng = rand::thread_rng();
        for _ in 0..100 { let _ = s.sample_next(None, &mut rng); }
    }

    #[test]
    fn weighted_sampler_favors_high_weight_continuation() {
        let s = WeightedSampler::default_weights();
        let mut rng = rand::thread_rng();
        let mut select_count = 0u32;
        for _ in 0..1000 {
            if s.sample_next(Some(" UNION "), &mut rng) == " SELECT " {
                select_count += 1;
            }
        }
        assert!(select_count > 150, "UNION→SELECT picked {select_count}/1000, expected >150");
    }

    #[test]
    fn placement_policy_append_only_always_appends() {
        let p = PlacementPolicy::append_only();
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            assert_eq!(p.sample(&mut rng), Placement::Append);
        }
    }

    #[test]
    fn placement_policy_zero_weight_never_fires() {
        let p = PlacementPolicy::new(1.0, 0.0, 0.0);
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            assert_eq!(p.sample(&mut rng), Placement::Append);
        }
    }

    #[test]
    fn length_policy_fixed_always_n() {
        let l = LengthPolicy::fixed(3);
        let mut rng = rand::thread_rng();
        for _ in 0..20 {
            assert_eq!(l.sample_count(&mut rng), 3);
        }
    }

    #[test]
    fn length_policy_stays_in_range() {
        let l = LengthPolicy::short();
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let n = l.sample_count(&mut rng);
            assert!(n >= l.min_atoms && n <= l.max_atoms);
        }
    }

    #[test]
    fn apply_chain_append_preserves_base() {
        let s = WeightedSampler::new(
            atoms_vec(), ChainTable::new(),
            PlacementPolicy::append_only(), LengthPolicy::fixed(1),
        );
        let mut rng = rand::thread_rng();
        let result = s.apply_chain("abc", &mut rng);
        assert!(result.starts_with("abc"), "append must keep base as prefix");
        assert!(result.len() > "abc".len());
    }

    #[test]
    fn apply_chain_prepend_preserves_base() {
        let s = WeightedSampler::new(
            atoms_vec(), ChainTable::new(),
            PlacementPolicy::prepend_only(), LengthPolicy::fixed(1),
        );
        let mut rng = rand::thread_rng();
        let result = s.apply_chain("abc", &mut rng);
        assert!(result.ends_with("abc"), "prepend must keep base as suffix");
    }

    #[test]
    fn apply_chain_no_panic_on_empty_base() {
        let s = WeightedSampler::default_weights();
        let mut rng = rand::thread_rng();
        for _ in 0..20 { let _ = s.apply_chain("", &mut rng); }
    }

    #[test]
    fn numeric_sampler_only_yields_numeric_atoms() {
        let s = WeightedSampler::numeric();
        let mut rng = rand::thread_rng();
        for _ in 0..50 {
            let atom = s.sample_next(None, &mut rng);
            assert!(NUMERIC_ATOMS.contains(&atom), "{atom:?} not in NUMERIC_ATOMS");
        }
    }

    #[test]
    fn atoms_tables_nonempty() {
        assert!(!ATOMS.is_empty());
        assert!(!NUMERIC_ATOMS.is_empty());
    }

    #[test]
    fn from_proto_config_no_atoms_uses_defaults() {
        let s = WeightedSampler::from_proto_config(
            vec![], vec![], PlacementPolicy::default(), LengthPolicy::medium(),
        );
        assert!(!s.atoms.is_empty());
        assert_eq!(s.atoms.len(), ATOMS.len());
    }

    #[test]
    fn from_proto_config_custom_atoms_and_weights() {
        let weights = vec![
            ("foo".to_string(), "bar".to_string(), 10.0f32),
        ];
        let s = WeightedSampler::from_proto_config(
            vec!["foo".to_string(), "bar".to_string(), "baz".to_string()],
            weights,
            PlacementPolicy::append_only(),
            LengthPolicy::fixed(1),
        );
        assert_eq!(s.atoms.len(), 3);
        assert_eq!(s.chain_table.weight("foo", "bar"), 10.0);
        assert_eq!(s.chain_table.weight("foo", "baz"), 1.0);
    }

    // ── Determinism calibration ───────────────────────────────────────────────
    //
    // Single-atom + append-only + fixed-length collapses all RNG choices to one
    // option each, so the output must be identical across every seed. Any
    // deviation means a sampling path is reading state it shouldn't.

    #[test]
    fn apply_chain_single_atom_any_seed_same_output() {
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        let s = WeightedSampler::from_proto_config(
            vec!["FUZZ".to_string()],
            vec![("FUZZ".to_string(), "FUZZ".to_string(), 20.0f32)],
            PlacementPolicy::append_only(),
            LengthPolicy::fixed(8),
        );
        let expected = "FUZZ".repeat(8);
        for seed in 0..=255u64 {
            let mut rng = SmallRng::seed_from_u64(seed);
            let result = s.apply_chain("", &mut rng);
            assert_eq!(result, expected, "seed {seed} produced {result:?}, expected {expected:?}");
        }
    }

    #[test]
    fn apply_chain_seeded_rng_is_reproducible() {
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        let s = WeightedSampler::default_weights();
        // Identical seeds must produce identical chains — catches accidental global state.
        for seed in [0u64, 1, 42, 0xDEAD_BEEF, u64::MAX / 2] {
            let mut rng_a = SmallRng::seed_from_u64(seed);
            let mut rng_b = SmallRng::seed_from_u64(seed);
            for _ in 0..20 {
                let a = s.apply_chain("'", &mut rng_a);
                let b = s.apply_chain("'", &mut rng_b);
                assert_eq!(a, b, "seed {seed}: diverged between two identically-seeded rngs");
            }
        }
    }

    #[test]
    fn apply_chain_long_chain_no_panic_or_overflow() {
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        // 50-atom chain of a 6-byte token = 300 bytes — well within stack, but
        // exercises any off-by-one in the length loop or placement logic.
        let s = WeightedSampler::from_proto_config(
            vec!["FUZZ--".to_string()],
            vec![],
            PlacementPolicy::append_only(),
            LengthPolicy::new(50, 50, 0.0),
        );
        let mut rng = SmallRng::seed_from_u64(1);
        let result = s.apply_chain("", &mut rng);
        assert_eq!(result, "FUZZ--".repeat(50),
            "50-atom chain wrong length: {} chars", result.len());
    }

    #[test]
    fn insert_and_replace_slice_no_panic_across_seeds() {
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        // Exercises char-boundary arithmetic in insert/replace_slice on
        // Unicode payloads — any out-of-bounds or mid-codepoint panic shows here.
        let s = WeightedSampler::default_weights();
        for seed in 0..128u64 {
            let mut rng = SmallRng::seed_from_u64(seed);
            let _ = s.insert("", &mut rng);
            let _ = s.insert("x", &mut rng);
            let _ = s.insert("' OR 1=1--", &mut rng);
            let _ = s.insert("café", &mut rng);
            let _ = s.insert("日本語", &mut rng);
            let _ = s.insert("🌟test🌟", &mut rng);
            let _ = s.replace_slice("", &mut rng);
            let _ = s.replace_slice("x", &mut rng);
            let _ = s.replace_slice("' OR 1=1--", &mut rng);
            let _ = s.replace_slice("café", &mut rng);
            let _ = s.replace_slice("日本語", &mut rng);
        }
    }

    #[test]
    fn random_char_boundary_always_valid() {
        use rand::SeedableRng;
        use rand::rngs::SmallRng;
        for payload in &["", "x", "café", "日本語", "a🌟b"] {
            let mut rng = SmallRng::seed_from_u64(1);
            for _ in 0..100 {
                let pos = random_char_boundary(payload, &mut rng);
                assert!(payload.is_char_boundary(pos),
                    "random_char_boundary returned {}, not a char boundary in {:?}", pos, payload);
            }
        }
    }
}
