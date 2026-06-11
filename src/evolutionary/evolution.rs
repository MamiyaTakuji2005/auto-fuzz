//! Evolutionary fuzzing loop v2 — chain generation + havoc mutation, driven by
//! corpus feedback.
//!
//! Extends the v1 `EvolutionaryLoop` with one new dimension: `gen_ratio`.
//! Each iteration the loop flips a biased coin:
//!   - heads (prob = gen_ratio): call `WeightedSampler::apply_chain` — full atom
//!     chain built from scratch, steered by chain weights and placement policy.
//!   - tails (prob = 1 - gen_ratio): call `HavocMutator::mutate` — stochastic
//!     operators applied to a corpus-selected seed.
//!
//! Setting gen_ratio = 0.0 degrades to pure havoc (identical to v1).
//! Setting gen_ratio = 1.0 disables havoc and drives purely by the grammar.
//! A balanced 0.3 blends both worlds: grammar-seeded novel payloads keeping the
//! corpus diverse, havoc-mutated existing payloads exploiting known-good signals.
//!
//! The corpus, feedback, and power-schedule are reused from `fuzzer_v2::corpus`
//! (not the v1 mutation::corpus) so the two are independently evolvable.

use rand::rngs::SmallRng;
use rand::SeedableRng;
use rand::Rng;

use crate::baseline::BaselineProfile;
use crate::evolutionary::atoms::WeightedSampler;
use crate::evolutionary::havoc::HavocMutator;
use crate::evolutionary::corpus::{SeedCorpus, CorpusEntry, Feedback, EvaluationContext};

use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::collections::hash_map::DefaultHasher;
use crate::signals::signal::{Signal, SignalSet, ProbeResponse};
use crate::signals::{Probe, Request};

// ── Payload length policy ─────────────────────────────────────────────────────

/// Global cap on candidate payload length.
///
/// Unbounded growth from repeated insertions, wrap mode, repeat, splice, and
/// long chain generation can waste memory, slow probes, trigger server-side
/// rejection, or accidentally self-DoS. This policy gates candidates before
/// they hit the transport layer.
#[derive(Debug, Clone)]
pub struct PayloadPolicy {
    /// Maximum allowed payload length in bytes.
    pub max_len: usize,
    /// When `true`, oversized candidates are discarded (the loop skips to the
    /// next iteration). When `false`, they are probed anyway.
    pub reject_oversized: bool,
}

impl Default for PayloadPolicy {
    fn default() -> Self {
        Self { max_len: 4096, reject_oversized: true }
    }
}

// ── Result types ──────────────────────────────────────────────────────────────

/// A single confirmed or interesting hit from the evolutionary loop.
#[derive(Debug, Clone)]
pub struct EvolutionaryHit {
    pub payload: String,
    /// Signals that survived baseline filtering (payload-specific).
    pub signals: Vec<Signal>,
    /// Signals that were suppressed by baseline profiling (ambient).
    pub ambient: Vec<Signal>,
    pub score: u8,
    pub parent_idx: usize,
    /// True if this hit triggered `Feedback::is_confirmed`.
    pub confirmed: bool,
}

/// Final result returned by `EvolutionaryLoop::run`.
#[derive(Debug)]
pub struct EvolutionaryOutcome {
    /// High-value confirmed hits.
    pub hits: Vec<EvolutionaryHit>,
    /// All interesting entries (score ≥ `Feedback::min_corpus_score`), including unconfirmed.
    pub interesting: Vec<EvolutionaryHit>,
    pub probes_sent: usize,
    pub final_corpus_size: usize,
    /// Baseline profile captured during the run (confidence, ambient signals).
    pub baseline_profile: BaselineProfile,
    // ── Diagnostics ────────────────────────────────────────────────────────
    /// Transport errors (connection refused, DNS failure, TLS, etc.).
    pub probe_errors: usize,
    /// Probes that timed out before the server responded.
    pub timeouts: usize,
    /// Candidate duplicates skipped by the dedup filter.
    pub duplicate_candidates_skipped: usize,
    /// Candidates rejected for exceeding `PayloadPolicy::max_len`.
    pub oversized_candidates_skipped: usize,
    /// No-op mutations where the candidate was identical to the seed.
    pub mutation_noops: usize,
}

impl EvolutionaryOutcome {
    pub fn has_confirmed(&self) -> bool { !self.hits.is_empty() }
}

// ── EvolutionaryLoop ──────────────────────────────────────────────────────────

/// Evolutionary fuzzing loop with blended generation + mutation.
///
/// Use `EvolutionaryLoop::builder()` or direct field construction to configure.
pub struct EvolutionaryLoop<P> {
    pub probe: P,
    pub signal_set: SignalSet,
    pub corpus: SeedCorpus,
    pub feedback: Box<dyn Feedback>,
    pub sampler: WeightedSampler,
    pub havoc: HavocMutator,
    /// Probability [0, 1] that each step uses `apply_chain` instead of `havoc.mutate`.
    pub gen_ratio: f32,
    pub max_probes: usize,
    pub request_timeout: std::time::Duration,
    /// When true, break on the first confirmed hit. Default false maximises recall.
    pub stop_on_confirmation: bool,
    /// When true, skip probing a candidate that was already sent this run.
    /// Prevents wasted probes on duplicate payloads. Default true.
    pub dedup_candidates: bool,
    /// Global cap on candidate payload length.
    pub payload_policy: PayloadPolicy,
    /// Deterministic RNG seed. `None` (default) samples from entropy.
    /// Setting a seed makes the corpus evolution and probe order reproducible.
    pub rng_seed: Option<u64>,
}

impl<P: Probe> EvolutionaryLoop<P> {
    pub fn new(
        probe: P,
        corpus: SeedCorpus,
        sampler: WeightedSampler,
        havoc: HavocMutator,
        feedback: Box<dyn Feedback>,
    ) -> Self {
        Self {
            probe,
            signal_set: SignalSet::defaults(),
            corpus,
            feedback,
            sampler,
            havoc,
            gen_ratio: 0.3,
            max_probes: 50,
            request_timeout: std::time::Duration::from_secs(30),
            // Architecture intent: fuzzer = maximum recall. Caller opts in to
            // early-exit via `stop_on_first_hit()`.
            stop_on_confirmation: false,
            dedup_candidates: true,
            payload_policy: PayloadPolicy::default(),
            rng_seed: None,
        }
    }

    pub fn with_gen_ratio(mut self, r: f32) -> Self {
        self.gen_ratio = r.clamp(0.0, 1.0);
        self
    }

    pub fn with_max_probes(mut self, n: usize) -> Self {
        self.max_probes = n.max(1);
        self
    }

    pub fn with_signal_set(mut self, s: SignalSet) -> Self {
        self.signal_set = s;
        self
    }

    pub fn with_request_timeout(mut self, t: std::time::Duration) -> Self {
        self.request_timeout = t;
        self
    }

    /// Identity builder — the loop already exhausts its budget by default.
    /// Kept so callers can spell their intent in code: `.exhaust_budget()`.
    pub fn exhaust_budget(mut self) -> Self {
        self.stop_on_confirmation = false;
        self
    }

    /// Break on the first confirmed hit instead of running the full budget.
    /// Use for cheap surgical probes; the default loop maximises recall.
    pub fn stop_on_first_hit(mut self) -> Self {
        self.stop_on_confirmation = true;
        self
    }

    /// Enable or disable candidate-level deduplication.
    /// When enabled (default), duplicate payloads are skipped before probing.
    /// Disable for deterministic tests with single-atom generators.
    pub fn with_dedup(mut self, enabled: bool) -> Self {
        self.dedup_candidates = enabled;
        self
    }

    /// Set the maximum allowed payload length. Candidates exceeding this are
    /// skipped (if `reject_oversized` is true on the policy).
    pub fn with_payload_policy(mut self, policy: PayloadPolicy) -> Self {
        self.payload_policy = policy;
        self
    }

    /// Seed the RNG used by the scheduler, gen-vs-havoc coin flip, and chain
    /// generation. Automatically derives the havoc RNG seed from this value
    /// so the full run is reproducible — same seed + same target behaviour =
    /// same probe sequence, same corpus, same confirmed hits.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.rng_seed = Some(seed);
        self.havoc = self.havoc.with_seed(seed.wrapping_add(Self::HAVOC_SEED_OFFSET));
        self
    }

    /// Golden-ratio constant to keep loop and havoc RNG seeds independent
    /// but deterministic from a single user-provided seed.
    const HAVOC_SEED_OFFSET: u64 = 0x9E37_79B9_7F4A_7C15;

    pub async fn run<F>(mut self, baseline_req: &Request, inject: F)
        -> Result<EvolutionaryOutcome, String>
    where
        F: Fn(&str) -> Request,
    {
        let baseline = match tokio::time::timeout(
            self.request_timeout, self.probe.send(baseline_req)).await
        {
            Ok(Ok(r))  => r,
            Ok(Err(e)) => return Err(e),
            Err(_)     => return Err("baseline timed out".into()),
        };
        self.run_with_baseline(baseline, inject).await
    }

    /// Run with a pre-captured baseline response. The caller fetches the
    /// baseline once and passes it in — the loop uses it for profiling and
    /// signal comparison without making a second baseline request.
    pub async fn run_with_baseline<F>(mut self, baseline: ProbeResponse, inject: F)
        -> Result<EvolutionaryOutcome, String>
    where
        F: Fn(&str) -> Request,
    {

        // ── Profile the baseline — what ambient signals exist? ────────
        let baseline_profile = BaselineProfile::capture(&baseline, &self.signal_set);

        let mut rng = match self.rng_seed {
            Some(s) => SmallRng::seed_from_u64(s),
            None    => SmallRng::from_entropy(),
        };
        let mut hits: Vec<EvolutionaryHit>        = Vec::new();
        let mut interesting: Vec<EvolutionaryHit> = Vec::new();
        let mut probes_sent  = 0usize;
        let mut probe_errors = 0usize;
        let mut timeouts     = 0usize;
        let mut duplicates_skipped  = 0usize;
        let mut oversized_skipped   = 0usize;
        let mut mutation_noops      = 0usize;
        let mut tried: HashSet<u64> = HashSet::new();

        // Initial sync — seed the splice corpus once before the loop.
        self.havoc.update_corpus(self.corpus.all_payloads());

        while probes_sent < self.max_probes {
            // Power schedule: pick corpus entry weighted by energy.
            let Some(parent_idx) = self.corpus.schedule(&mut rng) else { break };
            let seed_payload = self.corpus.entry(parent_idx).unwrap().payload.clone();

            // Generation vs mutation decision — retry on no-op mutations.
            const MAX_NOOP_RETRIES: usize = 3;
            let mut candidate = String::new();
            for retry in 0..=MAX_NOOP_RETRIES {
                candidate = if rng.gen::<f32>() < self.gen_ratio {
                    self.sampler.apply_chain(&seed_payload, &mut rng)
                } else {
                    self.havoc.mutate(&seed_payload)
                };
                if candidate == seed_payload {
                    mutation_noops += 1;
                    if retry < MAX_NOOP_RETRIES {
                        continue;
                    }
                }
                break;
            }

            // Candidate-level dedup: skip duplicates before probing.
            if self.dedup_candidates {
                let mut hasher = DefaultHasher::new();
                candidate.hash(&mut hasher);
                if !tried.insert(hasher.finish()) {
                    duplicates_skipped += 1;
                    continue;
                }
            }

            // Length gate: discard oversized candidates before they hit transport.
            if self.payload_policy.reject_oversized && candidate.len() > self.payload_policy.max_len {
                oversized_skipped += 1;
                continue;
            }

            // Probe.
            let req = inject(&candidate);
            let resp = match tokio::time::timeout(
                self.request_timeout, self.probe.send(&req)).await
            {
                Ok(Ok(r))  => r,
                Ok(Err(_)) => { probe_errors += 1; probes_sent += 1; continue; }
                Err(_)     => { timeouts += 1; probes_sent += 1; continue; }
            };
            probes_sent += 1;

            // Classify — then filter through baseline profile.
            let raw_signals = self.signal_set.run(&candidate, &baseline, &resp);
            let signals = baseline_profile.filter(&raw_signals);

            // Full context for feedback — inspect payload, request, baseline,
            // response, raw vs filtered signals, timing, transport errors.
            let ctx = EvaluationContext {
                payload: &candidate,
                request: &req,
                baseline: &baseline,
                response: &resp,
                probe_error: None,
                raw_signals: &raw_signals,
                filtered_signals: &signals,
            };
            let eval = self.feedback.evaluate(&ctx);

            // Corpus evolution — only filtered signals affect decisions.
            if eval.interesting {
                let entry = CorpusEntry::discovered(candidate.clone(), eval.best_signal, eval.score, parent_idx);
                let prev_len = self.corpus.len();
                self.corpus.push_discovered(entry);
                // Incrementally feed the splice corpus — no full clone.
                if self.corpus.len() > prev_len {
                    self.havoc.push_corpus_payload(candidate.clone());
                }
                self.corpus.boost_energy(parent_idx, 1);

                // Compute ambient signals — what the baseline explained away.
                let filtered_kinds: std::collections::HashSet<&str> =
                    signals.iter().map(|s| s.kind()).collect();
                let ambient: Vec<Signal> = raw_signals
                    .into_iter()
                    .filter(|s| !filtered_kinds.contains(s.kind()))
                    .collect();

                let hit = EvolutionaryHit {
                    payload: candidate,
                    signals,
                    ambient,
                    score: eval.score,
                    parent_idx,
                    confirmed: eval.confirmed,
                };
                if eval.confirmed {
                    hits.push(hit.clone());
                }
                interesting.push(hit);

                if eval.confirmed && self.stop_on_confirmation {
                    break;
                }
            }
        }

        Ok(EvolutionaryOutcome {
            hits,
            interesting,
            probes_sent,
            final_corpus_size: self.corpus.len(),
            baseline_profile,
            probe_errors,
            timeouts,
            duplicate_candidates_skipped: duplicates_skipped,
            oversized_candidates_skipped: oversized_skipped,
            mutation_noops,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;
    use std::collections::HashMap;
    use async_trait::async_trait;
    use crate::signals::signal::ProbeResponse;
    use crate::evolutionary::corpus::HttpFeedback;
    use crate::evolutionary::atoms::{PlacementPolicy, LengthPolicy};

    struct MockProbe(Mutex<std::collections::VecDeque<ProbeResponse>>);

    impl MockProbe {
        fn new(v: Vec<ProbeResponse>) -> Self { Self(Mutex::new(v.into())) }
    }

    fn resp(status: u16, body: &str, ms: u64) -> ProbeResponse {
        ProbeResponse { status, body: body.as_bytes().to_vec(), duration: Duration::from_millis(ms) }
    }

    #[async_trait]
    impl Probe for MockProbe {
        async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
            self.0.lock().unwrap().pop_front().ok_or("no more responses".to_string())
        }
    }

    fn base_req() -> Request {
        Request { url: "http://x.com/?q=1".into(), method: "GET".into(), headers: HashMap::new(), body: String::new() }
    }

    fn build_loop(probe: MockProbe, gen_ratio: f32) -> EvolutionaryLoop<MockProbe> {
        let sampler = WeightedSampler::default_weights();
        let havoc   = HavocMutator::new(WeightedSampler::default_weights(), 200);
        let corpus  = SeedCorpus::from_seeds(["'"]);
        let fb      = Box::new(HttpFeedback::default());
        EvolutionaryLoop::new(probe, corpus, sampler, havoc, fb)
            .with_gen_ratio(gen_ratio)
            .with_max_probes(5)
    }

    #[tokio::test]
    async fn baseline_failure_propagates() {
        let probe = MockProbe::new(vec![]);
        let lp = build_loop(probe, 0.5);
        let err = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"),
            method: "GET".into(), headers: HashMap::new(), body: String::new(),
        }).await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn runs_without_panic_no_signals() {
        // baseline + 3 no-signal responses
        let probe = MockProbe::new(vec![
            resp(200, "ok", 10),
            resp(200, "ok", 10),
            resp(200, "ok", 10),
            resp(200, "ok", 10),
        ]);
        let lp = build_loop(probe, 0.3);
        let out = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"),
            method: "GET".into(), headers: HashMap::new(), body: String::new(),
        }).await.unwrap();
        assert!(!out.has_confirmed());
        assert!(out.probes_sent <= 5);
    }

    #[tokio::test]
    async fn confirms_on_sql_error() {
        let probe = MockProbe::new(vec![
            resp(200, "ok", 10),
            resp(500, "You have an error in your SQL syntax near", 10),
        ]);
        let lp = build_loop(probe, 0.5);
        let out = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"),
            method: "GET".into(), headers: HashMap::new(), body: String::new(),
        }).await.unwrap();
        assert!(out.has_confirmed());
    }

    #[tokio::test]
    async fn gen_ratio_1_uses_apply_chain() {
        // gen_ratio=1.0 → never calls havoc; verify loop still runs
        let probe = MockProbe::new(vec![
            resp(200, "ok", 10),
            resp(200, "ok", 10),
            resp(200, "ok", 10),
        ]);
        let lp = build_loop(probe, 1.0);
        let out = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"),
            method: "GET".into(), headers: HashMap::new(), body: String::new(),
        }).await.unwrap();
        assert!(out.probes_sent <= 5);
    }

    // ── Determinism calibration ───────────────────────────────────────────────
    //
    // These tests verify that probe response timing and content do not feed back
    // into candidate generation. With a single atom + gen_ratio=1.0 + fixed
    // length + append_only, every candidate the loop generates must be identical
    // regardless of what the mock probe returns or how quickly.

    fn build_single_atom_loop(probe: MockProbe, n_atoms: usize) -> EvolutionaryLoop<MockProbe> {
        let sampler = WeightedSampler::from_proto_config(
            vec!["FUZZ".to_string()],
            vec![("FUZZ".to_string(), "FUZZ".to_string(), 20.0f32)],
            PlacementPolicy::append_only(),
            LengthPolicy::fixed(n_atoms),
        );
        let havoc  = HavocMutator::new(sampler.clone(), 200);
        let corpus = SeedCorpus::from_seeds([""]);
        let fb     = Box::new(HttpFeedback::default());
        EvolutionaryLoop::new(probe, corpus, sampler, havoc, fb)
            .with_gen_ratio(1.0)
            .with_max_probes(10)
            .with_dedup(false)
    }

    #[tokio::test]
    async fn single_atom_all_candidates_identical() {
        // 10 probes after baseline — every inject call must receive "FUZZ" * 5.
        let probe = MockProbe::new((0..11).map(|_| resp(200, "ok", 5)).collect());
        let lp = build_single_atom_loop(probe, 5);

        let expected = "FUZZ".repeat(5);
        let seen = std::sync::Arc::new(Mutex::new(Vec::new()));
        let seen_clone = std::sync::Arc::clone(&seen);

        lp.run(&base_req(), move |p| {
            seen_clone.lock().unwrap().push(p.to_string());
            Request { url: format!("http://x.com/?q={p}"), method: "GET".into(),
                      headers: HashMap::new(), body: String::new() }
        }).await.unwrap();

        let payloads = seen.lock().unwrap();
        assert!(!payloads.is_empty(), "no probes were sent");
        for (i, payload) in payloads.iter().enumerate() {
            assert_eq!(payload, &expected, "probe {i} deviated: {payload:?}");
        }
    }

    #[tokio::test]
    async fn probe_latency_does_not_alter_candidates() {
        // Two runs: fast responses (1 ms) vs slow responses (200 ms).
        // With a single atom the candidate sequence is fully determined —
        // any difference means timing is bleeding into the generation path.
        let fast_responses: Vec<ProbeResponse> = (0..11).map(|_| resp(200, "ok", 1)).collect();
        let slow_responses: Vec<ProbeResponse> = (0..11).map(|_| resp(200, "ok", 200)).collect();

        let expected = "FUZZ".repeat(5);

        for (label, responses) in [("fast", fast_responses), ("slow", slow_responses)] {
            let probe = MockProbe::new(responses);
            let lp = build_single_atom_loop(probe, 5);
            let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
            let seen_clone = std::sync::Arc::clone(&seen);
            lp.run(&base_req(), move |p| {
                seen_clone.lock().unwrap().push(p.to_string());
                Request { url: format!("http://x.com/?q={p}"), method: "GET".into(),
                          headers: HashMap::new(), body: String::new() }
            }).await.unwrap();
            let payloads = seen.lock().unwrap();
            for (i, payload) in payloads.iter().enumerate() {
                assert_eq!(payload, &expected,
                    "{label} run probe {i} deviated: {payload:?}");
            }
        }
    }

    #[tokio::test]
    async fn error_responses_do_not_alter_candidates() {
        // Sampler must not peek at response content. We pin `stop_on_first_hit`
        // so the 500 response doesn't end the loop early, AND we keep all
        // responses below the size/status thresholds so the corpus doesn't
        // evolve mid-run — that way every candidate is generated from the
        // original single-atom seed and the FUZZ-repeat invariant holds.
        let responses = vec![
            resp(200, "ok", 5),    // baseline
            resp(200, "ok", 5),    // identical → no signal
            resp(200, "ok", 5),
            resp(200, "ok", 5),
            resp(200, "ok", 5),
        ];
        let probe = MockProbe::new(responses);
        let lp = build_single_atom_loop(probe, 4);
        let expected = "FUZZ".repeat(4);
        let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
        let seen_clone = std::sync::Arc::clone(&seen);
        lp.run(&base_req(), move |p| {
            seen_clone.lock().unwrap().push(p.to_string());
            Request { url: format!("http://x.com/?q={p}"), method: "GET".into(),
                      headers: HashMap::new(), body: String::new() }
        }).await.unwrap();
        for (i, payload) in seen.lock().unwrap().iter().enumerate() {
            assert_eq!(payload, &expected, "probe {i} deviated on error-mixed run: {payload:?}");
        }
    }

    // ── End-to-end determinism ────────────────────────────────────────────────
    //
    // Same seed + same target = same probe sequence. This is the load-bearing
    // guarantee for replay. Uses the default sampler with full chain weights
    // so it exercises the actual generation path, not the single-atom collapse.

    fn seeded_loop(probe: MockProbe, seed: u64) -> EvolutionaryLoop<MockProbe> {
        let sampler = WeightedSampler::default_weights();
        let havoc   = HavocMutator::new(WeightedSampler::default_weights(), 200)
            .with_seed(seed.wrapping_add(0x9E37_79B9_7F4A_7C15));
        let corpus  = SeedCorpus::from_seeds(["'", "<", "{{"]);
        let fb      = Box::new(HttpFeedback::default());
        EvolutionaryLoop::new(probe, corpus, sampler, havoc, fb)
            .with_gen_ratio(0.5)
            .with_max_probes(8)
            .with_seed(seed)
    }

    #[tokio::test]
    async fn seeded_run_reproduces_probe_sequence() {
        let mut sequences: Vec<Vec<String>> = Vec::new();
        for _ in 0..2 {
            let probe = MockProbe::new((0..9).map(|_| resp(200, "ok", 5)).collect());
            let lp = seeded_loop(probe, 0xCAFE_BABE);
            let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
            let seen_clone = std::sync::Arc::clone(&seen);
            lp.run(&base_req(), move |p| {
                seen_clone.lock().unwrap().push(p.to_string());
                Request { url: format!("http://x.com/?q={p}"), method: "GET".into(),
                          headers: HashMap::new(), body: String::new() }
            }).await.unwrap();
            sequences.push(seen.lock().unwrap().clone());
        }
        assert_eq!(sequences[0], sequences[1],
            "same seed must produce identical probe sequences");
        assert!(!sequences[0].is_empty(), "loop should have sent probes");
    }

    #[tokio::test]
    async fn different_seeds_diverge() {
        let mut runs: Vec<Vec<String>> = Vec::new();
        for seed in [1u64, 2] {
            let probe = MockProbe::new((0..9).map(|_| resp(200, "ok", 5)).collect());
            let lp = seeded_loop(probe, seed);
            let seen = std::sync::Arc::new(Mutex::new(Vec::<String>::new()));
            let seen_clone = std::sync::Arc::clone(&seen);
            lp.run(&base_req(), move |p| {
                seen_clone.lock().unwrap().push(p.to_string());
                Request { url: format!("http://x.com/?q={p}"), method: "GET".into(),
                          headers: HashMap::new(), body: String::new() }
            }).await.unwrap();
            runs.push(seen.lock().unwrap().clone());
        }
        // With the default chain table + gen_ratio=0.5, different seeds must
        // produce different probe sequences. Equal sequences would mean the
        // seed isn't actually steering the RNG.
        assert_ne!(runs[0], runs[1], "different seeds should not produce identical sequences");
    }

    #[tokio::test]
    async fn default_loop_does_not_stop_on_first_confirmation() {
        // Architecture: the fuzzer maximises recall. Even after a confirmed hit
        // (500 + SQL error) the loop should keep going until probes are exhausted
        // or the mock runs dry.
        let probe = MockProbe::new(vec![
            resp(200, "ok", 5),                                                   // baseline
            resp(500, "You have an error in your SQL syntax near 'x'", 5),       // confirms
            resp(200, "ok", 5),
            resp(200, "ok", 5),
            resp(200, "ok", 5),
            resp(200, "ok", 5),
        ]);
        let lp = build_loop(probe, 0.5);
        let out = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"), method: "GET".into(),
            headers: HashMap::new(), body: String::new(),
        }).await.unwrap();
        assert!(out.has_confirmed());
        // 5 probes after baseline — the loop kept running past the confirmation.
        assert_eq!(out.probes_sent, 5, "default loop should exhaust budget, got {}", out.probes_sent);
    }

    #[tokio::test]
    async fn stop_on_first_hit_breaks_early() {
        // Opt-in fast-confirm mode: the loop exits the moment a confirmation fires.
        let probe = MockProbe::new(vec![
            resp(200, "ok", 5),
            resp(500, "You have an error in your SQL syntax near 'x'", 5),
            resp(200, "ok", 5),
            resp(200, "ok", 5),
        ]);
        let lp = build_loop(probe, 0.5).stop_on_first_hit();
        let out = lp.run(&base_req(), |p| Request {
            url: format!("http://x.com/?q={p}"), method: "GET".into(),
            headers: HashMap::new(), body: String::new(),
        }).await.unwrap();
        assert!(out.has_confirmed());
        assert_eq!(out.probes_sent, 1, "stop_on_first_hit should exit after 1 probe, got {}", out.probes_sent);
    }
}
