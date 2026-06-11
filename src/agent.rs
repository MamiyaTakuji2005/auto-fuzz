//! High-level facade for AI agents.
//!
//! The agent doesn't need to know about chain weights, power schedules,
//! or signal classifiers. It just picks a vulnerability class and a target.
//!
//! ```ignore
//! let result = Fuzzer::new(my_probe)
//!     .sql_injection()
//!     .target("https://example.com/search?q=", "GET")
//!     .budget(100)
//!     .run()
//!     .await
//!     .unwrap();
//! // result.confirmed: Vec<Hit> — all confirmed SQLi payloads
//! ```

use std::sync::Arc;
use async_trait::async_trait;

use crate::baseline::BaselineProfile;
use crate::evolutionary::*;
use crate::payloads;
use crate::signals::signal::*;
use crate::signals::{Probe, Request};
use std::collections::{HashMap, HashSet};
use std::time::Duration;

// ── Arc blanket impl for Probe ──────────────────────────────────────────

#[async_trait]
impl<P: Probe> Probe for Arc<P> {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        self.as_ref().send(req).await
    }
}

// ── Hit (simplified for agent consumption) ──────────────────────────────

/// A single confirmed or interesting hit, simplified for agent readability.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The payload string that triggered the hit.
    pub payload: String,
    /// Raw score from the feedback layer (0–6 for HttpFeedback).
    pub raw_score: u8,
    /// Confidence from baseline profiling (0.0 = unreliable, 1.0 = clean).
    pub confidence: f32,
    /// Adjusted score = raw_score × confidence.
    pub adjusted_score: f32,
    /// True if this is a confirmed vulnerability (and confidence > 0.3).
    pub confirmed: bool,
    /// Signal descriptions that survived baseline filtering.
    pub signals: Vec<String>,
    /// Signals that were suppressed because the baseline also triggered them.
    pub suppressed: Vec<String>,
}

/// Final result returned to the agent.
#[derive(Debug, Clone)]
pub struct FuzzResult {
    /// Confirmed hits (high-confidence vulnerabilities).
    pub confirmed: Vec<Hit>,
    /// All interesting payloads including unconfirmed.
    pub interesting: Vec<Hit>,
    /// How many probes were sent.
    pub probes_sent: usize,
    /// Final corpus size (seeds + discovered).
    pub corpus_size: usize,
    /// Baseline health summary for audit trail.
    pub baseline: String,
}

impl FuzzResult {
    pub fn has_hits(&self) -> bool { !self.confirmed.is_empty() }
}

// ── Vulnerability preset ────────────────────────────────────────────────

struct Preset {
    atoms: Vec<String>,
    chain: ChainTable,
    seeds: Vec<String>,
    signal_set: SignalSet,
    feedback: Box<dyn Feedback>,
    gen_ratio: f32,
    placement: PlacementPolicy,
    length: LengthPolicy,
    stop_on_confirmation: bool,
}

impl Default for Preset {
    fn default() -> Self {
        Self {
            atoms: ATOMS.iter().map(|s| s.to_string()).collect(),
            chain: ChainTable::defaults(),
            seeds: vec![],
            signal_set: SignalSet::defaults(),
            feedback: Box::new(HttpFeedback::default()),
            gen_ratio: 0.3,
            placement: PlacementPolicy::default(),
            length: LengthPolicy::medium(),
            stop_on_confirmation: false,
        }
    }
}

impl Preset {
    fn sql_injection() -> Self {
        Self {
            atoms: ATOMS.iter().map(|s| s.to_string()).collect(),
            chain: ChainTable::defaults(),
            seeds: payloads::SQLI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(ErrorClassifier::dbms_starter()))
                .with(Box::new(TimeDelayClassifier::default())),
            feedback: Box::new(HttpFeedback::default()),
            gen_ratio: 0.3,
            placement: PlacementPolicy::default(),
            length: LengthPolicy::medium(),
            stop_on_confirmation: false,
        }
    }

    fn xss() -> Self {
        Self {
            seeds: payloads::XSS_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(ReflectionClassifier))
                .with(Box::new(BodyDiffClassifier)),
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn ssti() -> Self {
        Self {
            seeds: payloads::SSTI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(SizeClassifier::default()))
                .with(Box::new(ReflectionClassifier))
                .with(Box::new(ErrorClassifier::dbms_starter())),
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn command_injection() -> Self {
        Self {
            seeds: payloads::CMD_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(TimeDelayClassifier::default()))
                .with(Box::new(SizeClassifier::default())),
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn path_traversal() -> Self {
        Self {
            seeds: payloads::PATH_TRAVERSAL_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(SizeClassifier::default()))
                .with(Box::new(ReflectionClassifier)),
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn nosql_injection() -> Self {
        Self {
            seeds: payloads::NOSQLI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(SizeClassifier::default()))
                .with(Box::new(ErrorClassifier::dbms_starter()))
                .with(Box::new(TimeDelayClassifier::default())),
            gen_ratio: 0.3,
            length: LengthPolicy::short(),
            ..Default::default()
        }
    }

    fn ssrf() -> Self {
        Self {
            seeds: payloads::SSRF_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(SizeClassifier::default()))
                .with(Box::new(TimeDelayClassifier::default())),
            gen_ratio: 0.0,
            ..Default::default()
        }
    }

    fn xxe() -> Self {
        Self {
            seeds: payloads::XXE_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set: SignalSet::new()
                .with(Box::new(StatusClassifier))
                .with(Box::new(SizeClassifier::default()))
                .with(Box::new(ReflectionClassifier)),
            gen_ratio: 0.0,
            ..Default::default()
        }
    }

    fn table_sweep() -> Self {
        Self {
            gen_ratio: 0.0,
            stop_on_confirmation: false,
            ..Default::default()
        }
    }
}

// ── Fuzzer builder ───────────────────────────────────────────────────────

/// High-level fuzzer interface for AI agents.
pub struct Fuzzer<P: Probe> {
    probe: Arc<P>,
    preset: Preset,
    target_url: String,
    method: String,
    budget: usize,
    replay_seed: Option<u64>,
    request_timeout: Duration,
    additional_seeds: Vec<String>,
}

impl<P: Probe> Fuzzer<P> {
    pub fn new(probe: Arc<P>) -> Self {
        Self {
            probe,
            preset: Preset::default(),
            target_url: String::new(),
            method: "GET".into(),
            budget: 50,
            replay_seed: None,
            request_timeout: Duration::from_secs(30),
            additional_seeds: vec![],
        }
    }

    pub fn sql_injection(mut self) -> Self { self.preset = Preset::sql_injection(); self }
    pub fn xss(mut self) -> Self { self.preset = Preset::xss(); self }
    pub fn ssti(mut self) -> Self { self.preset = Preset::ssti(); self }
    pub fn command_injection(mut self) -> Self { self.preset = Preset::command_injection(); self }
    pub fn path_traversal(mut self) -> Self { self.preset = Preset::path_traversal(); self }
    pub fn nosql_injection(mut self) -> Self { self.preset = Preset::nosql_injection(); self }
    pub fn ssrf(mut self) -> Self { self.preset = Preset::ssrf(); self }
    pub fn xxe(mut self) -> Self { self.preset = Preset::xxe(); self }
    pub fn table_sweep(mut self) -> Self { self.preset = Preset::table_sweep(); self }

    pub fn target(mut self, url: &str, method: &str) -> Self {
        self.target_url = url.to_string();
        self.method = method.to_uppercase();
        self
    }

    pub fn budget(mut self, probes: usize) -> Self { self.budget = probes.max(1); self }

    pub fn seeds<I, S>(mut self, seeds: I) -> Self
    where I: IntoIterator<Item = S>, S: Into<String>,
    { self.additional_seeds = seeds.into_iter().map(|s| s.into()).collect(); self }

    pub fn replay_seed(mut self, seed: u64) -> Self { self.replay_seed = Some(seed); self }
    pub fn request_timeout(mut self, t: Duration) -> Self { self.request_timeout = t; self }
    pub fn gen_ratio(mut self, r: f32) -> Self { self.preset.gen_ratio = r.clamp(0.0, 1.0); self }
    pub fn stop_on_first_hit(mut self) -> Self { self.preset.stop_on_confirmation = true; self }

    // ── Run ───────────────────────────────────────────────────────────

    pub async fn run(self) -> Result<FuzzResult, String> {
        let baseline_req = Request {
            url: self.target_url.clone(),
            method: self.method.clone(),
            headers: HashMap::new(),
            body: String::new(),
        };

        // ── Pre-flight: profile the baseline ──────────────────────────
        // Send the empty request. Run it through the same classifiers.
        // Subtract ambient signals so only payload-specific results survive.
        let baseline_resp = self.probe.send(&baseline_req).await
            .map_err(|e| format!("baseline probe failed: {e}"))?;
        let profile = BaselineProfile::capture(&baseline_resp, &self.preset.signal_set);

        // ── Build the engine ──────────────────────────────────────────
        // Unwrap the Arc to get P back (refcount is 1 after the pre-flight).
        let probe = Arc::try_unwrap(self.probe)
            .unwrap_or_else(|_| panic!("probe still referenced after pre-flight"));

        let sampler = WeightedSampler::new(
            self.preset.atoms,
            self.preset.chain,
            self.preset.placement,
            self.preset.length,
        );
        let havoc = HavocMutator::new(sampler.clone(), self.budget * 4);
        let mut corpus = SeedCorpus::from_seeds(&self.preset.seeds);
        for s in &self.additional_seeds {
            corpus.push_seed(s.clone());
        }

        let mut loop_ = EvolutionaryLoop::new(
            probe,
            corpus,
            sampler,
            havoc,
            self.preset.feedback,
        )
        .with_gen_ratio(self.preset.gen_ratio)
        .with_max_probes(self.budget)
        .with_signal_set(self.preset.signal_set)
        .with_request_timeout(self.request_timeout);

        if self.preset.stop_on_confirmation { loop_ = loop_.stop_on_first_hit(); }
        if let Some(s) = self.replay_seed { loop_ = loop_.with_seed(s); }

        let method = self.method.clone();
        let url = self.target_url.clone();
        let inject = move |payload: &str| -> Request {
            if method == "POST" {
                Request { url: url.clone(), method: method.clone(), headers: HashMap::new(), body: payload.to_string() }
            } else {
                Request { url: format!("{}?q={}", url, payload), method: method.clone(), headers: HashMap::new(), body: String::new() }
            }
        };

        let outcome = loop_.run(&baseline_req, inject).await?;

        // ── Post-filter: apply baseline profile to results ────────────
        let confidence = profile.confidence();
        let to_hit = |h: &EvolutionaryHit| {
            let raw: Vec<String> = h.signals.iter().map(|s| s.kind().to_string()).collect();
            let filtered = profile.filter(&h.signals);
            let keep: HashSet<String> = filtered.iter().map(|s| s.kind().to_string()).collect();
            let signals: Vec<String> = filtered.iter().map(|s| s.kind().to_string()).collect();
            let suppressed: Vec<String> = raw.iter().filter(|k| !keep.contains(*k)).cloned().collect();
            Hit {
                payload: h.payload.clone(),
                raw_score: h.score,
                confidence,
                adjusted_score: h.score as f32 * confidence,
                confirmed: h.confirmed && confidence > 0.3,
                signals,
                suppressed,
            }
        };

        Ok(FuzzResult {
            confirmed: outcome.hits.iter().map(to_hit).collect(),
            interesting: outcome.interesting.iter().map(to_hit).collect(),
            probes_sent: outcome.probes_sent,
            corpus_size: outcome.final_corpus_size,
            baseline: profile.summary(),
        })
    }
}
