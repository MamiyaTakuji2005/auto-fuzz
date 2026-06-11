//! High-level facade for AI agents.
//!
//! The agent doesn't need to know about chain weights, power schedules,
//! or signal classifiers. It just picks a vulnerability class and a target.
//!
//! ```ignore
//! # // Needs a Probe implementation (HTTP client, mock, etc.)
//! let hits = Fuzzer::new(my_probe)
//!     .sql_injection()
//!     .target("https://example.com/search?q=", "GET")
//!     .budget(100)
//!     .run()
//!     .await?;
//!
//! for h in &hits.confirmed {
//!     println!("SQLi: {}", h.payload);
//! }
//! ```

use crate::evolutionary::*;
use crate::payloads;
use crate::signals::signal::*;
use crate::signals::{Probe, Request};
use std::collections::HashMap;
use std::time::Duration;

// ── Hit (simplified for agent consumption) ──────────────────────────────

/// A single confirmed or interesting hit, simplified for agent readability.
#[derive(Debug, Clone)]
pub struct Hit {
    /// The payload string that triggered the hit.
    pub payload: String,
    /// Score from the feedback layer (0–6 for HttpFeedback).
    pub score: u8,
    /// True if this is a confirmed vulnerability.
    pub confirmed: bool,
    /// Human-readable signal descriptions.
    pub signals: Vec<String>,
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
}

impl FuzzResult {
    pub fn has_hits(&self) -> bool { !self.confirmed.is_empty() }
}

// ── Vulnerability preset ────────────────────────────────────────────────

/// Bundled configuration for one vulnerability class.
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
        let mut signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(ErrorClassifier::dbms_starter()))
            .with(Box::new(TimeDelayClassifier::default()));
        Self {
            atoms: ATOMS.iter().map(|s| s.to_string()).collect(),
            chain: ChainTable::defaults(), // SQL chain grammar already seeded
            seeds: payloads::SQLI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            feedback: Box::new(HttpFeedback::default()),
            gen_ratio: 0.3,
            placement: PlacementPolicy::default(),
            length: LengthPolicy::medium(),
            stop_on_confirmation: false,
        }
    }

    fn xss() -> Self {
        let mut signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(ReflectionClassifier))
            .with(Box::new(BodyDiffClassifier));
        Self {
            atoms: ATOMS.iter().map(|s| s.to_string()).collect(),
            chain: ChainTable::defaults(), // XSS chain grammar already seeded
            seeds: payloads::XSS_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn ssti() -> Self {
        let signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(ReflectionClassifier))
            .with(Box::new(ErrorClassifier::dbms_starter()));
        Self {
            seeds: payloads::SSTI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn command_injection() -> Self {
        let signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(TimeDelayClassifier::default()))
            .with(Box::new(SizeClassifier::default()));
        Self {
            seeds: payloads::CMD_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn path_traversal() -> Self {
        let signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(ReflectionClassifier));
        Self {
            seeds: payloads::PATH_TRAVERSAL_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.3,
            ..Default::default()
        }
    }

    fn nosql_injection() -> Self {
        let mut signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(ErrorClassifier::dbms_starter()))
            .with(Box::new(TimeDelayClassifier::default()));
        Self {
            seeds: payloads::NOSQLI_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.3,
            // NoSQL payloads are JSON — use minimal length chains
            length: LengthPolicy::short(),
            ..Default::default()
        }
    }

    fn ssrf() -> Self {
        let signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(TimeDelayClassifier::default()));
        Self {
            seeds: payloads::SSRF_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.0, // pure havoc — SSRF payloads are URLs, grammar adds wrong chars
            ..Default::default()
        }
    }

    fn xxe() -> Self {
        let signal_set = SignalSet::new()
            .with(Box::new(StatusClassifier))
            .with(Box::new(SizeClassifier::default()))
            .with(Box::new(ReflectionClassifier));
        Self {
            seeds: payloads::XXE_PAYLOADS.iter().map(|s| s.to_string()).collect(),
            signal_set,
            gen_ratio: 0.0, // pure havoc — XXE payloads are structured XML
            ..Default::default()
        }
    }

    /// Pure table sweep — no generation, no havoc. Just fire every seed once.
    /// Fast, deterministic, maximum precision, zero evolution.
    fn table_sweep() -> Self {
        Self {
            gen_ratio: 0.0,                         // no generation
            stop_on_confirmation: false,             // fire all seeds
            ..Default::default()
        }
    }
}

// ── Fuzzer builder ───────────────────────────────────────────────────────

/// High-level fuzzer interface for AI agents.
///
/// ```ignore
/// let result = Fuzzer::new(my_probe)
///     .sql_injection()
///     .target("https://example.com/search?q=", "GET")
///     .budget(100)
///     .run()
///     .await
///     .unwrap();
/// // result.confirmed: Vec<Hit> — all confirmed SQLi payloads
/// ```
pub struct Fuzzer<P: Probe> {
    probe: P,
    preset: Preset,
    target_url: String,
    method: String,
    budget: usize,
    replay_seed: Option<u64>,
    request_timeout: Duration,
    additional_seeds: Vec<String>,
}

impl<P: Probe> Fuzzer<P> {
    pub fn new(probe: P) -> Self {
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

    // ── Vulnerability class presets ──────────────────────────────────

    /// SQL injection: error-based, UNION, boolean, time-based.
    /// 68 table entries + chain-weighted grammar, error + status + time classifiers.
    pub fn sql_injection(mut self) -> Self {
        self.preset = Preset::sql_injection();
        self
    }

    /// Cross-site scripting: reflected, stored, DOM contexts.
    /// 26 table entries, reflection + status + body-diff classifiers.
    pub fn xss(mut self) -> Self {
        self.preset = Preset::xss();
        self
    }

    /// Server-side template injection: Jinja2, Thymeleaf, ERB, FreeMarker.
    /// 20 table entries, reflection + size + error classifiers.
    pub fn ssti(mut self) -> Self {
        self.preset = Preset::ssti();
        self
    }

    /// Command injection: pipe, semicolon, backtick, subshell.
    /// 24 table entries, time-delay + status + size classifiers.
    pub fn command_injection(mut self) -> Self {
        self.preset = Preset::command_injection();
        self
    }

    /// Path traversal / LFI: dot-dot-slash, encoding variants.
    /// 16 table entries, status + size + reflection classifiers.
    pub fn path_traversal(mut self) -> Self {
        self.preset = Preset::path_traversal();
        self
    }

    /// NoSQL injection: MongoDB $gt/$ne/$regex, boolean extract.
    /// 12 table entries, error + time + status classifiers.
    pub fn nosql_injection(mut self) -> Self {
        self.preset = Preset::nosql_injection();
        self
    }

    /// Server-side request forgery: cloud metadata, localhost, gopher, dict.
    /// 9 table entries, status + size + time classifiers. Pure havoc (no grammar).
    pub fn ssrf(mut self) -> Self {
        self.preset = Preset::ssrf();
        self
    }

    /// XML external entity: file read, OOB.
    /// 3 table entries, status + size + reflection classifiers. Pure havoc.
    pub fn xxe(mut self) -> Self {
        self.preset = Preset::xxe();
        self
    }

    /// Pure table sweep — fire each seed once, no evolution.
    /// Fast and deterministic. Combine with `.seeds(...)` or a vulnerability
    /// preset above to define the table.
    pub fn table_sweep(mut self) -> Self {
        self.preset = Preset::table_sweep();
        self
    }

    // ── Configuration ─────────────────────────────────────────────────

    /// Target URL. For GET, payloads are appended as `?q=<payload>`.
    /// For POST, payloads are sent as the request body.
    pub fn target(mut self, url: &str, method: &str) -> Self {
        self.target_url = url.to_string();
        self.method = method.to_uppercase();
        self
    }

    /// Maximum number of probes to send. Default 50.
    pub fn budget(mut self, probes: usize) -> Self {
        self.budget = probes.max(1);
        self
    }

    /// Additional seeds beyond the preset table. Use for target-specific
    /// reconnaissance data (discovered parameter names, auth tokens, etc.).
    pub fn seeds<I, S>(mut self, seeds: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.additional_seeds = seeds.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Deterministic replay seed. Same seed + same target = same results.
    pub fn replay_seed(mut self, seed: u64) -> Self {
        self.replay_seed = Some(seed);
        self
    }

    /// Per-request timeout. Default 30 seconds.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    /// Override gen_ratio. 0.0 = pure havoc, 1.0 = pure generation.
    /// The preset chooses a sensible default for each vuln class.
    pub fn gen_ratio(mut self, ratio: f32) -> Self {
        self.preset.gen_ratio = ratio.clamp(0.0, 1.0);
        self
    }

    /// Stop after the first confirmed hit instead of exhausting the budget.
    pub fn stop_on_first_hit(mut self) -> Self {
        self.preset.stop_on_confirmation = true;
        self
    }

    // ── Run ───────────────────────────────────────────────────────────

    pub async fn run(self) -> Result<FuzzResult, String> {
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
            self.probe,
            corpus,
            sampler,
            havoc,
            self.preset.feedback,
        )
        .with_gen_ratio(self.preset.gen_ratio)
        .with_max_probes(self.budget)
        .with_signal_set(self.preset.signal_set)
        .with_request_timeout(self.request_timeout);

        if self.preset.stop_on_confirmation {
            loop_ = loop_.stop_on_first_hit();
        }
        if let Some(s) = self.replay_seed {
            loop_ = loop_.with_seed(s);
        }

        let method = self.method.clone();
        let url = self.target_url.clone();
        let inject = move |payload: &str| -> Request {
            if method == "POST" {
                Request {
                    url: url.clone(),
                    method: method.clone(),
                    headers: HashMap::new(),
                    body: payload.to_string(),
                }
            } else {
                Request {
                    url: format!("{}?q={}", url, payload),
                    method: method.clone(),
                    headers: HashMap::new(),
                    body: String::new(),
                }
            }
        };

        let baseline = Request {
            url: self.target_url,
            method: self.method,
            headers: HashMap::new(),
            body: String::new(),
        };

        let outcome = loop_.run(&baseline, inject).await?;

        let to_hit = |h: &EvolutionaryHit| Hit {
            payload: h.payload.clone(),
            score: h.score,
            confirmed: h.confirmed,
            signals: h.signals.iter().map(|s| s.kind().to_string()).collect(),
        };

        Ok(FuzzResult {
            confirmed: outcome.hits.iter().map(to_hit).collect(),
            interesting: outcome.interesting.iter().map(to_hit).collect(),
            probes_sent: outcome.probes_sent,
            corpus_size: outcome.final_corpus_size,
        })
    }
}
