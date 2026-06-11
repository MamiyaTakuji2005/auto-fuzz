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
use url::Url;

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

// ── Injection point ────────────────────────────────────────────────────

/// Where the payload is injected into the request.
#[derive(Debug, Clone)]
pub enum InjectionPoint {
    /// URL-encoded into a query parameter. Produces `?name=<encoded>`.
    /// Default for GET.
    QueryParam(String),
    /// Body injection with optional template and Content-Type.
    /// `template` is a string with `{{payload}}` as placeholder.
    /// `None` = raw body (backward compatible).
    BodyRaw {
        template: Option<String>,
        content_type: Option<String>,
    },
    /// Injects into a header value (for Host, User-Agent, Cookie, etc.).
    Header(String),
    /// Appends to the URL path: `/existing/path/<payload>`.
    PathSegment,
}

impl InjectionPoint {
    /// Raw body, no template, no Content-Type.
    pub fn body_raw() -> Self {
        InjectionPoint::BodyRaw { template: None, content_type: None }
    }

    /// Form-encoded body: `key=value&param={{payload}}`.
    pub fn body_form(template: &str) -> Self {
        InjectionPoint::BodyRaw {
            template: Some(template.into()),
            content_type: Some("application/x-www-form-urlencoded".into()),
        }
    }

    /// JSON body: `{"key": "{{payload}}"}`.
    pub fn body_json(template: &str) -> Self {
        InjectionPoint::BodyRaw {
            template: Some(template.into()),
            content_type: Some("application/json".into()),
        }
    }

    /// XML body: `<key>{{payload}}</key>`.
    pub fn body_xml(template: &str) -> Self {
        InjectionPoint::BodyRaw {
            template: Some(template.into()),
            content_type: Some("application/xml".into()),
        }
    }

    /// GraphQL body: `{"query": "{ user(id: \"{{payload}}\") { name } }"}`.
    pub fn body_graphql(template: &str) -> Self {
        InjectionPoint::BodyRaw {
            template: Some(template.into()),
            content_type: Some("application/json".into()),
        }
    }

    /// Custom body with explicit Content-Type.
    pub fn body_template(content_type: &str, template: &str) -> Self {
        InjectionPoint::BodyRaw {
            template: Some(template.into()),
            content_type: Some(content_type.into()),
        }
    }
}

impl InjectionPoint {
    /// Apply the injection to a URL+method, producing a full Request.
    fn apply(&self, base_url: &str, method: &str, payload: &str) -> Request {
        match self {
            InjectionPoint::QueryParam(name) => {
                let mut url = Url::parse(base_url).unwrap_or_else(|_| {
                    Url::parse(&format!("http://{}/", base_url)).unwrap()
                });
                url.query_pairs_mut().append_pair(name, payload);
                Request {
                    url: url.to_string(),
                    method: method.to_string(),
                    headers: HashMap::new(),
                    body: String::new(),
                }
            }
            InjectionPoint::BodyRaw { template, content_type } => {
                let body = match template {
                    Some(tpl) => tpl.replace("{{payload}}", payload),
                    None => payload.to_string(),
                };
                let headers = match content_type {
                    Some(ct) => {
                        let mut h = HashMap::new();
                        h.insert("Content-Type".into(), ct.clone());
                        h
                    }
                    None => HashMap::new(),
                };
                Request {
                    url: base_url.to_string(),
                    method: method.to_string(),
                    headers,
                    body,
                }
            }
            InjectionPoint::Header(name) => {
                let mut headers = HashMap::new();
                headers.insert(name.clone(), payload.to_string());
                Request {
                    url: base_url.to_string(),
                    method: method.to_string(),
                    headers,
                    body: String::new(),
                }
            }
            InjectionPoint::PathSegment => {
                let mut url = Url::parse(base_url).unwrap_or_else(|_| {
                    Url::parse(&format!("http://{}/", base_url)).unwrap()
                });
                let path = url.path().trim_end_matches('/').to_string();
                url.set_path(&format!("{}/{}", path, payload));
                Request {
                    url: url.to_string(),
                    method: method.to_string(),
                    headers: HashMap::new(),
                    body: String::new(),
                }
            }
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
    injection: InjectionPoint,
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
            injection: InjectionPoint::QueryParam("q".into()), // default before target() overrides
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
        // Default injection: query param for GET, body for POST
        if self.method == "POST" {
            self.injection = InjectionPoint::body_raw();
        } else {
            self.injection = InjectionPoint::QueryParam("q".into());
        }
        self
    }

    /// Inject payloads into the named query parameter (URL-encoded).
    ///
    /// Produces: `https://target/path?name=<url-encoded payload>`.
    /// Handles existing query params correctly (appends `&name=...`).
    pub fn inject_query(mut self, param: &str) -> Self {
        self.injection = InjectionPoint::QueryParam(param.into());
        self
    }

    /// Inject payloads into a header value.
    pub fn inject_header(mut self, name: &str) -> Self {
        self.injection = InjectionPoint::Header(name.into());
        self
    }

    /// Inject payloads as the raw request body (no Content-Type).
    pub fn inject_body_raw(mut self) -> Self {
        self.injection = InjectionPoint::body_raw();
        self
    }

    /// Inject payloads as a path segment: `/existing/path/<payload>`.
    pub fn inject_path(mut self) -> Self {
        self.injection = InjectionPoint::PathSegment;
        self
    }

    /// Form-encoded POST body. `{{payload}}` is substituted.
    ///
    /// Sets `Content-Type: application/x-www-form-urlencoded`.
    ///
    /// Example: `.body_form("username=admin&password={{payload}}")`
    pub fn body_form(mut self, template: &str) -> Self {
        self.injection = InjectionPoint::body_form(template);
        self
    }

    /// JSON POST body. `{{payload}}` is substituted.
    ///
    /// Sets `Content-Type: application/json`.
    ///
    /// Example: `.body_json(r#"{"search":"{{payload}}"}"#)`
    pub fn body_json(mut self, template: &str) -> Self {
        self.injection = InjectionPoint::body_json(template);
        self
    }

    /// XML POST body. `{{payload}}` is substituted.
    ///
    /// Sets `Content-Type: application/xml`.
    pub fn body_xml(mut self, template: &str) -> Self {
        self.injection = InjectionPoint::body_xml(template);
        self
    }

    /// GraphQL POST body. `{{payload}}` is substituted.
    ///
    /// Sets `Content-Type: application/json`.
    ///
    /// Example: `.body_graphql(r#"{"query":"{user(id:\"{{payload}}\"){name}}"}"#)`
    pub fn body_graphql(mut self, template: &str) -> Self {
        self.injection = InjectionPoint::body_graphql(template);
        self
    }

    /// Custom body with explicit Content-Type. `{{payload}}` is substituted.
    ///
    /// Example: `.body_template("text/plain", "prefix-{{payload}}-suffix")`
    pub fn body_template(mut self, content_type: &str, template: &str) -> Self {
        self.injection = InjectionPoint::body_template(content_type, template);
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

        // ── Build the engine ──────────────────────────────────────────
        let probe = self.probe.clone();

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

        let injection = self.injection.clone();
        let url = self.target_url.clone();
        let method = self.method.clone();
        let inject = move |payload: &str| -> Request {
            injection.apply(&url, &method, payload)
        };

        let baseline_req = Request {
            url: self.target_url.clone(),
            method: self.method.clone(),
            headers: HashMap::new(),
            body: String::new(),
        };

        let outcome = loop_.run(&baseline_req, inject).await?;

        // Baseline filtering happened inside the loop already.
        // The outcome carries pre-filtered signals + ambient + profile.
        let profile = &outcome.baseline_profile;
        let confidence = profile.confidence();

        let to_hit = |h: &EvolutionaryHit| {
            Hit {
                payload: h.payload.clone(),
                raw_score: h.score,
                confidence,
                adjusted_score: h.score as f32 * confidence,
                confirmed: h.confirmed && confidence > 0.3,
                signals: h.signals.iter().map(|s| s.kind().to_string()).collect(),
                suppressed: h.ambient.iter().map(|s| s.kind().to_string()).collect(),
            }
        };

        Ok(FuzzResult {
            confirmed: outcome.hits.iter().map(to_hit).filter(|h| h.confirmed).collect(),
            interesting: outcome.interesting.iter().map(to_hit).collect(),
            probes_sent: outcome.probes_sent,
            corpus_size: outcome.final_corpus_size,
            baseline: profile.summary(),
        })
    }
}
