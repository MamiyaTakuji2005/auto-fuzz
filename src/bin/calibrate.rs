//! Calibration harness — config-driven mock targets, sweep across parameters.
//!
//! Run with:
//!     cargo run --bin calibrate --release
//!     cargo run --bin calibrate --release -- targets.toml
//!
//! Reads mock target definitions from a TOML file (defaults to targets.toml).
//! Each target defines trigger conditions and simulated responses.
//! Optionally override the atom vocabulary via a top-level `atoms` key.
//! No more hardcoded structs — add a new target by editing the TOML.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use auto_fuzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler,
    Feedback, FeedbackEval, EvaluationContext, BoostMode,
};
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::evolutionary::havoc::HavocSchedule;

use auto_fuzz::mock_config::{load_config, ConfigProbe, MockTarget};
use auto_fuzz::signals::signal::{
    BodySignatureClassifier, ErrorClassifier, ReflectionClassifier, StatusClassifier,
    TimeDelayClassifier, Signal, ReflectionEncoding,
};
use auto_fuzz::signals::{Request, SignalSet};

const DEFAULT_MAX_PROBES: usize = 300;
const DEFAULT_TRIALS: u32 = 20;
const BASE_SEED: u64 = 42;

// ── Havoc schedule presets ───────────────────────────────────────────────

fn structural_schedule() -> HavocSchedule {
    HavocSchedule {
        insert_token: 6.0, replace_token: 5.0, delete_chunk: 0.5,
        duplicate_chunk: 1.0, splice_suffix: 5.0, url_encode: 1.0,
        double_url_encode: 0.5, insert_boundary_value: 0.5,
        repeat_payload: 0.2, wrap_delimiter: 1.0, reverse: 0.1, uppercase: 0.1,
    }
}

fn destructive_schedule() -> HavocSchedule {
    HavocSchedule {
        insert_token: 1.0, replace_token: 1.0, delete_chunk: 4.0,
        duplicate_chunk: 3.0, splice_suffix: 1.0, url_encode: 0.5,
        double_url_encode: 0.5, insert_boundary_value: 0.5,
        repeat_payload: 4.0, wrap_delimiter: 2.0, reverse: 3.0, uppercase: 3.0,
    }
}

fn encoding_schedule() -> HavocSchedule {
    HavocSchedule {
        insert_token: 2.0, replace_token: 2.0, delete_chunk: 0.5,
        duplicate_chunk: 0.5, splice_suffix: 2.0, url_encode: 6.0,
        double_url_encode: 5.0, insert_boundary_value: 0.5,
        repeat_payload: 0.3, wrap_delimiter: 1.0, reverse: 0.2, uppercase: 0.2,
    }
}

// ── Configurable feedback (scoring table sweep) ───────────────────────────

/// Pluggable score table for testing alternative fitness functions.
#[derive(Clone, Copy)]
struct ScoreTable {
    error: u8,
    timedelay: u8,
    reflected: u8,
    status_high: u8,   // StatusDelta >= 500
    status_low: u8,    // StatusDelta < 500
    size_high: u8,     // SizeDelta >= 3x or <= 0.33x
    size_low: u8,
    bodydiff: u8,
    min_corpus_score: u8,
}

/// Which scoring preset to use.
#[derive(Clone, Copy, PartialEq)]
enum FeedbackPreset {
    Default,         // Matches HttpFeedback::default()
    Flat3,           // All signals score 3 — ranking irrelevant
    Flat6,           // All signals score 6 — max energy, no ranking
    Compressed,      // Scores 1-3 — smaller energy boosts
    Expanded,        // Scores doubled — larger energy boosts
    StatusOverError, // Swap error and status_high
    BodyDiffHigh,    // BodyDiff boosted from 2 to 5
    Strict,          // min_corpus_score=4 — only strong signals enter corpus
}

fn score_table(preset: FeedbackPreset) -> ScoreTable {
    match preset {
        FeedbackPreset::Default => ScoreTable {
            error: 6, timedelay: 5, reflected: 4,
            status_high: 4, status_low: 3,
            size_high: 3, size_low: 2,
            bodydiff: 2, min_corpus_score: 2,
        },
        FeedbackPreset::Flat3 => ScoreTable {
            error: 3, timedelay: 3, reflected: 3,
            status_high: 3, status_low: 3,
            size_high: 3, size_low: 3,
            bodydiff: 3, min_corpus_score: 2,
        },
        FeedbackPreset::Flat6 => ScoreTable {
            error: 6, timedelay: 6, reflected: 6,
            status_high: 6, status_low: 6,
            size_high: 6, size_low: 6,
            bodydiff: 6, min_corpus_score: 2,
        },
        FeedbackPreset::Compressed => ScoreTable {
            error: 3, timedelay: 3, reflected: 2,
            status_high: 2, status_low: 2,
            size_high: 2, size_low: 1,
            bodydiff: 1, min_corpus_score: 1,
        },
        FeedbackPreset::Expanded => ScoreTable {
            error: 12, timedelay: 10, reflected: 8,
            status_high: 8, status_low: 6,
            size_high: 6, size_low: 4,
            bodydiff: 4, min_corpus_score: 4,
        },
        FeedbackPreset::StatusOverError => ScoreTable {
            error: 4, timedelay: 5, reflected: 4,
            status_high: 6, status_low: 3,
            size_high: 3, size_low: 2,
            bodydiff: 2, min_corpus_score: 2,
        },
        FeedbackPreset::BodyDiffHigh => ScoreTable {
            error: 6, timedelay: 5, reflected: 4,
            status_high: 4, status_low: 3,
            size_high: 3, size_low: 2,
            bodydiff: 5, min_corpus_score: 2,
        },
        FeedbackPreset::Strict => ScoreTable {
            error: 6, timedelay: 5, reflected: 4,
            status_high: 4, status_low: 3,
            size_high: 3, size_low: 2,
            bodydiff: 2, min_corpus_score: 4,
        },
    }
}

struct ConfigurableFeedback {
    scores: ScoreTable,
}

impl Feedback for ConfigurableFeedback {
    fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FeedbackEval {
        let mut best = Signal::NoEffect;
        let mut best_rank: u8 = 0;
        let mut confirmed = false;

        for s in ctx.filtered_signals {
            let rank = match s {
                Signal::Error { .. } => { confirmed = true; self.scores.error }
                Signal::LeakSignature { .. } => { confirmed = true; 5 }
                Signal::TimeDelay { .. } => { confirmed = true; self.scores.timedelay }
                Signal::Reflected { encoding } => {
                    if matches!(encoding, ReflectionEncoding::Literal) { confirmed = true; }
                    self.scores.reflected
                }
                Signal::StatusDelta { to, .. } => {
                    if *to >= 500 { confirmed = true; self.scores.status_high }
                    else { self.scores.status_low }
                }
                Signal::SizeDelta { ratio, .. } => {
                    if *ratio >= 3.0 || *ratio <= 0.33 { self.scores.size_high }
                    else { self.scores.size_low }
                }
                Signal::BodyDiff => self.scores.bodydiff,
                Signal::Anomaly { .. } => 2,
                Signal::PrototypePollution { .. } => 5,
                Signal::NoEffect => 0,
            };
            if rank > best_rank {
                best_rank = rank;
                best = s.clone();
            }
        }

        let interesting = best_rank >= self.scores.min_corpus_score;
        FeedbackEval { score: best_rank, interesting, confirmed, best_signal: best }
    }
}

fn build_feedback(preset: FeedbackPreset) -> Box<dyn Feedback> {
    Box::new(ConfigurableFeedback { scores: score_table(preset) })
}

// ── Enriched vocabularies for ChainTable gap testing ───────────────────────

/// Default atoms as a Vec<String> (helper for the vocab sweep).
fn xss_default_vocab() -> Vec<String> {
    ATOMS.iter().map(|s| s.to_string()).collect()
}

/// XSS-enriched atom table: adds the building blocks for real XSS vectors.
/// Default ATOMS can't assemble <script> or <img src=x onerror=...> because
/// the words "script", "img", "svg" don't exist as atoms.
fn xss_enriched_atoms() -> Vec<String> {
    let mut a: Vec<String> = ATOMS.iter().map(|s| s.to_string()).collect();
    // HTML tag names
    a.extend_from_slice(&[
        "script".into(), "/script".into(), "img".into(), "svg".into(),
        "iframe".into(), "body".into(), "svg onload".into(),
        // Attribute fragments
        " src=".into(), "alert(1)".into(),
    ]);
    a
}

/// XSS-enriched chain table: strong chains that assemble XSS vectors.
fn xss_enriched_chain() -> ChainTable {
    let mut t = ChainTable::defaults();
    // <script> assembly
    t.set("<",       "script",     20.0)
     .set("script",  ">",         20.0)
     .set("script",  " alert(1)", 10.0)
     .set("/script", ">",         20.0)
     // <img src=... onerror=...> assembly
     .set("<",       "img",        15.0)
     .set("img",     " src=",      20.0)
     .set(" src=",   "x",          10.0)
     .set("x",       " ",           5.0)
     .set(" ",       "onerror=",   10.0)
     // <svg onload=...> assembly
     .set("<",       "svg onload", 15.0)
     .set("svg onload", "=",       10.0)
     .set("=",       "alert(1)",    5.0)
     // closing tags
     .set("alert(1)", ">",          5.0)
     .set("alert(1)", "</",         3.0)
     .set("<",       "/script",    10.0)
     .set("/script", "script",      5.0);
    t
}

/// SSTI-enriched: adds expression atoms for template injection.
fn ssti_enriched_atoms() -> Vec<String> {
    let mut a: Vec<String> = ATOMS.iter().map(|s| s.to_string()).collect();
    a.extend_from_slice(&[
        "{{7*'7'}}".into(), "{{config}}".into(), "${7*7}".into(),
        "{{self}}".into(), "{{''.__class__}}".into(),
    ]);
    a
}

fn ssti_enriched_chain() -> ChainTable {
    let mut t = ChainTable::defaults();
    t.set("{{", "7*7", 20.0)
     .set("{{", "config", 10.0)
     .set("{{", "self", 8.0)
     .set("{{", "7*'7'}}", 15.0)
     .set("7*7", "}}", 20.0)
     .set("7*'7'}}", "", 20.0);
    t
}

/// SQLi-enriched: adds missing chains for the most common SQLi patterns.
fn sqli_enriched_chain() -> ChainTable {
    let mut t = ChainTable::defaults();
    // Missing: OR -> 1=1, the most classic boolean SQLi
    t.set(" OR ",    "1=1",        15.0)
     .set(" OR ",    "'1'='1",     10.0)
     .set("1=1",     "--",         10.0)
     .set("1=1",     "#",           5.0)
     // Missing: SELECT -> NULL (UNION continuation)
     .set(" SELECT ", "NULL",      10.0)
     .set("NULL",    ",",            5.0)
     .set(",",       "NULL",         8.0)
     // Missing: ' -> OR chain (currently only ' -> OR at 5.0, but no OR -> 1=1)
     .set(" AND ",   "1=1",         8.0)
     .set(" AND ",   "1=2",         8.0);
    t
}

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CalibConfig {
    label: String,
    sweep_axis: &'static str,
    gen_ratio: f32,
    length_policy: LengthPolicy,
    placement_policy: PlacementPolicy,
    havoc_ops: usize,
    havoc_schedule: Option<HavocSchedule>,
    feedback_preset: FeedbackPreset,
    /// Override min_corpus_score on the feedback, regardless of preset.
    min_score_override: Option<u8>,
    /// Override atoms + chain table for vocab enrichment experiments.
    vocab_override: Option<(Vec<String>, ChainTable)>,
    boost_mode: Option<BoostMode>,
    max_energy: Option<u8>,
    max_probes: usize,
}

impl CalibConfig {
    fn new(axis: &'static str, label: &str, gen_ratio: f32,
           length: LengthPolicy, placement: PlacementPolicy,
           schedule: Option<HavocSchedule>) -> Self {
        Self {
            label: label.to_string(), sweep_axis: axis,
            gen_ratio, length_policy: length, placement_policy: placement,
            havoc_ops: 4, havoc_schedule: schedule,
            feedback_preset: FeedbackPreset::Default,
            min_score_override: None,
            vocab_override: None,
            boost_mode: None,
            max_energy: None,
            max_probes: DEFAULT_MAX_PROBES,
        }
    }

    /// Override havoc_ops_per_step for the ops sweep.
    fn with_ops(mut self, n: usize) -> Self {
        self.havoc_ops = n;
        self
    }

    /// Override the feedback scoring table for the feedback sweep.
    fn with_feedback(mut self, preset: FeedbackPreset) -> Self {
        self.feedback_preset = preset;
        self
    }

    /// Override min_corpus_score in isolation.
    fn with_min_score(mut self, score: u8) -> Self {
        self.min_score_override = Some(score);
        self
    }

    /// Override the atom vocabulary + chain table.
    /// Override the boost mode.
    fn with_boost(mut self, mode: BoostMode) -> Self {
        self.boost_mode = Some(mode);
        self
    }

    fn with_vocab(mut self, atoms: Vec<String>, chain: ChainTable) -> Self {
        self.vocab_override = Some((atoms, chain));
        self
    }

    /// Override the energy cap for the cap sweep.
    fn with_max_energy(mut self, cap: u8) -> Self {
        self.max_energy = Some(cap);
        self
    }
}

// ── Metrics ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct RunMetrics {
    time_to_first_hit_ms: u64,
    hits: usize,
    probes_sent: usize,
    final_corpus_size: usize,
    hits_per_1000: f64,
}

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    config: &CalibConfig,
    trial: u32,
) -> RunMetrics {
    let start = Instant::now();

    let mut corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()]);
    if let Some(mode) = config.boost_mode { corpus = corpus.with_boost_mode(mode); }
    if let Some(cap) = config.max_energy { corpus = corpus.with_max_energy(cap); }

    // Use vocab override if provided, otherwise the shared atom table + defaults.
    let (eff_atoms, eff_chain) = match &config.vocab_override {
        Some((a, c)) => (a.clone(), c.clone()),
        None => (atoms.to_vec(), ChainTable::defaults()),
    };

    let sampler = WeightedSampler::new(
        eff_atoms,
        eff_chain,
        config.placement_policy.clone(),
        config.length_policy.clone(),
    );

    let mut havoc = HavocMutator::new(sampler.clone(), config.max_probes * 4)
        .with_ops_per_step(config.havoc_ops);
    if let Some(ref sched) = config.havoc_schedule {
        havoc = havoc.with_schedule(sched.clone());
    }

    let mut signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));
    // Per-class confirmation: targets that leak identifiable content (path
    // traversal, SSRF) declare `confirm_signatures` so a match confirms a hit.
    // Gated so it never touches targets that don't need it.
    if !probe.target.response.confirm_signatures.is_empty() {
        signal_set = signal_set.with(Box::new(BodySignatureClassifier::from_needles(
            &probe.target.response.confirm_signatures,
        )));
    }

    let mut feedback = build_feedback(config.feedback_preset);
    if let Some(min_score) = config.min_score_override {
        // Replace with a copy that has the overridden min_corpus_score.
        let mut scores = score_table(config.feedback_preset);
        scores.min_corpus_score = min_score;
        feedback = Box::new(ConfigurableFeedback { scores });
    }

    let loop_ = EvolutionaryLoop::new(
        probe.clone(), corpus, sampler, havoc,
        feedback,
    )
    .with_gen_ratio(config.gen_ratio)
    .with_max_probes(config.max_probes)
    .with_seed(BASE_SEED + trial as u64)
    .with_signal_set(signal_set);

    let baseline_req = Request {
        url: probe.target.baseline_url.clone(),
        method: probe.target.baseline_method.clone(),
        headers: HashMap::new(),
        body: String::new(),
    };
    let inject = |p: &str| Request {
        url: format!("{}?q={}", probe.target.baseline_url.split('?').next().unwrap_or(&probe.target.baseline_url), p),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };

    let outcome = match loop_.run(&baseline_req, inject).await {
        Ok(o) => o,
        Err(_) => return RunMetrics {
            time_to_first_hit_ms: 999_999, hits: 0,
            probes_sent: 0, final_corpus_size: 0, hits_per_1000: 0.0,
        },
    };

    let elapsed = start.elapsed();
    let hits = outcome.hits.len();
    let probes = outcome.probes_sent;

    RunMetrics {
        time_to_first_hit_ms: elapsed.as_millis() as u64,
        hits,
        probes_sent: probes,
        final_corpus_size: outcome.final_corpus_size,
        hits_per_1000: if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 },
    }
}

// ── Batch runner — sweeps one target through all 4 phases ─────────────────

async fn batch_target(
    target: MockTarget,
    atoms: &[String],
    trials: u32,
) -> Vec<(String, String, String, u32, RunMetrics)> {
    let name = target.name.clone();
    let probe = Arc::new(ConfigProbe::new(target));
    let mut rows = Vec::new();

    // ── Phase 1: gen_ratio sweep ────────────────────────────────────────
    println!("  {} gen_ratio [0.0 .. 1.0]", name);
    let gr: &[f32] = &[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
    for &g in gr {
        let cfg = CalibConfig::new("gen_ratio", &format!("gen={:.1}", g),
                                    g, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", gr.len() * trials as usize);

    // ── Phase 2: LengthPolicy sweep at best gen_ratio ───────────────────
    let best_gr = 0.7;
    println!("  {} length [short, medium, long] @ gen={:.1}", name, best_gr);
    for (tag, lp) in &[("short", LengthPolicy::short()), ("medium", LengthPolicy::medium()), ("long", LengthPolicy::long())] {
        let cfg = CalibConfig::new("length", &format!("len={}", tag),
                                    best_gr, lp.clone(),
                                    PlacementPolicy::default(), None);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" 15");

    // ── Phase 3: Havoc schedule sweep at best (gen_ratio, length) ──────
    println!("  {} havoc [default, structural, destructive, encoding] @ gen={:.1} medium", name, best_gr);
    for (tag, sched) in &[
        ("default", None),
        ("structural", Some(structural_schedule())),
        ("destructive", Some(destructive_schedule())),
        ("encoding", Some(encoding_schedule())),
    ] {
        let cfg = CalibConfig::new("havoc", &format!("havoc={}", tag),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), sched.clone());
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" 20");

    // ── Phase 4: PlacementPolicy grid sweep at best gen_ratio ────────
    // Sweep (append_weight × prepend_weight) with wrap=0, plus wrap combos.
    println!("  {} placement [5×5 grid + 3 wrap] @ gen={:.1} medium", name, best_gr);
    let append_weights: &[f32] = &[0.0, 0.5, 1.0, 2.0, 4.0];
    let prepend_weights: &[f32] = &[0.0, 0.5, 1.0, 2.0, 4.0];
    let wrap_weights: f32 = 0.0;
    for &a in append_weights {
        for &p in prepend_weights {
            if a == 0.0 && p == 0.0 { continue; }  // degenerate
            let pl = PlacementPolicy::new(a, p, wrap_weights);
            let label = format!("place=a{:.1}_p{:.1}", a, p);
            let cfg = CalibConfig::new("placement", &label,
                                        best_gr, LengthPolicy::medium(),
                                        pl, None);
            for trial in 0..trials {
                let m = run_one(probe.clone(), atoms, &cfg, trial).await;
                rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
                print!(".");
            }
        }
    }
    // + wrap combos
    for (tag, pl) in &[
        ("default", PlacementPolicy::default()),
        ("wrap",    PlacementPolicy::wrap_only()),
        ("wrap+b",  PlacementPolicy::new(1.0, 0.0, 1.0)),
    ] {
        let cfg = CalibConfig::new("placement", &format!("place={}", tag),
                                    best_gr, LengthPolicy::medium(),
                                    pl.clone(), None);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    let total = (24 + 3) * trials as usize;
    println!(" {}", total);

    // ── Phase 5: ops_per_step sweep ────────────────────────────────────
    // How many havoc operators to chain per mutation. Default is 4.
    // Low values = conservative mutations near the seed. High values = aggressive
    // divergence, more no-ops, but potentially novel shapes.
    println!("  {} ops_per_step [1, 2, 4, 8, 16] @ gen={:.1} medium", name, best_gr);
    for &n in &[1usize, 2, 4, 8, 16] {
        let cfg = CalibConfig::new("ops", &format!("ops={}", n),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_ops(n);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 5 * trials as usize);

    // ── Phase 6: Feedback scoring table sweep ──────────────────────────
    // The fitness function maps signals to energy scores (0-12). This controls
    // corpus evolution: which payloads get energy, how fast parents climb.
    // Default is HttpFeedback's hardcoded table. Here we test alternatives.
    println!("  {} feedback [default, flat3, flat6, compressed, expanded, status>error, bodydiff+, strict] @ gen={:.1} medium", name, best_gr);
    for (tag, preset) in &[
        ("default",      FeedbackPreset::Default),
        ("flat3",        FeedbackPreset::Flat3),
        ("flat6",        FeedbackPreset::Flat6),
        ("compressed",   FeedbackPreset::Compressed),
        ("expanded",     FeedbackPreset::Expanded),
        ("status>error", FeedbackPreset::StatusOverError),
        ("bodydiff+",    FeedbackPreset::BodyDiffHigh),
        ("strict",       FeedbackPreset::Strict),
    ] {
        let cfg = CalibConfig::new("feedback", &format!("fb={}", tag),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_feedback(*preset);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 8 * trials as usize);

    // ── Phase 7: min_corpus_score sweep ───────────────────────────────
    // Controls which payloads enter the corpus. Default is 2 (any SizeDelta or
    // BodyDiff). Higher = stricter (only confirmed-worthy signals). Lower =
    // permissive (everything enters, corpus grows faster but noisier).
    println!("  {} min_corpus_score [1..6] @ gen={:.1} medium", name, best_gr);
    for &score in &[1u8, 2, 3, 4, 5, 6] {
        let cfg = CalibConfig::new("min_score", &format!("minscore={}", score),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_min_score(score);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 6 * trials as usize);

    // ── Phase 8: LengthPolicy stop_prob sweep ─────────────────────────
    // stop_prob controls the geometric distribution tail. Current presets:
    //   short=0.50, medium=0.25, long=0.10
    // Sweep stop_prob in isolation at min=1 and min=2 to see the shape.
    println!("  {} stop_prob [0.1, 0.25, 0.5, 0.75, 0.9] min=1 @ gen={:.1}", name, best_gr);
    for &sp in &[0.1f32, 0.25, 0.5, 0.75, 0.9] {
        let lp = LengthPolicy::new(1, 32, sp);
        let cfg = CalibConfig::new("stop_prob", &format!("stop={:.2}_min1", sp),
                                    best_gr, lp,
                                    PlacementPolicy::default(), None);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    // Also sweep min_atoms: does starting from 1 vs 2 matter?
    println!("  {} min_atoms [1, 2, 3, 4] @ stop=0.25 gen={:.1}", name, best_gr);
    for &mn in &[1usize, 2, 3, 4] {
        let lp = LengthPolicy::new(mn, 32, 0.25);
        let cfg = CalibConfig::new("min_atoms", &format!("min={}", mn),
                                    best_gr, lp,
                                    PlacementPolicy::default(), None);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", (5 + 4) * trials as usize);

    // ── Phase 9: Vocabulary enrichment sweep ───────────────────────────
    // Test whether adding missing atoms + chains fixes the targets that
    // generation can't currently reach. Default atoms can't assemble <script>
    // or <img src=x onerror=...>. Here we test enriched vocabularies.
    println!("  {} vocab [default, xss+, sqli+, ssti+] @ gen=1.0 medium", name);
    let gen_gr = 1.0;  // pure generation — isolates the chain table effect
    for (tag, atoms_fn, chain_fn) in &[
        ("default", xss_default_vocab as fn() -> Vec<String>, ChainTable::defaults as fn() -> ChainTable),
        ("xss+",    xss_enriched_atoms,                  xss_enriched_chain),
        ("sqli+",   xss_default_vocab,                   sqli_enriched_chain),
        ("ssti+",   ssti_enriched_atoms,                 ssti_enriched_chain),
    ] {
        let cfg = CalibConfig::new("vocab", &format!("vocab={}", tag),
                                    gen_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_vocab(atoms_fn(), chain_fn());
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 4 * trials as usize);

    // ── Phase 10: BoostMode sweep ───────────────────────────────────────
    // How parent energy grows when children find something.
    // Additive (current) vs flat vs multiplicative vs none.
    println!("  {} boost [none, additive, flat, multiplicative] @ gen={:.1} medium", name, best_gr);
    for (tag, mode) in [
        ("none",  BoostMode::None),
        ("add",   BoostMode::Additive),
        ("flat",  BoostMode::Flat),
        ("mult",  BoostMode::Multiplicative),
    ] {
        let cfg = CalibConfig::new("boost", &format!("boost={}", tag),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_boost(mode);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 4 * trials as usize);

    // ── Phase 11: Energy cap sweep ──────────────────────────────────────
    // The energy cap limits how many times a parent can be boosted.
    // Default is 64. Test whether a higher or lower cap changes behavior.
    // Uses additive boost (current default) to isolate the cap effect.
    println!("  {} max_energy [8, 16, 32, 64, 128, 255] @ boost=add gen={:.1} medium", name, best_gr);
    for &cap in &[8u8, 16, 32, 64, 128, 255] {
        let cfg = CalibConfig::new("cap", &format!("cap={}", cap),
                                    best_gr, LengthPolicy::medium(),
                                    PlacementPolicy::default(), None)
                    .with_boost(BoostMode::Additive)
                    .with_max_energy(cap);
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", 6 * trials as usize);

    rows
}

// ── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let config_path = args.get(1)
        .map(|s| PathBuf::from(s))
        .unwrap_or_else(|| PathBuf::from("targets.toml"));

    let config = match load_config(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error loading config: {}", e);
            eprintln!("Usage: cargo run --bin calibrate -- [targets.toml]");
            std::process::exit(1);
        }
    };

    let targets = config.targets;
    if targets.is_empty() {
        eprintln!("No targets defined in {}", config_path.display());
        std::process::exit(1);
    }

    // Atom vocabulary: config override or built-in ATOMS
    let atoms: Vec<String> = match config.atoms {
        Some(custom) => {
            println!("Using custom atom vocabulary ({} atoms)", custom.len());
            custom
        }
        None => {
            let a: Vec<String> = ATOMS.iter().map(|s| s.to_string()).collect();
            println!("Using built-in ATOMS vocabulary ({} atoms)", a.len());
            a
        }
    };

    println!("\nauto-fuzz Calibration Harness");
    println!("=============================");
    println!("Config: {}", config_path.display());
    println!("Targets: {}\n", targets.len());

    let mut results: Vec<(String, String, String, u32, RunMetrics)> = Vec::new();

    for target in &targets {
        println!("Target: {} (trigger: \"{}\")", target.name, target.trigger_payload);
        let batch = batch_target(target.clone(), &atoms, DEFAULT_TRIALS).await;
        results.extend(batch);
        println!();
    }

    // ── Write CSV ──────────────────────────────────────────────────────────
    let csv_path = config_path.with_extension("").with_file_name("calibration_results.csv");
    let mut f = File::create(&csv_path).unwrap();
    writeln!(f, "vuln_class,sweep_axis,config,trial,time_to_first_hit_ms,hits,probes_sent,final_corpus,hits_per_1000")
        .unwrap();

    for (cls, label, axis, trial, m) in &results {
        writeln!(f, "{},{},{},{},{},{},{},{},{:.2}",
            cls, axis, label, trial,
            m.time_to_first_hit_ms, m.hits,
            m.probes_sent, m.final_corpus_size, m.hits_per_1000).unwrap();
    }

    let total = results.len();
    println!("Done — {} data points written to {}", total, csv_path.display());

    // ── Quick per-axis summary ─────────────────────────────────────────────
    for axis in &["gen_ratio", "length", "havoc", "placement", "ops", "feedback", "min_score", "stop_prob", "min_atoms", "vocab", "boost", "cap"] {
        println!("\n--- {} sweep ---", axis);
        let mut grouped: HashMap<String, Vec<f64>> = HashMap::new();
        for (cls, label, ax, _trial, m) in &results {
            if ax.as_str() == *axis {
                grouped.entry(format!("{}/{}", cls, label)).or_default().push(m.hits_per_1000);
            }
        }
        let mut sorted: Vec<_> = grouped.into_iter().collect();
        sorted.sort_by_key(|(k, _)| k.clone());
        for (key, vals) in sorted {
            let avg = vals.iter().sum::<f64>() / vals.len() as f64;
            println!("  {:40} {:7.1} hits/1k", key, avg);
        }
    }
}
