//! Calibration harness — big-batch sweep across each dimension in isolation,
//! producing per-target response curves that can be graphed.
//!
//! Three phases per vulnerability class:
//!   Phase 1: gen_ratio sweep   [0.0 .. 1.0 in 0.1 steps]  × 5 trials
//!   Phase 2: LengthPolicy sweep [short, medium, long]      × 5 trials
//!   Phase 3: Havoc schedule sweep [4 presets]              × 5 trials
//!
//! Run with:
//!     cargo run --bin calibrate --release
//!     python stuff/plot_calibration.py calibration_results.csv
//!
//! Each row carries a `sweep_axis` column so the plotter can split by dimension.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use auto_fuzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, HttpFeedback, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler,
};
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::evolutionary::havoc::HavocSchedule;

use auto_fuzz::signals::signal::{
    ErrorClassifier, ProbeResponse, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
};
use auto_fuzz::signals::{Probe, Request, SignalSet};

const MAX_PROBES: usize = 300;
const TRIALS: u32 = 5;
const BASE_SEED: u64 = 42;

// ── Mock Targets ───────────────────────────────────────────────────────────

// ── Mock Targets ───────────────────────────────────────────────────────────

struct SqlInjectionTarget;
impl SqlInjectionTarget {
    fn name() -> &'static str { "sqli" }
    fn baseline_req() -> Request {
        Request { url: "http://mock/?q=1".into(), method: "GET".into(),
                  headers: HashMap::new(), body: String::new() }
    }
    fn trigger_payload() -> &'static str { "42'; DROP TABLE users--" }
}
#[async_trait]
impl Probe for SqlInjectionTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let (s, b, d) = if p.contains("42") || p.contains("' OR") {
            (500u16, format!("SQL error near '{}'", p).into_bytes(), 5u64)
        } else { (200u16, b"ok".to_vec(), 5u64) };
        Ok(ProbeResponse { status: s, body: b, duration: Duration::from_millis(d) })
    }
}

struct XssTarget;
impl XssTarget {
    fn name() -> &'static str { "xss" }
    fn baseline_req() -> Request {
        Request { url: "http://mock/?q=1".into(), method: "GET".into(),
                  headers: HashMap::new(), body: String::new() }
    }
    fn trigger_payload() -> &'static str { "<script>alert(1)</script>" }
}
#[async_trait]
impl Probe for XssTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let (s, b, d) = if p.contains("<script>") {
            (200u16, format!("<html>{}</html>", p).into_bytes(), 5u64)
        } else { (200u16, b"ok".to_vec(), 5u64) };
        Ok(ProbeResponse { status: s, body: b, duration: Duration::from_millis(d) })
    }
}

struct CmdiTarget;
impl CmdiTarget {
    fn name() -> &'static str { "cmdi" }
    fn baseline_req() -> Request {
        Request { url: "http://mock/?q=1".into(), method: "GET".into(),
                  headers: HashMap::new(), body: String::new() }
    }
    fn trigger_payload() -> &'static str { "; cat /etc/passwd" }
}
#[async_trait]
impl Probe for CmdiTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let (s, b, d) = if p.contains(';') || p.contains("cat ") {
            (500u16, b"command execution error".to_vec(), 25u64)
        } else { (200u16, b"ok".to_vec(), 5u64) };
        Ok(ProbeResponse { status: s, body: b, duration: Duration::from_millis(d) })
    }
}

struct SstiTarget;
impl SstiTarget {
    fn name() -> &'static str { "ssti" }
    fn baseline_req() -> Request {
        Request { url: "http://mock/?q=1".into(), method: "GET".into(),
                  headers: HashMap::new(), body: String::new() }
    }
    fn trigger_payload() -> &'static str { "{{7*7}}" }
}
#[async_trait]
impl Probe for SstiTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let (s, b, d) = if p.contains("{{") || p.contains("7*7") {
            (200u16, format!("<html>result: {}</html>", p).into_bytes(), 5u64)
        } else { (200u16, b"ok".to_vec(), 5u64) };
        Ok(ProbeResponse { status: s, body: b, duration: Duration::from_millis(d) })
    }
}

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

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CalibConfig {
    /// Human label for this config row (e.g. "gen=0.7").
    label: String,
    /// Which sweep dimension this row belongs to ("gen_ratio", "length", "havoc").
    sweep_axis: &'static str,
    gen_ratio: f32,
    length_policy: LengthPolicy,
    havoc_ops: usize,
    havoc_schedule: Option<HavocSchedule>,
    max_probes: usize,
}

impl CalibConfig {
    fn new(axis: &'static str, label: &str, gen_ratio: f32,
           length: LengthPolicy, schedule: Option<HavocSchedule>) -> Self {
        Self {
            label: label.to_string(), sweep_axis: axis,
            gen_ratio, length_policy: length,
            havoc_ops: 4, havoc_schedule: schedule, max_probes: MAX_PROBES,
        }
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

async fn run_one<T: Probe + 'static>(
    probe: Arc<T>,
    trigger: &str,
    baseline_req: &Request,
    config: &CalibConfig,
    trial: u32,
) -> RunMetrics {
    let start = Instant::now();

    let corpus = SeedCorpus::from_seeds(vec![trigger.to_string()]);
    let atoms: Vec<String> = ATOMS.iter().map(|s| s.to_string()).collect();
    let sampler = WeightedSampler::new(
        atoms,
        ChainTable::defaults(),
        PlacementPolicy::default(),
        config.length_policy.clone(),
    );

    let mut havoc = HavocMutator::new(sampler.clone(), config.max_probes * 4)
        .with_ops_per_step(config.havoc_ops);
    if let Some(ref sched) = config.havoc_schedule {
        havoc = havoc.with_schedule(sched.clone());
    }

    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));

    let loop_ = EvolutionaryLoop::new(
        probe, corpus, sampler, havoc,
        Box::new(HttpFeedback::default()),
    )
    .with_gen_ratio(config.gen_ratio)
    .with_max_probes(config.max_probes)
    .with_seed(BASE_SEED + trial as u64)
    .with_signal_set(signal_set);

    let baseline_req = baseline_req.clone();
    let inject = |p: &str| Request {
        url: format!("http://mock/?q={}", p),
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

// ── Batch runner — sweeps one target through all 3 phases ─────────────────

async fn batch_target<T: Probe + 'static>(
    probe: Arc<T>,
    name: &str,
    trigger: &str,
    baseline_req: &Request,
) -> Vec<(String, String, String, u32, RunMetrics)> {
    let mut rows = Vec::new();

    // ── Phase 1: gen_ratio sweep ────────────────────────────────────────
    println!("  {} gen_ratio [0.0 .. 1.0]", name);
    let gr: &[f32] = &[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
    for &g in gr {
        let cfg = CalibConfig::new("gen_ratio", &format!("gen={:.1}", g),
                                    g, LengthPolicy::medium(), None);
        for trial in 0..TRIALS {
            let m = run_one(probe.clone(), trigger, baseline_req, &cfg, trial).await;
            rows.push((name.to_string(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" {}", gr.len() * TRIALS as usize);

    // ── Phase 2: LengthPolicy sweep at best gen_ratio ───────────────────
    let best_gr = 0.7; // pre-calibrated; you can compute from Phase 1 data
    println!("  {} length [short, medium, long] @ gen={:.1}", name, best_gr);
    for (tag, lp) in &[("short", LengthPolicy::short()), ("medium", LengthPolicy::medium()), ("long", LengthPolicy::long())] {
        let cfg = CalibConfig::new("length", &format!("len={}", tag),
                                    best_gr, lp.clone(), None);
        for trial in 0..TRIALS {
            let m = run_one(probe.clone(), trigger, baseline_req, &cfg, trial).await;
            rows.push((name.to_string(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
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
                                    best_gr, LengthPolicy::medium(), sched.clone());
        for trial in 0..TRIALS {
            let m = run_one(probe.clone(), trigger, baseline_req, &cfg, trial).await;
            rows.push((name.to_string(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" 20");

    rows
}

// ── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("auto-fuzz Calibration Harness — Big Batch Sweep");
    println!("================================================\n");
    println!("Phases per target: gen_ratio × length × havoc");
    println!("{} probes/run, {} trials/point\n", MAX_PROBES, TRIALS);

    let mut results: Vec<(String, String, String, u32, RunMetrics)> = Vec::new();

    {
        let p = Arc::new(SqlInjectionTarget);
        let bl = SqlInjectionTarget::baseline_req();
        results.extend(
            batch_target(p, SqlInjectionTarget::name(),
                         SqlInjectionTarget::trigger_payload(), &bl).await);
    }
    {
        let p = Arc::new(XssTarget);
        let bl = XssTarget::baseline_req();
        results.extend(
            batch_target(p, XssTarget::name(),
                         XssTarget::trigger_payload(), &bl).await);
    }
    {
        let p = Arc::new(CmdiTarget);
        let bl = CmdiTarget::baseline_req();
        results.extend(
            batch_target(p, CmdiTarget::name(),
                         CmdiTarget::trigger_payload(), &bl).await);
    }
    {
        let p = Arc::new(SstiTarget);
        let bl = SstiTarget::baseline_req();
        results.extend(
            batch_target(p, SstiTarget::name(),
                         SstiTarget::trigger_payload(), &bl).await);
    }

    // ── Write CSV ──────────────────────────────────────────────────────────
    let mut f = File::create("calibration_results.csv").unwrap();
    writeln!(f, "vuln_class,sweep_axis,config,trial,time_to_first_hit_ms,hits,probes_sent,final_corpus,hits_per_1000")
        .unwrap();

    for (cls, label, axis, trial, m) in &results {
        writeln!(f, "{},{},{},{},{},{},{},{},{:.2}",
            cls, axis, label, trial,
            m.time_to_first_hit_ms, m.hits,
            m.probes_sent, m.final_corpus_size, m.hits_per_1000).unwrap();
    }

    let total = results.len();
    println!("\nDone — {} data points written to calibration_results.csv", total);
    println!("Run: python stuff/plot_calibration.py calibration_results.csv");

    // ── Quick per-axis summary ─────────────────────────────────────────────
    for axis in &["gen_ratio", "length", "havoc"] {
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
