//! Signal classifier threshold sweep — which classifiers and thresholds
//! actually detect mock target triggers?
//!
//! Run with:
//!     cargo run --bin signal_sweep --release -- targets.toml
//!
//! Key finding this tests: the calibration signal sets OMIT SizeClassifier
//! and BodyDiffClassifier. Mock targets `ssrf` and `path-traversal` get 0
//! hits because NO classifier fires when their triggers activate:
//!   - Status: 200 → 200 (no StatusDelta)
//!   - Error regex: trigger_body has no DBMS error patterns
//!   - Reflection: trigger_body does not contain the payload verbatim
//!   - TimeDelay: trigger_delay=200ms (ssrf) or 5ms (path-trav) < 500ms floor
//!   - SizeClassifier: NOT IN THE SIGNAL SET — but trigger_body is much larger
//!     than clean_body (13 vs 2 bytes for ssrf, 30 vs 2 for path-trav)
//!
//! Three phases:
//!   1. Classifier set — which classifiers matter per target
//!   2. SizeClassifier thresholds — min_abs × min_rel grid
//!   3. TimeDelayClassifier thresholds — min_factor × min_abs_ms grid
//!
//! Appends rows with sweep_axis="signal_clsfy" to calibration_results.csv.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use auto_fuzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler, HttpFeedback, BoostMode,
};
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::mock_config::{load_config, ConfigProbe};
use auto_fuzz::signals::signal::{
    ErrorClassifier, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
    SizeClassifier, BodyDiffClassifier, SignalSet,
};
use auto_fuzz::signals::Request;

const MAX_PROBES: usize = 500;
const TRIALS: u32 = 20;
const BASE_SEED: u64 = 42;
const BEST_GEN_RATIO: f32 = 0.7;

// ── Signal set factories ───────────────────────────────────────────────────

/// The calibration default — 4 classifiers, no Size, no BodyDiff.
fn sigset_baseline() -> SignalSet {
    SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()))
}

/// All 6 classifiers with custom SizeClassifier thresholds.
fn sigset_all6(size_min_abs: usize, size_min_rel: f64) -> SignalSet {
    SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()))
        .with(Box::new(SizeClassifier { min_abs: size_min_abs, min_rel: size_min_rel }))
        .with(Box::new(BodyDiffClassifier))
}

/// Baseline + SizeClassifier only (no BodyDiff).
fn sigset_plus_size(size_min_abs: usize, size_min_rel: f64) -> SignalSet {
    SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()))
        .with(Box::new(SizeClassifier { min_abs: size_min_abs, min_rel: size_min_rel }))
}

/// Baseline + BodyDiff only (no SizeClassifier).
fn sigset_plus_bodydiff() -> SignalSet {
    SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()))
        .with(Box::new(BodyDiffClassifier))
}

/// All 6 classifiers with custom TimeDelay params (SizeClassifier at default).
fn sigset_timedelay(min_factor: f64, min_abs_ms: u128) -> SignalSet {
    SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier { min_factor, min_abs_ms }))
        .with(Box::new(SizeClassifier::default()))
        .with(Box::new(BodyDiffClassifier))
}

// ── Run one trial ──────────────────────────────────────────────────────────

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    signal_set: SignalSet,
    trial: u32,
) -> (usize, usize, usize) {
    let corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()])
        .with_boost_mode(BoostMode::Additive)
        .with_max_energy(64);

    let sampler = WeightedSampler::new(
        atoms.to_vec(),
        ChainTable::defaults(),
        PlacementPolicy::default(),
        LengthPolicy::medium(),
    );

    let havoc = HavocMutator::new(sampler.clone(), MAX_PROBES * 4)
        .with_ops_per_step(4);

    let feedback = Box::new(HttpFeedback::default());

    let loop_ = EvolutionaryLoop::new(
        probe.clone(), corpus, sampler, havoc, feedback,
    )
    .with_gen_ratio(BEST_GEN_RATIO)
    .with_max_probes(MAX_PROBES)
    .with_seed(BASE_SEED + trial as u64)
    .with_signal_set(signal_set);

    let baseline_req = Request {
        url: probe.target.baseline_url.clone(),
        method: probe.target.baseline_method.clone(),
        headers: HashMap::new(),
        body: String::new(),
    };
    let inject = |p: &str| Request {
        url: format!("{}?q={}",
            probe.target.baseline_url.split('?').next().unwrap_or(&probe.target.baseline_url), p),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };

    let outcome = match loop_.run(&baseline_req, inject).await {
        Ok(o) => o,
        Err(_) => return (0, 0, 0),
    };

    (outcome.hits.len(), outcome.probes_sent, outcome.final_corpus_size)
}

fn write_row(f: &mut impl Write, target: &str, config: &str, trial: u32,
             hits: usize, probes: usize, corpus: usize) {
    let h1k = if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 };
    writeln!(f, "{},signal_clsfy,{},{},{},{},{},{},{:.2}",
        target, config, trial, 0u64, hits, probes, corpus, h1k).unwrap();
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
        Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
    };

    let atoms: Vec<String> = match config.atoms {
        Some(custom) => custom,
        None => ATOMS.iter().map(|s| s.to_string()).collect(),
    };

    let total_runs = (7 + 13 + 25) * TRIALS as usize * config.targets.len();
    println!("Signal classifier sweep — {} probes/run, {} trials, {} targets ({} total runs)",
        MAX_PROBES, TRIALS, config.targets.len(), total_runs);

    let csv_path = config_path.with_extension("").with_file_name("calibration_results.csv");
    let mut f = OpenOptions::new().create(true).append(true).open(&csv_path).unwrap();

    for target in &config.targets {
        let name = &target.name;
        let probe = Arc::new(ConfigProbe::new(target.clone()));

        // ── Phase 1: Classifier presence ──────────────────────────────
        println!("  {} phase1: classifier presence", name);

        let phase1: &[(&str, fn() -> SignalSet)] = &[
            ("baseline_4",       sigset_baseline),
            ("all6_size50",      || sigset_all6(50, 0.05)),
            ("all6_size10",      || sigset_all6(10, 0.0)),
            ("all6_size5",       || sigset_all6(5, 0.0)),
            ("all6_size0",       || sigset_all6(0, 0.0)),
            ("baseline+size5",   || sigset_plus_size(5, 0.0)),
            ("baseline+bodydiff", sigset_plus_bodydiff),
        ];

        for &(cfg_name, factory) in phase1 {
            print!("    {}", cfg_name);
            for trial in 0..TRIALS {
                let sig = factory();
                let (hits, probes, corpus) = run_one(probe.clone(), &atoms, sig, trial).await;
                write_row(&mut f, name, cfg_name, trial, hits, probes, corpus);
                print!(".");
            }
            println!(" {}", TRIALS);
        }

        // ── Phase 2: SizeClassifier parameter sweep ───────────────────
        println!("  {} phase2: SizeClassifier thresholds", name);

        // Sweep min_abs at min_rel=0
        for &min_abs in &[0usize, 1, 2, 5, 10, 20, 50] {
            let cfg_name = format!("size_abs={}", min_abs);
            print!("    {}", cfg_name);
            for trial in 0..TRIALS {
                let sig = sigset_all6(min_abs, 0.0);
                let (hits, probes, corpus) = run_one(probe.clone(), &atoms, sig, trial).await;
                write_row(&mut f, name, &cfg_name, trial, hits, probes, corpus);
                print!(".");
            }
            println!(" {}", TRIALS);
        }

        // Sweep min_rel at min_abs=0
        for &min_rel in &[0.0f64, 0.01, 0.03, 0.05, 0.10, 0.20] {
            let cfg_name = format!("size_rel={:.2}", min_rel);
            print!("    {}", cfg_name);
            for trial in 0..TRIALS {
                let sig = sigset_all6(0, min_rel);
                let (hits, probes, corpus) = run_one(probe.clone(), &atoms, sig, trial).await;
                write_row(&mut f, name, &cfg_name, trial, hits, probes, corpus);
                print!(".");
            }
            println!(" {}", TRIALS);
        }

        // ── Phase 3: TimeDelayClassifier parameter sweep ──────────────
        println!("  {} phase3: TimeDelayClassifier thresholds", name);

        for &min_factor in &[1.5f64, 2.0, 3.0, 5.0, 10.0] {
            for &min_abs_ms in &[25u128, 50, 100, 200, 500] {
                let cfg_name = format!("delay_f{:.1}_ms{}", min_factor, min_abs_ms);
                print!("    {}", cfg_name);
                for trial in 0..TRIALS {
                    let sig = sigset_timedelay(min_factor, min_abs_ms);
                    let (hits, probes, corpus) = run_one(probe.clone(), &atoms, sig, trial).await;
                    write_row(&mut f, name, &cfg_name, trial, hits, probes, corpus);
                    print!(".");
                }
                println!(" {}", TRIALS);
            }
        }
    }

    println!("\nDone — appended signal_sweep data to {}", csv_path.display());
}
