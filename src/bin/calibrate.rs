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
    ChainTable, EvolutionaryLoop, HavocMutator, HttpFeedback, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler,
};
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::evolutionary::havoc::HavocSchedule;

use auto_fuzz::mock_config::{load_config, ConfigProbe, MockTarget};
use auto_fuzz::signals::signal::{
    ErrorClassifier, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
};
use auto_fuzz::signals::{Request, SignalSet};

const DEFAULT_MAX_PROBES: usize = 300;
const DEFAULT_TRIALS: u32 = 5;
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

// ── Configuration ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CalibConfig {
    label: String,
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
            havoc_ops: 4, havoc_schedule: schedule, max_probes: DEFAULT_MAX_PROBES,
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

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    config: &CalibConfig,
    trial: u32,
) -> RunMetrics {
    let start = Instant::now();

    let corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()]);
    let sampler = WeightedSampler::new(
        atoms.to_vec(),
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
        probe.clone(), corpus, sampler, havoc,
        Box::new(HttpFeedback::default()),
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

// ── Batch runner — sweeps one target through all 3 phases ─────────────────

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
                                    g, LengthPolicy::medium(), None);
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
                                    best_gr, lp.clone(), None);
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
                                    best_gr, LengthPolicy::medium(), sched.clone());
        for trial in 0..trials {
            let m = run_one(probe.clone(), atoms, &cfg, trial).await;
            rows.push((name.clone(), cfg.label.clone(), cfg.sweep_axis.to_string(), trial, m));
            print!(".");
        }
    }
    println!(" 20");

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
