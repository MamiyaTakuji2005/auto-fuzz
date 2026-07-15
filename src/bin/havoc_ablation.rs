//! HavocOp ablation — zeroes each operator one at a time and measures hit delta.
//!
//! Run with:
//!     cargo run --bin havoc_ablation --release -- targets.toml
//!
//! Appends rows with sweep_axis="ablation" to calibration_results.csv.
//! Each config name is "ablate=<op>" for the ablated operator, plus "baseline"
//! for the unmodified default schedule.

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use auto_fuzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler, HttpFeedback, BoostMode,
};
use auto_fuzz::evolutionary::havoc::HavocSchedule;
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::mock_config::{load_config, ConfigProbe};
use auto_fuzz::signals::signal::{
    ErrorClassifier, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
};
use auto_fuzz::signals::{Request, SignalSet};

const MAX_PROBES: usize = 5000;
const TRIALS: u32 = 20;
const BASE_SEED: u64 = 42;
const BEST_GEN_RATIO: f32 = 0.7;

fn default_schedule() -> HavocSchedule {
    HavocSchedule::default()
}

fn ablate(schedule: &HavocSchedule, op: &str) -> HavocSchedule {
    let mut s = schedule.clone();
    match op {
        "insert_token"          => s.insert_token = 0.0,
        "replace_token"         => s.replace_token = 0.0,
        "delete_chunk"          => s.delete_chunk = 0.0,
        "duplicate_chunk"       => s.duplicate_chunk = 0.0,
        "splice_suffix"         => s.splice_suffix = 0.0,
        "url_encode"            => s.url_encode = 0.0,
        "double_url_encode"     => s.double_url_encode = 0.0,
        "insert_boundary_value" => s.insert_boundary_value = 0.0,
        "repeat_payload"        => s.repeat_payload = 0.0,
        "wrap_delimiter"        => s.wrap_delimiter = 0.0,
        "reverse"               => s.reverse = 0.0,
        "uppercase"             => s.uppercase = 0.0,
        _ => panic!("unknown op: {}", op),
    }
    s
}

const ALL_OPS: &[&str] = &[
    "insert_token", "replace_token", "delete_chunk", "duplicate_chunk",
    "splice_suffix", "url_encode", "double_url_encode", "insert_boundary_value",
    "repeat_payload", "wrap_delimiter", "reverse", "uppercase",
];

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    schedule: Option<HavocSchedule>,
    trial: u32,
) -> (usize, usize) {
    let corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()])
        .with_boost_mode(BoostMode::Additive)
        .with_max_energy(64);

    let sampler = WeightedSampler::new(
        atoms.to_vec(),
        ChainTable::defaults(),
        PlacementPolicy::default(),
        LengthPolicy::medium(),
    );

    let mut havoc = HavocMutator::new(sampler.clone(), MAX_PROBES * 4)
        .with_ops_per_step(4);
    if let Some(ref sched) = schedule {
        havoc = havoc.with_schedule(sched.clone());
    }

    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));

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
        Err(_) => return (0, 0),
    };

    (outcome.hits.len(), outcome.probes_sent)
}

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

    // 1 baseline + 12 ablations = 13 configs × 20 trials × 9 targets = 2340 runs
    let total_runs = (1 + ALL_OPS.len()) * TRIALS as usize * config.targets.len();
    println!("HavocOp ablation — {} probes/run, {} trials, {} targets ({} total runs)",
        MAX_PROBES, TRIALS, config.targets.len(), total_runs);

    let csv_path = config_path.with_extension("").with_file_name("calibration_results.csv");
    let mut f = OpenOptions::new().create(true).append(true).open(&csv_path).unwrap();

    for target in &config.targets {
        let name = &target.name;
        let probe = Arc::new(ConfigProbe::new(target.clone()));

        // Baseline (default schedule)
        print!("  {} baseline", name);
        for trial in 0..TRIALS {
            let (hits, probes) = run_one(probe.clone(), &atoms, None, trial).await;
            let h1k = if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 };
            writeln!(f, "{},ablation,baseline,{},{},{},{},{},{:.2}",
                name, trial, 0u64, hits, probes, 0usize, h1k).unwrap();
            print!(".");
        }
        println!(" 20");

        // Each op ablated
        for op in ALL_OPS {
            print!("  {} -{}", name, op);
            let sched = ablate(&default_schedule(), op);
            for trial in 0..TRIALS {
                let (hits, probes) = run_one(probe.clone(), &atoms, Some(sched.clone()), trial).await;
                let h1k = if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 };
                writeln!(f, "{},ablation,ablate={},{},{},{},{},{},{:.2}",
                    name, op, trial, 0u64, hits, probes, 0usize, h1k).unwrap();
                print!(".");
            }
            println!(" 20");
        }
    }

    println!("Done — appended ablation data to {}", csv_path.display());
}
