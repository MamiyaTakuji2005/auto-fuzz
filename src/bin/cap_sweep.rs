//! Targeted energy cap sweep — runs ONLY the max_energy sweep (Phase 11).
//!
//! Run with:
//!     cargo run --bin cap_sweep --release -- targets.toml

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;

use fuzzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler, HttpFeedback, BoostMode,
};
use fuzzz::evolutionary::atoms::ATOMS;

use fuzzz::mock_config::{load_config, ConfigProbe};
use fuzzz::signals::signal::{
    ErrorClassifier, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
};
use fuzzz::signals::{Request, SignalSet};

const MAX_PROBES: usize = 2000;
const TRIALS: u32 = 20;
const BASE_SEED: u64 = 42;

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    cap: u8,
    trial: u32,
) -> (usize, usize) {
    let corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()])
        .with_boost_mode(BoostMode::Additive)
        .with_max_energy(cap);

    let sampler = WeightedSampler::new(
        atoms.to_vec(),
        ChainTable::defaults(),
        PlacementPolicy::default(),
        LengthPolicy::medium(),
    );

    let havoc = HavocMutator::new(sampler.clone(), MAX_PROBES * 4)
        .with_ops_per_step(4);

    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));

    let feedback = Box::new(HttpFeedback::default());

    let loop_ = EvolutionaryLoop::new(
        probe.clone(), corpus, sampler, havoc, feedback,
    )
    .with_gen_ratio(0.7)
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

    println!("Energy cap sweep — {} targets, {} trials each", config.targets.len(), TRIALS);

    let csv_path = config_path.with_extension("").with_file_name("calibration_results.csv");
    let mut f = OpenOptions::new().create(true).append(true).open(&csv_path).unwrap();

    for target in &config.targets {
        let name = &target.name;
        let probe = Arc::new(ConfigProbe::new(target.clone()));

        println!("  {} max_energy [8, 16, 32, 64, 128, 255] @ boost=add gen=0.7 medium", name);
        for &cap in &[8u8, 16, 32, 64, 128, 255] {
            for trial in 0..TRIALS {
                let (hits, probes) = run_one(probe.clone(), &atoms, cap, trial).await;
                let hits_per_1k = if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 };
                writeln!(f, "{},cap,cap={},{},0,{},{},{},{:.2}",
                    name, cap, trial, hits, probes, 0usize, hits_per_1k).unwrap();
                print!(".");
            }
        }
        println!(" {}", 6 * TRIALS as usize);
    }

    println!("Done — appended cap sweep to {}", csv_path.display());
}
