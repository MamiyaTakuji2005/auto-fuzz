use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;

use auto_fuzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HavocMutator, HttpFeedback, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler,
};
use auto_fuzz::evolutionary::atoms::ATOMS;
use auto_fuzz::evolutionary::havoc::HavocSchedule;

use auto_fuzz::mock_config::{load_targets, ConfigProbe, MockTarget};
use auto_fuzz::signals::signal::{
    ErrorClassifier, ReflectionClassifier, StatusClassifier, TimeDelayClassifier,
};
use auto_fuzz::signals::{Request, SignalSet};

const PROBES_PER_RUN: usize = 1000;
const RUNS_PER_TARGET: usize = 200;
const BASE_SEED: u64 = 42;

async fn stress_run(
    probe: Arc<ConfigProbe>,
    gen_ratio: f32,
    trial: u32,
) -> bool {
    let corpus = SeedCorpus::from_seeds(vec![probe.target.trigger_payload.clone()]);
    let atoms: Vec<String> = ATOMS.iter().map(|s| s.to_string()).collect();
    let sampler = WeightedSampler::new(
        atoms,
        ChainTable::defaults(),
        PlacementPolicy::default(),
        LengthPolicy::medium(),
    );

    let havoc = HavocMutator::new(sampler.clone(), PROBES_PER_RUN * 4)
        .with_ops_per_step(4);

    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));

    let loop_ = EvolutionaryLoop::new(
        probe.clone(), corpus, sampler, havoc,
        Box::new(HttpFeedback::default()),
    )
    .with_gen_ratio(gen_ratio)
    .with_max_probes(PROBES_PER_RUN)
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

    match loop_.run(&baseline_req, inject).await {
        Ok(_) => true,
        Err(_) => false,
    }
}

#[tokio::main]
async fn main() {
    let config_path = std::env::args().nth(1)
        .unwrap_or_else(|| "stress_targets.toml".to_string());

    let targets = load_targets(&config_path).expect("failed to load targets");

    println!("Stress test: {} targets, {} runs x {} probes = {} total probes",
        targets.len(), RUNS_PER_TARGET, PROBES_PER_RUN,
        targets.len() * RUNS_PER_TARGET * PROBES_PER_RUN);

    let total = targets.len() * RUNS_PER_TARGET;
    let mut done = 0;
    let mut errors = 0;
    let start = Instant::now();

    for target in &targets {
        let probe = Arc::new(ConfigProbe::new(target.clone()));

        for trial in 0..RUNS_PER_TARGET as u32 {
            let gen_ratio = (trial % 11) as f32 / 10.0;
            let ok = stress_run(probe.clone(), gen_ratio, trial).await;

            done += 1;
            if !ok { errors += 1; }

            if done % 100 == 0 {
                let elapsed = start.elapsed().as_secs_f64();
                let rate = done as f64 / elapsed;
                let total_probes = done * PROBES_PER_RUN;
                println!("  [{}/{}] {} probes sent, {:.0} runs/s, {} errors",
                    done, total, total_probes, rate, errors);
            }
        }
    }

    let elapsed = start.elapsed();
    let total_probes = done * PROBES_PER_RUN;
    println!("\nDone in {:.1}s", elapsed.as_secs_f64());
    println!("  {} runs, {} total probes", done, total_probes);
    println!("  {:.0} probes/s", total_probes as f64 / elapsed.as_secs_f64());
    println!("  {} errors", errors);

    if errors > 0 {
        println!("\n  WARNING: {} runs returned errors — check above for any panics", errors);
        std::process::exit(1);
    } else {
        println!("\n  OK — no panics, no errors");
    }
}
