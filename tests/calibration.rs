//! Calibration regression guard.
//!
//! Runs every mock target in `targets.toml` through the evolutionary loop with
//! a fixed set of seeds and asserts each still clears a per-target hit-rate
//! floor. This locks in the mock-harness fixes (path-traversal / ssrf /
//! xss-reflected went from 0 to ~900 hits/1k) and the tuning gains, so a future
//! change that silently regresses calibration fails `cargo test`.
//!
//! Deterministic: fixed seeds, in-memory mock probe, no network. The signal set
//! mirrors the `calibrate` binary (incl. the per-target BodySignatureClassifier
//! wired from `confirm_signatures`).

use std::collections::HashMap;
use std::sync::Arc;

use fuzzz::evolutionary::*;
use fuzzz::mock_config::{load_targets, ConfigProbe, MockTarget};
use fuzzz::signals::{Request, SignalSet};
use fuzzz::signals::signal::{
    BodySignatureClassifier, ErrorClassifier, ReflectionClassifier, StatusClassifier,
    TimeDelayClassifier,
};

const MAX_PROBES: usize = 300;
const SEEDS: &[u64] = &[42, 43, 44];

/// Run one target at one seed, returning hits per 1000 probes.
fn hits_per_1000(target: &MockTarget, seed: u64) -> f64 {
    let probe = Arc::new(ConfigProbe::new(target.clone()));

    let corpus = SeedCorpus::from_seeds(vec![target.trigger_payload.clone()]);
    let sampler = WeightedSampler::new(
        atoms::ATOMS.iter().map(|s| s.to_string()).collect(),
        ChainTable::defaults(),
        PlacementPolicy::default(),
        LengthPolicy::medium(),
    );
    let havoc = HavocMutator::new(sampler.clone(), MAX_PROBES * 4);

    let mut signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));
    if !target.response.confirm_signatures.is_empty() {
        signal_set = signal_set.with(Box::new(BodySignatureClassifier::from_needles(
            &target.response.confirm_signatures,
        )));
    }

    let loop_ = EvolutionaryLoop::new(
        probe, corpus, sampler, havoc, Box::new(HttpFeedback::default()),
    )
    .with_gen_ratio(0.7)
    .with_max_probes(MAX_PROBES)
    .with_seed(seed)
    .with_signal_set(signal_set);

    let baseline_req = Request {
        url: target.baseline_url.clone(),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };
    let base = target.baseline_url.split('?').next().unwrap_or(&target.baseline_url).to_string();
    let inject = |p: &str| Request {
        url: format!("{}?q={}", base, p),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };

    let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
    let outcome = rt.block_on(loop_.run(&baseline_req, inject)).unwrap();
    if outcome.probes_sent == 0 {
        return 0.0;
    }
    (outcome.hits.len() as f64 / outcome.probes_sent as f64) * 1000.0
}

/// Average hits/1k over the fixed seed set.
fn avg_hits_per_1000(target: &MockTarget) -> f64 {
    let sum: f64 = SEEDS.iter().map(|&s| hits_per_1000(target, s)).sum();
    sum / SEEDS.len() as f64
}

/// Per-target floors. Deliberately generous (~15% below measured) so ordinary
/// RNG-path drift from refactors doesn't break the test, while the regressions
/// that matter — a target collapsing toward 0, or the ssrf timing re-probe
/// halving — are caught. `waf-blocked` is a dead-end target (always 403); it
/// must stay at 0.
fn floor_for(name: &str) -> f64 {
    match name {
        "waf-blocked" => 0.0,
        "xss" => 750.0,
        "sqli-strict" => 780.0,
        "xss-reflected" => 780.0,
        "ssrf" => 780.0,
        _ => 800.0, // sqli, cmdi, ssti, path-traversal
    }
}

#[test]
fn every_target_clears_its_floor() {
    let targets = load_targets("targets.toml").expect("load targets.toml");
    assert!(!targets.is_empty(), "no targets loaded");

    let mut failures = Vec::new();
    for t in &targets {
        let avg = avg_hits_per_1000(t);
        let floor = floor_for(&t.name);
        println!("{:<16} {:>7.1} hits/1k  (floor {:.0})", t.name, avg, floor);

        if t.name == "waf-blocked" {
            // Dead-end target: a hit here would mean a false positive.
            if avg != 0.0 {
                failures.push(format!("{}: expected 0 hits, got {:.1}", t.name, avg));
            }
        } else if avg < floor {
            failures.push(format!("{}: {:.1} hits/1k below floor {:.0}", t.name, avg, floor));
        }
    }

    assert!(failures.is_empty(), "calibration regressions:\n  {}", failures.join("\n  "));
}

/// Guard the specific targets that the mock-harness fixes rescued from 0.
/// If any drops back near 0, the fix has been broken.
#[test]
fn formerly_broken_targets_still_confirm() {
    let targets = load_targets("targets.toml").expect("load targets.toml");
    for name in ["xss-reflected", "path-traversal", "ssrf"] {
        let t = targets.iter().find(|t| t.name == name)
            .unwrap_or_else(|| panic!("target {name} missing from targets.toml"));
        let avg = avg_hits_per_1000(t);
        assert!(avg > 500.0, "{name} regressed to {avg:.1} hits/1k (mock fix broken?)");
    }
}
