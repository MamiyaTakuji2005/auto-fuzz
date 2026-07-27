//! Atom dead-weight audit — which atoms never appear in generated payloads?
//!
//! Run with:
//!     cargo run --bin atom_audit --release -- targets.toml
//!
//! Strategy: after each run, scan all corpus payloads (interesting + confirmed)
//! for atom substring occurrences. An atom that never appears in any corpus
//! payload after thousands of probes is dead weight — the generation engine
//! never emits it.
//!
//! Uses gen_ratio=0.7 (default blend) so both generation-mode (apply_chain)
//! and havoc-mode (insert/replace/...) atoms are exercised.
//!
//! Appends rows with sweep_axis="atom_audit" to calibration_results.csv.
//! Prints a per-atom frequency table to stdout.

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
    SignalSet,
};
use fuzzz::signals::Request;

const MAX_PROBES: usize = 5000;
const TRIALS: u32 = 10;
const BASE_SEED: u64 = 42;

/// Count atom substring occurrences across a list of payloads.
fn count_atom_occurrences(atoms: &[String], payloads: &[String]) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();
    for payload in payloads {
        for atom in atoms {
            // Count overlapping occurrences: " OR " in " OR  OR " = 2
            let mut start = 0;
            while let Some(pos) = payload[start..].find(atom.as_str()) {
                *counts.get_mut(atom).unwrap() += 1;
                start += pos + atom.len();
            }
        }
    }
    counts
}

/// Count how many UNIQUE payloads contain each atom at least once.
fn count_atom_presence(atoms: &[String], payloads: &[String]) -> HashMap<String, u64> {
    let mut counts: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();
    for payload in payloads {
        for atom in atoms {
            if payload.contains(atom.as_str()) {
                *counts.get_mut(atom).unwrap() += 1;
            }
        }
    }
    counts
}

// ── Run one trial ──────────────────────────────────────────────────────────

async fn run_one(
    probe: Arc<ConfigProbe>,
    atoms: &[String],
    gen_ratio: f32,
    trial: u32,
) -> (usize, usize, usize, Vec<String>) {
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

    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()))
        .with(Box::new(ReflectionClassifier))
        .with(Box::new(TimeDelayClassifier::default()));

    let feedback = Box::new(HttpFeedback::default());

    let loop_ = EvolutionaryLoop::new(
        probe.clone(), corpus, sampler, havoc, feedback,
    )
    .with_gen_ratio(gen_ratio)
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
        Err(_) => return (0, 0, 0, Vec::new()),
    };

    // Collect ALL corpus payloads (interesting entries only — seeds are trivial).
    let payloads: Vec<String> = outcome.interesting.iter()
        .map(|h| h.payload.clone())
        .collect();

    (outcome.hits.len(), outcome.probes_sent, outcome.final_corpus_size, payloads)
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

    let total_runs = config.targets.len() * TRIALS as usize;
    println!("Atom dead-weight audit — {} probes/run, {} trials, {} targets ({} total runs)",
        MAX_PROBES, TRIALS, config.targets.len(), total_runs);
    println!("Vocabulary: {} atoms\n", atoms.len());

    let csv_path = config_path.with_extension("").with_file_name("calibration_results.csv");
    let mut f = OpenOptions::new().create(true).append(true).open(&csv_path).unwrap();

    // Global atom occurrence counts across ALL targets and trials.
    let mut global_occurrence: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();
    // Global atom presence counts: how many payloads contain this atom.
    let mut global_presence: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();
    let mut total_payloads_analyzed = 0usize;

    for target in &config.targets {
        let name = &target.name;
        let probe = Arc::new(ConfigProbe::new(target.clone()));

        let mut target_occurrence: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();
        let mut target_presence: HashMap<String, u64> = atoms.iter().map(|a| (a.clone(), 0u64)).collect();

        println!("Target: {}", name);
        for trial in 0..TRIALS {
            let (hits, probes, corpus_size, payloads) =
                run_one(probe.clone(), &atoms, 0.7, trial).await;

            // Count atom occurrences.
            let occurrences = count_atom_occurrences(&atoms, &payloads);
            let presence = count_atom_presence(&atoms, &payloads);

            for atom in &atoms {
                *target_occurrence.get_mut(atom).unwrap() += occurrences[atom];
                *target_presence.get_mut(atom).unwrap() += presence[atom];
                *global_occurrence.get_mut(atom).unwrap() += occurrences[atom];
                *global_presence.get_mut(atom).unwrap() += presence[atom];
            }
            total_payloads_analyzed += payloads.len();

            let h1k = if probes > 0 { (hits as f64 / probes as f64) * 1000.0 } else { 0.0 };
            writeln!(f, "{},atom_audit,gen=0.7,{},{},{},{},{},{:.2}",
                name, trial, 0u64, hits, probes, corpus_size, h1k).unwrap();

            print!("  trial {}: hits={} corpus={} payloads={}", trial, hits, corpus_size, payloads.len());
            let zero: Vec<_> = atoms.iter().filter(|a| occurrences[*a] == 0).collect();
            if !zero.is_empty() {
                print!("  dead={}", zero.len());
            }
            println!();
        }

        // Per-target atom frequency table.
        let mut sorted: Vec<_> = target_occurrence.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));
        let zero_atoms: Vec<_> = sorted.iter().filter(|(_, c)| **c == 0).map(|(a, _)| (*a).as_str()).collect();
        println!("  Zero-occurrence atoms ({} / {}):", zero_atoms.len(), atoms.len());
        for atom in &zero_atoms {
            println!("    \"{}\"", atom);
        }
        println!("  Top-10 atoms by occurrence:");
        for (atom, count) in sorted.iter().take(10) {
            let p = target_presence[*atom];
            println!("    {:20} {:8} occ  {:5} payloads", format!("\"{}\"", atom), count, p);
        }
        println!();
    }

    // ── Global summary ─────────────────────────────────────────────────
    println!("=== GLOBAL atom frequency ({} targets × {} trials, {} payloads analyzed) ===",
        config.targets.len(), TRIALS, total_payloads_analyzed);

    let mut sorted: Vec<_> = global_occurrence.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let zero_occ: Vec<_> = sorted.iter().filter(|(_, c)| **c == 0).map(|(a, _)| (*a).as_str()).collect();
    println!("\nZero-occurrence atoms across ALL targets ({} / {}):", zero_occ.len(), atoms.len());
    for atom in &zero_occ {
        println!("  \"{}\"", atom);
    }

    println!("\nAll atoms by occurrence frequency:");
    println!("  {:20} {:>10} {:>10}  {}", "atom", "occurrences", "payloads", "bar");
    for (atom, count) in &sorted {
        let p = global_presence[*atom];
        let bar_len = (**count as f64).log10().max(0.0) as usize;
        let bar = "#".repeat(bar_len);
        println!("  {:20} {:>10} {:>10}  {}", format!("\"{}\"", atom), count, p, bar);
    }

    // ── Seed trigger payloads for reference ────────────────────────────
    println!("\n=== Seed trigger payloads ===");
    for target in &config.targets {
        println!("  {}: \"{}\"", target.name, target.trigger_payload);
    }

    println!("\nDone — appended atom_audit data to {}", csv_path.display());
}
