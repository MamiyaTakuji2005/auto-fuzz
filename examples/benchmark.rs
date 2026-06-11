//! Granular speed benchmark — full parameter sweeps.
//!
//! Run: `cargo run --example benchmark --release`

use auto_fuzz::evolutionary::*;
use auto_fuzz::signals::*;
use auto_fuzz::signals::signal::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

struct MockProbe;
#[async_trait]
impl Probe for MockProbe {
    async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
        Ok(ProbeResponse {
            status: 200,
            body: b"ok".to_vec(),
            duration: Duration::from_millis(1),
        })
    }
}

// ── Signal builders ────────────────────────────────────────────────────────

fn sig(name: &str) -> Option<Box<dyn Classifier>> {
    match name {
        "status" => Some(Box::new(StatusClassifier)),
        "size" => Some(Box::new(SizeClassifier::default())),
        "bodydiff" => Some(Box::new(BodyDiffClassifier)),
        "reflection" => Some(Box::new(ReflectionClassifier)),
        "timedelay" => Some(Box::new(TimeDelayClassifier::default())),
        "error" => Some(Box::new(ErrorClassifier::dbms_starter())),
        _ => None,
    }
}

fn signal_set_with(names: &[&str]) -> SignalSet {
    let mut set = SignalSet::new();
    for n in names {
        if let Some(c) = sig(n) {
            set = set.with(c);
        }
    }
    set
}

// ── Run one config ──────────────────────────────────────────────────────────

async fn run_config(
    probes: usize,
    gen_ratio: f32,
    signal_names: &[&str],
    havoc_ops: usize,
    length: LengthPolicy,
) -> (usize, Duration) {
    let atoms: Vec<String> = (0..=9).map(|d| d.to_string()).collect();
    let sampler = WeightedSampler::new(
        atoms,
        ChainTable::new(),
        PlacementPolicy::append_only(),
        length,
    );
    let havoc = HavocMutator::new(sampler.clone(), probes * 4)
        .with_ops_per_step(havoc_ops);
    let corpus = SeedCorpus::from_seeds(["1", "2", "3"]);
    let feedback: Box<dyn Feedback> = Box::new(HttpFeedback::default());

    let loop_ = EvolutionaryLoop::new(MockProbe, corpus, sampler, havoc, feedback)
        .with_gen_ratio(gen_ratio)
        .with_max_probes(probes)
        .with_signal_set(signal_set_with(signal_names));

    let baseline = Request {
        url: "http://x/?q=".into(),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };

    let start = Instant::now();
    let outcome = loop_
        .run(&baseline, |p| Request {
            url: format!("http://x/?q={p}"),
            method: "GET".into(),
            headers: HashMap::new(),
            body: String::new(),
        })
        .await
        .unwrap();
    (outcome.probes_sent, start.elapsed())
}

// ── Print helpers ───────────────────────────────────────────────────────────

fn pps_label(pps: f64) -> String {
    if pps >= 1_000_000.0 {
        format!("{:.2}M", pps / 1_000_000.0)
    } else if pps >= 1_000.0 {
        format!("{:.0}K", pps / 1_000.0)
    } else {
        format!("{:.0}", pps)
    }
}

fn us_label(us: f64) -> String { format!("{:.1}", us) }

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let n = 2000; // probes per config — higher for stable measurements

    // ══════════════════════════════════════════════════════════════════════
    println!("SWEEP 1 — gen_ratio  (0.0 to 1.0, step 0.1)");
    println!("         all 6 classifiers, ops=4, medium length, {n} probes\n");
    println!("{:<8} {:>10} {:>12} {:>10}", "gen", "time", "probes/sec", "μs/probe");
    println!("{}", "-".repeat(45));

    for g in 0..=10 {
        let gen = g as f32 / 10.0;
        let (probes, elapsed) = run_config(
            n, gen,
            &["status", "size", "bodydiff", "reflection", "timedelay", "error"],
            4, LengthPolicy::medium(),
        ).await;
        let ms = elapsed.as_secs_f64() * 1000.0;
        let pps = probes as f64 / elapsed.as_secs_f64();
        let us = elapsed.as_micros() as f64 / probes as f64;
        println!("{:<8} {:>8.1}ms {:>10} {:>8}μs", format!("{:.1}", gen), ms, pps_label(pps), us_label(us));
    }

    // ══════════════════════════════════════════════════════════════════════
    println!("\nSWEEP 2 — classifiers (add one at a time, cumulatively)");
    println!("         gen=0.3, ops=4, medium length, {n} probes\n");
    println!("{:<40} {:>10} {:>12} {:>10}", "classifiers active", "time", "probes/sec", "μs/probe");
    println!("{}", "-".repeat(75));

    let all_sigs = ["status", "size", "bodydiff", "reflection", "timedelay", "error"];
    for i in 0..=all_sigs.len() {
        let names: Vec<&str> = all_sigs[..i].to_vec();
        let label = if names.is_empty() {
            "(none)".to_string()
        } else {
            names.join(" + ")
        };
        let (probes, elapsed) = run_config(
            n, 0.3, &names, 4, LengthPolicy::medium(),
        ).await;
        let ms = elapsed.as_secs_f64() * 1000.0;
        let pps = probes as f64 / elapsed.as_secs_f64();
        let us = elapsed.as_micros() as f64 / probes as f64;
        println!("{:<40} {:>8.1}ms {:>10} {:>8}μs", label, ms, pps_label(pps), us_label(us));
    }

    // ══════════════════════════════════════════════════════════════════════
    println!("\nSWEEP 3 — havoc ops_per_step  (1 to 12)");
    println!("         gen=0.3, all 6 classifiers, medium length, {n} probes\n");
    println!("{:<8} {:>10} {:>12} {:>10}", "ops", "time", "probes/sec", "μs/probe");
    println!("{}", "-".repeat(45));

    for ops in 1..=12 {
        let (probes, elapsed) = run_config(
            n, 0.3,
            &["status", "size", "bodydiff", "reflection", "timedelay", "error"],
            ops, LengthPolicy::medium(),
        ).await;
        let ms = elapsed.as_secs_f64() * 1000.0;
        let pps = probes as f64 / elapsed.as_secs_f64();
        let us = elapsed.as_micros() as f64 / probes as f64;
        println!("{:<8} {:>8.1}ms {:>10} {:>8}μs", ops, ms, pps_label(pps), us_label(us));
    }

    // ══════════════════════════════════════════════════════════════════════
    println!("\nSWEEP 4 — chain length  (fixed lengths 1 to 20)");
    println!("         gen=0.3, all 6 classifiers, ops=4, {n} probes\n");
    println!("{:<8} {:>10} {:>12} {:>10}", "atoms", "time", "probes/sec", "μs/probe");
    println!("{}", "-".repeat(45));

    for atoms in 1..=20 {
        let (probes, elapsed) = run_config(
            n, 0.3,
            &["status", "size", "bodydiff", "reflection", "timedelay", "error"],
            4, LengthPolicy::fixed(atoms),
        ).await;
        let ms = elapsed.as_secs_f64() * 1000.0;
        let pps = probes as f64 / elapsed.as_secs_f64();
        let us = elapsed.as_micros() as f64 / probes as f64;
        println!("{:<8} {:>8.1}ms {:>10} {:>8}μs", atoms, ms, pps_label(pps), us_label(us));
    }

    println!("\nDone. mock probe, {n} probes per config, --release build.");
}
