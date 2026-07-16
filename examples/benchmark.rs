//! Speed benchmark — quiet vs noisy vs heavy targets.
//!
//! Run: `cargo run --example benchmark --release`

use auto_fuzz::evolutionary::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Probes: quiet, noisy, heavy ────────────────────────────────────────────

struct QuietProbe;
#[async_trait]
impl Probe for QuietProbe {
    async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
        Ok(ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(1) })
    }
}

/// Triggers all 6 classifier types based on payload content.
struct NoisyProbe;
#[async_trait]
impl Probe for NoisyProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let payload = req.url.split("?q=").nth(1).unwrap_or("");
        let (status, body_bytes, dur) = if payload.contains('\'') || payload.contains(" OR ") {
            (500u16, format!("You have an error in your SQL syntax near '{}'", payload).into_bytes(), 10u64)
        } else if payload.contains("<script>") || payload.contains("<svg") {
            (200u16, format!("<html>{}</html>", payload).into_bytes(), 5u64)
        } else if payload.contains("SLEEP") || payload.contains("sleep") {
            (200u16, b"ok".to_vec(), 20u64)
        } else if payload.len() > 30 {
            (200u16, "x".repeat(200).into_bytes(), 5u64)
        } else if payload.contains('7') {
            (500u16, b"error".to_vec(), 5u64)
        } else {
            (200u16, b"ok".to_vec(), 5u64)
        };
        Ok(ProbeResponse { status, body: body_bytes, duration: Duration::from_millis(dur) })
    }
}

/// Heavy body: always returns large responses so classifiers scan a lot.
struct HeavyProbe;
#[async_trait]
impl Probe for HeavyProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let payload = req.url.split("?q=").nth(1).unwrap_or("");
        let body = format!("<html>{}</html>", "x".repeat(500));
        let status = if payload.contains('\'') { 500 } else { 200 };
        Ok(ProbeResponse { status, body: body.into_bytes(), duration: Duration::from_millis(5) })
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
    for n in names { if let Some(c) = sig(n) { set = set.with(c); } }
    set
}

// ── Run one config ──────────────────────────────────────────────────────────

struct RunResult {
    probes: usize,
    elapsed: Duration,
    corpus_size: usize,
    confirmed: usize,
}

async fn run_config<P: Probe + 'static>(
    probe: P,
    probes: usize,
    gen_ratio: f32,
    signal_names: &[&str],
    havoc_ops: usize,
    length: LengthPolicy,
) -> RunResult {
    let atoms: Vec<String> = ATOMS.iter().map(|s: &&str| s.to_string()).collect();
    let sampler = WeightedSampler::new(
        atoms,
        ChainTable::defaults(),
        PlacementPolicy::default(),
        length,
    );
    let havoc = HavocMutator::new(sampler.clone(), probes * 4).with_ops_per_step(havoc_ops);
    let corpus = SeedCorpus::from_seeds(["'", "<", "{{", "1 OR 1=1"]);
    let feedback: Box<dyn Feedback> = Box::new(HttpFeedback::default());

    let loop_ = EvolutionaryLoop::new(probe, corpus, sampler, havoc, feedback)
        .with_gen_ratio(gen_ratio)
        .with_max_probes(probes)
        .with_signal_set(signal_set_with(signal_names));

    let baseline = Request {
        url: "http://x/?q=".into(), method: "GET".into(),
        headers: HashMap::new(), body: String::new(),
    };

    let start = Instant::now();
    let outcome = loop_.run(&baseline, |p| Request {
        url: format!("http://x/?q={p}"), method: "GET".into(),
        headers: HashMap::new(), body: String::new(),
    }).await.unwrap();

    RunResult {
        probes: outcome.probes_sent,
        elapsed: start.elapsed(),
        corpus_size: outcome.final_corpus_size,
        confirmed: outcome.hits.len(),
    }
}

// ── Print helpers ───────────────────────────────────────────────────────────

fn ms(d: Duration) -> f64 { d.as_secs_f64() * 1000.0 }

fn pps(r: &RunResult) -> f64 { r.probes as f64 / r.elapsed.as_secs_f64() }

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let n = 1000;

    // ══════════════════════════════════════════════════════════════════════
    println!("TARGET COMPARISON — gen=0.3, ops=4, medium, all classifiers, {n} probes\n");
    println!("{:<20} {:>10} {:>12} {:>10} {:>10} {:>10}", "target", "time", "probes/sec", "μs/probe", "corpus", "confirmed");
    println!("{}", "-".repeat(80));

    let defaults = (n, 0.3f32, &["status","size","bodydiff","reflection","timedelay","error"][..], 4usize, LengthPolicy::medium());

    {
        let r = run_config(QuietProbe, defaults.0, defaults.1, defaults.2, defaults.3, defaults.4.clone()).await;
        println!("{:<20} {:>8.1}ms {:>10.0} {:>8.1}μs {:>8} {:>8}", "quiet (200 ok)", ms(r.elapsed), pps(&r),
            r.elapsed.as_micros() as f64 / r.probes as f64, r.corpus_size, r.confirmed);
    }
    {
        let r = run_config(NoisyProbe, defaults.0, defaults.1, defaults.2, defaults.3, defaults.4.clone()).await;
        println!("{:<20} {:>8.1}ms {:>10.0} {:>8.1}μs {:>8} {:>8}", "noisy (varied)", ms(r.elapsed), pps(&r),
            r.elapsed.as_micros() as f64 / r.probes as f64, r.corpus_size, r.confirmed);
    }
    {
        let r = run_config(HeavyProbe, defaults.0, defaults.1, defaults.2, defaults.3, defaults.4.clone()).await;
        println!("{:<20} {:>8.1}ms {:>10.0} {:>8.1}μs {:>8} {:>8}", "heavy (500B body)", ms(r.elapsed), pps(&r),
            r.elapsed.as_micros() as f64 / r.probes as f64, r.corpus_size, r.confirmed);
    }

    // ══════════════════════════════════════════════════════════════════════
    println!("\nCLASSIFIER SWEEP — noisy target, gen=0.3, ops=4, medium, {n} probes\n");
    println!("{:<40} {:>10} {:>12} {:>10} {:>10}", "classifiers", "time", "probes/sec", "corpus", "confirmed");
    println!("{}", "-".repeat(85));

    let all_sigs = ["status", "size", "bodydiff", "reflection", "timedelay", "error"];
    for i in 0..=all_sigs.len() {
        let names: Vec<&str> = all_sigs[..i].to_vec();
        let label = if names.is_empty() { "(none)".to_string() } else { names.join("+") };
        let r = run_config(NoisyProbe, n, 0.3, &names, 4, LengthPolicy::medium()).await;
        println!("{:<40} {:>8.1}ms {:>10.0} {:>8} {:>8}",
            label, ms(r.elapsed), pps(&r), r.corpus_size, r.confirmed);
    }

    // ══════════════════════════════════════════════════════════════════════
    println!("\nHAVOC OPS SWEEP — noisy target, gen=0.3, all classifiers, medium, {n} probes\n");
    println!("{:<8} {:>10} {:>12} {:>10} {:>10}", "ops", "time", "probes/sec", "corpus", "confirmed");
    println!("{}", "-".repeat(55));

    for ops in 1..=12 {
        let r = run_config(NoisyProbe, n, 0.3, &all_sigs, ops, LengthPolicy::medium()).await;
        println!("{:<8} {:>8.1}ms {:>10.0} {:>8} {:>8}", ops, ms(r.elapsed), pps(&r), r.corpus_size, r.confirmed);
    }

    println!("\nDone. --release build, {n} probes/config. Noisy probe triggers all classifiers.");
}
