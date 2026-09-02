//! Benchmark & report suite — throughput, discovery, waste, and replay.
//!
//! Run: `cargo run --bin report --release`

use fuzzz::evolutionary::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ── Mock probes ──────────────────────────────────────────────────────────────

struct QuietProbe;
#[async_trait]
impl Probe for QuietProbe {
    async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
        Ok(ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(1) })
    }
}

struct NoisyProbe;
#[async_trait]
impl Probe for NoisyProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let (s, b, d) = if p.contains('\'') || p.contains(" OR ") {
            (500, format!("error near '{p}'").into_bytes(), 5u64)
        } else if p.contains("<script>") {
            (200, format!("<html>{p}</html>").into_bytes(), 3)
        } else if p.contains("SLEEP") {
            (200, b"ok".to_vec(), 30)
        } else if p.len() > 30 {
            (200, "x".repeat(200).into_bytes(), 4)
        } else {
            (200, b"ok".to_vec(), 4)
        };
        Ok(ProbeResponse { status: s, body: b, duration: Duration::from_millis(d) })
    }
}

// ── Discovery targets ────────────────────────────────────────────────────────

struct SqlErrorTarget;
#[async_trait]
impl Probe for SqlErrorTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let hit = p.contains('\'') && (p.contains(" OR ") || p.contains(" UNION ") || p.contains("--"));
        Ok(if hit {
            ProbeResponse { status: 500, body: format!("SQL error near '{p}'").into_bytes(), duration: Duration::from_millis(5) }
        } else {
            ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(3) }
        })
    }
}

struct XssTarget;
#[async_trait]
impl Probe for XssTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let hit = p.contains("<script>") || p.contains("<svg") || p.contains("onerror=");
        Ok(if hit {
            ProbeResponse { status: 200, body: format!("<html><body>{p}</body></html>").into_bytes(), duration: Duration::from_millis(3) }
        } else {
            ProbeResponse { status: 200, body: b"<html><body>ok</body></html>".to_vec(), duration: Duration::from_millis(3) }
        })
    }
}

struct TimingTarget;
#[async_trait]
impl Probe for TimingTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let d = if p.contains("SLEEP") || p.contains("BENCHMARK") { 500 } else { 5 };
        Ok(ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(d) })
    }
}

struct TraversalTarget;
#[async_trait]
impl Probe for TraversalTarget {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let p = req.url.split("?q=").nth(1).unwrap_or("");
        let hit = p.contains("../") && p.contains("etc/passwd");
        Ok(if hit {
            ProbeResponse { status: 200, body: b"root:x:0:0:root:/root:/bin/bash\n".to_vec(), duration: Duration::from_millis(3) }
        } else if p.len() > 100 {
            ProbeResponse { status: 500, body: b"bad request".to_vec(), duration: Duration::from_millis(3) }
        } else {
            ProbeResponse { status: 404, body: b"not found".to_vec(), duration: Duration::from_millis(3) }
        })
    }
}

// ── Builders ─────────────────────────────────────────────────────────────────

fn signal_set(names: &[&str]) -> SignalSet {
    let mut s = SignalSet::new();
    for &n in names {
        match n {
            "status"     => s = s.with(Box::new(StatusClassifier)),
            "size"       => s = s.with(Box::new(SizeClassifier::default())),
            "bodydiff"   => s = s.with(Box::new(BodyDiffClassifier)),
            "reflection" => s = s.with(Box::new(ReflectionClassifier)),
            "timedelay"  => s = s.with(Box::new(TimeDelayClassifier::default())),
            "error"      => s = s.with(Box::new(ErrorClassifier::dbms_starter())),
            _ => {}
        }
    }
    s
}

const ALL: &[&str] = &["status","size","bodydiff","reflection","timedelay","error"];

fn build_loop<P: Probe + 'static>(probe: P, probes: usize) -> EvolutionaryLoop<P> {
    let s = WeightedSampler::default_weights();
    let h = HavocMutator::new(s.clone(), probes * 4);
    let c = SeedCorpus::from_seeds(["'", "<", "{{", "1 OR 1=1"]);
    let f: Box<dyn Feedback> = Box::new(HttpFeedback::default());
    EvolutionaryLoop::new(probe, c, s, h, f)
        .with_gen_ratio(0.3)
        .with_max_probes(probes)
        .with_signal_set(signal_set(ALL))
}

fn baseline() -> Request {
    Request { url: "http://x/?q=".into(), method: "GET".into(), headers: HashMap::new(), body: String::new() }
}

fn inject(p: &str) -> Request {
    Request { url: format!("http://x/?q={p}"), method: "GET".into(), headers: HashMap::new(), body: String::new() }
}

// ── Print helpers ────────────────────────────────────────────────────────────

fn ms(d: Duration) -> f64 { d.as_secs_f64() * 1000.0 }

// ── 1. Throughput ────────────────────────────────────────────────────────────

async fn throughput_report() {
    let n = 2000;
    println!("═══════════════════════════════════════════════");
    println!("1. THROUGHPUT  ({n} probes, all classifiers)\n");
    println!("{:<28} {:>8} {:>10} {:>7} {:>8}", "config", "time", "probes/s", "corpus", "hits");
    println!("{}", "-".repeat(70));

    for (label, gen) in [("quiet (havoc only)", 0.0f32), ("quiet (gen only)", 1.0), ("quiet (mixed)", 0.3)] {
        let start = Instant::now();
        let o = build_loop(QuietProbe, n).with_gen_ratio(gen).run(&baseline(), inject).await.unwrap();
        let t = start.elapsed();
        println!("  {label:<26} {:>6.1}ms {:>8.0} {:>5} {:>6}",
            ms(t), o.probes_sent as f64 / t.as_secs_f64(), o.final_corpus_size, o.hits.len());
    }
    println!();
    for (label, gen) in [("noisy (havoc only)", 0.0f32), ("noisy (gen only)", 1.0), ("noisy (mixed)", 0.3)] {
        let start = Instant::now();
        let o = build_loop(NoisyProbe, n).with_gen_ratio(gen).run(&baseline(), inject).await.unwrap();
        let t = start.elapsed();
        println!("  {label:<26} {:>6.1}ms {:>8.0} {:>5} {:>6}",
            ms(t), o.probes_sent as f64 / t.as_secs_f64(), o.final_corpus_size, o.hits.len());
    }
}

// ── 2. Discovery ─────────────────────────────────────────────────────────────

async fn discovery_report() {
    let n = 200;
    println!("\n═══════════════════════════════════════════════");
    println!("2. DISCOVERY  ({n} probes per target)\n");
    println!("{:<20} {:>4} {:>4} {:>7} {:>5} {:>5} {:>5} {:>5} {:>5}",
        "target", "hits", "p", "p/s", "corp", "dups", "noop", "over", "err");
    println!("{}", "-".repeat(70));

    for (name, probe) in [
        ("SQL error",        Box::new(SqlErrorTarget) as Box<dyn Probe + Send>),
        ("reflected XSS",    Box::new(XssTarget)),
        ("timing (SLEEP)",   Box::new(TimingTarget)),
        ("path traversal",   Box::new(TraversalTarget)),
    ] {
        let o = boxed_run(probe, n).await;
        println!("  {name:<18} {:>4} {:>4} {:>5.0} {:>5} {:>5} {:>5} {:>5} {:>5}",
            o.hits, o.probes, o.probes as f64 / o.elapsed.as_secs_f64(),
            o.corpus, o.dups, o.noops, o.oversized, o.errors);
    }
}

struct Run {
    hits: usize,
    probes: usize,
    corpus: usize,
    elapsed: Duration,
    dups: usize,
    noops: usize,
    oversized: usize,
    errors: usize,
}

struct BoxedProbe(Box<dyn Probe + Send>);
#[async_trait]
impl Probe for BoxedProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> { self.0.send(req).await }
}

async fn boxed_run(probe: Box<dyn Probe + Send>, probes: usize) -> Run {
    let s = WeightedSampler::default_weights();
    let h = HavocMutator::new(s.clone(), probes * 4);
    let c = SeedCorpus::from_seeds(["'", "<", "{{", "1 OR 1=1"]);
    let f: Box<dyn Feedback> = Box::new(HttpFeedback::default());
    let start = Instant::now();
    let o = EvolutionaryLoop::new(BoxedProbe(probe), c, s, h, f)
        .with_gen_ratio(0.3)
        .with_max_probes(probes)
        .with_signal_set(signal_set(ALL))
        .run(&baseline(), inject).await.unwrap();
    Run {
        hits: o.hits.len(), probes: o.probes_sent, corpus: o.final_corpus_size,
        elapsed: start.elapsed(),
        dups: o.duplicate_candidates_skipped, noops: o.mutation_noops,
        oversized: o.oversized_candidates_skipped, errors: o.probe_errors + o.timeouts,
    }
}

// ── 3. Replay ────────────────────────────────────────────────────────────────

async fn replay_report() {
    println!("\n═══════════════════════════════════════════════");
    println!("3. REPLAY  (same seed → same outcome)\n");

    for &seed in &[0u64, 42, 0xDEAD_BEEF] {
        let o1 = seeded(seed, 50).await;
        let o2 = seeded(seed, 50).await;
        let ok = o1.hits == o2.hits && o1.probes == o2.probes && o1.corpus == o2.corpus;
        println!("  seed {seed:#012x}: {}  (hits={}, probes={}, corpus={})",
            if ok { "✓ match" } else { "✗ DIVERGED" }, o1.hits, o1.probes, o1.corpus);
    }

    // Different seeds must diverge
    let a = seeded(0, 50).await;
    let b = seeded(1, 50).await;
    let same = a.hits == b.hits && a.probes == b.probes && a.corpus == b.corpus;
    println!("  seeds 0 vs 1: {}  (should differ)", if same { "same (unlikely)" } else { "✓ different" });
}

async fn seeded(seed: u64, probes: usize) -> Run {
    let s = WeightedSampler::default_weights();
    let h = HavocMutator::new(s.clone(), probes * 4);
    let c = SeedCorpus::from_seeds(["'", "<", "{{", "1 OR 1=1"]);
    let f: Box<dyn Feedback> = Box::new(HttpFeedback::default());
    let start = Instant::now();
    let o = EvolutionaryLoop::new(NoisyProbe, c, s, h, f)
        .with_gen_ratio(0.3)
        .with_max_probes(probes)
        .with_signal_set(signal_set(ALL))
        .with_seed(seed)
        .run(&baseline(), inject).await.unwrap();
    Run {
        hits: o.hits.len(), probes: o.probes_sent, corpus: o.final_corpus_size,
        elapsed: start.elapsed(), dups: 0, noops: 0, oversized: 0, errors: 0,
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    throughput_report().await;
    discovery_report().await;
    replay_report().await;
    println!("\nDone. Run with `cargo run --example report --release`.");
}
