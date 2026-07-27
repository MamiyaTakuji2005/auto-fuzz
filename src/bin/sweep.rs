// Parameter sweep: corpus_size (0-9) × vocab_size (1-9), 5 trials each.
//
// Usage:
//   cargo run --bin sweep > results.csv              # no signals
//   cargo run --bin sweep -- --signal > results_signal.csv  # one confirmed signal per run
//   python plot_sweep.py results.csv results_signal.csv

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use fuzzz::evolutionary::{
    ChainTable, EvolutionaryLoop, HttpFeedback, LengthPolicy,
    PlacementPolicy, SeedCorpus, WeightedSampler,
};
use fuzzz::evolutionary::havoc::HavocMutator;
use fuzzz::evolutionary::atoms::ATOMS;
use fuzzz::signals::{Probe, Request};
use fuzzz::signals::signal::ProbeResponse;

// ── Probes ────────────────────────────────────────────────────────────────────

struct NoopProbe;

#[async_trait]
impl Probe for NoopProbe {
    async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
        Ok(ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(1) })
    }
}

// Fires a confirmed SQL error on the first actual probe (second send call —
// call 0 is the baseline). All other calls return clean 200.
struct SignalOnceProbe { call_count: AtomicUsize }

impl SignalOnceProbe {
    fn new() -> Self { Self { call_count: AtomicUsize::new(0) } }
}

#[async_trait]
impl Probe for SignalOnceProbe {
    async fn send(&self, _req: &Request) -> Result<ProbeResponse, String> {
        let n = self.call_count.fetch_add(1, Ordering::SeqCst);
        if n == 1 {
            // First probe (n=0 was baseline): confirmed SQL error.
            Ok(ProbeResponse {
                status: 500,
                body: b"You have an error in your SQL syntax near '".to_vec(),
                duration: Duration::from_millis(1),
            })
        } else {
            Ok(ProbeResponse { status: 200, body: b"ok".to_vec(), duration: Duration::from_millis(1) })
        }
    }
}

// ── Sweep parameters ──────────────────────────────────────────────────────────

const MAX_PROBES: usize = 2000;
const TRIALS: u64 = 5;
const GEN_RATIO: f32 = 0.5;

// ── Builders ──────────────────────────────────────────────────────────────────

fn build_corpus(size: usize) -> SeedCorpus {
    SeedCorpus::from_seeds((0..size).map(|i| "a".repeat(i + 1)))
}

fn build_sampler(vocab_size: usize) -> WeightedSampler {
    let atoms: Vec<String> = ATOMS[..vocab_size].iter().map(|s| s.to_string()).collect();
    WeightedSampler::new(atoms, ChainTable::new(), PlacementPolicy::default(), LengthPolicy::medium())
}

fn base_req() -> Request {
    Request { url: "http://x.test/?q=1".into(), method: "GET".into(),
              headers: HashMap::new(), body: String::new() }
}

// ── Run one cell ──────────────────────────────────────────────────────────────

async fn run_cell<P: Probe + 'static>(
    probe: P,
    corpus_size: usize,
    vocab_size: usize,
    seed: u64,
) -> Option<(usize, usize, usize, usize)> {
    let corpus  = build_corpus(corpus_size);
    let sampler = build_sampler(vocab_size);
    let havoc   = HavocMutator::new(sampler.clone(), 200);
    let fb      = Box::new(HttpFeedback::default());

    let lp = EvolutionaryLoop::new(probe, corpus, sampler, havoc, fb)
        .with_gen_ratio(GEN_RATIO)
        .with_max_probes(MAX_PROBES)
        .with_seed(seed);

    lp.run(&base_req(), |p| Request {
        url: format!("http://x.test/?q={p}"),
        method: "GET".into(), headers: HashMap::new(), body: String::new(),
    }).await.ok().map(|out| (
        out.probes_sent,
        out.duplicate_candidates_skipped,
        out.mutation_noops,
        out.final_corpus_size,
    ))
}

// ── Main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let signal_mode = std::env::args().any(|a| a == "--signal");

    let corpus_range: Vec<usize> = (0..=9).collect();
    let vocab_range:  Vec<usize> = (1..=9).collect();
    let total = corpus_range.len() * vocab_range.len() * TRIALS as usize;
    let mode_label = if signal_mode { "signal-once" } else { "noop" };

    eprintln!("Mode: {mode_label} | {total} configurations ({MAX_PROBES} probes each)...");
    println!("corpus_size,vocab_size,trial,probes_sent,dedup_skipped,mutation_noops,final_corpus_size");

    for &corpus_size in &corpus_range {
        for &vocab_size in &vocab_range {
            for trial in 0..TRIALS {
                if corpus_size == 0 {
                    println!("{corpus_size},{vocab_size},{trial},0,0,0,0");
                    continue;
                }

                let seed = trial * 1000 + corpus_size as u64 * 10 + vocab_size as u64;

                let result = if signal_mode {
                    run_cell(SignalOnceProbe::new(), corpus_size, vocab_size, seed).await
                } else {
                    run_cell(NoopProbe, corpus_size, vocab_size, seed).await
                };

                match result {
                    Some((probes, dedup, noops, final_corpus)) =>
                        println!("{corpus_size},{vocab_size},{trial},{probes},{dedup},{noops},{final_corpus}"),
                    None =>
                        eprintln!("ERROR corpus={corpus_size} vocab={vocab_size} trial={trial}"),
                }
            }
        }
    }

    eprintln!("Done.");
}
