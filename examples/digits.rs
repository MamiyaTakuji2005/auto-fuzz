//! Step-by-step demo of the evolutionary fuzzer with atoms 0–9.
//!
//! Run: `cargo run --example digits`
//!
//! Hidden target: returns "ok" for most inputs, "SQL error near '42'" for "42",
//! and 500 for any payload containing "7". Seeds are ["1","2","3"] — the fuzzer
//! must discover "7" and "42" through evolution.

use auto_fuzz::evolutionary::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

// ── Mock target ────────────────────────────────────────────────────────────
// contains "42" → DBMS error (score 6, confirmed)
// contains "7"  → 500 status (score 4, interesting)
// else          → 200 "ok"

fn simulate(payload: &str) -> ProbeResponse {
    std::thread::sleep(Duration::from_millis(3));
    if payload.contains("42") {
        ProbeResponse {
            status: 500,
            body: "You have an error in your SQL syntax near '42'".into(),
            duration: Duration::from_millis(8),
        }
    } else if payload.contains('7') {
        ProbeResponse {
            status: 500,
            body: "internal error".into(),
            duration: Duration::from_millis(8),
        }
    } else {
        ProbeResponse {
            status: 200,
            body: b"ok".to_vec(),
            duration: Duration::from_millis(8),
        }
    }
}

struct MockServer;
#[async_trait]
impl Probe for MockServer {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        let payload = req.url.split("?q=").nth(1).unwrap_or("");
        Ok(simulate(payload))
    }
}

// ── Custom feedback — simple: error = confirmed, status delta = interesting ─

struct SimpleFeedback;
impl Feedback for SimpleFeedback {
    fn evaluate(&self, ctx: &EvaluationContext<'_>) -> FeedbackEval {
        let mut best = Signal::NoEffect;
        let mut best_rank: u8 = 0;
        let mut confirmed = false;
        for s in ctx.filtered_signals {
            let rank = match s {
                Signal::Error { .. } => { confirmed = true; 6 }
                Signal::StatusDelta { .. } => 4,
                _ => 0,
            };
            if rank > best_rank { best_rank = rank; best = s.clone(); }
        }
        FeedbackEval { score: best_rank, interesting: best_rank >= 2, confirmed, best_signal: best }
    }
}

// ── Main ───────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    println!("╔══════════════════════════════════════════════════════════════╗");
    println!("║         auto-fuzz — atoms [0-9], find \"7\" and \"42\"          ║");
    println!("╚══════════════════════════════════════════════════════════════╝\n");

    // ── 1. Atoms: just 0–9 ──────────────────────────────────────────────
    let atoms: Vec<String> = (0..=9).map(|d| d.to_string()).collect();
    println!("Atoms:      {atoms:?}");

    // ── 2. Chain weights: mild steer toward "42" ────────────────────────
    let mut chain = ChainTable::new();
    chain.set("4", "2", 5.0); // 4 is 5× more likely to be followed by 2
    println!("Chain:      4→2 weight=5.0 (mild grammatical steer)");

    let sampler = WeightedSampler::new(
        atoms,
        chain,
        PlacementPolicy::append_only(), // chain after base
        LengthPolicy::new(1, 4, 0.5),  // 1–4 digits per chain
    );

    // ── 3. Pure generation — gen_ratio=1.0, no havoc ───────────────────
    // With gen_ratio=1.0, every candidate is built from scratch via
    // apply_chain(). Havoc never runs, so no outside chars leak in.
    let havoc = HavocMutator::new(sampler.clone(), 200);

    // ── 4. Seeds ────────────────────────────────────────────────────────
    let seeds = vec!["1".to_string(), "2".to_string(), "3".to_string()];
    let corpus = SeedCorpus::from_seeds(&seeds);
    println!("Seeds:      {seeds:?}");

    // ── 5. Signal set — only status and DBMS error ──────────────────────
    let signal_set = SignalSet::new()
        .with(Box::new(StatusClassifier))
        .with(Box::new(ErrorClassifier::dbms_starter()));

    // ── 6. Build loop ───────────────────────────────────────────────────
    let loop_ = EvolutionaryLoop::new(
        MockServer,
        corpus,
        sampler,
        havoc,
        Box::new(SimpleFeedback),
    )
    .with_gen_ratio(1.0)      // pure generation
    .with_max_probes(30)
    .with_seed(99)
    .with_signal_set(signal_set);

    println!();
    println!("Engine:     gen_ratio=1.0, max_probes=30, seed=99");
    println!("Feedback:   Error→confirmed(6), StatusDelta→interesting(4)");
    println!("Classifiers: StatusClassifier, ErrorClassifier(dbms)");
    println!("Note:       Havoc disabled — only apply_chain() used.");
    println!("            No other characters can appear.\n");

    // ── 7. Run ──────────────────────────────────────────────────────────
    println!("══════════════════════════════════════════════════════════════");
    println!("RUNNING — 30 probes");
    println!("══════════════════════════════════════════════════════════════\n");

    let baseline_req = Request {
        url: "http://mock/?q=".into(),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    };

    let log = Mutex::new(Vec::new());
    let inject = |payload: &str| -> Request {
        log.lock().unwrap().push(payload.to_string());
        Request {
            url: format!("http://mock/?q={payload}"),
            method: "GET".into(),
            headers: HashMap::new(),
            body: String::new(),
        }
    };

    let outcome = loop_.run(&baseline_req, inject).await.unwrap();
    let log = log.into_inner().unwrap();

    // ── 8. Walk through each probe ──────────────────────────────────────
    println!("PROBE LOG  (●=interesting ·=no signal  ✓=confirmed):\n");
    for (i, payload) in log.iter().enumerate() {
        let resp = simulate(payload);
        let baseline = simulate("");
        let signals = SignalSet::defaults().run(payload, &baseline, &resp);
        let ctx = EvaluationContext {
            payload,
            request: &Request { url: "".into(), method: "GET".into(), headers: std::collections::HashMap::new(), body: "".into() },
            baseline: &baseline,
            response: &resp,
            probe_error: None,
            raw_signals: &signals,
            filtered_signals: &signals,
        };
        let fb = SimpleFeedback;
        let eval = fb.evaluate(&ctx);
        let icon = if eval.confirmed { "✓" } else if eval.interesting { "●" } else { "·" };
        let sigs: Vec<String> = signals.iter().map(|s| s.kind().to_string()).collect();
        println!(
            "  {icon}  #{:<2}  payload={:<10}  status={}  score={}  {sigs:?}",
            i + 1,
            format!("{:?}", payload),
            resp.status,
            eval.score,
        );
    }
    println!();

    // ── 9. Results ─────────────────────────────────────────────────────
    println!("══════════════════════════════════════════════════════════════");
    println!("RESULTS");
    println!("══════════════════════════════════════════════════════════════");
    println!("  Probes sent:  {}", outcome.probes_sent);
    println!("  Corpus:       {} → {} entries", seeds.len(), outcome.final_corpus_size);
    println!("  Confirmed:    {}", outcome.hits.len());
    println!("  Interesting:  {}", outcome.interesting.len());

    for h in &outcome.hits {
        let s: Vec<String> = h.signals.iter().map(|s| s.kind().to_string()).collect();
        println!("\n  ✓ CONFIRMED: payload={:?}  score={}  signals={s:?}", h.payload, h.score);
        println!("    ↳ DBMS error snippet matched — the fuzzer found \"42\"");
    }
    for h in &outcome.interesting {
        if !h.confirmed {
            let s: Vec<String> = h.signals.iter().map(|s| s.kind().to_string()).collect();
            println!("\n  ● INTERESTING: payload={:?}  score={}  signals={s:?}", h.payload, h.score);
            println!("    ↳ Status changed 200→500 — the fuzzer found \"7\"");
        }
    }

    println!("\nDONE.\n");
    println!("How it worked:");
    println!("  Seeds [\"1\",\"2\",\"3\"] → power schedule picks parent → apply_chain()");
    println!("  builds 1–4 digit payloads → probe → classify → if interesting,");
    println!("  payload joins corpus → boosted energy makes it more likely to be");
    println!("  picked as parent → mutations build on prior success → convergence.");
}
