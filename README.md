# auto-fuzz

An evolutionary fuzzer engine — feed it a target, a vocabulary, and a budget. It mutates, probes, classifies results, and evolves a corpus of promising payloads toward confirmed hits. Transport-agnostic, fully deterministic, and built for both batch sweeps and long-running campaigns.

## Features

**Dual-engine generation** — blends grammar-based chain generation (52 web-attack atoms with weighted transitions) and 12 stochastic havoc operators, controlled by a single `gen_ratio` knob. Generation builds novel payloads from scratch; havoc mutates existing ones. Blend them or go pure.

**Power-scheduled corpus** — entries carry energy (1–12). A bucket-based O(1) scheduler picks parents proportional to energy, so high-signal payloads receive more mutations. Corpus deduplication with payload-to-index map keeps lookup O(1) and upgrades energy when a stronger signal is rediscovered.

**Six signal classifiers** — Status, Size, BodyDiff, Reflection (literal / percent-encoded / HTML-encoded), TimeDelay, and Error (DBMS regex patterns). Composable via `SignalSet` — pick only what you need for your target.

**Baseline-aware filtering** — a `BaselineProfile` captures ambient signals from a clean request. Before evaluating feedback, the loop strips anything the baseline already exhibits. Variant-specific matching (not just `kind()` labels) keeps filtering precise.

**Context-aware feedback** — `Feedback::evaluate(&EvaluationContext)` receives the full probe picture: payload, request, baseline response, probe response, raw signals, filtered signals, timing, and transport errors. Single-pass evaluation with no repeated iteration.

**Candidate-level dedup** — fast u64 fingerprint (`DefaultHasher`) prevents duplicate probes. Combined with no-op mutation retry (resample up to 3× if the candidate equals the seed).

**Weighted operator schedule** — `HavocSchedule` with 12 per-operator weights (all `pub` for future adaptive tuning). Defaults bias toward structural ops (insert/replace/splice at 3.0) and away from destructive ones (reverse/uppercase at 0.3). Swap in `HavocSchedule::uniform()` for classic behavior.

**Global payload cap** — `PayloadPolicy { max_len, reject_oversized }` gates candidates before transport. Prevents memory pressure, server-side rejection, and accidental self-DoS from unbounded growth.

**Diagnostic counters** — `EvolutionaryOutcome` reports `probe_errors`, `timeouts`, `duplicate_candidates_skipped`, `oversized_candidates_skipped`, and `mutation_noops`. See at a glance whether a run was effective or wasted.

**Deterministic replay** — seed the RNG once; the engine auto-derives a separate seed for havoc via golden-ratio offset. Same seed + same target behavior = same probe sequence, same corpus, same hits. Dual-mode RNG: `SmallRng` for throughput, `ChaCha12Rng` for cross-platform bit-identical replay.

**Agent facade** — `Fuzzer` builder with 8 vulnerability presets (SQLi, XSS, SSTI, CMD injection, path traversal, NoSQLi, SSRF, XXE) and 8 `InjectionPoint` strategies (query param, form body, JSON body, XML, GraphQL, headers, path segments, raw body templates). One-liner: `Fuzzer::sql_injection().target(url, "GET").inject_query("q").run().await`.

**Transport-agnostic** — the `Probe` trait abstracts the wire. Ships with mock probes for testing; plug in HTTP, TCP, or anything else.

## Strengths

**Hot-path performance** — per-iteration cost dominated by the network probe, not the engine:

| Operation | Approach |
|-----------|----------|
| Power schedule | O(1) 12-bucket weighted draw |
| Corpus dedup | O(1) `HashMap<String, usize>` |
| Atom sampling | Precomputed cumulative transition tables, zero allocations |
| Havoc operator selection | Stack-allocated `[HavocOp; 32]` array |
| Corpus splice sync | Incremental `push_corpus_payload()` — one string per growth |
| Char-boundary ops | ASCII fast path — direct byte indexing, no `char_indices` scans |
| Candidate dedup | `DefaultHasher::finish()` → `HashSet<u64>` |
| No-op detection | Post-hoc `candidate != seed` comparison |

**Binary size** — ~1 MB (release, LTO, stripped). `rand_chacha` adds negligible overhead.

**Zero unsafe** — entire crate compiles clean without unsafe blocks.

**73 tests** — deterministic replay, single-atom invariance, Unicode safety, operator coverage, classifier precision, baseline filtering, corpus power schedule, and ASCII/Unicode fast-path validation.

## Architecture

```
atoms → sampler → mutator → loop (with signals + feedback) → transport
```

### Atoms (`evolutionary/atoms.rs`)
- **ATOMS** — 52 web-attack atoms (`'`, `"`, `<`, `{{`, `}}`, ` OR `, ` UNION `, `..`, etc.)
- **NUMERIC_ATOMS** — 18 boundary values (`0`, `-1`, `NaN`, `Infinity`, `2147483647`, etc.)
- **ChainTable** — sparse `(from, to) → f32` weight map. 0.0 = never, 1.0 = default, 20.0 = near-deterministic. Pre-seeded with SQL/XSS/template/command/path chains.
- **PlacementPolicy** — append, prepend, or wrap with configurable weights.
- **LengthPolicy** — geometric stop probability. `short()`, `medium()`, `long()`, or `fixed(N)`.
- **WeightedSampler** — wires atoms + chain table + placement + length. Precomputed cumulative transition tables for zero-allocation sampling. Presets: `default_weights()`, `uniform()`, `numeric()`, `from_proto_config()`.

### Signals (`signals/`)
- Composable `SignalSet` with 6 classifiers. Each returns zero or more signals per probe.
- **BaselineProfile** — captures ambient signals from a clean request and filters them out before feedback evaluation. Variant-specific matching (status class+direction, error family+snippet, magnitude thresholds).
- `Probe` trait — `async fn send(&self, req: &Request) -> Result<ProbeResponse, String>`.

### Havoc (`evolutionary/havoc.rs`)
- **12 operators** — InsertToken, ReplaceWithToken, DeleteChunk, DuplicateChunk, SpliceSuffix, UrlEncodeChar, DoubleUrlEncodeChar, InsertBoundaryValue, RepeatPayload, WrapDelimiter, Reverse, Uppercase.
- **HavocSchedule** — per-operator weight table, `pub` fields for adaptive tuning. `sample()` is a single `gen::<f32>()` + 12-entry linear scan.
- UTF-8 safe: all string slicing uses `random_char_boundary()`. ASCII fast path skips char counting.

### Corpus & Feedback (`evolutionary/corpus.rs`)
- **SeedCorpus** — entries are never removed (AFL-style). Energy-weighted power schedule. Deduplication with energy upgrade on rediscovery.
- **Feedback** trait — `evaluate(&EvaluationContext) -> FeedbackEval`. Full context: payload, request, baseline, response, raw & filtered signals.
- **HttpFeedback** — signal-strength implementation. Scores 0–6; confirmed thresholds for Error, TimeDelay, Reflected(Literal), and StatusDelta(≥500).

### Loop (`evolutionary/evolution.rs`)
- **EvolutionaryLoop\<P: Probe\>** — `gen_ratio` blends generation and havoc. `max_probes` caps the budget. `stop_on_confirmation` for surgical probes. `PayloadPolicy` gates length. Candidate dedup and no-op retry.
- **EvolutionaryOutcome** — `hits`, `interesting`, `probes_sent`, `final_corpus_size`, `baseline_profile`, and 5 diagnostic counters.

### Transport
- `Request` — url, method, headers, body.
- `ProbeResponse` — status, body, duration.
- Implement `Probe` for any protocol.

## Quick Start

```rust
use auto_fuzz::evolutionary::*;
use auto_fuzz::signals::*;

// 1. Define transport
struct HttpProbe;
impl Probe for HttpProbe { /* ... */ }

// 2. Build the loop
let sampler = WeightedSampler::default_weights();
let havoc   = HavocMutator::new(sampler.clone(), 200);
let corpus  = SeedCorpus::from_seeds(["'", "\"", "<"]);
let fb      = Box::new(HttpFeedback::default());

let outcome = EvolutionaryLoop::new(HttpProbe, corpus, sampler, havoc, fb)
    .with_gen_ratio(0.3)
    .with_max_probes(100)
    .with_seed(42)
    .run(&baseline_req, |payload| Request {
        url: format!("http://target.com/?q={payload}"),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    }).await?;

println!("hits: {}, probes: {}", outcome.hits.len(), outcome.probes_sent);
```

Or use the agent facade:

```rust
use auto_fuzz::agent::Fuzzer;

let result = Fuzzer::sql_injection()
    .target("http://target.com", "GET")
    .inject_query("q")
    .with_seed(42)
    .run()
    .await?;

for hit in &result.hits {
    println!("confirmed: {} (score {})", hit.payload, hit.score);
}
```

## Payload Tables (`payloads.rs`)

Classic high-probability probes. Use as seed corpus:

| Table | Entries | Coverage |
|-------|---------|----------|
| `SQLI_PAYLOADS` | 68 | error, boolean, UNION, time, stacked |
| `XSS_PAYLOADS` | 26 | script, img, svg, iframe, attribute |
| `SSTI_PAYLOADS` | 20 | Jinja2, Thymeleaf, ERB, FreeMarker |
| `CMD_PAYLOADS` | 24 | pipe, semicolon, backtick, subshell |
| `PATH_TRAVERSAL_PAYLOADS` | 16 | dot-dot-slash, encoding variants |
| `XXE_PAYLOADS` | 3 | external entity, OOB |
| `NOSQLI_PAYLOADS` | 12 | $gt, $ne, $regex, $where |
| `SSRF_PAYLOADS` | 9 | metadata, localhost, gopher, dict |

## Cheat Sheet

| Goal | How |
|------|-----|
| Deterministic replay | `.with_seed(42)` |
| Cross-platform replay | `.with_rng_mode(RngMode::ChaCha12).with_seed(42)` |
| Only generation | `.with_gen_ratio(1.0)` |
| Only havoc | `.with_gen_ratio(0.0)` |
| Freeze corpus | `HttpFeedback { min_corpus_score: 255 }` |
| Single shot | `.with_max_probes(1).stop_on_first_hit()` |
| No signals | `SignalSet::new()` |
| Fixed-length chains | `LengthPolicy::fixed(N)` |
| Append-only | `PlacementPolicy::append_only()` |
| Uniform atoms | `WeightedSampler::uniform()` |
| One atom only | `atoms = ["X"]` |
| Custom feedback | `impl Feedback` trait |
| Custom transport | `impl Probe` trait |
| Sweep payload table | `SeedCorpus::from_seeds(payloads::SQLI_PAYLOADS)` |
| Enable candidate dedup | `.with_dedup(true)` (default) |
| Cap payload length | `.with_payload_policy(PayloadPolicy::default())` (4096 bytes) |

## Running

```bash
# Demo
cargo run --example digits

# Benchmark
cargo run --example benchmark --release

# GUI workbench
cargo run --bin fuzz-gui --features gui --release

# Tests
cargo test
```
