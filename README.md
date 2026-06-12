# auto-fuzz

A simple fuzzing engine — feed it a target, a vocabulary, and a budget. It mutates, probes, classifies results, and evolves a corpus of promising payloads toward confirmed hits, all from a tiny initial table. Tries to be transport-agnostic, fully deterministic, and built for both batch sweeps and long runs.

## What it does

Generates candidate payloads by blending two strategies: chain-based grammar generation (atoms drawn from a weighted vocabulary) and stochastic havoc mutation (random operators applied to existing payloads). A single `gen_ratio` knob controls the mix — 0.0 is pure havoc, 1.0 is pure generation, 0.3 balances both.

Probes are sent through a `Probe` trait (HTTP, TCP, mock — anything that implements `async fn send`). Results are classified by a composable set of signal detectors (status, size, reflection, timing, error patterns, body diff). A baseline profile captured from a clean request filters out ambient noise before feedback evaluation decides what's interesting.

Interesting payloads join a living corpus. Entries carry energy scores (1–12); a power schedule picks parents proportional to energy, so payloads that triggered strong signals get mutated more often. The corpus never shrinks, but duplicates are rejected (energy is upgraded if the same payload is rediscovered with a stronger signal).

The loop stops when the probe budget is spent, a confirmed hit is found (if `stop_on_confirmation` is set), or the corpus runs dry.

## Why these choices

**Chain-weighted grammar** — instead of a fixed mutation table, atoms carry transition weights. `'` → ` OR ` is 5× more likely than `'` → `&`. This steers generation toward known-useful sequences without hardcoding paths. Unlisted pairs default to uniform, so the engine still explores.

**Generation + havoc blend** — pure grammar is predictable; pure havoc is chaotic. Blending them keeps the corpus diverse (generation finds novel shapes) while still exploiting promising leads (havoc mutates from high-energy parents).

**Baseline-aware signals** — a clean probe often triggers false signals (status codes, error pages, WAF fingerprints). Profiling the baseline once and filtering ambient signals per-variant (not just per-kind) keeps the corpus from filling with noise.

**Corpus power schedule** — LibAFL-style energy-weighted scheduling. Not every interesting payload is equally interesting — the ones that triggered errors or time delays deserve more CPU. Energy climbs with each interesting child (ratchet upward), so signal-rich lineages deepen their draw dominance over time. This is intentional: the fuzzer exploits depth when it finds signal, rather than balancing explore/exploit.

**Determinism** — one seed produces the same probe sequence every time. The loop and havoc RNGs are derived from a single seed via a golden-ratio offset so they stay independent but reproducible. Switch to `ChaCha12Rng` for bit-identical replay across Rust versions and platforms.

**Transport agnosticism** — the engine doesn't know what HTTP is. A `Probe` trait with a single `send` method abstracts the wire. Mock probes in tests, real HTTP in production, TCP for binary protocols — same loop.

## Performance notes

Per-iteration CPU cost is kept small so the network round-trip dominates:

- Power schedule: O(1) 12-bucket weighted draw (not O(n) linear scan)
- Corpus dedup: O(1) `HashMap<String, usize>` lookup
- Atom sampling: precomputed cumulative transition tables (no per-sample allocation)
- Operator selection: stack-allocated array, no heap allocation per mutate call
- Splice sync: incremental push on corpus growth (no full clone)
- Char-boundary ops: ASCII fast path (direct byte indexing instead of char counting)
- Candidate dedup: parent-scoped `HashSet<u64>` — resets on each new parent so every lineage explores its full neighbourhood independently

Release binary is ~1 MB (LTO, stripped). No unsafe code.

## Architecture

```
atoms → sampler → mutator → loop (signals + feedback) → transport
```

### Atoms (`evolutionary/atoms.rs`)
- 52 web-attack atoms (`'`, `"`, `<`, `{{`, `}}`, ` OR `, ` UNION `, `..`, etc.) plus 18 numeric boundary values
- `ChainTable` — sparse `(from, to) → f32` weight map. 0.0 = never, 1.0 = default, 20.0 = near-deterministic. Pre-seeded SQL/XSS/template/command chains
- `PlacementPolicy` — append, prepend, or wrap with weighted probabilities
- `LengthPolicy` — geometric stop probability. `short()`, `medium()`, `long()`, `fixed(n)`

### Signals (`signals/`)
- Six classifiers: Status, Size, BodyDiff, Reflection (literal / percent-encoded / HTML-encoded), TimeDelay, Error (DBMS regex library)
- `BaselineProfile` — captures and filters ambient signals. Variant-specific matching (status class + direction, error family + snippet, magnitude)
- `Probe` trait — `async fn send(&self, req: &Request) -> Result<ProbeResponse, String>`

### Havoc (`evolutionary/havoc.rs`)
- 12 operators: InsertToken, ReplaceWithToken, DeleteChunk, DuplicateChunk, SpliceSuffix, UrlEncodeChar, DoubleUrlEncodeChar, InsertBoundaryValue, RepeatPayload, WrapDelimiter, Reverse, Uppercase
- `HavocSchedule` — per-operator weight table with `pub` fields. Defaults bias toward structural ops (insert/replace/splice ~3.0) over destructive ones (reverse/uppercase ~0.3)
- All string slicing is UTF-8 safe via `random_char_boundary()`. ASCII payloads take a fast path

### Corpus & Feedback (`evolutionary/corpus.rs`)
- `SeedCorpus` — entries never removed. Bucket-based power schedule. Payload-to-index dedup
- `Feedback` trait — `evaluate(&EvaluationContext) -> FeedbackEval`. Receives payload, request, baseline, response, raw & filtered signals, timing
- `HttpFeedback` — default implementation. Scores signals 0–6. Confirmed on Error, TimeDelay, Reflected(Literal), StatusDelta(≥500)

### Loop (`evolutionary/evolution.rs`)
- `EvolutionaryLoop<P: Probe>` — blends generation and havoc via `gen_ratio`. Configurable probe budget, timeout, dedup, payload length cap, no-op retry, and RNG backend
- `EvolutionaryOutcome` — hits, interesting entries, probes sent, corpus size, baseline profile, plus diagnostic counters (errors, timeouts, duplicates/oversized skipped, no-op mutations)

## Quick start

```rust
use auto_fuzz::evolutionary::*;
use auto_fuzz::signals::*;

let sampler = WeightedSampler::default_weights();
let havoc   = HavocMutator::new(sampler.clone(), 200);
let corpus  = SeedCorpus::from_seeds(["'", "\"", "<"]);
let fb      = Box::new(HttpFeedback::default());

let outcome = EvolutionaryLoop::new(my_probe, corpus, sampler, havoc, fb)
    .with_gen_ratio(0.3)
    .with_max_probes(100)
    .with_seed(42)
    .run(&baseline_req, |payload| Request {
        url: format!("http://target.com/?q={payload}"),
        method: "GET".into(),
        headers: HashMap::new(),
        body: String::new(),
    }).await?;
```

Or use the agent facade for common vulnerability classes:

```rust
use auto_fuzz::agent::Fuzzer;

let result = Fuzzer::sql_injection()
    .target("http://target.com", "GET")
    .inject_query("q")
    .run()
    .await?;
```

## Payload tables (`payloads.rs`)

Pre-built probe sets for common vulnerability classes. Use as seed corpus:

| Table | Entries | Covers |
|-------|---------|--------|
| `SQLI_PAYLOADS` | 68 | error, boolean, UNION, time, stacked |
| `XSS_PAYLOADS` | 26 | script, img, svg, iframe, attribute |
| `SSTI_PAYLOADS` | 20 | Jinja2, Thymeleaf, ERB, FreeMarker |
| `CMD_PAYLOADS` | 24 | pipe, semicolon, backtick, subshell |
| `PATH_TRAVERSAL_PAYLOADS` | 16 | dot-dot-slash, encoding variants |
| `XXE_PAYLOADS` | 3 | external entity, OOB |
| `NOSQLI_PAYLOADS` | 12 | $gt, $ne, $regex, $where |
| `SSRF_PAYLOADS` | 9 | metadata, localhost, gopher, dict |

## Cheat sheet

| Goal | How |
|------|-----|
| Deterministic replay | `.with_seed(42)` |
| Cross-platform replay | `.with_rng_mode(RngMode::ChaCha12).with_seed(42)` (or `.with_seed(42).with_rng_mode(RngMode::ChaCha12)` — both work) |
| Only generation | `.with_gen_ratio(1.0)` |
| Only havoc | `.with_gen_ratio(0.0)` |
| Freeze corpus | `HttpFeedback { min_corpus_score: 255 }` |
| Single shot | `.with_max_probes(1).stop_on_first_hit()` |
| No signals | `SignalSet::new()` |
| Fixed-length chains | `LengthPolicy::fixed(n)` |
| Append-only | `PlacementPolicy::append_only()` |
| Uniform atom choice | `WeightedSampler::uniform()` |
| One atom only | `atoms = ["X"]` |
| Custom scoring | `impl Feedback` trait |
| Custom transport | `impl Probe` trait |
| Exact table sweep (no mutation) | `Fuzzer::sql_injection().mode(FuzzMode::Table).target("http://x", "GET").run().await` |
| Exact user inputs (no mutation) | `Fuzzer::sql_injection().mode(FuzzMode::InputsOnly).seeds([...]).run().await` |
| Cap payload length | `.with_payload_policy(PayloadPolicy::default())` |
| Disable candidate dedup | `.with_dedup(false)` |

## Running

```bash
cargo run --example digits              # demo
cargo run --example benchmark --release # speed test
cargo run --bin fuzz-gui --features gui --release  # desktop workbench
cargo test                              # 77 tests
```
