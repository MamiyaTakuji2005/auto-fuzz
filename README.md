# auto-fuzz

An evolutionary fuzzing engine for web targets. Atom-chain generation with havoc mutation, driven by response signal feedback.

Extracted from the [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise) project as a standalone library and binary.

## What it does

auto-fuzz discovers payloads by evolving a corpus of candidates through two stages per iteration:

1. **Generation** — builds new payloads from an atom vocabulary using weighted chain transitions (what follows what)
2. **Havoc mutation** — applies a random sequence of 12 stochastic operators to existing corpus entries

Each candidate is sent to a target via a user-supplied `Probe` trait. Responses are classified into typed signals (status change, reflection, error family, time delay, size delta). Signals feed back into the corpus scheduler: interesting payloads get more energy, uninteresting ones get less.

This is not a static payload list. The engine has no fixed set of attack strings — it discovers them.

## Architecture

```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│ Atom Tables  │────▶│ ChainTable   │────▶│  Weighted    │
│ (vocabulary) │     │ (transitions)│     │  Sampler     │
└─────────────┘     └──────────────┘     └──────┬──────┘
                                                 │
                   ┌──────────────┐     ┌────────▼───────┐
                   │ HavocMutator │────▶│ EvolutionaryLoop│
                   │ (12 operators)│     │ (corpus + feedback)│
                   └──────────────┘     └────────┬───────┘
                                                 │
                                       ┌─────────▼────────┐
                                       │   Probe (trait)   │
                                       │   → HTTP / mock   │
                                       └─────────┬────────┘
                                                 │
                                       ┌─────────▼────────┐
                                       │  SignalSet        │
                                       │  (classifiers)    │
                                       └─────────┬────────┘
                                                 │
                                       ┌─────────▼────────┐
                                       │  Feedback → Energy│
                                       │  (power schedule) │
                                       └──────────────────┘
```

### Four decoupled primitives

| Primitive | Role |
|-----------|------|
| **Atom tables** | The vocabulary — from single bytes (`'`, `<`) to space-padded keywords (` OR `, ` UNION `) |
| **ChainTable** | Weighted (prefix, suffix) transitions. 0.0 = never, 1.0 = default, 5.0 = strong preference, 20.0 = near-deterministic |
| **PlacementPolicy** | Where generated chains land: append, prepend, wrap |
| **LengthPolicy** | Geometric stop probability, decoupled from chain weights |

### Signal classifiers

Each classifier inspects a `(baseline, probe)` pair and returns one signal variant:

| Classifier | Detects |
|------------|---------|
| `StatusClassifier` | HTTP status code changes |
| `SizeClassifier` | Body length changes |
| `ReflectionClassifier` | Payload reflected in response (with encoding detection) |
| `ErrorClassifier` | Regex-matched error families (MySQL, PostgreSQL, Java stack traces) |
| `TimeDelayClassifier` | Response time crosses threshold |

### Havoc operators

12 mutation operators, selected by weighted schedule: `InsertToken`, `ReplaceWithToken`, `DeleteChunk`, `DuplicateChunk`, `SpliceSuffix`, `UrlEncode`, `DoubleUrlEncode`, `InsertBoundaryValue`, `RepeatPayload`, `WrapDelimiter`, `Reverse`, `Uppercase`.

## Usage as a library

```rust
use auto_fuzz::agent::Fuzzer;
use auto_fuzz::signals::{Probe, Request};
use auto_fuzz::signals::signal::ProbeResponse;
use std::time::Duration;

struct MyProbe;
#[async_trait::async_trait]
impl Probe for MyProbe {
    async fn send(&self, req: &Request) -> Result<ProbeResponse, String> {
        // Your HTTP logic here
        todo!()
    }
}

let result = Fuzzer::new(MyProbe)
    .sql_injection()
    .target("https://example.com/search?q=", "GET")
    .budget(100)
    .run()
    .await
    .unwrap();

// result.confirmed — all confirmed SQLi payloads
// result.rejected — payloads that triggered signals but didn't confirm
```

### Presets

Each preset configures the appropriate signal classifiers, chain weights, and generation parameters for a vulnerability class:

```rust
Fuzzer::new(probe).sql_injection()   // Status + Error + TimeDelay classifiers
Fuzzer::new(probe).xss()             // Status + Reflection + SizeDiff classifiers
Fuzzer::new(probe).command_injection() // Status + Size + Reflection + Error + TimeDelay
Fuzzer::new(probe).ssrf()            // Status + TimeDelay + Size
Fuzzer::new(probe).path_traversal()  // Status + Size + Reflection
Fuzzer::new(probe).custom()          // User-configured
```

### Fuzz modes

```rust
// Table mode — sweep a fixed payload list, then evolve from confirmed hits
Fuzzer::new(probe).table_mode(payloads)

// Evolutionary mode — generate + mutate from scratch
Fuzzer::new(probe).evolutionary_mode()

// TableThenEvolutionary — sweep table first, feed confirmed hits into evolutionary
Fuzzer::new(probe).table_then_evolutionary(payloads)
```

## Running examples

```bash
# Benchmark report — throughput, discovery, waste metrics
cargo run --example report --release

# Simple demonstration
cargo run --example digits --release

# GUI (requires gui feature)
cargo run --bin fuzz-gui --features gui --release
```

## Calibration

Internal benchmarks for tuning preset parameters across vulnerability classes:

```bash
cargo run --bin calibrate --release
```

Sweeps three axes (gen_ratio, length policy, havoc schedule) across four mock targets (SQLi, XSS, CMDi, SSTI), 5 trials per point. Writes `calibration_results.csv`.

## Deterministic replay

The engine supports seeded replay via `ChaCha12Rng`:

```rust
let loop = EvolutionaryLoop::new(probe, corpus, sampler, havoc, feedback)
    .with_seed(42)  // same seed + same target = same probe sequence
    .with_rng_mode(RngMode::ChaCha12);  // stable across Rust versions
```

Same seed produces the same corpus evolution and confirmed payloads in the same order. Useful for reproducing findings and comparing parameter changes.

## Feature flags

| Feature | Description |
|---------|-------------|
| `gui` | Enables `fuzz-gui` binary (reqwest + egui) |
| (default) | Core library only — no GUI dependencies |

## License

MIT
