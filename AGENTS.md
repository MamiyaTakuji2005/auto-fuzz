# AGENTS.md — auto-fuzz

## What This Project Is

Evolutionary web fuzzer engine in Rust. Atom-chain generation + havoc mutation, driven by response signal feedback. Extracted from [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise).

## Build & Run

```bash
cargo check                              # type-check (fast)
cargo test                               # run all unit tests
cargo run --example report --release     # benchmarks
cargo run --bin calibrate --release -- targets.toml   # calibration sweep
cargo run --bin stress --release -- stress_targets.toml
cargo run --bin fuzz-gui --features gui --release   # GUI workbench
```

Binaries (`src/bin/`): `calibrate`, `stress`, `signal_sweep`, `atom_audit`, `cap_sweep`, `havoc_ablation`, `sweep`, `fuzz-gui` (feature `gui`).

**fuzz-gui** is the interactive workbench — exposes all 8 presets, 4 fuzz modes, 6 injection points, request timeout, and stop-on-first-hit. Uses the `Fuzzer` builder API directly with progress reporting and cancellation.

## Architecture

```
atoms → WeightedSampler (ChainTable) → HavocMutator → EvolutionaryLoop (signals + feedback) → Probe/transport
```

| Module | Responsibility |
|--------|---------------|
| `src/evolutionary/atoms.rs` | Atom vocabulary, ChainTable (Markov-like transitions), WeightedSampler, PlacementPolicy, LengthPolicy |
| `src/evolutionary/havoc.rs` | 12 stochastic mutation operators with weighted scheduling |
| `src/evolutionary/corpus.rs` | SeedCorpus with energy-bucketed power scheduling, Feedback trait, HttpFeedback |
| `src/evolutionary/evolution.rs` | Main loop blending generation (gen_ratio) with mutation |
| `src/evolutionary/rng.rs` | Dual-mode RNG (SmallRng for speed, ChaCha12 for replay stability) |
| `src/signals/signal.rs` | 7 classifiers: Status, Size, Reflection, TimeDelay, BodyDiff, Error, BodySignature (per-class leak-content signatures) |
| `src/signals/mutator.rs` | Signal-guided payload mutator (alternative to evolutionary engine) |
| `src/baseline.rs` | BaselineProfile — null-hypothesis signal filtering + confidence scoring |
| `src/agent.rs` | Fuzzer builder API with 8 vuln presets (SQLi, XSS, SSTI, CMDi, SSRF, path traversal, NoSQLi, XXE) |
| `src/payloads.rs` | Classic payload tables (179 payloads across 8 categories) |
| `src/mock_config.rs` | TOML-defined mock targets for offline calibration |

## Key Concepts

- **Atoms**: Minimal string tokens (`'`, `<`, `UNION`, `{{`, etc.) — the vocabulary.
- **ChainTable**: Sparse `(from, to) → weight` map for transition probabilities. Missing pairs default to 1.0.
- **gen_ratio**: 0.0 = pure havoc mutation, 1.0 = pure generation, 0.7 = default blend.
- **HavocOps**: 12 mutation operators (insert, replace, delete, duplicate, splice, URL-encode, boundary values, repeat, wrap, reverse, uppercase).
- **SeedCorpus**: AFL-inspired energy scheduling. High-energy entries get more mutations.
- **BaselineProfile**: Sends empty-payload request first, classifies ambient signals, filters them from probe results.

## Conventions

- Release profile: `opt-level = "z"`, LTO, single codegen unit, stripped symbols (size-optimized).
- Deterministic replay: use `RngMode::ChaCha12` + fixed seed.
- Mock targets defined in TOML (`targets.toml`, `stress_targets.toml`, `nums_targets.toml`).
- Calibration data/plots/scripts live in `stuff/` (gitignored).

## Calibration Status

Analysis is complete (see `stuff/CALIBRATION_TODO.md` and `stuff/CALIBRATION_IMPLICATIONS.md`).

**Mock-harness fixes applied** (previously three targets were stuck at 0 hits due
to test-harness artifacts, not the engine):
- Fixed `mock_config.rs` payload truncation at `=` → `xss-reflected` 0 → ~272/300.
- Realistic mock leak bodies + new `BodySignatureClassifier` (per-class content
  signatures) so path-traversal / SSRF can confirm on leaked content rather than
  the deliberately-noisy `SizeDelta` → both 0 → ~280/300. Targets declare
  `confirm_signatures` in TOML; `calibrate` wires them per-target.

**Tuning changes applied** (before/after via `calibrate targets.toml`, gen=0.7
baseline; all 8 targets improved, avg +20.1 hits/1k):

1. ✅ `ops_per_step`: 4 → 1 (`havoc.rs`) — fewer ops stay near the seed.
2. ✅ `replace_token` weight: 3.0 → 0.5 (`havoc.rs`) — replacing pushes off-trigger.
3. ✅ `repeat_payload` weight: 0.5 → 1.5 (`havoc.rs`) — repetition keeps trigger intact.
5. ✅ Remove `SizeClassifier` from SSTI preset (`agent.rs`).
6. ✅ `LengthPolicy` presets bias short + `min_atoms=1` (`atoms.rs`); the three
   presets that used `long()` (xss, ssti, path_traversal) switched to `short()`.

**Deferred:**

4. ⏸️ `TimeDelayClassifier.min_abs_ms`: 500 → 200 (`signal.rs`). Applying it
   *halved* ssrf's hits/1k — not lost detection, but the timing re-probe
   confirmation (`evolution.rs:354`) doubles probe cost on ssrf's deterministic
   200ms mock delay. No target in the current suite lives in the 200–500ms band
   to justify 200, so it buys nothing here. Revisit once a real time-based target
   in that band exists (and consider: a definitive non-timing confirmation
   like `LeakSignature`/`Error` should let the loop skip the timing re-probe).

## File Layout

```
src/
├── lib.rs                 # crate root
├── agent.rs               # Fuzzer builder API (main public interface)
├── baseline.rs            # null-hypothesis signal filtering
├── mock_config.rs         # TOML mock targets
├── payloads.rs            # classic payload tables
├── bin/                   # 8 tool binaries
├── evolutionary/          # core engine (atoms, havoc, corpus, evolution, rng)
└── signals/               # classification + mutator primitives
examples/                  # benchmark, digits demo, report suite
stuff/                     # calibration data, plots, scripts (gitignored)
targets.toml               # main calibration mock targets
stress_targets.toml        # extended stress test targets
nums_targets.toml          # numeric distribution test targets
```
