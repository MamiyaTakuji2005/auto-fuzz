# auto-fuzz

A simple fuzzing engine — feed it a target, a vocabulary, and a budget. It mutates, probes, classifies results, and evolves a corpus of promising payloads toward confirmed hits, all from a tiny initial table. Tries to be transport-agnostic, fully deterministic, and built for both batch sweeps and long runs.

## What it does

Generates candidate payloads by blending two strategies: chain-based grammar generation (atoms drawn from a weighted vocabulary) and stochastic havoc mutation (random operators applied to existing payloads). A single `gen_ratio` knob controls the mix — 0.0 is pure havoc, 1.0 is pure generation, 0.3 balances both.

Probes are sent through a `Probe` trait (HTTP, TCP, mock — anything that implements `async fn send`). Results are classified by a composable set of signal detectors (status, size, reflection, timing, error patterns, body diff). A baseline profile captured from a clean request filters out ambient noise before feedback evaluation decides what's interesting.

Interesting payloads join a living corpus. Entries carry energy scores (1–64); a power schedule picks parents proportional to energy, so payloads that triggered strong signals get mutated more often. The corpus never shrinks, but duplicates are rejected (energy is upgraded if the same payload is rediscovered with a stronger signal).

The loop stops when the probe budget is spent, a confirmed hit is found (if `stop_on_confirmation` is set), or the corpus runs dry.

## Why these choices

**Chain-weighted grammar** — instead of a fixed mutation table, atoms carry transition weights. `'` → ` OR ` is 5× more likely than `'` → `&`. This steers generation toward known-useful sequences without hardcoding paths. Unlisted pairs default to uniform, so the engine still explores.

**Generation + havoc blend** — pure grammar is predictable; pure havoc is chaotic. Blending them keeps the corpus diverse (generation finds novel shapes) while still exploiting promising leads (havoc mutates from high-energy parents).

**Baseline-aware signals** — a clean probe often triggers false signals (status codes, error pages, WAF fingerprints). Profiling the baseline once and filtering ambient signals per-variant (not just per-kind) keeps the corpus from filling with noise.

**Corpus power schedule** — LibAFL-style energy-weighted scheduling. Not every interesting payload is equally interesting — the ones that triggered errors or time delays deserve more CPU. Energy climbs with each interesting child (ratchet upward, proportional to signal score), so signal-rich lineages deepen their draw dominance over time. The 1–64 cap preserves asymmetry among hot leads — a time-delay parent climbs faster than a body-diff one. This is intentional: the fuzzer exploits depth when it finds signal, rather than balancing explore/exploit.

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
cargo run --bin calibrate --release     # calibration sweep
cargo test                              # 77 tests
```

## Calibration notes

Run via: `cargo run --bin calibrate --release -- targets.toml`

DEFAULT_TRIALS = 20, BASE_SEED = 42, DEFAULT_MAX_PROBES = 300.

---

### 1. PlacementPolicy sweep — 5×5 grid + 3 wrap combos

Swept (append, prepend) at [0.0, 0.5, 1.0, 2.0, 4.0] with wrap=0, plus default/wrap/wrap+b.

- Single-digit targets: placement irrelevant (~965–982 all combos).
- `pair-42`: pure prepend best (908), append (902), default (894). ~14 hit gap.
- `pair-90`: pure append best (910), prepend (900), default (895). ~10 hit gap.
- `triple-137`: **wrap-only wins** (868). Default (862). Grid cells cluster at 853–862.
  Wrap doubles chain length, so 3-atom trigger has more landing chances.

- Against real web targets: placement matters MORE.
  `cmdi`: append-only smokes prepend-only (974 vs 723). Default (850) in the middle.
  `sqli`: same pattern, append-only = 951 vs prepend-only = 673. Default = 801.
  `sqli-strict`: same (913 append vs 703 prepend).
  `xss`: append-only = 623, prepend-only = 599, default = 602.

Takeaway: append is almost always better than prepend. Default (1.5/1.0/0.5) softens the
blow by mostly appending anyway. Wrap helps long-chain targets but hurts short-chain ones.

---

### 2. ops_per_step sweep — 1, 2, 4, 8, 16

**Monotonic decay: fewer ops = more hits.**

| Target | ops=1 | ops=2 | ops=4 (default) | ops=8 | ops=16 |
|--------|-------|-------|-----------------|-------|--------|
| digit-0 | 984 | 978 | 963 | 948 | 940 |
| digit-3 | 983 | 981 | 975 | 979 | 974 |
| pair-42 | 947 | 917 | 894 | 865 | 845 |
| triple-137 | 934 | 897 | 862 | 835 | 797 |
| sqli | 864 | 843 | 801 | 777 | 720 |
| xss | 704 | 654 | 602 | 553 | 519 |
| cmdi | 880 | 866 | 850 | 817 | 774 |
| ssti | 757 | 731 | 708 | 669 | 655 |

xss-reflected is the ONLY exception: ops=4 (433) > ops=1 (363). Complex XSS vectors
need more mutation steps to assemble.

Cause: each havoc operator pushes payload further from seed. With 4 ops the candidate
is so mutated it rarely contains the trigger. With 1 op it stays in the high-signal
neighbourhood.

Default of 4 is leaving 30–90 hits/1k on the table for most targets.

---

### 3. HttpFeedback rank calibration — 8 scoring presets

Tested: default, flat3 (all=3), flat6 (all=6), compressed (1–3), expanded (4–12),
status>error (swap top 2), bodydiff+ (5), strict (min_corpus_score=4).

| Target | default | flat3 | flat6 | compressed | expanded | status>error | bodydiff+ | strict |
|--------|---------|-------|-------|-----------|---------|--------------|-----------|--------|
| cmdi | 850 | 841 | 850 | 843 | 839 | 850 | 850 | 850 |
| sqli | 801 | 809 | 810 | 811 | 810 | 810 | 801 | 801 |
| ssti | 708 | 703 | 720 | 710 | 703 | 708 | 708 | 708 |
| xss | 602 | 609 | 599 | 598 | 595 | 602 | 602 | 602 |
| xss-reflected | 433 | 438 | 444 | 451 | 444 | 433 | 433 | 433 |

Ranking barely matters. Default vs flat3 vs flat6 are within noise (±10 hits/1k) on
every target. The hardcoded Error=6 > TimeDelay=5 > Reflected=4 hierarchy provides
no measurable advantage over flat scoring.

Takeaway: the energy cap at 64 absorbs score differences. Current scoring is fine.

---

### 4. min_corpus_score sweep — 1 through 6

Flat at 1–4 for all targets. All firing signals score ≥3–6, so threshold 1 vs 4
changes nothing. At 5 most targets die (strongest signal is 4 for StatusDelta/Reflected).
At 6 only sqli-strict survives (has Error=6).

Takeaway: step function gated by signal score. Default of 2 is safe.

---

### 5. LengthPolicy internal params — stop_prob + min_atoms

**stop_prob sweep** (min_atoms=1, max=32):

| Target | stop=0.10 | 0.25 (medium) | 0.50 (short) | 0.75 | 0.90 |
|--------|-----------|--------------|-------------|------|------|
| sqli | 769 | 827 | 874 | 892 | 897 |
| xss | 518 | 643 | 711 | 736 | 746 |
| cmdi | 805 | 873 | 898 | 918 | 928 |
| ssti | 599 | 738 | 819 | 842 | 855 |
| xss-refl | 362 | 459 | 527 | 562 | 579 |

Monotonic increase. Higher stop_prob = shorter chains = more hits. Current medium
preset (0.25) is second-worst. Optimal is 0.90 — chains of 1–2 atoms almost always.

**min_atoms sweep** (stop_prob=0.25, max=32):

| Target | min=1 | min=2 (medium) | min=3 | min=4 (long) |
|--------|-------|----------------|-------|--------------|
| sqli | 827 | 812 | 795 | 778 |
| xss | 643 | 596 | 569 | 524 |
| cmdi | 873 | 841 | 834 | 804 |
| ssti | 738 | 703 | 668 | 636 |

Also monotonic: min_atoms=1 always best.

**KEY INSIGHT:** The presets are backwards. `long()` (used by XSS, SSTI, path_traversal
in agent.rs) is the worst choice for every target. Combined with ops_per_step finding:
conservative payloads win. Short chains, few mutations, stay close to the seed.

---

### 6. Vocab enrichment — per-class atom tables

Tested: xss+ (added `script`, `img`, `svg`, `src=`, `alert(1)` + chains),
sqli+ (added ` OR `→`1=1`, ` SELECT `→`NULL`, ` AND `→`1=2`),
ssti+ (added `{{7*'7'}}`, `{{config}}` as single atoms).

Results at gen_ratio=1.0 (pure generation):

| Target | default | xss+ | sqli+ | ssti+ |
|--------|---------|------|-------|-------|
| xss | 678 | 655 | 683 | 712 |
| ssti | 678 | 655 | 683 | 712 |
| sqli | 841 | 822 | 844 | 846 |
| sqli-strict | 863 | 843 | 867 | 875 |
| cmdi | 848 | 828 | 856 | 859 |
| xss-reflected | 0 | 0 | 0 | 0 |
| path-traversal | 0 | 0 | 0 | 0 |
| ssrf | 0 | 0 | 0 | 0 |

Adding atoms HURTS. XSS+ scored WORSE (655 vs 678) — more atoms = lower probability
of picking useful ones. Vocabulary dilution outweighs chain connectivity.

Adding complete-probe atoms (ssti+) helps slightly (+34 hits/1k) but that's just
embedding known-good probes into the vocabulary, not generation from fragments.

xss-reflected stays at 0 always. Root cause: mock probe bug in `mock_config.rs:91`
(split('=').nth(1) truncates at `=`). Not actually about the chain table.

path-traversal + ssrf stay at 0 always. Root cause: SizeDelta min_abs=50 is too
high for their small mock trigger bodies — see item 9.

**Takeaway:** Shared atom table is actively harmful. Each vulnerability class should
have its own focused atom vocabulary. The architecture already supports this via
`WeightedSampler::from_proto_config()`. Currently all agent.rs presets use the full
ATOMS table — they shouldn't.

---

### 7. Energy boost mechanism — BoostMode

Not yet calibrated. BoostMode enum added to SeedCorpus:
- `None` — no energy growth (pure exploration)
- `Additive` — energy += score (current)
- `Flat` — energy += 1 regardless of signal
- `Multiplicative` — energy *= (6+score)/6 (exponential)

---

### 8. Individual HavocOp ablation

Not yet done.

---

### 9. Signal classifier thresholds

Not yet done. Known issue: SizeClassifier `min_abs=50` is too high for small mock
trigger bodies. path-traversal body is 33 bytes, ssrf body is 12 bytes — both below
threshold, so no signal fires, so the engine can never confirm these targets regardless
of how good the payload is.

---

### 10. Atom dead-weight audit

Not yet done.

---

### Old calibrated defaults (v0.2, pre-audit)

These are from the old 3-phase sweep. Most values are now known to be suboptimal:

| Preset | gen_ratio | LengthPolicy | Notes |
|--------|-----------|-------------|-------|
| `sql_injection` | 0.8 | medium | — |
| `xss` | 0.8 | **long** | Should be short or stop=0.75 |
| `ssti` | 0.8 | **long** | Should be short — long actively hurts |
| `command_injection` | 0.7 | short | OK |
| `path_traversal` | 0.7 | **long** | Should be short |
| `nosql_injection` | 0.7 | short | OK |
| `ssrf` | 0.0 | medium | OK (pure havoc anyway) |
| `xxe` | 0.0 | medium | OK (pure havoc anyway) |

Also: `ops_per_step` should be 1 or 2, not 4. And all presets should use focused
atom tables instead of the full ATOMS.

---

### Mock probe bug

`src/mock_config.rs:91`: `req.url.split('?').nth(1).split('=').nth(1)` truncates
payload at the second `=` sign. Candidate `<img src=x onerror=alert(1)>` extracts
as `<img src`. The trigger check still matches `<img`, but the response body only
reflects the truncated version, so ReflectionClassifier compares full candidate
against truncated body → no match.

This makes xss-reflected untestable with the current mock probe.
