auto-fuzz README
================

An evolutionary fuzzer engine. Feed it a target, a vocabulary,
and a budget — it mutates, probes, classifies the results, and
evolves a corpus of promising payloads toward confirmed hits.

Architecture: four decoupled layers stacked below a loop.
  atoms → sampler → mutator → loop (with signals + feedback)


═══════════════════════════════════════════════════════════════
LAYER 1 — ATOMS (src/evolutionary/atoms.rs)
═══════════════════════════════════════════════════════════════

The vocabulary. Each "atom" is a short string the engine can
chain together to build payloads.

  ATOMS            — 52 web-attack atoms  (' " < {{ }} ; OR  .. % etc.)
  NUMERIC_ATOMS    — 18 boundary values   (0 1 -1 NaN Infinity 2147483647 etc.)

              ┌─ Hardcoded. You can pass your own Vec<String> instead.
              │
  Fixed →     │  atoms = ["X"]    (one atom, one possible payload path)
              │  atoms = []       (falls back to ATOMS — still variable)
              └─ ChainTable controls choice BETWEEN atoms (see below).


ChainTable
  A sparse (from, to) → weight map. When the sampler decides "what atom
  comes next after this one?", it looks up the weight. Unlisted pairs
  default to 1.0.

  Weight bands:  0.0=never   0.2=unlikely   1.0=default
                 2.0=mild    5.0=strong     20.0=near-deterministic

              ┌─ new() → all pairs weight=1.0 (uniform random)
  Default →   │
  Fixed →     │  chain.set("4", "2", 5.0)    — steers "4→2" 5× more likely
              │  chain.set("X", "Y", 20.0)   — nearly always "X→Y"
              │  Empty table = uniform       — every atom equally likely
              └─ No way to disable; weights only steer, never force.


PlacementPolicy
  Where the generated chain lands relative to the base payload.
  Three weights: append (default 1.5), prepend (1.0), wrap (0.5).

  append  →  base + chain
  prepend →  chain + base
  wrap    →  chain + base + chain

              ┌─ append_only()   → every chain ALWAYS appends
  Fixed →     │  prepend_only()  → always prepends
              │  wrap_only()     → always wraps
              └─ Set a weight to 0.0 to disable that direction entirely.


LengthPolicy
  How many atoms per generated chain. Geometric distribution: after
  min_atoms, each extra atom has stop_prob chance of stopping.

              ┌─ fixed(N)    → exactly N atoms, every time
  Fixed →     │  short()     → 1–6 atoms, 0.5 stop probability
              │  medium()    → 2–12 atoms, 0.25 stop (default)
              │  long()      → 4–24 atoms, 0.1 stop
              └─ min=max + stop=1.0  → same as fixed(N)


WeightedSampler
  Wires atoms + chain_table + placement + length into one object.
  Used by BOTH generation (apply_chain) and mutation (insert/replace).

              ┌─ default_weights()  → ATOMS + seeded chain table
  Presets →    │  uniform()         → ATOMS + blank chain table (all equal)
              │  numeric()          → NUMERIC_ATOMS + append-only + short
              └─ from_proto_config(…) → fully custom, atoms + weights + placement + length


═══════════════════════════════════════════════════════════════
LAYER 2 — SIGNALS (src/signals/)
═══════════════════════════════════════════════════════════════

Classify what changed between the baseline response and the probe
response. Each classifier looks for ONE kind of signal.

  Signal variants:  NoEffect    StatusDelta    SizeDelta
                    Reflected   Error          TimeDelay    BodyDiff

SignalSet
  A collection of classifiers. Runs all of them; returns every
  signal detected (not just the strongest). The feedback layer
  decides which signal to act on.

              ┌─ new() → empty set (nothing ever detected)
  Disable →   │
  Default →   │  SignalSet::defaults()  (all 6 classifiers below)
              └─ SignalSet::new().with(…)  → pick only the ones you want


StatusClassifier
  Detects when the HTTP status code changed between baseline and probe.

              ┌─ Always active when included. No config knobs.
  Disable →   │  Don't add it to your SignalSet.


SizeClassifier
  Detects when the response body grew or shrank enough.

  Config:  min_abs = 50   (minimum byte delta to care about)
           min_rel = 0.05 (minimum ratio delta)

              ┌─ min_abs=0, min_rel=0.0  → ANY size change is a signal
  All-on →    │  min_abs=usize::MAX      → effectively never fires
  Disable →   └─ Don't include in SignalSet.


ReflectionClassifier
  Detects when the injected payload appears in the response body,
  possibly percent-encoded (%3C) or HTML-encoded (&lt;).
  Skips single-char payloads (too many false positives).

              ┌─ Always active when included. No config knobs.
              │  Skips payloads shorter than 3 characters.
  Disable →   └─ Don't include in SignalSet.


TimeDelayClassifier
  Detects when the probe took noticeably longer than the baseline.

  Config:  min_factor = 3.0   (probe must be 3× slower)
           min_abs_ms = 500   (floor — 10ms→30ms is NOT a signal)

              ┌─ min_factor=1.0, min_abs_ms=0 → ANY slowdown
  All-on →    │  min_factor=1_000_000.0       → effectively never fires
  Disable →   └─ Don't include in SignalSet.


ErrorClassifier
  Regex library matching database error messages in the response body.

  Patterns database:  mysql, postgres, mssql, sqlite, oracle, generic
  (about a dozen regexes total)

              ┌─ dbms_starter() → the built-in DBMS patterns
  Default →   │  new(&[])       → empty pattern list, never matches
  Disable →   └─ Don't include in SignalSet.


BodyDiffClassifier
  Detects when the body changed structurally despite the SAME byte
  length. Catches ORDER BY injection and content reordering.

              ┌─ Always active when included. No config knobs.
  Disable →   └─ Don't include in SignalSet.


═══════════════════════════════════════════════════════════════
LAYER 3 — MUTATORS (src/signals/mutator.rs, evolutionary/havoc.rs)
═══════════════════════════════════════════════════════════════

Turn one payload string into another. The loop calls these each
iteration to produce candidates.

Mutator trait
  next_payload(&mut self, current: &str, signals: &[Signal]) -> Option<String>
  Returns None when the budget is exhausted → loop terminates.

StaticListMutator
  Walks a fixed list in order. Ignores signals. Batch-sweep pattern.

              ┌─ StaticListMutator::new(["a","b","c"])
              │  Returns "a", then "b", then "c", then None.
  Fixed →     └─ Same sequence every run.


SignalGuidedMutator
  Looks up the next payload by the strongest signal's kind.
  Table is a HashMap:  "error" → ["err1","err2"], "no_effect" → ["retry"]

              ┌─ Exhausts each bucket in order. Falls back to "no_effect"
              │  bucket when the signal-matched bucket runs dry.
              │  Once "no_effect" is also empty → returns None.
  Fixed →     └─ Same table = same response to same signals. RNG not involved.


HavocMutator
  12 stochastic operators (InsertToken, ReplaceWithToken, DeleteChunk,
  DuplicateChunk, SpliceSuffix, UrlEncodeChar, DoubleUrlEncodeChar,
  InsertBoundaryValue, RepeatPayload, WrapDelimiter, Reverse, Uppercase).
  Chains ops_per_step random ops each call. Uses its own internal RNG.

  Config:  budget      — max mutations before returning None
           ops_per_step — operators per call (default 4, min 1)

              ┌─ budget=0           → next_payload() returns None immediately
  Off →       │                        (= no mutations ever happen)
              │  with_seed(N)       → deterministic RNG for a given seed
  Fixed →     │  ops_per_step=1     → only 1 operator per call (less chaos)
              │  update_corpus([])  → empty corpus → SpliceSuffix is a no-op
              └─ gen_ratio=0.0      → loop never calls apply_chain, only havoc
                                      (set on EvolutionaryLoop, not HavocMutator)

  Operators (individual):
    InsertToken        — inserts a chain-weighted atom at random position
    ReplaceWithToken   — replaces random slice with chain-weighted atom
    DeleteChunk        — deletes random contiguous chunk
    DuplicateChunk     — duplicates a chunk and inserts it elsewhere
    SpliceSuffix       — appends a random suffix from the corpus
    UrlEncodeChar      — percent-encodes one random byte
    DoubleUrlEncode    — double-encodes (%25XX)
    InsertBoundaryVal  — inserts 0, -1, null, NaN, true, [], etc.
    RepeatPayload      — repeats the payload 2–4×
    WrapDelimiter      — wraps in ('', "", (), [], /* */, {{ }}, etc.)
    Reverse            — reverses the string
    Uppercase          — uppercases

              ┌─ No way to selectively disable individual operators through
              │  the public API. All 12 run with equal probability.
              └─ gen_ratio=1.0 on the loop disables ALL havoc (see below).


═══════════════════════════════════════════════════════════════
LAYER 4 — CORPUS (src/evolutionary/corpus.rs)
═══════════════════════════════════════════════════════════════

The living payload pool. Starts with seeds. Grows as interesting
payloads are discovered. Never shrinks (AFL-style).

CorpusEntry
  A single payload + what we know about it.
    payload       — the string
    best_signal   — strongest signal seen (None for unprobed seeds)
    energy        — 1–12, determines how often it gets picked as parent
    fuzz_count    — how many mutation children spawned from it
    parent_idx    — which entry it was derived from (None for original seeds)

SeedCorpus
  The collection. Entries are NEVER removed.

    from_seeds(…)     — build from a list of strings (energy=1 each)
    schedule(rng)     — power schedule: pick by energy weight
    push_discovered() — add a payload that triggered an interesting signal
    boost_energy()    — reward a parent whose child found something
    all_payloads()    — all strings, used by SpliceSuffix

              ┌─ from_seeds([])       → empty corpus → schedule() returns None
  Frozen →    │                         → loop breaks immediately
              │  from_seeds(["X"])    → single seed, energy=1, no evolution
              │                         until a hit raises its energy
              └─ No way to remove entries. Corpus only grows.

Feedback (trait)
  Decides what's interesting, how much energy to assign, and what's
  confirmed. Replaceable — implement the trait for custom logic.

    is_interesting(signals) → bool   — add to corpus?
    score(signals)          → u8     — what energy (0 = discard, 1–12)
    is_confirmed(signals)   → bool   — high-value hit, stop if asked

HttpFeedback (default implementation)
  Scores signals on a 0–6 scale:
    Error ...................................... 6
    TimeDelay ................................. 5
    Reflected ................................. 4
    StatusDelta(to ≥ 500) ..................... 4
    StatusDelta(other) ........................ 3
    SizeDelta(ratio ≥ 3.0 or ≤ 0.33) .......... 3
    SizeDelta(other) .......................... 2
    BodyDiff .................................. 2
    NoEffect .................................. 0

  is_interesting → score ≥ min_corpus_score (default 2)

  is_confirmed → Error, TimeDelay, Reflected(Literal), or StatusDelta(≥500)

              ┌─ min_corpus_score=0   → EVERYTHING joins the corpus
  All-in →    │                         (even NoEffect payloads)
              │
  Frozen →    │  min_corpus_score=255 → NOTHING ever joins the corpus
              │                         (corpus stays exactly the seeds)
              └─ Implement your own Feedback trait for full control.


═══════════════════════════════════════════════════════════════
LAYER 5 — EVOLUTIONARY LOOP (src/evolutionary/evolution.rs)
═══════════════════════════════════════════════════════════════

The main driver. Each iteration:

  1. corpus.schedule()   → pick parent by energy-weighted draw
  2. havoc.update_corpus → sync splice snapshot
  3. coin flip:
       heads (prob=gen_ratio): sampler.apply_chain(parent)   → grammar generation
       tails:                  havoc.mutate(parent)           → stochastic mutation
  4. probe.send(inject(candidate)) → get ProbeResponse
  5. signal_set.run(baseline, response) → classify signals
  6. feedback.is_interesting? → add to corpus, boost parent energy
  7. feedback.is_confirmed?   → record hit, maybe stop
  8. repeat until max_probes or corpus empty

EvolutionaryLoop<P>
  Config:
    gen_ratio           — f32, 0.0–1.0. Blend of generation vs havoc.
    max_probes          — usize, total probes to send.
    stop_on_confirmation — bool, stop after first confirmed hit (default false).
    rng_seed            — Option<u64>, deterministic replay.
    signal_set          — which classifiers to use.
    feedback            — Box<dyn Feedback>, scoring policy.
    request_timeout     — Duration, per-probe timeout.

  Builder methods:
    .with_gen_ratio(0.3)       — 30% generation / 70% havoc
    .with_max_probes(50)       — default
    .with_signal_set(…)        — custom classifiers
    .with_request_timeout(…)   — default 30s
    .with_seed(…)
    .stop_on_first_hit()       — break on first confirmed
    .exhaust_budget()          — keep going after confirmed (default)

              ┌─ gen_ratio=0.0  → NEVER generates chains, ONLY havoc
  Fixed →     │  gen_ratio=1.0  → ONLY generates chains, NEVER havoc
              │
              │  max_probes=1   → one probe, then stop
              │
              │  rng_seed=Some(N) → deterministic replay
              │    (same seed + same target behavior = same probe sequence,
              │     same corpus evolution, same hits — verified by tests)
              │
              │  stop_on_confirmation=true + max_probes=1
              │    → "surgical probe": one shot, report immediately
              │
  Off →       │  SeedCorpus::from_seeds([])
              │    → schedule() returns None → loop breaks instantly
              └─

EvolutionaryOutcome (returned by run())
  hits               — Vec<EvolutionaryHit>    (confirmed only)
  interesting        — Vec<EvolutionaryHit>    (all score ≥ threshold)
  probes_sent        — usize
  final_corpus_size  — usize

EvolutionaryHit
  payload    — String
  signals    — Vec<Signal>
  score      — u8
  parent_idx — usize
  confirmed  — bool


═══════════════════════════════════════════════════════════════
TRANSPORT LAYER (src/signals/mod.rs)
═══════════════════════════════════════════════════════════════

Probe trait  —  async fn send(&self, req: &Request) -> Result<ProbeResponse, String>
  Abstract transport. The loop doesn't know if it's HTTP, TCP, or a mock.
  Implement this to connect to your target.

Request
  url, method, headers (HashMap), body (String)

ProbeResponse
  status (u16), body (Vec<u8>), duration (Duration)


═══════════════════════════════════════════════════════════════
CHEAT SHEET
═══════════════════════════════════════════════════════════════

"Make it deterministic"       →  rng_seed = Some(42), gen_ratio = 1.0
"Disable havoc"               →  gen_ratio = 1.0
"Disable generation"          →  gen_ratio = 0.0
"Freeze the corpus"           →  min_corpus_score = 255
"Single shot"                 →  max_probes = 1, stop_on_first_hit = true
"No signals"                  →  SignalSet::new()  (empty — nothing detected)
"Only status signals"         →  SignalSet::new().with(Box::new(StatusClassifier))
"Fixed-length payloads"       →  LengthPolicy::fixed(N)
"Append-only"                 →  PlacementPolicy::append_only()
"Uniform atom choice"         →  ChainTable::new()  (all weights 1.0)
"One atom only"               →  atoms = ["X"]
"Empty corpus (no probes)"    →  SeedCorpus::from_seeds([])
"Custom feedback"             →  impl Feedback trait
"Custom transport"            →  impl Probe trait, pass to EvolutionaryLoop::new()
"Sweep SQLi payload table"    →  SeedCorpus::from_seeds(payloads::SQLI_PAYLOADS)

Run the demo:  cargo run --example digits
Launch the GUI: cargo run --bin fuzz-gui --features gui --release


═══════════════════════════════════════════════════════════════
PAYLOAD TABLES (src/payloads.rs)
═══════════════════════════════════════════════════════════════

Classic high-probability probes for common vulnerability classes.
Use as seed corpus to start from known-good payloads — the engine
mutates from there instead of from scratch.

  payloads::SQLI_PAYLOADS        — 68 entries  (error, boolean, UNION, time, stacked)
  payloads::XSS_PAYLOADS         — 26 entries  (script, img, svg, iframe, attribute)
  payloads::SSTI_PAYLOADS        — 20 entries  (Jinja2, Thymeleaf, ERB, FreeMarker)
  payloads::CMD_PAYLOADS         — 24 entries  (pipe, semicolon, backtick, subshell)
  payloads::PATH_TRAVERSAL_PAYLOADS — 16 entries (dot-dot-slash, encoding variants)
  payloads::XXE_PAYLOADS         —  3 entries  (external entity, OOB)
  payloads::NOSQLI_PAYLOADS      — 12 entries  ($gt, $ne, $regex, $where)
  payloads::SSRF_PAYLOADS        —  9 entries  (metadata, localhost, gopher, dict)

Usage:

  let seeds = payloads::SQLI_PAYLOADS;
  let corpus = SeedCorpus::from_seeds(seeds);  // 68 seeds, energy=1 each

  // Optional: also mix in atoms vocabulary seeds for exploration
  corpus.push_seed("'".into());
  corpus.push_seed("\"".into());

  let loop_ = EvolutionaryLoop::new(probe, corpus, sampler, havoc, feedback)
      .with_gen_ratio(0.3)  // 70% havoc mutates existing table entries
      .with_max_probes(200); // 200 probes covers most of the table +
                              // neighborhood exploration

The engine starts by scheduling table entries (all equal energy).
Havoc mutates them — splice, delete, insert, URL-encode. The ones
that trigger signals get energy boosts and produce more children.
Over time the corpus evolves beyond the table into novel payloads.
