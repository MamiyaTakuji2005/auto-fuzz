# Calibration TODO

## 1. PlacementPolicy sweep — Sweep `(append, prepend, wrap)` weights

**Status: DONE** — 5×5 grid + 3 wrap combos, 20 trials per cell, `nums_targets.toml`.

Findings:
- Single-digit targets: placement irrelevant (~965–982 across all combos).
- Multi-atom targets show small but real effects:
  - `pair-42`: pure prepend best (908), append (902), default (894). ~14 hit gap.
  - `pair-90`: pure append best (910), prepend (900), default (895). ~10 hit gap.
  - `triple-137`: **wrap-only wins** (868) — wrap doubles chain length, giving the 3-atom chain more chances to land the trigger. Default (862) in the middle.
- `PlacementPolicy::default()` (1.5/1.0/0.5) is competitive but not optimal for any target. The effect is secondary to gen_ratio and ops_per_step.

## 2. ops_per_step sweep — Sweep 1, 2, 4, 8, 16 havoc operators per step

**Status: DONE** — 5 values, 20 trials each, `nums_targets.toml`.

Findings:
- **Monotonic decay: fewer ops = more hits. `ops=1` dominates every target.**

| Target | ops=1 | ops=2 | ops=4 (default) | ops=8 | ops=16 |
|--------|-------|-------|-----------------|-------|--------|
| digit-0 | 984 | 978 | 963 | 948 | 940 |
| digit-3 | 983 | 981 | 975 | 979 | 974 |
| digit-7 | 984 | 977 | 962 | 954 | 949 |
| pair-42 | 947 | 917 | 894 | 865 | 845 |
| pair-90 | 949 | 925 | 895 | 859 | 841 |
| triple-137 | 934 | 897 | 862 | 835 | 797 |

- Current default of 4 is leaving 30–90 hits/1k on the table.
- Cause: each havoc operator pushes the payload further from the seed. With 4 ops the candidate is so mutated it rarely contains the trigger pattern. With 1 op it stays in the high-signal neighborhood.
- This interacts with `gen_ratio=0.7` — only 30% of iterations use havoc. If gen_ratio were lower, the gap would widen.
- **Action: default should be lowered to 1 or 2. Needs validation against real web targets (not numeric) before committing.**

## 3. HttpFeedback rank calibration — Fitness function ranks (0–6) are hardcoded, never validated

**Status: DONE** — 8 scoring presets × 20 trials, both `nums_targets.toml` and `targets.toml`.

Presets tested: `default`, `flat3` (all=3), `flat6` (all=6), `compressed` (1–3), `expanded` (4–12), `status>error` (swap top 2), `bodydiff+` (BodyDiff=5), `strict` (min_corpus_score=4).

Findings:
- **Ranking barely matters.** Default vs flat3 vs flat6 are within noise (±5–10 hits/1k) on every target. The hardcoded Error=6 > TimeDelay=5 > Reflected=4 hierarchy provides no measurable advantage over flat scoring.
- **`status>error` is identical to default** on SQLi targets — both Error and StatusDelta fire simultaneously, so swapping their ranks doesn't change which signal wins.
- **`flat6` marginally helps SSTI** (720 vs 708) — higher absolute scores = faster energy accumulation.
- **`compressed` marginally helps sqli** (811 vs 801) and **xss-reflected** (451 vs 433) — its min_corpus_score=1 lets more payloads into the corpus.
- **`strict` and `bodydiff+` have zero effect** — the signals that fire are all ≥4, and BodyDiff never fires on these mock targets.
- **Conclusion:** the current scoring table is fine. The energy cap at 64 absorbs score differences. No action needed — the ranking is robust but not impactful. The real levers are gen_ratio, ops_per_step, and length policy.

**Also discovered from full targets.toml run:**
- `path-traversal` and `ssrf` get **0 hits across ALL sweeps** — the engine literally cannot generate `../../../../etc/passwd` or `http://169.254.169.254/...` from the current atom table + chain weights. Confirms item 6 (missing chains).
- `xss-reflected` gets **0 hits at gen=1.0** — pure generation can't assemble `<img src=x onerror=alert(1)>`. Only havoc from the seed works.
- `xss-reflected` ops sweep is **inverted**: ops=4 best (433), ops=1 worst (363). Complex payloads need more mutation steps to assemble.
- `ssti` **decreases** with higher gen_ratio (769 at gen=0.0 → 678 at gen=1.0). The chain table hurts SSTI generation.

## 4. min_corpus_score sweep — Corpus admission threshold (default 2) never swept

**Status: DONE** — 6 values (1–6) × 20 trials, `targets.toml`.

Findings:
- **Flat at 1–4 for all targets.** The threshold doesn't matter in this range because all firing signals score ≥3 (SizeDelta-high) to ≥6 (Error). Changing min_score from 2 to 4 has zero effect.
- **min_score=5**: kills all targets except `sqli-strict` (which fires Error=6). Any target whose strongest signal is StatusDelta(4) or Reflected(4) gets zero corpus entries → zero hits.
- **min_score=6**: only `sqli-strict` survives (Error=6).
- **Conclusion:** `min_corpus_score` is a step function gated by the signal's score. Current default of 2 is safe — it's in the "everything passes" zone. The threshold only matters for signals scoring 1–2 (BodyDiff, small SizeDelta), which don't fire on any current mock target. For real targets with dynamic content, this WOULD matter — worth revisiting with noisier mocks.

## 5. LengthPolicy internal params — Only presets swept; never `stop_prob`, `min_atoms` independently

**Status: DONE** — 5 stop_prob values + 4 min_atoms values × 20 trials, `targets.toml`.

### stop_prob sweep (min_atoms=1, max=32)

| Target | stop=0.10 | stop=0.25 (medium) | stop=0.50 (short) | stop=0.75 | stop=0.90 |
|--------|-----------|-------------------|-------------------|----------|----------|
| sqli   | 769       | 827               | 874               | 892      | **897**  |
| xss    | 518       | 643               | 711               | 736      | **746**  |
| cmdi   | 805       | 873               | 898               | 918      | **928**  |
| ssti   | 599       | 738               | 819               | 842      | **855**  |
| xss-refl | 362     | 459               | 527               | 562      | **579**  |

**Monotonic increase.** Higher stop_prob = shorter chains = more hits. The current `medium()` preset (stop=0.25) is the second-worst value. Optimal is stop=0.90, meaning chains of 1–2 atoms almost always.

### min_atoms sweep (stop_prob=0.25, max=32)

| Target | min=1 | min=2 (medium) | min=3 | min=4 (long) |
|--------|-------|----------------|-------|--------------|
| sqli   | **827** | 812          | 795   | 778          |
| xss    | **643** | 596          | 569   | 524          |
| cmdi   | **873** | 841          | 834   | 804          |
| ssti   | **738** | 703          | 668   | 636          |

Also monotonic: `min_atoms=1` is always best.

**KEY INSIGHT:** The current LengthPolicy presets are backwards. `long()` (used by XSS, SSTI, path_traversal presets in `agent.rs`) is the worst choice for every target. The engine performs best with very short chains (1–2 atoms). A single atom like `'` or `<` is a valid probe; a 12-atom chain of random atoms is noise.

Combined with the ops_per_step finding (item 2), the pattern is clear: **conservative payloads win.** Both short chains (high stop_prob) and few mutations (low ops_per_step) keep candidates close to known-good shapes.

**Action:** `agent.rs` presets using `LengthPolicy::long()` should be changed to `LengthPolicy::short()` or a custom `LengthPolicy::new(1, 32, 0.75)`. This could recover 100–200 hits/1k on XSS and SSTI alone.

## 6. ChainTable missing XSS chains — No chains produce `<script>` or `<svg onload>`; XSS bottleneck

**Status: DONE** — 4 vocab variants × 20 trials, `targets.toml`, gen_ratio=1.0 (pure generation).

### Enriched vocabularies tested
- `xss+`: added atoms `script`, `img`, `svg`, `iframe`, `src=`, `alert(1)` + chains (`<`→`script` 20.0, `img`→` src=` 20.0, etc.)
- `sqli+`: added chains (` OR `→`1=1` 15.0, ` SELECT `→`NULL` 10.0, ` AND `→`1=2` 8.0)
- `ssti+`: added atoms `{{7*'7'}}`, `{{config}}`, `{{self}}` + chains

### Results (hits/1k, gen_ratio=1.0, pure generation)

| Target | default | xss+ | sqli+ | ssti+ |
|--------|---------|------|-------|-------|
| xss    | 678     | 655  | 683   | 712   |
| ssti   | 678     | 655  | 683   | 712   |
| sqli   | 841     | 822  | 844   | 846   |
| sqli-strict | 863 | 843 | 867  | 875   |
| cmdi   | 848     | 828  | 856   | 859   |
| xss-reflected | 0 | 0  | 0     | 0     |
| path-traversal | 0 | 0  | 0     | 0     |
| ssrf   | 0       | 0    | 0     | 0     |

### Key findings

1. **Adding atoms HURTS.** XSS+ enrichment scored WORSE (655 vs 678). More atoms = lower probability of picking useful ones. Vocabulary dilution outweighs chain connectivity.

2. **Adding complete-probe atoms helps slightly.** SSTI+ gained 34 hits/1k (678→712) by adding `{{7*'7'}}` as a single atom. But this is just a bigger seed table, not chain assembly — the single atom gets picked randomly and inserted.

3. **xss-reflected stays at 0 regardless.** Root cause is NOT the chain table — it's a **mock probe bug**: `mock_config.rs:91` uses `.split('=').nth(1)` which truncates payloads at the second `=` sign. `<img src=x onerror=alert(1)>` extracts as `<img src`. The trigger fires, but the response body only reflects the truncated payload, so ReflectionClassifier can't match the full candidate.

4. **path-traversal and ssrf stay at 0.** Also NOT chain table — confirmed in item 5 analysis: their trigger bodies are too small (33 and 10 bytes) to exceed SizeDelta's `min_abs=50` threshold. This is an item 9 problem.

5. **Why XSS still gets hits at gen=1.0 without `script` atom:** The seed corpus contains the trigger payload. `apply_chain` APPENDS/PREPENDS/WRAPS a generated chain around the seed base. The seed's `<script>` substring survives in the candidate, so the mock target still triggers.

### Conclusion
The ChainTable's value is NOT in generating novel multi-atom patterns from scratch. It's in **steering havoc mutations** — when havoc picks InsertToken, the chain weights guide which atom gets inserted near the seed. The real bottleneck is vocabulary dilution: adding atoms to fix gaps makes every other atom less likely to be picked.

**Action:** Don't expand the shared ATOMS table. Instead, use per-preset atoms (the architecture already supports this via `WeightedSampler::from_proto_config`). Each vulnerability class should have its own focused atom vocabulary. The `agent.rs` presets currently all use `ATOMS` — they should use class-specific subsets.

## 7. Energy boost mechanism — Additive vs multiplicative, cap at 64 never validated

**Status: TODO**

## 8. Individual HavocOp ablation — Which operators actually contribute? Ablation study needed

**Status: TODO**

## 9. Signal classifier thresholds — `min_factor`, `min_abs_ms`, `min_abs`, `min_rel` never swept

**Status: TODO**

## 10. Atom dead-weight audit — Which atoms never fire? Instrument emission frequencies

**Status: TODO**
