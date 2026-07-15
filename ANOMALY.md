# Anomaly detection — recall-first design (planned)

Status: **design note, not yet built.** Captures the intended direction so the
thresholds and reporting can be built toward it later. Inline `// recall-first:`
comments in the code point back here.

## The base-rate inversion

Content-discovery fuzzers (ffuf, wfuzz, gobuster) optimize **precision**: real
endpoints are common, so the enemy is noise — 10k rows you can't read. They
learn the "boring" response and filter it hard, accepting the odd miss.

Vulnerability discovery is the opposite base rate: a real hit is a
once-in-100k rarity, and **a miss is the whole exercise failing**. So we want
**recall first — precision is the human's post-filter, not the detector's job.**
Same machinery as ffuf, opposite tuning. Every threshold's *direction* should be
"sensitive," not "quiet."

## What "no false negatives" actually means (the black-box limit)

You cannot catch a hit that produces **no observable response difference** — see
the `login.php` decoy in testing: a genuine-but-silent bug is invisible no matter
how sensitive you are. So the achievable, precise rule is:

> Flag on **any** observable deviation across **all** cheap features:
> status, size, word count, line count, timing, structure.

If the response differs in any of those, even slightly, it goes in the report.
That's the reachable ceiling.

## How real tools fingerprint (the lightweight core)

No statistics, no ML — a tiny feature vector and set membership:

- **Feature vector:** `status`, `size (bytes)`, `word count`, `line count`.
  Size alone catches most; word/line counts cheaply catch "same length,
  different shape" before you'd reach for a full byte-diff.
- **ffuf `-ac` autocalibration:** fire a few bogus/random requests first, record
  their fingerprints as the "boring set," filter those, surface the rest.
- **sqlmap** goes deeper *only* for boolean-blind: body **similarity ratio**
  (difflib, ~0.85 threshold) after **removing dynamic content** (the parts that
  change between two identical requests). Its real cleverness is that removal.

## Two tiers, decoupled

- **`confirmed`** stays precise — signature-gated (SQL error regex, literal
  reflection, `LeakSignature`). High bar, low noise: the "probably real" list.
- **`anomalous`** becomes greedy — the OR-union of every detector at maximum
  sensitivity plus strict boring-set membership. **Never suppressed.** The
  "don't you dare miss it" bucket.

## Lightweight build sketch

1. **Autocalibration in `BaselineProfile`** — instead of one baseline sample,
   fire ~3 requests (empty + two junk tokens) and record each as a fingerprint
   `(status, size, words, lines)`. That set is "boring." Cost: 2 extra requests,
   O(response) to compute.
2. **`NoveltyClassifier`** — fingerprint each probe; if it's not within tolerance
   of any boring-set entry, emit an `Anomaly` signal → straight to the report,
   no signature required.
3. **Wobble (dynamic content):** compare the calibration probes to *each other*.
   If size varies across identical-intent requests, widen the size tolerance or
   lean on word/line counts (more stable). The cheap 80% of sqlmap's dynamic
   removal without per-line diffing.

## Where precision currently costs recall

These are fine as *confirmation* gates but are false-negative machines as
*anomaly* gates. A `SignalSet::sensitive()` / `--hunt` mode should flip them,
leaving the calibrated defaults intact for benchmarking:

- `SizeClassifier` — ANDs `min_abs >= 50 && min_rel >= 0.05`. Recall-first: OR
  them, lower both. A 40-byte delta on a 2 KB page is exactly the outlier.
- `ReflectionClassifier` — skips payloads `< 3` chars. A deliberate blind spot.
- `TimeDelayClassifier` — the `min_abs_ms` floor (see the ssrf saga in git log).
  Coarse on purpose; too coarse for anomaly flagging.

## Triage lives in the report, not the detector

Recall-first means **many false positives by design** — so the effort moves from
suppressing them to making them cheap to scan: **rank** by deviation magnitude,
**group** identical fingerprints (500 identical 403s = one line), **dedup**
payloads. A ranked, grouped list of ~30 buckets is scannable; 3k raw rows is not.
That is the actual work of a recall-first fuzzer.

## Corpus-feedback nuance

Recall-first is a **reporting** stance, not necessarily a **corpus-feedback**
stance. Pour every mild anomaly back in as high energy and heavy havoc starts
*chasing noise* — exploration degrades. Detection recall and exploration
guidance are separate dials: you can flag everything to the human while keeping
the energy/feedback loop more selective. Or accept the noise — but choose it
knowingly.
