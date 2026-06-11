#!/usr/bin/env python3
"""Graph the auto-fuzz engine's core mathematical functions."""
import numpy as np
import matplotlib.pyplot as plt

plt.rcParams.update({'font.size': 10, 'figure.dpi': 120})

# ── 1. Length distribution (geometric) ───────────────────────────────────

fig, axes = plt.subplots(1, 3, figsize=(14, 4), sharey=True)

policies = {
    "short()  min=1 max=6  p_stop=0.50": (1, 6, 0.50),
    "medium() min=2 max=12 p_stop=0.25": (2, 12, 0.25),
    "long()   min=4 max=24 p_stop=0.10": (4, 24, 0.10),
}

for ax, (label, (lo, hi, stop)) in zip(axes, policies.items()):
    n_range = np.arange(lo, hi + 1)
    probs = []
    for n in n_range:
        if n == lo:
            p = stop
        elif n < hi:
            p = stop * (1 - stop) ** (n - lo)
        else:
            p = (1 - stop) ** (hi - lo)
        probs.append(p)
    total = sum(probs)
    probs = [p / total for p in probs]
    ax.bar(n_range, probs, color='#4a90d9', edgecolor='white')
    ax.set_title(label, fontsize=9)
    ax.set_xlabel("atoms per chain")
    ax.set_ylabel("probability" if ax is axes[0] else "")
    mean_n = sum(n * p for n, p in zip(n_range, probs))
    ax.axvline(mean_n, color='#d94a4a', linestyle='--', linewidth=1.5,
               label=f"mean={mean_n:.1f}")
    ax.legend(fontsize=8)

fig.suptitle("LengthPolicy — how many atoms per generated chain", fontsize=12, y=1.02)
plt.tight_layout()
plt.savefig("length_distribution.png", bbox_inches='tight')
plt.close()
print("-> length_distribution.png")

# ── 2. Power schedule — energy-weighted selection ────────────────────────

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

corpus_labels = ["seed 1", "seed 2", "seed 3", "probe 1", "probe 2", "probe 3"]

# Flat corpus — all energy=1
energies_flat = [1] * 6
probs_flat = [e / sum(energies_flat) for e in energies_flat]
ax1.bar(range(6), probs_flat, color='#4a90d9')
ax1.set_title("Flat corpus (all energy=1)\nUniform sampling", fontsize=10)
ax1.set_xticks(range(6))
ax1.set_xticklabels(corpus_labels, rotation=30, ha='right', fontsize=8)
ax1.set_ylabel("P(selected as parent)")

# Evolved corpus — energy follows signal strength
energies_evolved = [1, 1, 1, 6, 4, 3]
probs_evolved = [e / sum(energies_evolved) for e in energies_evolved]
colors = ['#4a90d9'] * 3 + ['#d9b44a'] * 3
bars = ax2.bar(range(6), probs_evolved, color=colors)
ax2.set_title("Evolved corpus (energies vary by signal)\nWeighted toward promising entries", fontsize=10)
ax2.set_xticks(range(6))
ax2.set_xticklabels(corpus_labels, rotation=30, ha='right', fontsize=8)
ax2.set_ylabel("P(selected as parent)")
# Add energy labels
for i, (e, p) in enumerate(zip(energies_evolved, probs_evolved)):
    ax2.text(i, p + 0.01, f"e={e}", ha='center', fontsize=8)

fig.suptitle("Power Schedule — P(pick corpus entry) ∝ energy", fontsize=12)
plt.tight_layout()
plt.savefig("power_schedule.png", bbox_inches='tight')
plt.close()
print("-> power_schedule.png")

# ── 3. Chain weights — transition probability ──────────────────────────

fig, ax = plt.subplots(figsize=(10, 5))

atoms = ["'", '"', " OR ", " AND ", "--", "<", ">", "{{", "7*7", ".."]
n = len(atoms)

# Build weight matrix (SQL chain grammar)
weight_matrix = np.ones((n, n))
idx = {a: i for i, a in enumerate(atoms)}

# Seed key weights
weights_seeded = [
    ("'", " OR ", 5.0), ("'", " AND ", 3.0), ("'", "--", 5.0),
    ("'", "", 1.0), # default for unlisted
    ("{{", "7*7", 20.0), ("{{", "}}", 5.0),
    (" OR ", "NULL", 3.0), ("..", "/", 10.0),
]
for a, b, w in weights_seeded:
    if b and a in idx and b in idx:
        weight_matrix[idx[a], idx[b]] = w

# Show transition probabilities FROM "'"
from_atom = "'"
from_idx_val = idx[from_atom]
probs = weight_matrix[from_idx_val] / weight_matrix[from_idx_val].sum()

colors_bar = []
for a, p in zip(atoms, probs):
    if p > 0.15:
        colors_bar.append('#d94a4a')  # strong preference
    elif p > 0.10:
        colors_bar.append('#d9b44a')  # mild
    else:
        colors_bar.append('#4a90d9')  # default
bars = ax.bar(range(n), probs, color=colors_bar)
ax.set_xticks(range(n))
ax.set_xticklabels([f'"{a}"' for a in atoms], rotation=30, ha='right', fontsize=9)
ax.set_ylabel("P(next atom | current = \"'\")")
ax.set_title(f"ChainTable — transition probabilities from \"{from_atom}\"", fontsize=11)

# Add weight labels on significant bars
for i, (a, p) in enumerate(zip(atoms, probs)):
    if p > 1.0 / n:
        w_val = weight_matrix[from_idx_val, i]
        ax.text(i, p + 0.005, f"w={w_val:.0f}", ha='center', fontsize=8)

# Legend
from matplotlib.patches import Patch
legend = [
    Patch(color='#d94a4a', label='strong (w≥5)'),
    Patch(color='#d9b44a', label='mild (w≥2)'),
    Patch(color='#4a90d9', label='default (w=1)'),
]
ax.legend(handles=legend, fontsize=8)

plt.tight_layout()
plt.savefig("chain_weights.png", bbox_inches='tight')
plt.close()
print("-> chain_weights.png")

# ── 4. gen_ratio blend ──────────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(8, 4))

gen_ratios = np.linspace(0, 1, 100)
generation_prob = gen_ratios
havoc_prob = 1 - gen_ratios

ax.fill_between(gen_ratios, 0, generation_prob, color='#4a90d9', alpha=0.6, label='apply_chain() generation')
ax.fill_between(gen_ratios, generation_prob, 1, color='#d9b44a', alpha=0.6, label='havoc.mutate()')
ax.set_xlabel("gen_ratio")
ax.set_ylabel("probability")
ax.set_title("gen_ratio — blend between generation and havoc", fontsize=11)
ax.axvline(0.3, color='#d94a4a', linestyle='--', linewidth=1.5, label='default=0.3')
ax.legend(fontsize=9)
ax.set_ylim(0, 1)

plt.tight_layout()
plt.savefig("gen_ratio.png", bbox_inches='tight')
plt.close()
print("-> gen_ratio.png")

# ── 5. Signal score mapping ─────────────────────────────────────────────

fig, ax = plt.subplots(figsize=(9, 5))

signals = ["NoEffect", "BodyDiff", "SizeDelta", "SizeDelta\n(large)",
           "StatusDelta", "StatusDelta\n(500+)", "Reflected", "TimeDelay", "Error"]
scores = [0, 2, 2, 3, 3, 4, 4, 5, 6]
colors_score = ['#888888', '#4a90d9', '#4a90d9', '#6ab0e8',
                '#d9b44a', '#d9b44a', '#e8a040', '#d97a4a', '#d94a4a']

bars = ax.bar(signals, scores, color=colors_score)
for bar, score in zip(bars, scores):
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.1,
            str(score), ha='center', fontsize=10, fontweight='bold')

# Confirmation threshold line
ax.axhline(4, color='green', linestyle=':', linewidth=1, alpha=0.5)
ax.text(8.3, 4.1, "confirmed ≥ 4", fontsize=8, color='green')

ax.set_ylabel("score")
ax.set_title("HttpFeedback::score() — signal -> energy", fontsize=11)
ax.set_ylim(0, 7)
plt.tight_layout()
plt.savefig("signal_scoring.png", bbox_inches='tight')
plt.close()
print("-> signal_scoring.png")

# ── 6. Confidence degradation ───────────────────────────────────────────

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# Confidence vs ambient signal count
ambient_counts = np.arange(0, 7)
confidence = np.array([1.0 * (0.7**max(0, c-1)) * (0.4**max(0, c-3)) for c in ambient_counts])
ax1.plot(ambient_counts, confidence, 'o-', color='#4a90d9', linewidth=2, markersize=8)
ax1.fill_between(ambient_counts, 0, confidence, alpha=0.2, color='#4a90d9')
ax1.set_xlabel("ambient signals detected in baseline")
ax1.set_ylabel("confidence")
ax1.set_title("Confidence vs target noise", fontsize=10)
ax1.set_ylim(0, 1.05)
ax1.grid(True, alpha=0.3)

# Confidence vs baseline status
statuses = np.array([200, 301, 401, 500, 503])
conf_status = np.array([1.0, 0.8, 0.6, 0.3, 0.3])
colors_conf = ['#4ad94a', '#a0d94a', '#d9b44a', '#d97a4a', '#d94a4a']
ax2.bar(range(len(statuses)), conf_status, color=colors_conf)
ax2.set_xticks(range(len(statuses)))
ax2.set_xticklabels([f"{s}\n{'OK' if s<400 else 'client err' if s<500 else 'unstable'}"
                      for s in statuses], fontsize=8)
ax2.set_ylabel("confidence multiplier")
ax2.set_title("Confidence vs baseline health", fontsize=10)
ax2.set_ylim(0, 1.05)
ax2.grid(True, alpha=0.3, axis='y')

fig.suptitle("BaselineProfile — confidence in signal quality", fontsize=12)
plt.tight_layout()
plt.savefig("confidence.png", bbox_inches='tight')
plt.close()
print("-> confidence.png")

# ── 7. Havoc operator distribution ──────────────────────────────────────

fig, ax = plt.subplots(figsize=(9, 4))

ops = ["InsertToken", "ReplaceToken", "DeleteChunk", "Duplicate",
       "SpliceSuffix", "URLEncode", "DoubleURL", "BoundaryVal",
       "Repeat", "WrapDelim", "Reverse", "Uppercase"]
counts = [1] * 12  # uniform
ax.barh(ops, counts, color='#4a90d9')
ax.set_xlabel("relative probability")
ax.set_title("HavocMutator — 12 operators, equal probability per draw\n(ops_per_step=4 -> 4 random ops chained per mutation)", fontsize=10)
ax.set_xlim(0, 1.5)
# Remove x ticks since it's uniform
ax.set_xticks([])
for i in range(len(ops)):
    ax.text(0.05, i, "1/12", va='center', fontsize=9, fontweight='bold')

plt.tight_layout()
plt.savefig("havoc_ops.png", bbox_inches='tight')
plt.close()
print("-> havoc_ops.png")

print("\nDone. 7 graphs saved.")
