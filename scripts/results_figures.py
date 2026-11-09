"""Figures for the Phase 2 results report, drawn only from reports/metrics/*.json.

Run: .venv/Scripts/python scripts/results_figures.py
"""
from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
M = ROOT / "reports" / "metrics"
FIG = ROOT / "reports" / "figures"
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"
FS_COL = {"text": "#2a78d6", "context": "#eb6834", "full": "#1baf7a", "full+source": "#eda100"}
plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF, "axes.edgecolor": AXIS,
    "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.spines.top": False,
    "axes.spines.right": False, "font.size": 10, "axes.titlesize": 12, "axes.titleweight": "bold",
    "axes.titlelocation": "left", "legend.frameon": False})


def load(name):
    return json.loads((M / f"{name}.json").read_text(encoding="utf-8"))


def save(fig, name):
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=150)
    plt.close(fig)
    print("saved", name)


s2 = load("stage2")
ab = s2["ablation_untuned"]
splits = list(ab)
short = {"A_temporal_ORG-0004": "A: ORG-0004\ntemporal", "B_temporal_ORG-0005": "B: ORG-0005\ntemporal",
         "POOLED_temporal": "Pooled\ntemporal", "C_cross_0004_to_0005": "Cross\n0004→0005",
         "C_cross_0005_to_0004": "Cross\n0005→0004"}

# R1: stage-2 PR-AUC by split and feature set (random forest), with chance baseline
for model in ["random_forest", "logreg"]:
    fig, ax = plt.subplots(figsize=(10, 4.4))
    fsets = ["text", "context", "full", "full+source"]
    w = 0.2
    x = np.arange(len(splits))
    for i, fs in enumerate(fsets):
        vals = [ab[s].get(fs, {}).get(model, {}).get("pr_auc_positive") for s in splits]
        xs = [x[j] + (i - 1.5) * w for j, v in enumerate(vals) if v is not None]
        vs = [v for v in vals if v is not None]
        ax.bar(xs, vs, w - 0.03, color=FS_COL[fs], label=fs)
    base = [ab[s]["full"][model]["positive_rate_baseline"] for s in splits]
    for j, b in enumerate(base):
        ax.plot([x[j] - 2 * w, x[j] + 2 * w], [b, b], color=INK, lw=1.5, ls="--")
    ax.plot([], [], color=INK, ls="--", label="chance (malicious rate)")
    ax.set_xticks(x, [short[s] for s in splits])
    ax.set_ylabel("PR-AUC (malicious)")
    ax.set_ylim(0, max(0.5, ax.get_ylim()[1]))
    ax.set_title(f"Stage 2 (suspicious vs malicious), {model.replace('_', ' ')}, untuned: PR-AUC vs chance")
    ax.legend(ncols=5, loc="upper left", fontsize=8)
    ax.grid(axis="x", visible=False)
    save(fig, f"R1_stage2_prauc_{model}.png")

# R2: 3-class confusion matrices (hierarchical RF, flat RF)
tc = load("three_class")
fig, axes = plt.subplots(1, 4, figsize=(17, 4.2))
panels = [("hierarchical", "logreg"), ("hierarchical", "random_forest"), ("flat", "logreg"), ("flat", "random_forest")]
for ax, (kind, m) in zip(axes, panels):
    r = tc[kind][m]
    cm = np.array(r["confusion_matrix"], dtype=float)
    norm = cm / cm.sum(1, keepdims=True)
    ax.imshow(norm, cmap="Blues", vmin=0, vmax=1)
    for i in range(3):
        for j in range(3):
            ax.text(j, i, f"{int(cm[i, j]):,}\n{norm[i, j]:.0%}", ha="center", va="center", fontsize=8,
                    color="#ffffff" if norm[i, j] > 0.55 else INK)
    ax.set_xticks(range(3), r["labels"])
    ax.set_yticks(range(3), r["labels"])
    ax.set_xlabel("predicted")
    ax.set_ylabel("true")
    ax.grid(False)
    ax.set_title(f"{kind} {m.replace('_', ' ')}\nmacro-F1 {r['macro_f1']:.3f}", fontsize=10)
save(fig, "R2_three_class_confusion.png")

# R3: stage-1 ablation (benign vs alert)
s1 = load("stage1")["results"]
rows = [("text", "logreg"), ("context", "logreg"), ("full", "logreg"), ("full", "random_forest"), ("full+source", "logreg")]
fig, ax = plt.subplots(figsize=(8, 3.8))
lab = [f"{fs}\n{m.replace('random_forest', 'RF').replace('logreg', 'LR')}" for fs, m in rows]
vals = [s1[fs][m]["macro_f1"] for fs, m in rows]
pr = [s1[fs][m]["pr_auc_positive"] for fs, m in rows]
x = np.arange(len(rows))
ax.bar(x - 0.18, vals, 0.34, color="#2a78d6", label="macro-F1")
ax.bar(x + 0.18, pr, 0.34, color="#eb6834", label="PR-AUC (alert)")
for i, (a, b) in enumerate(zip(vals, pr)):
    ax.annotate(f"{a:.3f}", (i - 0.18, a), ha="center", va="bottom", fontsize=7, color=INK2, xytext=(0, 2), textcoords="offset points")
    ax.annotate(f"{b:.3f}", (i + 0.18, b), ha="center", va="bottom", fontsize=7, color=INK2, xytext=(0, 2), textcoords="offset points")
ax.set_xticks(x, lab)
ax.set_ylim(0, 1.1)
ax.set_title("Stage 1 (benign vs alert) on the test window: feature ablation")
ax.legend(loc="lower right")
ax.grid(axis="x", visible=False)
save(fig, "R3_stage1_ablation.png")
