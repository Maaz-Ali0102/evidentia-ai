"""Phase 1 EDA figures for the WitFoo Precinct6 `signals` table.

Every figure is computed from the local parquet files (via DuckDB) or from
reports/audit_results.json written by scripts/audit_dataset.py.
Output: reports/figures/*.png

Run:  .venv/Scripts/python scripts/eda_figures.py
"""
from __future__ import annotations

import json
from pathlib import Path

import duckdb
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
SIG = (ROOT / "data/raw/precinct6/signals/signals.parquet").as_posix()
FIG = ROOT / "reports" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
R = json.loads((ROOT / "reports/audit_results.json").read_text(encoding="utf-8"))

# Validated reference palette (dataviz skill, light mode), categorical slots 1-3 in fixed order.
LABELS = ["benign", "suspicious", "malicious"]
COLOR = {"benign": "#2a78d6", "suspicious": "#eb6834", "malicious": "#1baf7a"}
INK, INK2, MUTED, GRID, AXIS, SURF = "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7", "#fcfcfb"

plt.rcParams.update({
    "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF,
    "axes.edgecolor": AXIS, "axes.labelcolor": INK2, "xtick.color": MUTED, "ytick.color": MUTED,
    "text.color": INK, "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6,
    "axes.spines.top": False, "axes.spines.right": False, "font.size": 10,
    "axes.titlesize": 12, "axes.titleweight": "bold", "axes.titlelocation": "left",
    "legend.frameon": False,
})

con = duckdb.connect()
con.execute(f"CREATE VIEW sig AS SELECT * FROM '{SIG}'")


def save(fig, name: str):
    fig.tight_layout()
    fig.savefig(FIG / name, dpi=150)
    plt.close(fig)
    print("saved", name)


def bar_labels(ax, bars, fmt="{:,.0f}"):
    for b in bars:
        h = b.get_height()
        if h > 0:
            ax.annotate(fmt.format(h), (b.get_x() + b.get_width() / 2, h), ha="center",
                        va="bottom", fontsize=8, color=INK2, xytext=(0, 2), textcoords="offset points")


# 01 class distribution -----------------------------------------------------
lab = {r["label_binary"]: r["n"] for r in R["labels_signals"]}
fig, ax = plt.subplots(figsize=(6.5, 4))
bars = ax.bar(LABELS, [lab[l] for l in LABELS], color=[COLOR[l] for l in LABELS], width=0.55)
ax.set_yscale("log")
tot = sum(lab.values())
for b, l in zip(bars, LABELS):
    ax.annotate(f"{lab[l]:,}\n({lab[l]/tot:.2%})", (b.get_x() + b.get_width() / 2, lab[l]),
                ha="center", va="bottom", fontsize=9, color=INK2, xytext=(0, 3), textcoords="offset points")
ax.set_ylabel("rows (log scale)")
ax.set_ylim(1e3, 1e7)
ax.set_title("Class distribution in `signals` (2,011,674 rows)")
ax.grid(axis="x", visible=False)
save(fig, "01_class_distribution.png")

# 02 labels by organisation -------------------------------------------------
orgs = [r for r in R["labels_by_org"]]
x = np.arange(len(orgs))
w = 0.26
fig, ax = plt.subplots(figsize=(8, 4.2))
for i, l in enumerate(LABELS):
    vals = [max(o[l], 0.8) for o in orgs]  # 0 shown as empty
    bars = ax.bar(x + (i - 1) * w, vals, w - 0.02, color=COLOR[l], label=l)
    for b, o in zip(bars, orgs):
        ax.annotate(f"{o[l]:,}", (b.get_x() + b.get_width() / 2, max(o[l], 1)), ha="center",
                    va="bottom", fontsize=7, color=INK2, xytext=(0, 2), textcoords="offset points")
ax.set_xticks(x, [o["org_id"] for o in orgs])
ax.set_yscale("log")
ax.set_ylim(0.8, 3e6)
ax.set_ylabel("rows (log scale)")
ax.set_title("Labels per organisation\nonly ORG-0004 and ORG-0005 have usable malicious rows")
ax.legend(ncols=3, loc="upper right")
ax.grid(axis="x", visible=False)
save(fig, "02_labels_by_org.png")

# 03 daily volume per org (coverage is uneven) ------------------------------
days = sorted({r["dt"] for r in R["labels_by_day"]})
org_names = ["ORG-0004", "ORG-0005", "ORG-0003", "ORG-0001"]
org_col = {"ORG-0004": "#2a78d6", "ORG-0005": "#eb6834", "ORG-0003": "#1baf7a", "ORG-0001": "#eda100"}
fig, axes = plt.subplots(1, 2, figsize=(11, 4), sharex=True)
for ax, (title, filt) in zip(axes, [("All rows per day", None), ("Malicious rows per day", "malicious")]):
    for o in org_names:
        vals = [sum(r["n"] for r in R["labels_by_day"] if r["dt"] == d and r["org_id"] == o
                    and (filt is None or r["label_binary"] == filt)) for d in days]
        ax.plot(range(len(days)), vals, marker="o", ms=5, lw=2, color=org_col[o], label=o)
    ax.set_title(title)
    ax.set_xticks(range(len(days)), [d[5:] for d in days])
axes[0].set_ylabel("rows")
axes[0].legend()
fig.suptitle("Temporal coverage (dates in PKT, UTC+5): ORG-0005 spans only 2 calendar dates (0.78 days); no malicious rows after 30 Jul",
             x=0.01, ha="left", fontsize=10, color=INK2)
save(fig, "03_daily_coverage.png")

# 04 hourly pattern by label (share of each label per hour, UTC) ------------
hr = con.execute("""SELECT hour(to_timestamp(timestamp) AT TIME ZONE 'UTC') h, label_binary, count(*) n
                    FROM sig GROUP BY ALL""").fetchall()
fig, ax = plt.subplots(figsize=(9, 4))
for l in LABELS:
    v = np.zeros(24)
    for h, lb, n in hr:
        if lb == l:
            v[h] = n
    ax.plot(range(24), v / v.sum() * 100, lw=2, marker="o", ms=4, color=COLOR[l], label=l)
ax.set_xticks(range(0, 24, 2))
ax.set_xlabel("hour of day (UTC, ingest time)")
ax.set_ylabel("% of that label's rows")
ax.set_title("Hourly activity profile per label")
ax.legend()
save(fig, "04_hourly_profile.png")

# 05 missing values by label (heatmap) ---------------------------------------
miss = [m for m in R["missing_rate_signals"] if m["column"] not in ("label_binary",)]
cols = [m["column"] for m in miss]
mat = np.array([[m[l] for l in LABELS] for m in miss]) * 100
fig, ax = plt.subplots(figsize=(6.2, 10))
im = ax.imshow(mat, cmap="Blues", aspect="auto", vmin=0, vmax=100)
ax.set_xticks(range(3), LABELS)
ax.set_yticks(range(len(cols)), cols, fontsize=8)
ax.grid(False)
for i in range(len(cols)):
    for j in range(3):
        ax.text(j, i, f"{mat[i, j]:.0f}", ha="center", va="center", fontsize=7,
                color="#ffffff" if mat[i, j] > 55 else INK)
fig.colorbar(im, ax=ax, shrink=0.5, label="% missing / empty")
ax.set_title("Missing values by label (%)\nmissingness itself differs by class")
save(fig, "05_missing_by_label.png")

# 06 top streams by label ------------------------------------------------------
st = con.execute("""SELECT stream_name, label_binary, count(*) n FROM sig GROUP BY ALL""").fetchall()
tot_by_stream: dict = {}
for s, l, n in st:
    tot_by_stream.setdefault(s, {}).update({l: n})
top = sorted(tot_by_stream, key=lambda s: -sum(tot_by_stream[s].values()))[:12]
top = top + [s for s in tot_by_stream if s in ("aws_vpc_flow_log", "cisco_asa") and s not in top]
fig, ax = plt.subplots(figsize=(9, 5.8))
left = np.zeros(len(top))
totals = np.array([sum(tot_by_stream[s].values()) for s in top])
for l in LABELS:
    v = np.array([tot_by_stream[s].get(l, 0) for s in top]) / totals * 100
    ax.barh(top, v, left=left, color=COLOR[l], label=l, edgecolor=SURF, linewidth=1)
    left += v
for i, t in enumerate(totals):
    ax.annotate(f"{t:,}", (100, i), xytext=(4, 0), textcoords="offset points", va="center", fontsize=8, color=INK2)
ax.invert_yaxis()
ax.set_xlim(0, 112)
ax.set_xlabel("% of the stream's rows (total rows at right)")
ax.set_title("Label mix per log stream\nnon-benign rows come from only 2 streams")
ax.legend(loc="lower center", bbox_to_anchor=(0.45, -0.22), ncols=3)
ax.grid(axis="y", visible=False)
save(fig, "06_streams_by_label.png")

# 07 message length by label --------------------------------------------------
ml = con.execute("""SELECT label_binary, length(message_sanitized) FROM sig
                    WHERE message_sanitized IS NOT NULL AND message_sanitized <> ''
                    USING SAMPLE 300000 ROWS (reservoir, 7)""").fetchall()
mal_all = con.execute("""SELECT length(message_sanitized) FROM sig WHERE label_binary='malicious'""").fetchall()
data = {l: [n for lb, n in ml if lb == l] for l in LABELS}
data["malicious"] = [r[0] for r in mal_all]
fig, ax = plt.subplots(figsize=(7.5, 4))
bp = ax.boxplot([data[l] for l in LABELS], tick_labels=LABELS, showfliers=False, patch_artist=True, widths=0.5)
for p, l in zip(bp["boxes"], LABELS):
    p.set_facecolor(COLOR[l]); p.set_alpha(0.85); p.set_edgecolor(INK2)
for m in bp["medians"]:
    m.set_color(INK)
ax.set_ylabel("characters")
ax.set_title("Message length by label (non-empty messages, outliers hidden)")
ax.grid(axis="x", visible=False)
save(fig, "07_message_length.png")

# 08 single-column lookup: leakage screen -------------------------------------
lk = [r for r in R["single_column_lookup"]]
lk.sort(key=lambda r: ({"post_label": 0, "source_meta": 1, "event": 2}[r["group"]], -(r["rec_mal"] or 0)))
names = [f"{r['column']}  [{r['group']}]" for r in lk]
fig, ax = plt.subplots(figsize=(9, 9.5))
y = np.arange(len(lk))
ax.barh(y - 0.2, [r["rec_susp"] or 0 for r in lk], 0.38, color=COLOR["suspicious"], label="suspicious recall")
ax.barh(y + 0.2, [r["rec_mal"] or 0 for r in lk], 0.38, color=COLOR["malicious"], label="malicious recall")
ax.set_yticks(y, names, fontsize=8)
ax.invert_yaxis()
ax.set_xlim(0, 1.05)
ax.set_xlabel("recall of a lookup table that uses ONLY this column")
ax.set_title("Leakage screen: what a single column can 'predict' by itself")
ax.legend(loc="lower right")
ax.grid(axis="y", visible=False)
save(fig, "08_single_column_leakage.png")

# 09 duplicates & label conflicts ---------------------------------------------
c = R["conflicting_labels_same_message"]
dup = {r["label_binary"]: r["share_rows_with_duplicate_text"] for r in R["duplicate_share_by_label"]}
fig, axes = plt.subplots(1, 2, figsize=(11, 4))
bars = axes[0].bar(LABELS, [dup[l] * 100 for l in LABELS], color=[COLOR[l] for l in LABELS], width=0.55)
bar_labels(axes[0], bars, "{:.0f}%")
axes[0].set_ylabel("% rows whose exact text appears again")
axes[0].set_title("Exact duplicate message text")
axes[0].set_ylim(0, 100)
axes[0].grid(axis="x", visible=False)
v = [c["malicious_total"] - c["malicious_rows_whose_text_also_appears_with_other_label"],
     c["malicious_rows_whose_text_also_appears_with_other_label"]]
bars = axes[1].bar(["text unique to\nmalicious", "same text also\nlabelled otherwise"], v,
                   color=[COLOR["malicious"], MUTED], width=0.55)
bar_labels(axes[1], bars)
axes[1].set_title("Malicious rows: is the text alone enough?")
axes[1].set_ylabel("malicious rows")
axes[1].grid(axis="x", visible=False)
save(fig, "09_duplicates_conflicts.png")

# 10 incident size distribution (group structure) -----------------------------
inc = con.execute("""
  WITH m AS (SELECT org_id, unnest(CAST(json_extract_string(incident_ids, '$[*]') AS VARCHAR[])) inc
             FROM sig WHERE label_binary='malicious')
  SELECT org_id, inc, count(*) n FROM m GROUP BY ALL""").fetchall()
fig, ax = plt.subplots(figsize=(8, 4))
bins = np.logspace(0, np.log10(600), 25)
for o in ["ORG-0004", "ORG-0005"]:
    ax.hist([n for org, _, n in inc if org == o], bins=bins, color=org_col[o], alpha=0.8, label=o,
            edgecolor=SURF)
ax.set_xscale("log")
ax.set_xlabel("malicious rows per incident (log)")
ax.set_ylabel("incidents")
ax.set_title("Incident sizes: ORG-0004 = 81 large incidents, ORG-0005 = 1,490 small ones")
ax.legend()
save(fig, "10_incident_sizes.png")

# 11 behavioural context: events from same src_ip in previous 10 min ----------
ctx = con.execute("""
  WITH s AS (SELECT org_id, src_ip, timestamp, label_binary FROM sig
             WHERE stream_name IN ('cisco_asa','aws_vpc_flow_log') AND src_ip IS NOT NULL
               AND label_binary <> 'benign'),
  w AS (SELECT *, count(*) OVER (PARTITION BY org_id, src_ip ORDER BY timestamp
                   RANGE BETWEEN 600 PRECEDING AND CURRENT ROW) - 1 prev10m FROM s)
  SELECT org_id, label_binary, prev10m FROM w""").fetchall()
fig, axes = plt.subplots(1, 2, figsize=(11, 4))
for ax, o in zip(axes, ["ORG-0004", "ORG-0005"]):
    d = [[np.log10(p + 1) for org, lb, p in ctx if org == o and lb == l] for l in ["suspicious", "malicious"]]
    bp = ax.boxplot(d, tick_labels=["suspicious", "malicious"], showfliers=False, patch_artist=True, widths=0.5)
    for p, l in zip(bp["boxes"], ["suspicious", "malicious"]):
        p.set_facecolor(COLOR[l]); p.set_alpha(0.85); p.set_edgecolor(INK2)
    for m in bp["medians"]:
        m.set_color(INK)
    ax.set_title(o)
    ax.set_ylabel("log10(1 + earlier events, same src IP, 10 min)")
    ax.grid(axis="x", visible=False)
fig.suptitle("Context signal: prior activity of the same source IP differs between suspicious and malicious — in opposite directions per org",
             x=0.01, ha="left", fontsize=10, color=INK2)
save(fig, "11_context_prev10m.png")

# 12 cross-org vocabulary overlap ---------------------------------------------
o = R["message_type_overlap_0004_0005"]
fig, ax = plt.subplots(figsize=(7, 3.6))
cats = ["only ORG-0004", "shared", "only ORG-0005"]
vals = [o["types_0004"] - o["shared"], o["shared"], o["types_0005"] - o["shared"]]
bars = ax.bar(cats, vals, color=[org_col["ORG-0004"], MUTED, org_col["ORG-0005"]], width=0.55)
bar_labels(ax, bars)
ax.set_ylabel("distinct message_type values")
ax.set_title("Domain shift: ORG-0004 and ORG-0005 share 11 message types\n(identical message texts across orgs: "
             f"{R['cross_org_shared_messages']})")
ax.grid(axis="x", visible=False)
save(fig, "12_org_overlap.png")
