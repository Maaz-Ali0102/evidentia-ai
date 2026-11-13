"""Stage 2 model comparison: LR and RF (the project's models) vs three boosting models.

Usage:
  .venv/Scripts/python scripts/compare_models.py

Separate experiment. It never changes models/ or the existing metric files. It writes
reports/metrics/model_comparison.json and reports/figures/C*.png (both shown on the Model
evaluation page) and reports/comparison/COMPARISON.md.

Rules (same as scripts/train_models.py):
  - same Stage 2 rows, temporal splits, dropped incident-crossing rows and features;
  - feature set, hyper-parameters and decision threshold are chosen by StratifiedGroupKFold
    (groups = incidents / 2-hour blocks) on the training window only;
  - the test window is scored once, after every choice is fixed;
  - every model gets class weighting for the rare malicious class.

HistGradientBoosting cannot take sparse input, and densifying 20k TF-IDF columns does not
fit in memory, so it only sees the "context" feature set (categorical + behaviour context).
The other four models choose between "context" and "full" (context + text) by CV.
"""
from __future__ import annotations

import json
import sys
import time
import warnings
from pathlib import Path

import joblib
import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
from sklearn.base import clone  # noqa: E402
from sklearn.ensemble import HistGradientBoostingClassifier  # noqa: E402
from sklearn.metrics import precision_recall_curve  # noqa: E402
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold, cross_val_predict  # noqa: E402
from sklearn.pipeline import Pipeline  # noqa: E402
from sklearn.preprocessing import FunctionTransformer  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import duckdb  # noqa: E402

from evidentia.ml.config import FEATURE_VERSION, SEED, SIGNALS_PARQUET, STAGE2_ORGS  # noqa: E402
from evidentia.ml.data import LOAD_COLS, build_dataset, stage2_frame, stage2_splits  # noqa: E402
from evidentia.ml.evaluate import best_f1_threshold, binary_report  # noqa: E402
from evidentia.ml.features import build_transformer, input_columns  # noqa: E402
from evidentia.ml.models import make_lr, make_rf  # noqa: E402

warnings.filterwarnings("ignore", category=UserWarning)

CACHE_S2 = ROOT / "data" / "processed" / f"stage2_{FEATURE_VERSION}.joblib"
OUT = ROOT / "reports" / "comparison"          # COMPARISON.md + cached test scores
FIG = ROOT / "reports" / "figures"              # C*.png, served on the Model evaluation page
METRIC = ROOT / "reports" / "metrics" / "model_comparison.json"  # read by /api/metrics/model_comparison
OUT.mkdir(parents=True, exist_ok=True)
S2_NAMES = ("suspicious", "malicious")
SPLITS = ["POOLED_temporal", "B_temporal_ORG-0005", "A_temporal_ORG-0004"]
NICE = {"logreg": "Logistic Regression", "random_forest": "Random Forest",
        "hist_gb": "HistGradientBoosting", "xgboost": "XGBoost", "lightgbm": "LightGBM"}
SHORT = {"logreg": "LR", "random_forest": "RF", "hist_gb": "HistGB", "xgboost": "XGBoost", "lightgbm": "LightGBM"}
COLORS = {"logreg": "#4C78A8", "random_forest": "#59A14F", "hist_gb": "#B07AA1",
          "xgboost": "#E15759", "lightgbm": "#F28E2B"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def class_counts() -> dict:
    """Label counts over every row, straight from the parquet file (no full load)."""
    q = f"SELECT label_binary, count(*) FROM '{SIGNALS_PARQUET.as_posix()}' GROUP BY 1"
    return {k: int(v) for k, v in duckdb.connect().execute(q).fetchall()}


def load_stage2() -> pd.DataFrame:
    """Stage 2 rows, built one organisation at a time so it fits in ~8 GB of RAM.

    Equivalent to stage2_frame(build_dataset(load_signals())) because every org-dependent
    step in build_dataset is per organisation: context features are computed per org_id,
    cut-offs are per org, and no incident id appears in more than one organisation
    (checked on the data), so the incident-crossing drop is per org as well.
    """
    if CACHE_S2.exists():
        return joblib.load(CACHE_S2)
    # Benign rows are dropped by stage2_frame and their text is only used row by row
    # (prepare_frame / raw_text), never by the context features, so it is not loaded.
    sel = ", ".join("CASE WHEN label_binary = 'benign' THEN NULL ELSE message_sanitized END AS message_sanitized"
                    if c == "message_sanitized" else c for c in LOAD_COLS)
    parts = []
    for org in STAGE2_ORGS:
        con = duckdb.connect()
        df = con.execute(f"SELECT {sel} FROM '{SIGNALS_PARQUET.as_posix()}' WHERE org_id = '{org}'").df()
        for c in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "severity",
                  "message_type", "message_sanitized"]:
            df[c] = df[c].replace("", np.nan)
        parts.append(stage2_frame(build_dataset(df)))
        log("built", org, len(parts[-1]), "alert rows")
        del df
    s2 = pd.concat(parts).sort_values("timestamp", kind="stable").reset_index(drop=True)
    CACHE_S2.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(s2, CACHE_S2)
    return s2


def _dense(x):
    return x.toarray() if hasattr(x, "toarray") else x


def make_hgb() -> Pipeline:
    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.1, class_weight="balanced",
                                         early_stopping=False, random_state=SEED)
    return Pipeline([("features", build_transformer("context")),
                     ("dense", FunctionTransformer(_dense, accept_sparse=True)), ("clf", clf)])


def make_xgb(scale_pos_weight: float) -> Pipeline:
    from xgboost import XGBClassifier
    clf = XGBClassifier(n_estimators=300, learning_rate=0.1, max_depth=6, subsample=0.8,
                        colsample_bytree=0.8, tree_method="hist", eval_metric="aucpr",
                        scale_pos_weight=scale_pos_weight, n_jobs=-1, random_state=SEED)
    return Pipeline([("features", build_transformer("full")), ("clf", clf)])


def make_lgbm() -> Pipeline:
    from lightgbm import LGBMClassifier
    clf = LGBMClassifier(n_estimators=300, learning_rate=0.1, num_leaves=31, subsample=0.8,
                         subsample_freq=1, colsample_bytree=0.8, class_weight="balanced",
                         n_jobs=-1, random_state=SEED, verbose=-1)
    return Pipeline([("features", build_transformer("full")), ("clf", clf)])


def grids(scale_pos_weight: float) -> dict:
    fsets = [build_transformer("context"), build_transformer("full")]
    return {
        # identical to the grids in scripts/train_models.py
        "logreg": (make_lr("full"), {"features": fsets, "clf__C": [0.1, 1.0, 10.0]}),
        "random_forest": (make_rf("full", n_estimators=100),
                          {"features": fsets, "clf__max_depth": [None, 20], "clf__min_samples_leaf": [1, 5]}),
        # boosting models: same CV, small grids of the parameters that matter most
        "hist_gb": (make_hgb(), {"clf__max_leaf_nodes": [15, 31], "clf__l2_regularization": [0.0, 1.0]}),
        "xgboost": (make_xgb(scale_pos_weight), {"features": fsets, "clf__max_depth": [4, 8],
                                                 "clf__min_child_weight": [1, 5]}),
        "lightgbm": (make_lgbm(), {"features": fsets, "clf__num_leaves": [15, 63],
                                   "clf__min_child_samples": [20, 100]}),
    }


def feature_set_of(est: Pipeline) -> str:
    names = [p[0] for p in est.named_steps["features"].transformers]
    return "full" if "text" in names else "context"


def run() -> dict:
    t0 = time.time()
    s2 = load_stage2()
    log("stage 2 rows", s2.shape)
    splits = stage2_splits(s2)
    cols = input_columns("full")

    res = {"task": "Stage 2: suspicious (0) vs malicious (1), alert rows of ORG-0004/ORG-0005",
           "class_counts_all_rows": class_counts(),
           "split_sizes": {}, "results": {}}
    probas: dict = {}
    for name in SPLITS:
        a, b = splits[name]
        tr, te = s2.loc[a], s2.loc[b]
        n_pos = int(tr["y"].sum())
        spw = (len(tr) - n_pos) / max(n_pos, 1)
        res["split_sizes"][name] = {"train": len(tr), "train_malicious": n_pos,
                                    "test": len(te), "test_malicious": int(te["y"].sum())}
        cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
        for mname, (base, grid) in grids(spw).items():
            t = time.time()
            gs = GridSearchCV(base, grid, scoring="average_precision", cv=cv, n_jobs=1, refit=True)
            gs.fit(tr[cols], tr["y"], groups=tr["cv_group"])
            best = gs.best_estimator_
            oof = cross_val_predict(clone(best), tr[cols], tr["y"], groups=tr["cv_group"],
                                    cv=cv, method="predict_proba")[:, 1]
            thr = best_f1_threshold(tr["y"], oof)
            tune_s = time.time() - t
            # --- the test window is scored here, once, with everything already fixed ---
            t = time.time()
            proba = best.predict_proba(te[cols])[:, 1]
            inf_s = time.time() - t
            probas.setdefault(name, {})[mname] = (te["y"].to_numpy(), proba)
            res["results"].setdefault(name, {})[mname] = {
                "selected_feature_set": feature_set_of(best),
                "selected_params": {k: v for k, v in gs.best_params_.items() if k != "features"},
                "cv_pr_auc_mean": round(float(gs.best_score_), 4),
                "threshold_from_train_oof": round(thr, 4),
                "test": binary_report(te["y"], proba, thr, S2_NAMES),
                "tuning_seconds": round(tune_s, 1),
                "inference_ms_per_1k_rows": round(inf_s / len(te) * 1e6, 2),
            }
            r = res["results"][name][mname]
            log(name, mname, r["selected_feature_set"], "CV", r["cv_pr_auc_mean"],
                "test PR-AUC", r["test"]["pr_auc_positive"], "ROC", r["test"]["roc_auc"],
                f"({tune_s:.0f}s)")
            METRIC.write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    res["total_seconds"] = round(time.time() - t0, 1)
    METRIC.write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    joblib.dump(probas, OUT / "_test_probas.joblib", compress=3)
    return res, probas


# --------------------------------------------------------------------------- figures
def fig_class_imbalance(res):
    order = ["benign", "suspicious", "malicious"]
    counts = [res["class_counts_all_rows"].get(k, 0) for k in order]
    total = sum(counts)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    bars = ax.bar(order, counts, color=["#9DB4C0", "#F2B134", "#D1495B"])
    ax.set_yscale("log")
    ax.set_ylabel("records (log scale)")
    ax.set_title("Class imbalance in the WitFoo Precinct6 signals")
    for b, c in zip(bars, counts):
        ax.text(b.get_x() + b.get_width() / 2, c * 1.15, f"{c:,}\n{c / total:.2%}", ha="center", fontsize=9)
    ax.set_ylim(top=max(counts) * 8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "C1_class_imbalance.png", dpi=150)
    plt.close(fig)


def fig_prauc_bars(res):
    names = SPLITS
    models = list(NICE)
    fig, axes = plt.subplots(1, len(names), figsize=(15, 4.6), sharey=False)
    for ax, split in zip(axes, names):
        r = res["results"][split]
        vals = [r[m]["test"]["pr_auc_positive"] for m in models]
        chance = r[models[0]]["test"]["positive_rate_baseline"]
        bars = ax.bar(range(len(models)), vals, color=[COLORS[m] for m in models])
        ax.axhline(chance, ls="--", color="black", lw=1)
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.005, f"{v:.3f}", ha="center", fontsize=8)
        ax.set_xticks(range(len(models)), [SHORT[m] for m in models], fontsize=9)
        ax.set_title(split.replace("_temporal", "").replace("_", " ") + f"  (chance {chance:.3f})")
        ax.set_ylim(0, max(max(vals), chance) * 1.25)
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("test PR-AUC (malicious)")
    fig.suptitle("Stage 2 PR-AUC on the test window (dashed = random-guess level)")
    fig.tight_layout()
    fig.savefig(FIG / "C2_prauc_bars.png", dpi=150)
    plt.close(fig)


def fig_confusion(res, split):
    models = list(NICE)
    fig, axes = plt.subplots(1, len(models), figsize=(18, 3.9))
    for ax, m in zip(axes, models):
        t = res["results"][split][m]["test"]
        cm = np.array(t["confusion_matrix"])
        pct = cm / cm.sum(axis=1, keepdims=True)
        ax.imshow(pct, cmap="Blues", vmin=0, vmax=1)
        for i in range(2):
            for j in range(2):
                ax.text(j, i, f"{cm[i, j]:,}\n{pct[i, j]:.0%}", ha="center", va="center",
                        color="white" if pct[i, j] > 0.6 else "black", fontsize=9)
        ax.set_xticks([0, 1], ["suspicious", "malicious"])
        ax.set_yticks([0, 1], ["suspicious", "malicious"])
        ax.set_xlabel("predicted")
        if m == models[0]:
            ax.set_ylabel("true")
        mal = t["per_class"]["malicious"]
        ax.set_title(f"{NICE[m]}\nPR-AUC {t['pr_auc_positive']:.3f} · mal. recall {mal['recall']:.0%}", fontsize=9)
    fig.suptitle(f"Stage 2 confusion matrices, {split} (threshold chosen on training data)")
    fig.tight_layout()
    fig.savefig(FIG / f"C3_confusion_{split}.png", dpi=150)
    plt.close(fig)


def fig_pr_curves(res, probas):
    fig, axes = plt.subplots(1, len(SPLITS), figsize=(15, 4.6))
    for ax, split in zip(axes, SPLITS):
        for m in NICE:
            y, p = probas[split][m]
            prec, rec, _ = precision_recall_curve(y, p)
            ax.plot(rec, prec, color=COLORS[m], lw=1.5,
                    label=f"{NICE[m]} ({res['results'][split][m]['test']['pr_auc_positive']:.3f})")
        chance = float(np.mean(probas[split]["logreg"][0]))
        ax.axhline(chance, ls="--", color="black", lw=1)
        ax.set_xlabel("recall (malicious)")
        ax.set_ylim(0, 1.02)
        ax.set_title(split.replace("_temporal", "").replace("_", " "))
        ax.legend(fontsize=7, loc="upper right")
        ax.spines[["top", "right"]].set_visible(False)
    axes[0].set_ylabel("precision (malicious)")
    fig.suptitle("Precision-recall curves on the test window (dashed = random-guess level)")
    fig.tight_layout()
    fig.savefig(FIG / "C4_pr_curves.png", dpi=150)
    plt.close(fig)


def fig_metric_bars(res, split):
    models = list(NICE)
    metrics = [("PR-AUC", lambda t: t["pr_auc_positive"]), ("ROC-AUC", lambda t: t["roc_auc"]),
               ("malicious recall", lambda t: t["per_class"]["malicious"]["recall"]),
               ("malicious precision", lambda t: t["per_class"]["malicious"]["precision"]),
               ("malicious F1", lambda t: t["per_class"]["malicious"]["f1"]),
               ("accuracy", lambda t: t["accuracy"])]
    x = np.arange(len(metrics))
    w = 0.16
    fig, ax = plt.subplots(figsize=(13, 4.8))
    for i, m in enumerate(models):
        t = res["results"][split][m]["test"]
        ax.bar(x + (i - 2) * w, [f(t) for _, f in metrics], w, color=COLORS[m], label=NICE[m])
    ax.set_xticks(x, [n for n, _ in metrics])
    ax.set_ylim(0, 1.05)
    ax.legend(fontsize=8, ncol=5, loc="upper left")
    ax.set_title(f"All metrics, {split}. Accuracy is high for every model only because suspicious rows dominate")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / f"C5_metrics_{split}.png", dpi=150)
    plt.close(fig)


def write_markdown(res):
    lines = ["# Stage 2 model comparison (separate experiment)", "",
             "Generated by `scripts/compare_models.py`. Does not change `models/` or any existing metric file.", "",
             "Task: suspicious (0) vs malicious (1) among alert rows. Same rows, splits, features and leakage "
             "rules as the main pipeline. Feature set, hyper-parameters and threshold chosen by "
             "StratifiedGroupKFold on the training window; test window scored once. HistGradientBoosting "
             "uses the context feature set only (it cannot take sparse TF-IDF).", "",
             "## Class imbalance", "",
             "| Class | All rows | Share |", "|---|---|---|"]
    tot = sum(res["class_counts_all_rows"].values())
    for k in ["benign", "suspicious", "malicious"]:
        v = res["class_counts_all_rows"].get(k, 0)
        lines.append(f"| {k} | {v:,} | {v / tot:.2%} |")
    lines += ["", "| Split | Train rows | Train malicious | Test rows | Test malicious |", "|---|---|---|---|---|"]
    for s, v in res["split_sizes"].items():
        lines.append(f"| {s} | {v['train']:,} | {v['train_malicious']:,} | {v['test']:,} | {v['test_malicious']:,} |")
    for split in SPLITS:
        r = res["results"][split]
        lines += ["", f"## {split}", "",
                  "| Model | Features (CV) | CV PR-AUC | Test PR-AUC | Chance | Test ROC-AUC | Mal. precision | "
                  "Mal. recall | Mal. F1 | Macro-F1 | Accuracy | Tuning s |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for m in NICE:
            e, t = r[m], r[m]["test"]
            mal = t["per_class"]["malicious"]
            lines.append(f"| {NICE[m]} | {e['selected_feature_set']} | {e['cv_pr_auc_mean']} | "
                         f"**{t['pr_auc_positive']}** | {t['positive_rate_baseline']} | {t['roc_auc']} | "
                         f"{mal['precision']} | {mal['recall']} | {mal['f1']} | {t['macro_f1']} | "
                         f"{t['accuracy']} | {e['tuning_seconds']} |")
        best = max(NICE, key=lambda m: r[m]["test"]["pr_auc_positive"])
        lines += ["", f"Highest test PR-AUC: **{NICE[best]}** ({r[best]['test']['pr_auc_positive']}). "
                  "Selected parameters: " + "; ".join(f"{NICE[m]} {r[m]['selected_params']}" for m in NICE)]
    lines += ["", "## Figures", ""] + [f"![{p.stem}](../figures/{p.name})" for p in sorted(FIG.glob("C*.png"))]
    (OUT / "COMPARISON.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "figures":
        res = json.loads(METRIC.read_text(encoding="utf-8"))
        probas = joblib.load(OUT / "_test_probas.joblib")
    else:
        res, probas = run()
    fig_class_imbalance(res)
    fig_prauc_bars(res)
    fig_pr_curves(res, probas)
    for s in SPLITS:
        fig_confusion(res, s)
    fig_metric_bars(res, "POOLED_temporal")
    fig_metric_bars(res, "B_temporal_ORG-0005")
    write_markdown(res)
    log("done ->", OUT)
