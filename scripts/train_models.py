"""Phase 2: train and evaluate every model, write metrics + persisted models.

Usage:
  .venv/Scripts/python scripts/train_models.py            # all parts
  .venv/Scripts/python scripts/train_models.py stage2     # one part: stage2 | stage1 | iforest | three_class

Outputs: reports/metrics/<part>.json, models/*.joblib (+ models/registry.json)
Rules followed: no random splits; every learned transform is inside a Pipeline fitted
on training rows only; hyper-parameters, feature set and decision threshold are chosen
with grouped CV on the training window; the test window is scored once.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold, cross_val_predict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidentia.ml.config import (FEATURE_VERSION, LABELS, METRICS_DIR, MODELS_DIR, SEED,  # noqa: E402
                                 STAGE1_BENIGN_TRAIN_SAMPLE)
from evidentia.ml.data import (build_dataset, load_signals, stage1_split, stage2_frame,  # noqa: E402
                               stage2_splits)
from evidentia.ml.evaluate import best_f1_threshold, binary_report, multiclass_report  # noqa: E402
from evidentia.ml.features import build_transformer, input_columns  # noqa: E402
from evidentia.ml.models import make_iforest, make_lr, make_rf  # noqa: E402

CACHE = ROOT / "data" / "processed" / f"dataset_{FEATURE_VERSION}.joblib"
METRICS_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)
S2_NAMES = ("suspicious", "malicious")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def load_dataset() -> pd.DataFrame:
    if CACHE.exists():
        return joblib.load(CACHE)
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    ds = build_dataset(load_signals())
    joblib.dump(ds, CACHE)
    return ds


def write(name: str, obj) -> None:
    (METRICS_DIR / f"{name}.json").write_text(json.dumps(obj, indent=2, default=float), encoding="utf-8")
    log("wrote", name)


def model_size_mb(model) -> float:
    tmp = MODELS_DIR / "_size_probe.joblib"
    joblib.dump(model, tmp, compress=3)
    size = tmp.stat().st_size / 1e6
    tmp.unlink()
    return round(size, 2)


def extra_metrics(df_test: pd.DataFrame, proba: np.ndarray, threshold: float, train_texts: set) -> dict:
    """Incident-level recall + scores on test rows whose exact text never appeared in training."""
    y = df_test["y"].to_numpy()
    pred = proba >= threshold
    mal = df_test["y"] == 1
    inc = df_test.loc[mal, "incident"].to_numpy()
    hit = pd.Series(pred[mal.to_numpy()]).groupby(inc).any()
    novel = ~df_test["raw_text"].isin(train_texts).to_numpy()
    out = {"incident_level": {"incidents": int(hit.size), "detected": int(hit.sum()),
                              "recall": round(float(hit.mean()), 4) if hit.size else None},
           "novel_text_subset": None}
    if novel.sum() and len(np.unique(y[novel])) == 2:
        out["novel_text_subset"] = binary_report(y[novel], proba[novel], threshold, S2_NAMES)
    out["novel_text_share_of_test"] = round(float(novel.mean()), 4)
    return out


def fit_eval(model, tr, te, cols, threshold=0.5, train_texts=None):
    t = time.time()
    model.fit(tr[cols], tr["y"])
    fit_s = time.time() - t
    t = time.time()
    proba = model.predict_proba(te[cols])[:, 1]
    inf_s = time.time() - t
    rep = binary_report(te["y"], proba, threshold, S2_NAMES)
    rep["train_seconds"] = round(fit_s, 1)
    rep["inference_ms_per_1k_rows"] = round(inf_s / len(te) * 1e6, 2)
    if train_texts is not None:
        rep.update(extra_metrics(te, proba, threshold, train_texts))
    return rep, proba


# --------------------------------------------------------------------------- stage 2
def run_stage2(ds: pd.DataFrame) -> dict:
    s2 = stage2_frame(ds)
    splits = stage2_splits(s2)
    res = {"task": "suspicious (0) vs malicious (1) among alert rows of ORG-0004/ORG-0005",
           "split_sizes": {k: {"train": len(a), "train_malicious": int(s2.loc[a, "y"].sum()),
                               "test": len(b), "test_malicious": int(s2.loc[b, "y"].sum())}
                           for k, (a, b) in splits.items()},
           "ablation_untuned": {}, "tuned": {}}

    # 1. Feature ablation with fixed, untuned hyper-parameters (same for every split).
    for name, (a, b) in splits.items():
        tr, te = s2.loc[a], s2.loc[b]
        texts = set(tr["raw_text"])
        fsets = ["text", "context", "full"] + (["full+source"] if name == "POOLED_temporal" else [])
        for fs in fsets:
            cols = input_columns(fs)
            for mname, model in [("logreg", make_lr(fs)), ("random_forest", make_rf(fs))]:
                rep, _ = fit_eval(model, tr, te, cols, 0.5, texts)
                res["ablation_untuned"].setdefault(name, {}).setdefault(fs, {})[mname] = rep
                log("stage2", name, fs, mname, "PR-AUC", rep["pr_auc_positive"], "ROC", rep["roc_auc"])
        write("stage2", res)

    # 2. Tuned models: feature set + hyper-parameters chosen by grouped CV on training rows.
    cols = input_columns("full")  # superset; the transformer picks its own columns
    grids = {
        "logreg": (make_lr("full"), {"features": [build_transformer("context"), build_transformer("full")],
                                     "clf__C": [0.1, 1.0, 10.0]}),
        "random_forest": (make_rf("full", n_estimators=100),
                          {"features": [build_transformer("context"), build_transformer("full")],
                           "clf__max_depth": [None, 20], "clf__min_samples_leaf": [1, 5]}),
    }
    for name in ["POOLED_temporal", "B_temporal_ORG-0005", "A_temporal_ORG-0004"]:
        a, b = splits[name]
        tr, te = s2.loc[a], s2.loc[b]
        cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
        for mname, (base, grid) in grids.items():
            t = time.time()
            gs = GridSearchCV(base, grid, scoring="average_precision", cv=cv, n_jobs=1, refit=True)
            gs.fit(tr[cols], tr["y"], groups=tr["cv_group"])
            oof = cross_val_predict(gs.best_estimator_, tr[cols], tr["y"], groups=tr["cv_group"],
                                    cv=cv, method="predict_proba")[:, 1]
            thr = best_f1_threshold(tr["y"], oof)
            tune_s = time.time() - t
            best = gs.best_estimator_
            t = time.time()
            proba = best.predict_proba(te[cols])[:, 1]
            inf_s = time.time() - t
            fs_name = "full" if "text" in [p[0] for p in best.named_steps["features"].transformers] else "context"
            params = {k: v for k, v in gs.best_params_.items() if k != "features"}
            entry = {
                "selected_feature_set": fs_name, "selected_params": params,
                "cv_pr_auc_mean": round(gs.best_score_, 4),
                "cv_results": [{"feature_set": "full" if "text" in [p[0] for p in r["features"].transformers] else "context",
                                **{k: v for k, v in r.items() if k != "features"}, "pr_auc": round(s, 4)}
                               for r, s in zip(gs.cv_results_["params"], gs.cv_results_["mean_test_score"])],
                "threshold_from_train_oof": round(thr, 4),
                "test_at_0.5": binary_report(te["y"], proba, 0.5, S2_NAMES),
                "test_at_tuned_threshold": binary_report(te["y"], proba, thr, S2_NAMES),
                "tuning_seconds": round(tune_s, 1),
                "inference_ms_per_1k_rows": round(inf_s / len(te) * 1e6, 2),
                "model_size_mb": model_size_mb(best),
            }
            entry.update(extra_metrics(te, proba, thr, set(tr["raw_text"])))
            res["tuned"].setdefault(name, {})[mname] = entry
            log("stage2 tuned", name, mname, fs_name, params, "CV", entry["cv_pr_auc_mean"],
                "test PR-AUC", entry["test_at_0.5"]["pr_auc_positive"])
            if name == "POOLED_temporal":
                joblib.dump({"model": best, "threshold": thr, "feature_set": fs_name, "columns": cols},
                            MODELS_DIR / f"stage2_{mname}.joblib", compress=3)
            write("stage2", res)
    return res


# --------------------------------------------------------------------------- stage 1
def run_stage1(ds: pd.DataFrame) -> dict:
    a, b = stage1_split(ds, STAGE1_BENIGN_TRAIN_SAMPLE, SEED)
    d = ds[["label_binary", "org_id", "incident", "raw_text"]].copy()
    d["y"] = (ds["label_binary"] != "benign").astype(int)
    feat_cols = input_columns("full+source")
    d[feat_cols] = ds[feat_cols]
    tr, te = d.loc[a], d.loc[b]
    names = ("benign", "alert")
    res = {"task": "benign (0) vs alert = suspicious or malicious (1), all organisations",
           "train_rows": len(tr), "train_alerts": int(tr["y"].sum()),
           "train_benign_sampled": int((tr["y"] == 0).sum()),
           "test_rows": len(te), "test_alerts": int(te["y"].sum()),
           "note": "Benign training rows are a random sample (class prior differs from test); "
                   "test keeps the natural distribution.", "results": {}}
    runs = [("full", "logreg"), ("full", "random_forest"), ("text", "logreg"),
            ("context", "logreg"), ("full+source", "logreg")]
    for fs, mname in runs:
        cols = input_columns(fs)
        model = make_lr(fs) if mname == "logreg" else make_rf(fs, n_estimators=100, min_samples_leaf=2)
        t = time.time()
        model.fit(tr[cols], tr["y"])
        fit_s = time.time() - t
        t = time.time()
        proba = model.predict_proba(te[cols])[:, 1]
        inf_s = time.time() - t
        rep = binary_report(te["y"], proba, 0.5, names)
        rep.update({"train_seconds": round(fit_s, 1),
                    "inference_ms_per_1k_rows": round(inf_s / len(te) * 1e6, 2)})
        rep["per_org_recall_alert"] = {o: round(float((proba[(te["org_id"] == o).to_numpy() & (te["y"] == 1).to_numpy()] >= 0.5).mean()), 4)
                                       for o in te["org_id"].unique() if ((te["org_id"] == o) & (te["y"] == 1)).any()}
        res["results"].setdefault(fs, {})[mname] = rep
        log("stage1", fs, mname, "macroF1", rep["macro_f1"], "PR-AUC", rep["pr_auc_positive"])
        if fs == "full":
            rep["model_size_mb"] = model_size_mb(model)
            joblib.dump({"model": model, "threshold": 0.5, "feature_set": fs, "columns": cols},
                        MODELS_DIR / f"stage1_{mname}.joblib", compress=3)
            np.save(MODELS_DIR / f"_stage1_test_proba_{mname}.npy", proba)
        write("stage1", res)
    np.save(MODELS_DIR / "_stage1_test_index.npy", np.asarray(b))
    return res


# --------------------------------------------------------------------------- 3-class
def run_three_class(ds: pd.DataFrame) -> dict:
    a, b = stage1_split(ds, STAGE1_BENIGN_TRAIN_SAMPLE, SEED)
    cols = input_columns("full")
    tr, te = ds.loc[a], ds.loc[b]
    y_te = te["label_binary"].to_numpy()
    res = {"task": "3-class benign / suspicious / malicious on every test-window row",
           "test_rows": len(te), "test_distribution": te["label_binary"].value_counts().to_dict(),
           "hierarchical": {}, "flat": {}}
    s1_idx = np.load(MODELS_DIR / "_stage1_test_index.npy")
    assert np.array_equal(s1_idx, np.asarray(b)), "stage1 test index mismatch: rerun stage1"
    for mname in ["logreg", "random_forest"]:
        p1 = np.load(MODELS_DIR / f"_stage1_test_proba_{mname}.npy")
        s2 = joblib.load(MODELS_DIR / f"stage2_{mname}.joblib")
        p2 = s2["model"].predict_proba(te[s2["columns"]])[:, 1]
        probs = np.column_stack([1 - p1, p1 * (1 - p2), p1 * p2])
        # decision: alert if p1 >= 0.5, then malicious if p2 >= stage-2 threshold (from training OOF)
        pred = np.where(p1 < 0.5, "benign", np.where(p2 >= s2["threshold"], "malicious", "suspicious"))
        rep = multiclass_report(y_te, pred, LABELS)
        rep["argmax_of_combined_probabilities"] = multiclass_report(y_te, np.array(LABELS)[probs.argmax(1)], LABELS)
        res["hierarchical"][mname] = rep
        log("3class hierarchical", mname, rep["macro_f1"])
    for mname in ["logreg", "random_forest"]:
        model = make_lr("full", multiclass=True) if mname == "logreg" else make_rf("full", n_estimators=100, min_samples_leaf=2)
        t = time.time()
        model.fit(tr[cols], tr["label_binary"])
        fit_s = time.time() - t
        pred = model.predict(te[cols])
        rep = multiclass_report(y_te, pred, LABELS)
        rep["train_seconds"] = round(fit_s, 1)
        res["flat"][mname] = rep
        log("3class flat", mname, rep["macro_f1"])
        write("three_class", res)
    return res


# --------------------------------------------------------------------------- isolation forest
def run_iforest(ds: pd.DataFrame) -> dict:
    cols = input_columns("context")
    res = {"note": "Anomaly scores are reported separately from class probabilities. "
                   "Higher score = more anomalous (negated sklearn score_samples).", "experiments": {}}
    # (a) fitted on alert rows of the training window, unsupervised -> does it rank malicious higher?
    s2 = stage2_frame(ds)
    a, b = stage2_splits(s2)["POOLED_temporal"]
    tr, te = s2.loc[a], s2.loc[b]
    t = time.time()
    iso = make_iforest(contamination=0.01).fit(tr[cols])
    fit_s = time.time() - t
    tr_score = -iso.score_samples(tr[cols])
    te_score = -iso.score_samples(te[cols])
    thr = float(np.quantile(tr_score, 0.99))  # flag the top 1% of training-window scores
    rep = binary_report(te["y"], te_score, thr, S2_NAMES)
    rep.update({"fit_on": "POOLED_temporal training alerts (labels unused)", "threshold_rule":
                "99th percentile of training anomaly scores", "train_seconds": round(fit_s, 1),
                "model_size_mb": model_size_mb(iso), "flag_rate_test": round(float((te_score >= thr).mean()), 4)})
    res["experiments"]["alerts_malicious_vs_suspicious"] = rep
    joblib.dump({"model": iso, "threshold": thr, "columns": cols}, MODELS_DIR / "iforest.joblib", compress=3)
    log("iforest alerts PR-AUC", rep["pr_auc_positive"], "ROC", rep["roc_auc"])

    # disagreement with the tuned RF classifier on the same test rows
    rf = joblib.load(MODELS_DIR / "stage2_random_forest.joblib")
    rf_pred = rf["model"].predict_proba(te[rf["columns"]])[:, 1] >= rf["threshold"]
    flag = te_score >= thr
    tab = pd.crosstab([te["label_binary"].to_numpy()], [np.where(rf_pred, "RF:malicious", "RF:suspicious"),
                                                         np.where(flag, "IF:anomaly", "IF:normal")])
    res["experiments"]["disagreement_with_random_forest"] = {
        "rows": {str(k): {f"{c[0]} & {c[1]}": int(v) for c, v in row.items()} for k, row in tab.iterrows()}}

    # (b) benign reference: fitted on benign training sample only -> are alerts anomalous?
    a1, b1 = stage1_split(ds, STAGE1_BENIGN_TRAIN_SAMPLE, SEED)
    ben = ds.loc[a1]
    ben = ben[ben["label_binary"] == "benign"]
    te1 = ds.loc[b1]
    iso_b = make_iforest(contamination=0.01).fit(ben[cols])
    s_tr = -iso_b.score_samples(ben[cols])
    s_te = -iso_b.score_samples(te1[cols])
    thr_b = float(np.quantile(s_tr, 0.99))
    y_alert = (te1["label_binary"] != "benign").astype(int).to_numpy()
    y_mal = (te1["label_binary"] == "malicious").astype(int).to_numpy()
    res["experiments"]["benign_reference_alert_vs_benign"] = binary_report(y_alert, s_te, thr_b, ("benign", "alert"))
    res["experiments"]["benign_reference_malicious_vs_rest"] = binary_report(y_mal, s_te, thr_b, ("rest", "malicious"))
    log("iforest benign-ref alert PR-AUC", res["experiments"]["benign_reference_alert_vs_benign"]["pr_auc_positive"])
    write("iforest", res)
    return res


def write_registry():
    reg = {}
    for p in sorted(MODELS_DIR.glob("*.joblib")):
        if p.name.startswith("_"):
            continue
        reg[p.stem] = {"file": p.name, "size_mb": round(p.stat().st_size / 1e6, 2),
                       "feature_version": FEATURE_VERSION,
                       "trained": time.strftime("%Y-%m-%d %H:%M", time.localtime(p.stat().st_mtime))}
    (MODELS_DIR / "registry.json").write_text(json.dumps(reg, indent=2), encoding="utf-8")


if __name__ == "__main__":
    parts = sys.argv[1:] or ["stage2", "stage1", "three_class", "iforest"]
    log("loading dataset")
    ds = load_dataset()
    log("dataset", ds.shape)
    for p in parts:
        {"stage2": run_stage2, "stage1": run_stage1, "three_class": run_three_class,
         "iforest": run_iforest}[p](ds)
    write_registry()
    log("done")
