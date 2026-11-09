"""Train / validation / test scores for the persisted models, measured the same way.

  train      = the model scored on the rows it was fitted on (shows over-fitting)
  validation = out-of-fold predictions from the same grouped 3-fold CV used for tuning
               (StratifiedGroupKFold, groups = incident or org + 2-hour block)
  test       = the held-out future window (never used for any choice)
All at the model's own decision threshold. Reads models/ (never writes it).
Output: reports/metrics/train_val_test.json
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import StratifiedGroupKFold, cross_val_predict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidentia.ml.config import (FEATURE_VERSION, METRICS_DIR, MODELS_DIR, SEED,  # noqa: E402
                                 STAGE1_BENIGN_TRAIN_SAMPLE)
from evidentia.ml.data import stage1_split, stage2_frame, stage2_splits  # noqa: E402
from evidentia.ml.evaluate import binary_report  # noqa: E402

CACHE = ROOT / "data" / "processed" / f"dataset_{FEATURE_VERSION}.joblib"
KEEP = ("accuracy", "macro_f1", "pr_auc_positive", "roc_auc", "positive_rate_baseline", "n", "n_positive")


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def short(rep: dict, pos: str) -> dict:
    out = {k: rep[k] for k in KEEP}
    out[f"{pos}_precision"] = rep["per_class"][pos]["precision"]
    out[f"{pos}_recall"] = rep["per_class"][pos]["recall"]
    out[f"{pos}_f1"] = rep["per_class"][pos]["f1"]
    return out


def main() -> None:
    ds = joblib.load(CACHE)
    res = {"definitions": {
        "train": "persisted model scored on its own training rows",
        "validation": "out-of-fold predictions, StratifiedGroupKFold(3) on the training window, same groups as tuning",
        "test": "held-out future window"}, "stage2_pooled": {}, "stage1": {}}

    # Stage 2 (POOLED split, the persisted models).
    s2 = stage2_frame(ds)
    a, b = stage2_splits(s2)["POOLED_temporal"]
    tr, te = s2.loc[a], s2.loc[b]
    cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=SEED)
    names = ("suspicious", "malicious")
    for m in ("logreg", "random_forest"):
        art = joblib.load(MODELS_DIR / f"stage2_{m}.joblib")
        model, thr, cols = art["model"], art["threshold"], art["columns"]
        p_tr = model.predict_proba(tr[cols])[:, 1]
        p_val = cross_val_predict(clone(model), tr[cols], tr["y"], groups=tr["cv_group"], cv=cv,
                                  method="predict_proba")[:, 1]
        p_te = model.predict_proba(te[cols])[:, 1]
        res["stage2_pooled"][m] = {"threshold": round(float(thr), 4), "feature_set": art["feature_set"],
                                   **{k: short(binary_report(y, p, thr, names), "malicious")
                                      for k, y, p in [("train", tr["y"], p_tr), ("validation", tr["y"], p_val),
                                                      ("test", te["y"], p_te)]}}
        log("stage2", m, {k: res["stage2_pooled"][m][k]["accuracy"] for k in ("train", "validation", "test")})

    # Stage 1 (persisted models; validation skipped: refitting on 306k rows x3 adds nothing to a 1.0 score).
    a1, b1 = stage1_split(ds, STAGE1_BENIGN_TRAIN_SAMPLE, SEED)
    y = (ds["label_binary"] != "benign").astype(int)
    for m in ("logreg", "random_forest"):
        art = joblib.load(MODELS_DIR / f"stage1_{m}.joblib")
        model, cols = art["model"], art["columns"]
        p_tr = model.predict_proba(ds.loc[a1, cols])[:, 1]
        p_te = np.load(MODELS_DIR / f"_stage1_test_proba_{m}.npy")
        res["stage1"][m] = {k: short(binary_report(yy, p, 0.5, ("benign", "alert")), "alert")
                            for k, yy, p in [("train", y.loc[a1], p_tr), ("test", y.loc[b1], p_te)]}
        log("stage1", m, {k: res["stage1"][m][k]["accuracy"] for k in ("train", "test")})

    out = METRICS_DIR / "train_val_test.json"
    out.write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    log("wrote", out)


if __name__ == "__main__":
    main()
