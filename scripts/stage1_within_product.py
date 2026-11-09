"""Stage 1 without the log-type shortcut: benign vs alert *inside one product*.

Why: across all logs Stage 1 scores ~1.0 because alerts come from different products
than benign rows. Inside a single product that shortcut is gone.

Facts that decide which products can be tested (computed below, written to JSON):
  ASA Firewall and AWS VPC Security are (almost) all alerts -> no benign class to test.
  Windows Active Directory and Barracuda WAF have both classes -> tested here.

Two measurements, both on the same held-out future window as the main Stage 1:
  (a) the persisted all-products Stage 1 models, sliced to one product's test rows;
  (b) fresh models trained on that product's training rows only.
Reads models/ (never writes it). Output: reports/metrics/stage1_within_product.json
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidentia.ml.config import FEATURE_VERSION, METRICS_DIR, MODELS_DIR, SEED  # noqa: E402
from evidentia.ml.evaluate import binary_report  # noqa: E402
from evidentia.ml.features import input_columns  # noqa: E402
from evidentia.ml.models import make_lr, make_rf  # noqa: E402

CACHE = ROOT / "data" / "processed" / f"dataset_{FEATURE_VERSION}.joblib"
NAMES = ("benign", "alert")
MIN_TEST_ALERTS = 10


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def main() -> None:
    np.random.seed(SEED)
    ds = joblib.load(CACHE)
    ds["y"] = (ds["label_binary"] != "benign").astype(int)
    tr_mask = ~ds["is_test"] & ~ds["drop_from_train"]

    counts = (ds.groupby(["product_name", "is_test"])["y"].agg(rows="size", alerts="sum")
              .reset_index())
    counts["benign"] = counts["rows"] - counts["alerts"]
    res = {"task": "benign (0) vs alert (1) inside a single product (no log-type shortcut)",
           "product_counts": counts.to_dict("records"), "products": {}}

    # Persisted Stage 1 test predictions (all products, same test window).
    test_idx = np.load(MODELS_DIR / "_stage1_test_index.npy")
    persisted = {m: pd.Series(np.load(MODELS_DIR / f"_stage1_test_proba_{m}.npy"), index=test_idx)
                 for m in ("logreg", "random_forest")}

    for prod, g in counts.groupby("product_name"):
        te_row = g[g["is_test"]]
        tr_row = g[~g["is_test"]]
        if te_row.empty or tr_row.empty:
            continue
        te_alerts, te_benign = int(te_row["alerts"].iloc[0]), int(te_row["benign"].iloc[0])
        tr_alerts, tr_benign = int(tr_row["alerts"].iloc[0]), int(tr_row["benign"].iloc[0])
        if min(te_alerts, te_benign) < MIN_TEST_ALERTS or min(tr_alerts, tr_benign) < MIN_TEST_ALERTS:
            res["products"][prod] = {"tested": False,
                                     "reason": f"too few rows of one class (train benign {tr_benign}, "
                                               f"train alerts {tr_alerts}, test benign {te_benign}, "
                                               f"test alerts {te_alerts}; need >= {MIN_TEST_ALERTS})"}
            continue

        pm = ds["product_name"] == prod
        tr, te = ds.loc[pm & tr_mask], ds.loc[pm & ds["is_test"]]
        entry = {"tested": True, "train_rows": len(tr), "train_alerts": int(tr["y"].sum()),
                 "test_rows": len(te), "test_alerts": int(te["y"].sum()),
                 "persisted_all_products_model": {}, "within_product_model": {}}

        for m, p in persisted.items():
            proba = p.loc[te.index].to_numpy()
            entry["persisted_all_products_model"][m] = binary_report(te["y"], proba, 0.5, NAMES)
            log(prod, "persisted", m, "PR-AUC", entry["persisted_all_products_model"][m]["pr_auc_positive"])

        for fs, m in [("full", "logreg"), ("full", "random_forest"), ("text", "logreg"), ("context", "logreg")]:
            cols = input_columns(fs)
            model = make_lr(fs) if m == "logreg" else make_rf(fs, n_estimators=100, min_samples_leaf=2)
            t = time.time()
            model.fit(tr[cols], tr["y"])
            proba = model.predict_proba(te[cols])[:, 1]
            rep = binary_report(te["y"], proba, 0.5, NAMES)
            rep["seconds"] = round(time.time() - t, 1)
            entry["within_product_model"].setdefault(fs, {})[m] = rep
            log(prod, "within", fs, m, "PR-AUC", rep["pr_auc_positive"], "ROC", rep["roc_auc"])
        res["products"][prod] = entry

    # Is the Stage 1 label a deterministic function of (product, message_type)?
    key = ds["product_name"].astype(str) + "|" + ds["message_type"].astype(str)
    purity = pd.crosstab(key, ds["y"])
    mixed = purity[(purity.get(0, 0) > 0) & (purity.get(1, 0) > 0)]
    # Lookup-table baseline: learn key -> majority label on training rows; unseen key -> benign.
    tr_keys = ds.loc[tr_mask].groupby(key[tr_mask])["y"].mean()
    te = ds.loc[ds["is_test"]]
    te_key = key[ds["is_test"]]
    seen = te_key.isin(tr_keys.index)
    pred = te_key.map(tr_keys).fillna(0.0).to_numpy()
    res["label_is_function_of_event_type"] = {
        "distinct_product_message_type_keys": int(len(purity)),
        "keys_with_both_benign_and_alert": int(len(mixed)),
        "rows_in_mixed_keys": int(key.isin(mixed.index).sum()),
        "total_rows": int(len(ds)),
        "lookup_table_baseline_on_test": binary_report(te["y"], pred, 0.5, NAMES),
        "test_rows_with_key_unseen_in_train": int((~seen).sum()),
        "test_alerts_with_key_unseen_in_train": int(((~seen) & (te["y"] == 1)).sum()),
    }
    log("mixed keys", len(mixed), "lookup baseline macroF1",
        res["label_is_function_of_event_type"]["lookup_table_baseline_on_test"]["macro_f1"])

    out =METRICS_DIR / "stage1_within_product.json"
    out.write_text(json.dumps(res, indent=2, default=float), encoding="utf-8")
    log("wrote", out)


if __name__ == "__main__":
    main()
