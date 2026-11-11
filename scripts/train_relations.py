"""Learn and evaluate the relationship mapper's weights on WitFoo incidents.

Ground truth: two alert events are RELATED when they share an incident id. Incident ids are used
only as labels here; they are never an input of the mapper.

For each organisation (ORG-0005, ORG-0004) and each side of the same temporal cut-off as the ML
models (train window / test window), queries are malicious events; candidates come from the same
candidate generator the app uses (nearest-in-time events sharing an indicator) among that side's
alert rows. The combined logistic regression is fitted on train-window pairs only and every scorer
is evaluated on test-window queries: P@5, MRR, recall@10 and the candidate generator's own recall.

Caveat (stated in the report): WitFoo built incidents partly from shared hosts and time, so the
entity and temporal signals are favoured by this ground truth.

Output: models/relations.joblib, reports/metrics/relations.json
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import joblib
import numpy as np
from sklearn.linear_model import LogisticRegression

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidentia.ingestion.entities import extract  # noqa: E402
from evidentia.ml.config import FEATURE_VERSION, METRICS_DIR, MODELS_DIR, SEED  # noqa: E402
from evidentia.rag import embed  # noqa: E402
from evidentia.relations import mapper  # noqa: E402

CACHE = ROOT / "data" / "processed" / f"dataset_{FEATURE_VERSION}.joblib"
MAX_QUERIES = 1500
TAU = 300.0


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def build_part(part, rng) -> dict:
    ids = part.index.to_numpy()
    ts = dict(zip(ids, part["timestamp"].astype(float)))
    ents = {i: set(extract(t)) for i, t in zip(ids, part["raw_text"])}
    inc = {i: set(json.loads(s)) if isinstance(s, str) and s else set() for i, s in zip(ids, part["incident_ids"])}
    mal = [i for i in ids if inc[i]]
    queries = list(rng.choice(mal, size=min(MAX_QUERIES, len(mal)), replace=False)) if mal else []
    pairs = sorted(mapper.candidate_pairs(ts, {i: 0 for i in ids}, ents, queries=queries, k_entity=10, k_cross=0))
    idf = mapper.entity_idf(ents)
    rows, vecs_cache = embed.embed_unique(list(part["raw_text"]), None)
    vec_row = dict(zip(ids, rows.tolist()))
    F, _, _ = mapper.pair_features(pairs, ts, ents, idf, vec_row, vecs_cache["vecs"], TAU)
    y = np.array([int(bool(inc[a] & inc[b])) for a, b in pairs])
    # how many true related events exist per query (within this part), for candidate recall
    by_inc: dict = {}
    for i in mal:
        for c in inc[i]:
            by_inc.setdefault(c, set()).add(i)
    true_n = {q: len(set().union(*(by_inc[c] for c in inc[q])) - {q}) for q in queries}
    return {"pairs": pairs, "F": F, "y": y, "queries": queries, "true_n": true_n}


def rank_metrics(part: dict, scores: np.ndarray) -> dict:
    per_q: dict = {}
    for (a, b), s, yy in zip(part["pairs"], scores, part["y"]):
        for q, other in ((a, b), (b, a)):
            if q in part["true_n"]:
                per_q.setdefault(q, []).append((s, yy))
    p5, mrr, r10 = [], [], []
    for q, lst in per_q.items():
        if part["true_n"][q] == 0:
            continue
        lst.sort(key=lambda t: -t[0])
        labels = [yy for _, yy in lst]
        p5.append(sum(labels[:5]) / 5)
        first = next((k for k, yy in enumerate(labels) if yy), None)
        mrr.append(0.0 if first is None else 1.0 / (first + 1))
        r10.append(sum(labels[:10]) / min(10, part["true_n"][q]))
    found = sum(sum(yy for _, yy in lst) for q, lst in per_q.items())
    total = sum(n for n in part["true_n"].values())
    return {"queries": len(p5), "p_at_5": round(float(np.mean(p5)), 4) if p5 else None,
            "mrr": round(float(np.mean(mrr)), 4) if mrr else None,
            "recall_at_10": round(float(np.mean(r10)), 4) if r10 else None,
            "candidate_recall": round(found / total, 4) if total else None}


def main() -> None:
    rng = np.random.default_rng(SEED)
    log("loading dataset")
    ds = joblib.load(CACHE)
    parts = {}
    for org in ("ORG-0005", "ORG-0004"):
        alerts = ds[(ds["org_id"] == org) & (ds["label_binary"] != "benign")]
        for side, mask in (("train", ~alerts["is_test"] & ~alerts["drop_from_train"]), ("test", alerts["is_test"])):
            t = time.time()
            parts[(org, side)] = build_part(alerts[mask], rng)
            p = parts[(org, side)]
            log(org, side, "rows", int(mask.sum()), "queries", len(p["queries"]), "pairs", len(p["pairs"]),
                "positive", int(p["y"].sum()), f"{time.time() - t:.0f}s")
    del ds
    # 1) Unconstrained LR, kept as a diagnostic: inside the candidate set every pair already shares an
    #    indicator, so similarity can get NEGATIVE weights (bursts of near-identical lines from different
    #    incidents). Such weights would rank strong shared evidence lower in a case, so they are not used.
    Ftr = np.vstack([parts[(o, "train")]["F"] for o in ("ORG-0005", "ORG-0004")])
    ytr = np.concatenate([parts[(o, "train")]["y"] for o in ("ORG-0005", "ORG-0004")])
    lr = LogisticRegression(class_weight="balanced", max_iter=1000).fit(Ftr, ytr)
    unconstrained = {"coef": [round(float(c), 4) for c in lr.coef_[0]], "intercept": round(float(lr.intercept_[0]), 4)}
    log("unconstrained LR (diagnostic)", unconstrained)
    # 2) Used weights: non-negative mix chosen on TRAIN queries by mean MRR over both orgs (grid on the
    #    simplex, step 0.05), then a 1-D logistic calibration of the mix so the score reads as a probability.
    best, best_mrr = None, -1.0
    grid = [(a / 20, b / 20, (20 - a - b) / 20) for a in range(21) for b in range(21 - a)]
    for w in grid:
        m = np.mean([rank_metrics(parts[(o, "train")], parts[(o, "train")]["F"] @ np.array(w))["mrr"]
                     for o in ("ORG-0005", "ORG-0004")])
        if m > best_mrr:
            best, best_mrr = w, m
    mix = Ftr @ np.array(best)
    cal = LogisticRegression(class_weight="balanced", max_iter=1000).fit(mix.reshape(-1, 1), ytr)
    a, b0 = float(cal.coef_[0][0]), float(cal.intercept_[0])
    weights = {"coef": [round(a * w, 4) for w in best], "intercept": round(b0, 4), "mix": list(best),
               "tau": TAU, "features": list(mapper.FEATURES), "trained": time.strftime("%Y-%m-%d %H:%M"),
               "train_pairs": int(len(ytr)), "train_positive": int(ytr.sum()),
               "selection": "non-negative mix maximising mean train MRR (simplex grid, step 0.05) + 1-D logistic calibration",
               "train_mrr": round(float(best_mrr), 4)}
    log("weights", weights)

    scorers = {"temporal_only": lambda F: F[:, 0], "entity_only": lambda F: F[:, 1],
               "semantic_only": lambda F: F[:, 2], "equal_average": lambda F: F.mean(1),
               "combined_learned": lambda F: mapper.combine(F, weights),
               "unconstrained_lr_diagnostic": lambda F: mapper.combine(F, unconstrained)}
    res = {"ground_truth": "two alert events share a WitFoo incident id (labels only; never an input)",
           "caveat": "WitFoo built incidents partly from shared hosts and time, so entity and temporal "
                     "signals are favoured by this ground truth.",
           "candidates": "nearest-in-time events sharing an indicator (k=10 per indicator), alert rows of the "
                         "same organisation and side of the temporal cut-off",
           "weights": weights, "unconstrained_lr_diagnostic": unconstrained, "results": {}}
    for (org, side), p in parts.items():
        res["results"].setdefault(org, {})[side] = {
            "queries_sampled": len(p["queries"]), "pairs": len(p["pairs"]), "positive_pairs": int(p["y"].sum()),
            **{name: rank_metrics(p, f(p["F"])) for name, f in scorers.items()}}
        log(org, side, {k: v["mrr"] for k, v in res["results"][org][side].items() if isinstance(v, dict)})
    joblib.dump(weights, MODELS_DIR / "relations.joblib")
    (METRICS_DIR / "relations.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    log("wrote models/relations.joblib and reports/metrics/relations.json")


if __name__ == "__main__":
    main()
