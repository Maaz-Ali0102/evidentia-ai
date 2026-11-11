"""Evidence relationship mapper.

Two events are scored on three signals:

  temporal  exp(-|dt| / tau)                       closeness in time (0 when a time is missing)
  entity    IDF-weighted Jaccard of their indicators  shared IPs, domains, users, hashes... (rare ones weigh more)
  semantic  cosine of their sentence embeddings     same kind of content in different words

The combined score is a logistic function of a NON-NEGATIVE mix of the three signals, chosen on
WitFoo training-window pairs (scripts/train_relations.py: events of the same incident = related)
and saved in models/relations.joblib; until that file exists, fixed fallback weights are used.
On WitFoo the chosen mix is time only (entity and content did not improve ranking among candidates
that already share an indicator), so build_edges adds an evidence gate: time alone never links two
events; a link needs a shared indicator or content similarity >= SEMANTIC_MIN.

Pairs are not all-against-all: candidates are the nearest-in-time events that share an indicator,
plus the nearest events from other files (so a browser visit can meet a firewall line).
"""
from __future__ import annotations

import math
from collections import defaultdict
from pathlib import Path

import joblib
import numpy as np

ROOT = Path(__file__).resolve().parents[2]
WEIGHTS_PATH = ROOT / "models" / "relations.joblib"
FEATURES = ("temporal", "entity", "semantic")
SEMANTIC_MIN = 0.6
FALLBACK = {"coef": [2.5, 4.0, 2.0], "intercept": -4.0, "tau": 300.0, "source": "fallback (not trained)"}


def load_weights() -> dict:
    if WEIGHTS_PATH.exists():
        w = joblib.load(WEIGHTS_PATH)
        return {**w, "source": f"learned ({w.get('trained', '?')})"}
    return dict(FALLBACK)


def entity_idf(ents: dict[int, set]) -> dict:
    df: dict = defaultdict(int)
    for s in ents.values():
        for e in s:
            df[e] += 1
    n = max(len(ents), 1)
    return {e: math.log((n + 1) / (c + 1)) + 1.0 for e, c in df.items()}


def candidate_pairs(ts: dict[int, float], files: dict[int, int], ents: dict[int, set],
                    queries=None, k_entity: int = 6, k_cross: int = 2) -> set:
    """Candidate (a, b) pairs with a < b. `queries` limits the anchors (all events by default)."""
    anchors = list(ts) if queries is None else list(queries)
    by_ent: dict = defaultdict(list)
    for eid, s in ents.items():
        t = ts.get(eid)
        key = t if t is not None and not math.isnan(t) else math.inf
        for e in s:
            by_ent[e].append((key, eid))
    for v in by_ent.values():
        v.sort()
    pos = {e: {eid: i for i, (_, eid) in enumerate(v)} for e, v in by_ent.items()}
    pairs: set = set()
    half = max(k_entity // 2, 1)
    for a in anchors:
        for e in ents.get(a, ()):
            lst = by_ent[e]
            if len(lst) < 2:
                continue
            i = pos[e][a]
            for j in range(max(0, i - half), min(len(lst), i + half + 1)):
                b = lst[j][1]
                if b != a:
                    pairs.add((a, b) if a < b else (b, a))
    if k_cross:
        timed = sorted((t, eid) for eid, t in ts.items() if t is not None and not math.isnan(t))
        order = {eid: i for i, (_, eid) in enumerate(timed)}
        for a in anchors:
            if a not in order:
                continue
            i, got = order[a], 0
            for step in range(1, 40):
                for j in (i - step, i + step):
                    if 0 <= j < len(timed) and got < k_cross:
                        b = timed[j][1]
                        if files.get(b) != files.get(a):
                            pairs.add((a, b) if a < b else (b, a))
                            got += 1
                if got >= k_cross:
                    break
    return pairs


def pair_features(pairs: list, ts: dict, ents: dict, idf: dict, vec_row: dict, vecs: np.ndarray | None,
                  tau: float) -> tuple[np.ndarray, list, np.ndarray]:
    n = len(pairs)
    F = np.zeros((n, 3), dtype=np.float32)
    dts = np.full(n, np.nan)
    shared_all = []
    for k, (a, b) in enumerate(pairs):
        ta, tb = ts.get(a), ts.get(b)
        if ta is not None and tb is not None and not (math.isnan(ta) or math.isnan(tb)):
            dt = abs(ta - tb)
            dts[k] = dt
            F[k, 0] = math.exp(-dt / tau)
        ea, eb = ents.get(a, set()), ents.get(b, set())
        sh = ea & eb
        if sh:
            un = ea | eb
            F[k, 1] = sum(idf.get(e, 1.0) for e in sh) / sum(idf.get(e, 1.0) for e in un)
        shared_all.append(sorted(sh, key=lambda e: -idf.get(e, 1.0))[:6])
    if vecs is not None and len(vecs) and n:
        ia = np.array([vec_row.get(a, -1) for a, _ in pairs])
        ib = np.array([vec_row.get(b, -1) for _, b in pairs])
        ok = (ia >= 0) & (ib >= 0)
        F[ok, 2] = np.clip((vecs[ia[ok]] * vecs[ib[ok]]).sum(1), 0, 1)
    return F, shared_all, dts


def combine(F: np.ndarray, w: dict) -> np.ndarray:
    z = F @ np.asarray(w["coef"], dtype=np.float32) + float(w["intercept"])
    return 1.0 / (1.0 + np.exp(-z))


def build_edges(ts: dict, files: dict, ents: dict, vec_row: dict, vecs, weights: dict | None = None,
                top_k: int = 5, min_score: float = 0.5) -> list[dict]:
    """Scored relationship edges for a whole case (each event keeps its top_k strongest links)."""
    w = weights or load_weights()
    idf = entity_idf(ents)
    pairs = sorted(candidate_pairs(ts, files, ents))
    if not pairs:
        return []
    F, shared, dts = pair_features(pairs, ts, ents, idf, vec_row, vecs, float(w["tau"]))
    s = combine(F, w)
    # Evidence gate: time alone never creates a link. On WitFoo incidents the learned ranking is driven by
    # time (reports/metrics/relations.json), but a case mixes artifacts, so a link also needs a shared
    # indicator or clearly similar content.
    keep = (s >= min_score) & ((F[:, 1] > 0) | (F[:, 2] >= SEMANTIC_MIN))
    best: dict = defaultdict(list)
    for k in np.flatnonzero(keep):
        a, b = pairs[k]
        best[a].append((s[k], k))
        best[b].append((s[k], k))
    chosen = set()
    for lst in best.values():
        lst.sort(reverse=True)
        chosen.update(k for _, k in lst[:top_k])
    out = []
    for k in sorted(chosen):
        a, b = pairs[k]
        out.append({"a": a, "b": b, "score": round(float(s[k]), 4), "temporal": round(float(F[k, 0]), 4),
                    "entity": round(float(F[k, 1]), 4), "semantic": round(float(F[k, 2]), 4),
                    "shared": [f"{kind}:{val}" for kind, val in shared[k]],
                    "dt": None if math.isnan(dts[k]) else round(float(dts[k]), 1)})
    return out
