"""Retrieval for the investigation assistant (the "R" in RAG).

For one question it gathers, from ONE case only:
  1. case facts      counts per class and file, top flagged indicators, time span (structured, exact)
  2. focused events  events that match the question's indicators / class words / time window,
                     most severe first
  3. search hits     hybrid search over every event: BM25 (exact tokens such as IPs and hashes)
                     + sentence embeddings (meaning), fused by reciprocal rank
  4. linked events   the relationship mapper's strongest edges from the top hits
  5. knowledge       WitFoo lead rules (if the dataset reference file is present) + the measured
                     limits of the models
Every item carries an id ([E12], [K3], [S]) so the answer can cite it.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import CountVectorizer

from ..cases.pipeline import case_vectors
from ..cases.store import CaseStore
from ..ingestion.entities import extract
from . import embed

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "data" / "raw" / "precinct6" / "reference" / "lead_rules_catalog.json"
TOKEN = r"(?u)[A-Za-z0-9_][A-Za-z0-9_.:/@\\-]*[A-Za-z0-9_]|[A-Za-z0-9_]"
SEVERITY = {"malicious": 3, "suspicious": 2, "benign": 1, "not applicable": 0}

MODEL_FACTS = [
    "Labels mean WitFoo Precinct's automated triage, not analyst-verified ground truth. 'Malicious' means the "
    "event resembles events WitFoo's correlation engine put into an incident; it is not a confirmed attack.",
    "Measured on future, unseen incidents of the organisation with Cisco ASA logs: ROC-AUC about 0.955 and "
    "PR-AUC about 17 times chance; the Random Forest touched 90% of test incidents. Malicious precision is "
    "only about 0.26 to 0.36, so most 'malicious' flags still need an analyst.",
    "The models do not transfer to other organisations or log products (cross-organisation results are at "
    "chance). They only score Cisco ASA firewall and AWS VPC flow-style security events; other evidence "
    "is marked 'not applicable'.",
    "Benign vs alert (stage 1) is decided by the event type and is near-perfect; the learning is in stage 2, "
    "suspicious vs malicious. Probabilities are not calibrated.",
    "The Isolation Forest anomaly flag is a separate, label-free signal for alert traffic. It catches different "
    "malicious events than the Random Forest and is never merged into the class probabilities.",
    "Relationship links are inferences from shared indicators, closeness in time and similar content; they are "
    "not proof that two events belong to the same incident.",
]


def _bm25(tf, k1: float = 1.2, b: float = 0.75):
    tf = tf.tocsr().astype(np.float32)
    n = tf.shape[0]
    dl = np.asarray(tf.sum(1)).ravel()
    avg = dl.mean() if n else 1.0
    df = np.bincount(tf.indices, minlength=tf.shape[1])
    idf = np.log(1 + (n - df + 0.5) / (df + 0.5)).astype(np.float32)
    rows = np.repeat(np.arange(n), np.diff(tf.indptr))
    data = tf.data * (k1 + 1) / (tf.data + k1 * (1 - b + b * dl[rows] / avg))
    w = tf.copy()
    w.data = data * idf[tf.indices]
    return w


@dataclass
class CaseIndex:
    version: tuple
    events: pd.DataFrame
    ents: dict
    vec: CountVectorizer
    bm25: object
    vec_row: dict
    vecs: np.ndarray
    knowledge: list = field(default_factory=list)
    k_vec: CountVectorizer | None = None
    k_bm25: object = None


_cache: dict[str, CaseIndex] = {}
_lock = threading.Lock()


def _knowledge() -> list[dict]:
    docs = [{"id": f"K{i + 1}", "kind": "model", "title": "Model limits", "text": t} for i, t in enumerate(MODEL_FACTS)]
    if RULES.exists():
        d = json.loads(RULES.read_text(encoding="utf-8"))
        prod = d.get("products", {})
        sets = d.get("sets", {})
        for r in d.get("lead_rules", []):
            p = prod.get(str(r.get("product_id")), {})
            docs.append({"id": f"K{len(docs) + 1}", "kind": "rule",
                         "title": f"WitFoo lead rule {r['id']}: {r['description']}",
                         "text": f"{r['description']}. Criteria: {r.get('criteria', '')}. Product: "
                                 f"{p.get('vendor', '')} {p.get('name', '')}. Client role: "
                                 f"{sets.get(str(r.get('client_set_id')), '?')}; server role: "
                                 f"{sets.get(str(r.get('server_set_id')), '?')}."})
    return docs


def case_index(store: CaseStore, case_id: str) -> CaseIndex:
    with store.db(case_id) as con:
        version = tuple(con.execute("SELECT (SELECT COUNT(*) FROM events), (SELECT COUNT(*) FROM edges), "
                                    "(SELECT COUNT(*) FROM files)").fetchone())
    with _lock:
        hit = _cache.get(case_id)
        if hit and hit.version == version:
            return hit
    with store.db(case_id) as con:
        ev = pd.read_sql_query(
            "SELECT e.event_id, e.file_id, f.name AS file, f.artifact_type, e.source_row, e.ts, e.message, "
            "e.message_type, e.action, e.src_ip, e.dst_ip, e.dst_port, m.applicable, m.lr_class, m.lr_p_mal, "
            "m.rf_class, m.rf_p_mal, m.agree, m.an_flag FROM events e JOIN files f USING(file_id) "
            "LEFT JOIN ml m USING(event_id) ORDER BY e.event_id", con)
        ent = pd.read_sql_query("SELECT event_id, kind, value FROM entities", con)
    ev["cls"] = np.where(ev["applicable"] == 1, ev["lr_class"], "not applicable")
    for c in ("message", "message_type", "action", "file", "artifact_type"):
        ev[c] = ev[c].fillna("").astype(str)
    for c in ("src_ip", "dst_ip", "dst_port", "rf_class"):
        ev[c] = ev[c].astype(object).where(ev[c].notna(), None)
    ents: dict[int, set] = {}
    for eid, kind, val in ent.itertuples(index=False):
        ents.setdefault(int(eid), set()).add((kind, val))
    docs = [" ".join(filter(None, [m or "", mt or "", a or "", f"ml {c}", " ".join(v for _, v in ents.get(int(e), ()))]))
            for e, m, mt, a, c in zip(ev["event_id"], ev["message"], ev["message_type"], ev["action"], ev["cls"])]
    vec = CountVectorizer(token_pattern=TOKEN, lowercase=True, min_df=1)
    tf = vec.fit_transform(docs) if docs else None
    vec_row, vecs = case_vectors(store, case_id, ev) if len(ev) else ({}, np.zeros((0, 1), np.float32))
    know = _knowledge()
    k_vec = CountVectorizer(token_pattern=TOKEN, lowercase=True, stop_words="english")
    k_tf = k_vec.fit_transform([k["title"] + " " + k["text"] for k in know])
    idx = CaseIndex(version, ev, ents, vec, _bm25(tf) if tf is not None else None, vec_row, vecs, know,
                    k_vec, _bm25(k_tf))
    with _lock:
        _cache[case_id] = idx
    return idx


# ---------------------------------------------------------------------- question analysis
_TIME = re.compile(r"\b([01]?\d|2[0-3]):([0-5]\d)\b")


def analyze_question(q: str) -> dict:
    ql = q.lower()
    classes = [c for c in ("malicious", "suspicious", "benign") if c in ql]
    if re.search(r"\bnot applicable|unscored|refused\b", ql):
        classes.append("not applicable")
    times = [int(h) * 3600 + int(m) * 60 for h, m in _TIME.findall(q)]
    window = None
    if len(times) >= 2:
        window = (min(times[:2]), max(times[:2]))
    elif times:
        if re.search(r"\bafter\b|\bsince\b|\bfrom\b", ql):
            window = (times[0], 86400)
        elif re.search(r"\bbefore\b|\buntil\b", ql):
            window = (0, times[0])
        else:
            window = (times[0] - 900, times[0] + 900)
    intent = ("count" if re.search(r"\bhow many\b|\bnumber of\b|\bcount\b", ql) else
              "related" if re.search(r"\brelat|\bconnect|\blink", ql) else
              "timeline" if re.search(r"\bwhen\b|\btimeline\b|\bfirst\b|\blast\b|\bsequence\b", ql) else
              "explain" if re.search(r"\bwhy\b|\bexplain\b|\bwhat does\b|\bmean\b|\btrust\b|\breliab", ql) else
              "list" if re.search(r"\bwhich\b|\blist\b|\btop\b|\bshow\b|\bwho\b", ql) else "general")
    return {"entities": extract(q), "classes": classes, "window_utc_seconds_of_day": window,
            "anomaly": bool(re.search(r"anomal|unusual|outlier", ql)),
            "disagree": bool(re.search(r"disagree|conflict", ql)), "intent": intent}


# ---------------------------------------------------------------------- retrieval
def _rank(order: np.ndarray) -> dict:
    return {int(i): r for r, i in enumerate(order)}


def case_facts(idx: CaseIndex) -> dict:
    ev = idx.events
    files = (ev.groupby(["file_id", "file", "artifact_type"]).agg(events=("event_id", "size"),
             malicious=("cls", lambda s: int((s == "malicious").sum())),
             suspicious=("cls", lambda s: int((s == "suspicious").sum())),
             not_applicable=("cls", lambda s: int((s == "not applicable").sum())))
             .reset_index().to_dict("records"))
    flagged = ev[ev["cls"].isin(["malicious"])]
    top_ips = []
    if len(flagged):
        ips = pd.concat([flagged["src_ip"], flagged["dst_ip"]]).dropna().value_counts().head(8)
        top_ips = [{"ip": k, "malicious_events": int(v)} for k, v in ips.items()]
    ts = ev["ts"].dropna()
    return {"events": int(len(ev)), "classes": {k: int((ev["cls"] == k).sum()) for k in SEVERITY},
            "anomaly_flags": int(ev["an_flag"].fillna(0).sum()),
            "model_disagreements": int(((ev["applicable"] == 1) & (ev["agree"] == 0)).sum()),
            "files": files, "top_ips_in_malicious_events": top_ips,
            "first_event_utc": pd.to_datetime(ts.min(), unit="s", utc=True).isoformat() if len(ts) else None,
            "last_event_utc": pd.to_datetime(ts.max(), unit="s", utc=True).isoformat() if len(ts) else None,
            "classifier_shown": "Logistic Regression (Random Forest also stored per event)"}


def retrieve(store: CaseStore, case_id: str, question: str, k_focus: int = 12, k_search: int = 12,
             k_links: int = 2) -> dict:
    idx = case_index(store, case_id)
    qa = analyze_question(question)
    ev = idx.events
    out = {"analysis": qa, "facts": case_facts(idx), "events": [], "knowledge": [], "links": []}
    if ev.empty:
        return out
    sev = ev["cls"].map(SEVERITY).fillna(0).to_numpy() + ev["an_flag"].fillna(0).to_numpy() * 0.5
    mask = np.ones(len(ev), bool)
    filtered = False
    if qa["entities"]:
        want = {v for _, v in qa["entities"]}
        hit = np.array([bool({v for _, v in idx.ents.get(int(e), ())} & want) for e in ev["event_id"]])
        mask &= hit
        filtered = True
    if qa["classes"]:
        mask &= ev["cls"].isin(qa["classes"]).to_numpy()
        filtered = True
    if qa["anomaly"]:
        mask &= ev["an_flag"].fillna(0).to_numpy() == 1
        filtered = True
    if qa["disagree"]:
        mask &= ((ev["applicable"] == 1) & (ev["agree"] == 0)).to_numpy()
        filtered = True
    if qa["window_utc_seconds_of_day"]:
        lo, hi = qa["window_utc_seconds_of_day"]
        tod = (ev["ts"] % 86400).to_numpy()
        mask &= (tod >= lo) & (tod <= hi)
        filtered = True
    chosen: dict[int, str] = {}
    if filtered:
        ids = np.flatnonzero(mask)
        out["focus_matches"] = int(len(ids))
        p = ev["lr_p_mal"].fillna(0).to_numpy()
        order = ids[np.lexsort((-p[ids], -sev[ids]))] if qa["intent"] != "timeline" else ids[np.argsort(ev["ts"].to_numpy()[ids])]
        for i in order[:k_focus]:
            chosen[int(i)] = "matches the question's filters"
    # hybrid search
    qv = idx.vec.transform([question])
    bm = np.asarray((idx.bm25 @ qv.T).todense()).ravel() if idx.bm25 is not None else np.zeros(len(ev))
    qe = embed.Embedder.get().embed([embed.norm_text(question)])[0]
    rows = np.array([idx.vec_row.get(int(e), -1) for e in ev["event_id"]])
    dense = np.where(rows >= 0, idx.vecs[np.clip(rows, 0, None)] @ qe, 0.0)
    pool = np.flatnonzero(mask) if filtered and mask.sum() > 0 else np.arange(len(ev))
    r_bm, r_de = _rank(pool[np.argsort(-bm[pool])]), _rank(pool[np.argsort(-dense[pool])])
    rrf = {i: 1 / (60 + r_bm[i]) + 1 / (60 + r_de[i]) + 0.002 * sev[i] for i in pool}
    for i in sorted(rrf, key=rrf.get, reverse=True)[: k_search * 3]:
        if len(chosen) >= k_focus + k_search:
            break
        chosen.setdefault(int(i), "search match")
    # linked events from the relationship mapper
    seeds = [int(ev.at[i, "event_id"]) for i in list(chosen)[:5]]
    if seeds:
        with store.db(case_id) as con:
            q_marks = ",".join("?" * len(seeds))
            edges = con.execute(f"SELECT a, b, score, shared, dt FROM edges WHERE a IN ({q_marks}) OR b IN ({q_marks}) "
                                f"ORDER BY score DESC", seeds + seeds).fetchall()
        pos = {int(e): i for i, e in enumerate(ev["event_id"])}
        per_seed: dict = {}
        for a, b, s, sh, dt in edges:
            seed, other = (a, b) if a in seeds else (b, a)
            if per_seed.get(seed, 0) >= k_links or other not in pos:
                continue
            per_seed[seed] = per_seed.get(seed, 0) + 1
            out["links"].append({"from": f"E{seed}", "to": f"E{other}", "score": s, "shared": json.loads(sh),
                                 "dt_seconds": dt})
            chosen.setdefault(pos[other], "linked to a retrieved event")
    for i, why in chosen.items():
        r = ev.iloc[i]
        out["events"].append({
            "id": f"E{int(r.event_id)}", "event_id": int(r.event_id), "file": r.file, "row": int(r.source_row),
            "artifact_type": r.artifact_type,
            "time_utc": None if pd.isna(r.ts) else pd.to_datetime(r.ts, unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S"),
            "message": (r.message or "")[:300], "src_ip": r.src_ip, "dst_ip": r.dst_ip, "dst_port": r.dst_port,
            "ml": {"class_lr": r.cls, "class_rf": r.rf_class if r.applicable == 1 else "not applicable",
                   "p_malicious_lr": None if pd.isna(r.lr_p_mal) else round(float(r.lr_p_mal), 3),
                   "anomaly_flag": bool(r.an_flag == 1)},
            "why_retrieved": why})
    # knowledge
    kq = idx.k_vec.transform([question])
    ks = np.asarray((idx.k_bm25 @ kq.T).todense()).ravel()
    model_docs = [k for k in idx.knowledge if k["kind"] == "model"]
    rules = [idx.knowledge[i] for i in np.argsort(-ks)[:3] if ks[i] > 0 and idx.knowledge[i]["kind"] == "rule"]
    out["knowledge"] = model_docs + rules
    return out
