"""Processing pipeline for one uploaded evidence file, then case-wide derivatives.

    store original (hash, read-only) -> parse -> events -> ML (security logs) -> entities
      -> embeddings (case cache) -> relationship edges (whole case)

ML runs once here, at upload; questions later read the stored results.
"""
from __future__ import annotations

import json
import math
import threading
import traceback

import numpy as np
import pandas as pd

from ..ingestion.entities import extract
from ..ingestion.upload import EVENT_COLS, parse_upload
from ..rag import embed
from ..relations import mapper
from .store import CaseStore

_case_locks: dict[str, threading.Lock] = {}
_guard = threading.Lock()


def case_lock(case_id: str) -> threading.Lock:
    with _guard:
        return _case_locks.setdefault(case_id, threading.Lock())


def _clean(v):
    try:
        if v is None or pd.isna(v):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(v, (np.floating,)):
        return None if np.isnan(v) else float(v)
    if isinstance(v, (np.integer,)):
        return int(v)
    return v


def _artifact_type(ext: str, parser: dict, n: int, n_app: int) -> str:
    fm = parser.get("line_formats", {})
    if n and (n_app / n >= 0.5 or (fm.get("cisco_asa", 0) + fm.get("aws_vpc_flow", 0)) / n >= 0.5):
        return "security_log"
    if ext in ("html", "htm"):
        return "web_page"
    cols = [c.lower() for c in parser.get("columns_available", [])]
    if any(c in ("url", "visit_url", "page_url") for c in cols):
        return "browser_history"
    if ext in ("txt", "log", ""):
        return "text"
    return "table"


def process_file(store: CaseStore, orch, case_id: str, file_id: int, file_name: str, data: bytes,
                 column_map: dict | None = None) -> None:
    lock = case_lock(case_id)
    with lock:
        try:
            parsed = parse_upload(file_name, data, column_map)
            ev = parsed.events.reset_index(drop=True)
            with store.db(case_id) as con:
                start = (con.execute("SELECT COALESCE(MAX(event_id), 0) FROM events").fetchone()[0]) + 1
            n = len(ev)
            ids = np.arange(start, start + n)
            extra_cols = [c for c in ev.columns if c not in EVENT_COLS and c not in ("source_file", "source_row")]
            rows = []
            for i in range(n):
                r = ev.iloc[i]
                extra = {c: _clean(r[c]) for c in extra_cols if _clean(r[c]) not in (None, "")}
                rows.append((int(ids[i]), file_id, int(r["source_row"]), _clean(r["timestamp"]),
                             _clean(r["message_sanitized"]), *(None if _clean(r[c]) is None else str(r[c])
                                                               for c in EVENT_COLS[2:]),
                             json.dumps(extra) if extra else None))
            ml_rows, n_app = [], 0
            if n:
                ev_ml = ev.copy()
                ev_ml["file"] = str(file_id)
                res = orch.analyze(ev_ml, scope_col="file")
                for i, r in enumerate(res):
                    a, c = r["applicability"], r["classifiers"]
                    n_app += int(a["applicable"])
                    ml_rows.append((int(ids[i]), int(a["applicable"]), a["reason"], a["token_coverage"],
                                    c["logreg"]["predicted_class"], c["logreg"]["p_alert_stage1"],
                                    c["logreg"]["p_malicious_given_alert_stage2"],
                                    c["random_forest"]["predicted_class"], c["random_forest"]["p_alert_stage1"],
                                    c["random_forest"]["p_malicious_given_alert_stage2"], int(r["models_agree"]),
                                    int(r["anomaly"]["scored"]), int(r["anomaly"]["flagged"]), r["anomaly"]["score"],
                                    json.dumps({k: r[k] for k in ("classifiers", "anomaly", "notes", "decision_rule",
                                                                  "label_semantics", "versions", "applicability")})))
            ent_rows = []
            for i in range(n):
                r = ev.iloc[i]
                for kind, val in extract(_clean(r["message_sanitized"]),
                                         {"src_ip": _clean(r["src_ip"]), "dst_ip": _clean(r["dst_ip"])}):
                    ent_rows.append((int(ids[i]), kind, val))
            art = _artifact_type(parsed.file_type, parsed.parser_counts, n, n_app)
            with store.db(case_id) as con:
                con.executemany("INSERT INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
                con.executemany("INSERT INTO ml VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)", ml_rows)
                con.executemany("INSERT INTO entities VALUES (?,?,?)", ent_rows)
                con.execute("UPDATE files SET status='linking', file_type=?, artifact_type=?, n_events=?, "
                            "n_applicable=?, warnings=?, parser=? WHERE file_id=?",
                            (parsed.file_type, art, n, n_app, json.dumps(parsed.warnings),
                             json.dumps(parsed.parser_counts, default=str), file_id))
            rebuild_links(store, case_id)
            with store.db(case_id) as con:
                con.execute("UPDATE files SET status='ready' WHERE file_id=?", (file_id,))
        except Exception as e:  # keep the case usable; report the error on the file
            with store.db(case_id) as con:
                con.execute("UPDATE files SET status='error', error=? WHERE file_id=?",
                            (f"{type(e).__name__}: {e}\n{traceback.format_exc(limit=3)}", file_id))


def load_case_frame(store: CaseStore, case_id: str) -> tuple[pd.DataFrame, dict[int, set]]:
    with store.db(case_id) as con:
        ev = pd.read_sql_query("SELECT event_id, file_id, ts, message, message_type FROM events", con)
        ent = pd.read_sql_query("SELECT event_id, kind, value FROM entities", con)
    ents: dict[int, set] = {}
    for eid, kind, val in ent.itertuples(index=False):
        ents.setdefault(int(eid), set()).add((kind, val))
    return ev, ents


def case_vectors(store: CaseStore, case_id: str, ev: pd.DataFrame) -> tuple[dict, np.ndarray]:
    """Embedding row per event, using and extending the case's cache file."""
    path = store.embeddings_path(case_id)
    texts = [m if isinstance(m, str) and m.strip() else (mt or "") for m, mt in zip(ev["message"], ev["message_type"])]
    rows, cache = embed.embed_unique(texts, embed.load_cache(path))
    embed.save_cache(path, cache)
    return dict(zip(ev["event_id"].astype(int), rows.tolist())), cache["vecs"]


def rebuild_links(store: CaseStore, case_id: str) -> int:
    ev, ents = load_case_frame(store, case_id)
    if ev.empty:
        return 0
    vec_row, vecs = case_vectors(store, case_id, ev)
    ts = {int(e): (None if pd.isna(t) else float(t)) for e, t in zip(ev["event_id"], ev["ts"])}
    files = dict(zip(ev["event_id"].astype(int), ev["file_id"].astype(int)))
    edges = mapper.build_edges(ts, files, ents, vec_row, vecs)
    with store.db(case_id) as con:
        con.execute("DELETE FROM edges")
        con.executemany("INSERT INTO edges VALUES (?,?,?,?,?,?,?,?)",
                        [(e["a"], e["b"], e["score"], e["temporal"], e["entity"], e["semantic"],
                          json.dumps(e["shared"]), e["dt"]) for e in edges])
    return len(edges)
