"""Evidentia AI backend (FastAPI). Runs locally:

    .venv/Scripts/python -m uvicorn evidentia.api.main:app --port 8000

then open http://localhost:8000 (the built frontend in frontend/dist is served from /).
Nothing leaves the machine except, when GEMINI_API_KEY is set, the retrieved case text sent to
Gemini to write chat answers.
"""
from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Literal

import pandas as pd
from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from ..cases import pipeline
from ..cases.store import CaseNotFound, CaseStore
from ..ml.orchestrator import MLOrchestrator
from ..rag import embed
from ..rag.answer import answer
from ..ingestion.entities import KINDS
from ..ingestion.upload import ALIASES
from ..rag.llm import llm_status
from ..relations import mapper

ROOT = Path(__file__).resolve().parents[2]
SAMPLES = ROOT / "data" / "samples"
METRICS = ROOT / "reports" / "metrics"
FIGURES = ROOT / "reports" / "figures"
DIST = ROOT / "frontend" / "dist"
MAX_UPLOAD = 50 * 1024 * 1024
MAX_FILES_PER_UPLOAD = 20
MAX_SEARCH = 200            # longest search text / indicator accepted in a query string
CHUNK = 1024 * 1024
Model = Literal["lr", "rf"]
Cls = Literal["benign", "suspicious", "malicious", "not applicable"]
SEV = {"malicious": 3, "suspicious": 2, "benign": 1, "not applicable": 0}

app = FastAPI(title="Evidentia AI", version="2.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
                   allow_methods=["*"], allow_headers=["*"])
store = CaseStore()
_orch: MLOrchestrator | None = None
_orch_lock = threading.Lock()


def orch() -> MLOrchestrator:
    global _orch
    with _orch_lock:
        if _orch is None:
            _orch = MLOrchestrator.load()
        return _orch


@app.exception_handler(CaseNotFound)
def _nf(_req, exc):
    return JSONResponse({"detail": f"Case not found: {exc}"}, status_code=404)


def _cls_sql(model: str) -> str:
    col = "rf_class" if model == "rf" else "lr_class"
    return f"CASE WHEN m.applicable=1 THEN m.{col} ELSE 'not applicable' END"


def _rows(cur) -> list[dict]:
    return [dict(r) for r in cur.fetchall()]


def _like(text: str) -> str:
    """User text for a LIKE pattern: % and _ are matched literally (used with ESCAPE '\\')."""
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _check_column_map(cmap) -> dict[str, str] | None:
    """A column mapping must be {target field: source column}, targets from ALIASES; anything else is a 400."""
    if cmap is None:
        return None
    if not isinstance(cmap, dict) or len(cmap) > len(ALIASES):
        raise HTTPException(400, "column_map must be an object {field: column}")
    for k, v in cmap.items():
        if k not in ALIASES:
            raise HTTPException(400, f"column_map: unknown field '{k}'. Allowed: {', '.join(sorted(ALIASES))}")
        if not isinstance(v, str) or not 0 < len(v) <= 200:
            raise HTTPException(400, f"column_map: column name for '{k}' must be text of 1-200 characters")
    return cmap


async def _read_limited(f: UploadFile) -> bytes:
    """Read an upload in 1 MB chunks and stop as soon as it passes MAX_UPLOAD (never holds more than that)."""
    buf = bytearray()
    while chunk := await f.read(CHUNK):
        buf += chunk
        if len(buf) > MAX_UPLOAD:
            raise HTTPException(413, f"{f.filename} is larger than 50 MB")
    return bytes(buf)


# ---------------------------------------------------------------------------------------- meta
@app.get("/api/health")
def health():
    w = mapper.load_weights()
    return {"ok": True, "llm": llm_status(), "embedder": embed.Embedder.get().name if embed.Embedder._inst else "lazy",
            "relations": {"source": w["source"], "mix": w.get("mix"), "tau": w["tau"]},
            "models": json.loads((ROOT / "models" / "registry.json").read_text()) if (ROOT / "models" / "registry.json").exists() else {}}


@app.get("/api/samples")
def samples():
    return [{"name": p.name, "size": p.stat().st_size} for p in sorted(SAMPLES.glob("*")) if p.is_file()]


@app.get("/api/metrics/{name}")
def metric(name: str):
    p = METRICS / f"{name}.json"
    if not p.resolve().is_relative_to(METRICS.resolve()) or not p.exists():
        raise HTTPException(404, "unknown metric")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/api/figures/{name}")
def figure(name: str):
    p = FIGURES / name
    if not p.resolve().is_relative_to(FIGURES.resolve()) or not p.exists() or p.suffix != ".png":
        raise HTTPException(404, "unknown figure")
    return FileResponse(p, media_type="image/png")


@app.get("/api/reports/eda-summary")
def eda_summary():
    return {"markdown": (ROOT / "reports" / "eda_summary.md").read_text(encoding="utf-8")}


# ---------------------------------------------------------------------------------------- cases
class NewCase(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=2000)


@app.get("/api/cases")
def list_cases():
    return store.list_cases()


@app.post("/api/cases", status_code=201)
def create_case(body: NewCase):
    return store.summary(store.create_case(body.name, body.description)["id"])


@app.get("/api/cases/{cid}")
def get_case(cid: str):
    return store.summary(cid)


@app.delete("/api/cases/{cid}", status_code=204)
def delete_case(cid: str):
    store.delete_case(cid)


# ---------------------------------------------------------------------------------------- evidence files
def _file_rows(cid: str) -> list[dict]:
    with store.db(cid) as con:
        rows = _rows(con.execute("SELECT file_id, name, sha256, size, uploaded, file_type, artifact_type, status, "
                                 "error, n_events, n_applicable, warnings, parser FROM files ORDER BY file_id"))
    for r in rows:
        r["warnings"] = json.loads(r["warnings"] or "[]")
        r["parser"] = json.loads(r["parser"] or "{}")
        if r["error"]:
            r["error"] = r["error"].splitlines()[0]
    return rows


def _start(cid: str, name: str, data: bytes, column_map: dict | None) -> dict:
    rec = store.store_original(cid, name, data)
    threading.Thread(target=pipeline.process_file, args=(store, orch(), cid, rec["file_id"], name, data, column_map),
                     daemon=True).start()
    return rec


@app.get("/api/cases/{cid}/files")
def list_files(cid: str):
    return _file_rows(cid)


@app.post("/api/cases/{cid}/files", status_code=202)
async def upload_files(cid: str, files: list[UploadFile] = File(...), column_map: str | None = Form(default=None)):
    store.meta(cid)
    if len(files) > MAX_FILES_PER_UPLOAD:
        raise HTTPException(400, f"at most {MAX_FILES_PER_UPLOAD} files per upload")
    try:
        cmap = json.loads(column_map) if column_map else None
    except json.JSONDecodeError:
        raise HTTPException(400, "column_map is not valid JSON")
    cmap = _check_column_map(cmap)
    datas = [(f.filename or "upload", await _read_limited(f)) for f in files]   # all checked before any is stored
    return [_start(cid, name, data, cmap) for name, data in datas]


class SampleReq(BaseModel):
    names: list[str] = Field(default_factory=list, max_length=50)


@app.post("/api/cases/{cid}/samples", status_code=202)
def add_samples(cid: str, body: SampleReq):
    store.meta(cid)
    names = body.names or [p.name for p in SAMPLES.glob("*") if p.is_file()]
    out = []
    for n in names:
        p = SAMPLES / n
        if not p.resolve().is_relative_to(SAMPLES.resolve()) or not p.is_file():
            raise HTTPException(404, f"unknown sample {n}")
        out.append(_start(cid, p.name, p.read_bytes(), None))
    return out


@app.get("/api/cases/{cid}/files/{fid}/verify")
def verify(cid: str, fid: int):
    try:
        return store.verify_file(cid, fid)
    except KeyError:
        raise HTTPException(404, "unknown file")


class Remap(BaseModel):
    column_map: dict[str, str] = Field(max_length=len(ALIASES))


@app.post("/api/cases/{cid}/files/{fid}/remap", status_code=202)
def remap(cid: str, fid: int, body: Remap):
    """Re-parse a stored original with a hand-made column mapping (the original is not modified)."""
    _check_column_map(body.column_map)
    try:
        path = store.original_path(cid, fid)
    except KeyError:
        raise HTTPException(404, "unknown file")
    with store.db(cid) as con:
        row = con.execute("SELECT name, status FROM files WHERE file_id=?", (fid,)).fetchone()
        if row["status"] == "processing":
            raise HTTPException(409, "This file is still being processed. Remap it when it is ready.")
        name = row["name"]
        ids = "SELECT event_id FROM events WHERE file_id=?"
        for t in ("ml", "entities"):
            con.execute(f"DELETE FROM {t} WHERE event_id IN ({ids})", (fid,))
        con.execute("DELETE FROM events WHERE file_id=?", (fid,))
        con.execute("UPDATE files SET status='processing', error=NULL WHERE file_id=?", (fid,))
    threading.Thread(target=pipeline.process_file,
                     args=(store, orch(), cid, fid, name, path.read_bytes(), body.column_map), daemon=True).start()
    return {"file_id": fid, "status": "processing"}


# ---------------------------------------------------------------------------------------- events
@app.get("/api/cases/{cid}/events")
def events(cid: str, model: Model = "lr", cls: list[Cls] = Query(default=[]), file_id: int | None = None,
           q: str | None = Query(default=None, max_length=MAX_SEARCH),
           entity: str | None = Query(default=None, max_length=MAX_SEARCH),
           anomaly: bool = False, disagree: bool = False,
           t0: float | None = None, t1: float | None = None,
           sort: Literal["time", "risk", "row"] = "time", offset: int = Query(default=0, ge=0),
           limit: int = Query(default=100, ge=1, le=500)):
    if t0 is not None and t1 is not None and t0 > t1:
        raise HTTPException(400, "t0 must not be after t1")
    c = _cls_sql(model)
    where, args = ["1=1"], []
    if t0 is not None:
        where.append("e.ts >= ?")
        args.append(t0)
    if t1 is not None:
        where.append("e.ts < ?")
        args.append(t1)
    if cls:
        where.append(f"{c} IN ({','.join('?' * len(cls))})")
        args += cls
    if file_id is not None:
        where.append("e.file_id=?")
        args.append(file_id)
    if q:
        where.append("e.message LIKE ? ESCAPE '\\'")
        args.append(_like(q))
    if entity:
        where.append("e.event_id IN (SELECT event_id FROM entities WHERE value=?)")
        args.append(entity)
    if anomaly:
        where.append("m.an_flag=1")
    if disagree:
        where.append("m.applicable=1 AND m.agree=0")
    order = {"time": "e.ts IS NULL, e.ts, e.event_id",
             "risk": f"CASE {c} WHEN 'malicious' THEN 3 WHEN 'suspicious' THEN 2 WHEN 'benign' THEN 1 ELSE 0 END DESC, "
                     f"m.{'rf' if model == 'rf' else 'lr'}_p_mal DESC",
             "row": "e.file_id, e.source_row"}[sort]
    base = f"FROM events e JOIN files f USING(file_id) LEFT JOIN ml m USING(event_id) WHERE {' AND '.join(where)}"
    with store.db(cid) as con:
        total = con.execute(f"SELECT COUNT(*) {base}", args).fetchone()[0]
        rows = _rows(con.execute(
            f"SELECT e.event_id, e.file_id, f.name AS file, e.source_row, e.ts, e.message, e.message_type, e.action, "
            f"e.src_ip, e.dst_ip, e.dst_port, {c} AS cls, m.lr_class, m.rf_class, m.lr_p_mal, m.rf_p_mal, "
            f"m.applicable, m.agree, m.an_flag, m.an_score, json_extract(e.extra, '$.reference_label_witfoo') AS reference_label "
            f"{base} ORDER BY {order} LIMIT ? OFFSET ?", args + [limit, offset]))
    return {"total": total, "offset": offset, "rows": rows}


@app.get("/api/cases/{cid}/events/{eid}")
def event_detail(cid: str, eid: int):
    with store.db(cid) as con:
        e = con.execute("SELECT e.*, f.name AS file, f.sha256, f.artifact_type FROM events e JOIN files f USING(file_id) "
                        "WHERE event_id=?", (eid,)).fetchone()
        if e is None:
            raise HTTPException(404, "unknown event")
        m = con.execute("SELECT * FROM ml WHERE event_id=?", (eid,)).fetchone()
        ents = _rows(con.execute("SELECT kind, value, (SELECT COUNT(*) FROM entities x WHERE x.value=en.value) AS seen "
                                 "FROM entities en WHERE event_id=? ORDER BY kind, value", (eid,)))
        links = _rows(con.execute(
            "SELECT CASE WHEN a=? THEN b ELSE a END AS other, score, temporal, entity, semantic, shared, dt "
            "FROM edges WHERE a=? OR b=? ORDER BY score DESC LIMIT 12", (eid, eid, eid)))
        for l in links:
            o = con.execute("SELECT e.event_id, f.name AS file, e.source_row, e.ts, substr(e.message,1,160) AS message, "
                            "CASE WHEN m.applicable=1 THEN m.lr_class ELSE 'not applicable' END AS cls "
                            "FROM events e JOIN files f USING(file_id) LEFT JOIN ml m USING(event_id) WHERE event_id=?",
                            (l["other"],)).fetchone()
            l["event"] = dict(o) if o else None
            l["shared"] = json.loads(l["shared"] or "[]")
    d = dict(e)
    d["extra"] = json.loads(d["extra"]) if d.get("extra") else {}
    d["ml"] = None
    if m is not None:
        md = dict(m)
        md["detail"] = json.loads(md["detail"])
        d["ml"] = md
    d["entities"] = ents
    d["links"] = links
    return d


@app.get("/api/cases/{cid}/timeline")
def timeline(cid: str, model: Model = "lr", bucket: int = 60):
    c = _cls_sql(model)
    p = "rf_p_mal" if model == "rf" else "lr_p_mal"
    bucket = max(10, min(bucket, 86400))
    with store.db(cid) as con:
        hist = _rows(con.execute(
            f"SELECT CAST(e.ts/? AS INTEGER)*? AS t, {c} AS cls, COUNT(*) AS n FROM events e LEFT JOIN ml m "
            f"USING(event_id) WHERE e.ts IS NOT NULL GROUP BY 1, 2 ORDER BY 1", (bucket, bucket)))
        pts = _rows(con.execute(
            f"SELECT e.event_id, e.ts, {c} AS cls, m.{p} AS p_mal, m.an_flag, e.src_ip, e.dst_ip FROM events e "
            f"JOIN ml m USING(event_id) WHERE e.ts IS NOT NULL AND {c} IN ('suspicious','malicious') "
            f"ORDER BY CASE {c} WHEN 'malicious' THEN 0 ELSE 1 END, m.an_flag DESC, m.{p} DESC LIMIT 2500"))
        thr = None
        r = con.execute("SELECT detail FROM ml LIMIT 1").fetchone()
        if r:
            thr = json.loads(r["detail"])["classifiers"]["random_forest" if model == "rf" else "logreg"]["stage2_threshold"]
    return {"bucket": bucket, "histogram": hist, "alerts": pts, "threshold": thr}


@app.get("/api/cases/{cid}/entities")
def entities(cid: str, kind: Literal[KINDS] | None = None, q: str | None = Query(default=None, max_length=MAX_SEARCH),
             limit: int = Query(default=50, ge=1, le=500)):
    where, args = ["1=1"], []
    if kind:
        where.append("en.kind=?")
        args.append(kind)
    if q:
        where.append("en.value LIKE ? ESCAPE '\\'")
        args.append(_like(q))
    with store.db(cid) as con:
        return _rows(con.execute(
            "SELECT en.kind, en.value, COUNT(*) AS events, COUNT(DISTINCT e.file_id) AS files, "
            "SUM(m.applicable=1 AND m.lr_class='malicious') AS malicious, "
            "SUM(m.applicable=1 AND m.lr_class='suspicious') AS suspicious, SUM(COALESCE(m.an_flag,0)) AS anomalies "
            f"FROM entities en JOIN events e USING(event_id) LEFT JOIN ml m USING(event_id) WHERE {' AND '.join(where)} "
            "GROUP BY en.kind, en.value ORDER BY malicious DESC, anomalies DESC, suspicious DESC, events DESC LIMIT ?",
            args + [limit]))


@app.get("/api/cases/{cid}/graph")
def graph(cid: str, focus: str | None = Query(default=None, max_length=MAX_SEARCH),
          limit: int = Query(default=60, ge=1, le=200)):
    """Evidence graph. Without focus: the riskiest indicators, the files they appear in, and how often
    indicators occur together. With focus=<indicator>: its events, their mapper links and co-indicators."""
    with store.db(cid) as con:
        ent = pd.read_sql_query(
            "SELECT en.event_id, en.kind, en.value, e.file_id, f.name AS file, "
            "CASE WHEN m.applicable=1 THEN m.lr_class ELSE 'not applicable' END AS cls, COALESCE(m.an_flag,0) AS an "
            "FROM entities en JOIN events e USING(event_id) JOIN files f USING(file_id) LEFT JOIN ml m USING(event_id)", con)
        files = pd.read_sql_query("SELECT file_id, name, artifact_type FROM files", con)
    if ent.empty:
        return {"nodes": [], "edges": [], "focus": focus}
    ent["sev"] = ent["cls"].map(SEV).fillna(0)
    g = ent.groupby(["kind", "value"]).agg(events=("event_id", "nunique"), sev=("sev", "max"),
                                           malicious=("cls", lambda s: int((s == "malicious").sum())),
                                           anomalies=("an", "sum"), files=("file_id", "nunique")).reset_index()
    if focus:
        ev_ids = set(ent.loc[ent["value"] == focus, "event_id"])
        if not ev_ids:
            raise HTTPException(404, "indicator not in this case")
        with store.db(cid) as con:
            q = ",".join(map(str, ev_ids))
            linked = pd.read_sql_query(f"SELECT a, b, score FROM edges WHERE a IN ({q}) OR b IN ({q})", con)
        ev_ids |= set(linked["a"]) | set(linked["b"])
        sub = ent[ent["event_id"].isin(ev_ids)]
        keep = g.merge(sub[["kind", "value"]].drop_duplicates(), on=["kind", "value"])
    else:
        keep = g
    keep = keep.assign(rank=keep["malicious"] * 3 + keep["anomalies"] * 2 + keep["sev"] + (keep["files"] > 1) * 2 + keep["events"] / 1e6)
    keep = keep.sort_values("rank", ascending=False).head(limit)
    if focus and focus not in set(keep["value"]):
        keep = pd.concat([g[g["value"] == focus], keep]).head(limit)
    chosen = set(zip(keep["kind"], keep["value"]))
    sub = ent[[k in chosen for k in zip(ent["kind"], ent["value"])]]
    nodes = [{"id": f"{r.kind}:{r.value}", "type": "entity", "kind": r.kind, "label": r.value, "events": int(r.events),
              "malicious": int(r.malicious), "anomalies": int(r.anomalies), "files": int(r.files),
              "worst": {3: "malicious", 2: "suspicious", 1: "benign", 0: "not applicable"}[int(r.sev)]}
             for r in keep.itertuples()]
    used_files = set(sub["file_id"])
    nodes += [{"id": f"file:{r.file_id}", "type": "file", "kind": "file", "label": r.name, "artifact_type": r.artifact_type}
              for r in files.itertuples() if r.file_id in used_files]
    edges = []
    fe = sub.groupby(["kind", "value", "file_id"]).size().reset_index(name="n")
    edges += [{"source": f"{r.kind}:{r.value}", "target": f"file:{r.file_id}", "type": "appears_in", "weight": int(r.n)}
              for r in fe.itertuples()]
    pairs = sub.merge(sub, on="event_id")
    pairs = pairs[(pairs["kind_x"] + pairs["value_x"]) < (pairs["kind_y"] + pairs["value_y"])]
    co = pairs.groupby(["kind_x", "value_x", "kind_y", "value_y"]).size().reset_index(name="n")
    co = co.sort_values("n", ascending=False).head(limit * 3)
    edges += [{"source": f"{r.kind_x}:{r.value_x}", "target": f"{r.kind_y}:{r.value_y}", "type": "seen_together",
               "weight": int(r.n)} for r in co.itertuples()]
    return {"nodes": nodes, "edges": edges, "focus": focus}


# ---------------------------------------------------------------------------------------- assistant
class Ask(BaseModel):
    question: str = Field(min_length=2, max_length=1000)


@app.get("/api/detection-rules")
def detection_rules():
    """The built-in rules and the Sigma rules the engine has loaded (and any it could not run)."""
    from ..detect.sigma import rules_status
    return {"builtin": ["brute_force", "slow_brute_force", "brute_force_success", "privilege_after_login",
                        "tool_download", "host_scan"], "sigma": rules_status()}


@app.get("/api/cases/{cid}/findings")
def findings(cid: str):
    """Detection-rule findings for the whole case (evidentia/detect/rules.py), most severe first."""
    from ..rag.retrieve import case_index
    return case_index(store, cid).findings


@app.post("/api/cases/{cid}/ask")
def ask(cid: str, body: Ask):
    store.meta(cid)
    with store.db(cid) as con:
        if con.execute("SELECT COUNT(*) FROM files WHERE status NOT IN ('ready','error')").fetchone()[0]:
            raise HTTPException(409, "Evidence is still being processed. Ask again when every file is ready.")
    return answer(store, cid, body.question)


@app.get("/api/cases/{cid}/chats")
def chats(cid: str):
    with store.db(cid) as con:
        return [json.loads(r["answer"]) | {"chat_id": r["chat_id"], "ts": r["ts"]}
                for r in con.execute("SELECT chat_id, ts, answer FROM chats ORDER BY chat_id")]


@app.get("/api/llm")
def llm():
    return llm_status()


# ---------------------------------------------------------------------------------------- frontend
if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/{path:path}", include_in_schema=False)
    def spa(path: str):
        if path == "api" or path.startswith("api/"):      # an unknown API address is a 404, not the web page
            raise HTTPException(404, "unknown API endpoint")
        p = DIST / path
        if path and p.resolve().is_relative_to(DIST.resolve()) and p.is_file():
            return FileResponse(p)
        # index.html must be revalidated so a rebuilt frontend (new hashed assets) is picked up.
        return FileResponse(DIST / "index.html", headers={"Cache-Control": "no-cache"})
