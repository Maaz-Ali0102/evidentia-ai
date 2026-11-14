"""Case store: one folder per investigation case.

    cases/<case_id>/
      case.json         id, name, description, created (UTC epoch)
      original/         uploaded files, byte-for-byte, made read-only after writing
      case.sqlite       files, events, ML results, entities, relationship edges, chat history
      embeddings.npz    sentence embeddings of the digit-masked event texts (shared by RAG + mapper)

Evidence rules: originals are never modified (their SHA-256 is recorded at upload and re-checked
on demand); every event keeps its file and row; missing values stay missing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CASES_DIR = Path(os.environ.get("EVIDENTIA_CASES_DIR", ROOT / "cases"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
  file_id INTEGER PRIMARY KEY, name TEXT, sha256 TEXT, size INTEGER, uploaded REAL, file_type TEXT,
  artifact_type TEXT, status TEXT, error TEXT, n_events INTEGER DEFAULT 0, n_applicable INTEGER DEFAULT 0,
  warnings TEXT, parser TEXT, stored_as TEXT);
CREATE TABLE IF NOT EXISTS events (
  event_id INTEGER PRIMARY KEY, file_id INTEGER, source_row INTEGER, ts REAL, message TEXT,
  message_type TEXT, action TEXT, protocol TEXT, severity TEXT, src_ip TEXT, dst_ip TEXT,
  src_port TEXT, dst_port TEXT, extra TEXT);
CREATE TABLE IF NOT EXISTS ml (
  event_id INTEGER PRIMARY KEY, applicable INTEGER, reason TEXT, coverage REAL,
  lr_class TEXT, lr_p_alert REAL, lr_p_mal REAL, rf_class TEXT, rf_p_alert REAL, rf_p_mal REAL,
  agree INTEGER, an_scored INTEGER, an_flag INTEGER, an_score REAL, detail TEXT);
CREATE TABLE IF NOT EXISTS entities (event_id INTEGER, kind TEXT, value TEXT);
CREATE TABLE IF NOT EXISTS edges (
  a INTEGER, b INTEGER, score REAL, temporal REAL, entity REAL, semantic REAL, shared TEXT,
  dt REAL, PRIMARY KEY (a, b));
CREATE TABLE IF NOT EXISTS chats (chat_id INTEGER PRIMARY KEY, ts REAL, question TEXT, answer TEXT);
CREATE INDEX IF NOT EXISTS ix_events_file ON events(file_id);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_ent_value ON entities(value);
CREATE INDEX IF NOT EXISTS ix_ent_event ON entities(event_id);
CREATE INDEX IF NOT EXISTS ix_edges_b ON edges(b);
"""

_ID = re.compile(r"^[a-z0-9-]{6,64}$")


class CaseNotFound(KeyError):
    pass


def _slug(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:32] or "case"
    return f"{s}-{uuid.uuid4().hex[:6]}"


class CaseStore:
    def __init__(self, root: Path = CASES_DIR):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ cases
    def _dir(self, case_id: str) -> Path:
        if not _ID.match(case_id or ""):
            raise CaseNotFound(case_id)
        d = self.root / case_id
        if not (d / "case.json").exists():
            raise CaseNotFound(case_id)
        return d

    def create_case(self, name: str, description: str = "") -> dict:
        name = (name or "").strip() or "Untitled case"
        cid = _slug(name)
        d = self.root / cid
        (d / "original").mkdir(parents=True)
        meta = {"id": cid, "name": name[:120], "description": (description or "")[:2000], "created": time.time()}
        (d / "case.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        with self.db(cid) as con:
            con.executescript(SCHEMA)
        return meta

    def meta(self, case_id: str) -> dict:
        return json.loads((self._dir(case_id) / "case.json").read_text(encoding="utf-8"))

    def list_cases(self) -> list[dict]:
        out = []
        for d in sorted(self.root.iterdir()):
            if (d / "case.json").exists():
                try:
                    out.append(self.summary(d.name))
                except Exception:  # a broken case must not hide the others
                    continue
        return sorted(out, key=lambda c: c["created"], reverse=True)

    def delete_case(self, case_id: str) -> None:
        d = self._dir(case_id)

        def _writable(func, path, _exc):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(d, onexc=_writable)

    @contextmanager
    def db(self, case_id: str):
        path = self._dir(case_id) / "case.sqlite"   # same ID check (regex + case.json) as every other access
        con = sqlite3.connect(path, timeout=30)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def summary(self, case_id: str) -> dict:
        meta = self.meta(case_id)
        with self.db(case_id) as con:
            files = con.execute("SELECT COUNT(*), SUM(status IN ('processing','linking')) FROM files").fetchone()
            n_ev = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            cls = dict(con.execute(
                "SELECT CASE WHEN applicable=1 THEN lr_class ELSE 'not applicable' END, COUNT(*) "
                "FROM ml GROUP BY 1").fetchall())
            flags = con.execute("SELECT COALESCE(SUM(an_flag),0), COALESCE(SUM(applicable=1 AND agree=0),0) "
                                "FROM ml").fetchone()
            n_edges = con.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            span = con.execute("SELECT MIN(ts), MAX(ts) FROM events").fetchone()
        return {**meta, "files": files[0], "processing": int(files[1] or 0), "events": n_ev,
                "classes": {k: cls.get(k, 0) for k in ("benign", "suspicious", "malicious", "not applicable")},
                "anomalies": int(flags[0]), "disagreements": int(flags[1]), "links": n_edges,
                "time_span": [span[0], span[1]]}

    # ------------------------------------------------------------------ evidence files
    def store_original(self, case_id: str, file_name: str, data: bytes) -> dict:
        d = self._dir(case_id)
        sha = hashlib.sha256(data).hexdigest()
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", Path(file_name).name)[:120] or "upload"
        with self.db(case_id) as con:
            cur = con.execute(
                "INSERT INTO files(name, sha256, size, uploaded, file_type, status, warnings, parser) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (Path(file_name).name, sha, len(data), time.time(),
                 safe.rsplit(".", 1)[-1].lower() if "." in safe else "", "processing", "[]", "{}"))
            fid = cur.lastrowid
            stored = f"{fid:04d}_{safe}"
            con.execute("UPDATE files SET stored_as=? WHERE file_id=?", (stored, fid))
        target = d / "original" / stored
        target.write_bytes(data)
        os.chmod(target, stat.S_IREAD)  # evidence is read-only from here on
        return {"file_id": fid, "sha256": sha, "stored_as": stored}

    def original_path(self, case_id: str, file_id: int) -> Path:
        with self.db(case_id) as con:
            row = con.execute("SELECT stored_as FROM files WHERE file_id=?", (file_id,)).fetchone()
        if row is None:
            raise KeyError(file_id)
        return self._dir(case_id) / "original" / row["stored_as"]

    def verify_file(self, case_id: str, file_id: int) -> dict:
        """Re-hash the stored original and compare with the hash recorded at upload."""
        path = self.original_path(case_id, file_id)
        with self.db(case_id) as con:
            rec = con.execute("SELECT sha256 FROM files WHERE file_id=?", (file_id,)).fetchone()["sha256"]
        now = hashlib.sha256(path.read_bytes()).hexdigest()
        return {"file_id": file_id, "recorded": rec, "current": now, "intact": now == rec}

    def embeddings_path(self, case_id: str) -> Path:
        return self._dir(case_id) / "embeddings.npz"
