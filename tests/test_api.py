"""End-to-end tests of the case workflow: upload -> parse -> ML -> entities -> links -> questions.

Runs on a temporary cases folder with the built-in (no-LLM) answerer, so no network is used
except the first-time download of the embedding model.
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["EVIDENTIA_CASES_DIR"] = tempfile.mkdtemp(prefix="evidentia_cases_")
os.environ["EVIDENTIA_LLM"] = "builtin"

from fastapi.testclient import TestClient  # noqa: E402

from evidentia.api.main import app  # noqa: E402
from evidentia.ingestion.entities import extract  # noqa: E402
from evidentia.relations import mapper  # noqa: E402

SAMPLES = ROOT / "data" / "samples"
ASA = (SAMPLES / "witfoo_sample_asa_lines.log").read_text(encoding="utf-8").splitlines()[:300]
BROWSER = ("visit_time,url,title\n"
           "2024-07-26T20:49:13Z,http://198.51.100.27/login,Portal login\n"
           "2024-07-26T20:55:00Z,https://example.org/recipes,Recipes\n")
NO_TIME = "when,msg\n" + "\n".join(f'2024-07-26T20:49:{i:02d}Z,"{ASA[i].replace(chr(34), chr(34) * 2)}"'
                                    for i in range(5))


def _wait(client, cid, timeout=180):
    t = time.time()
    while time.time() - t < timeout:
        files = client.get(f"/api/cases/{cid}/files").json()
        if files and all(f["status"] in ("ready", "error") for f in files):
            return files
        time.sleep(0.5)
    raise AssertionError("processing did not finish")


@pytest.fixture(scope="module")
def case():
    client = TestClient(app)
    cid = client.post("/api/cases", json={"name": "Test case"}).json()["id"]
    up = [("files", ("asa.log", "\n".join(ASA).encode(), "text/plain")),
          ("files", ("history.csv", BROWSER.encode(), "text/csv")),
          ("files", ("notes.txt", (SAMPLES / "synthetic_non_security_notes.txt").read_bytes(), "text/plain")),
          ("files", ("no_time.csv", NO_TIME.encode(), "text/csv"))]
    r = client.post(f"/api/cases/{cid}/files", files=up)
    assert r.status_code == 202 and len(r.json()) == 4
    files = _wait(client, cid)
    return client, cid, {f["name"]: f for f in files}


def test_files_processed_and_typed(case):
    _, _, files = case
    assert all(f["status"] == "ready" for f in files.values()), {k: v["error"] for k, v in files.items()}
    assert files["asa.log"]["artifact_type"] == "security_log"
    assert files["asa.log"]["n_applicable"] >= 290
    assert files["history.csv"]["artifact_type"] == "browser_history"
    assert files["history.csv"]["n_applicable"] == 0          # not a security log: no ML guess
    assert files["notes.txt"]["n_applicable"] == 0
    assert files["no_time.csv"]["parser"].get("missing_required") == ["timestamp"]
    assert any("No timestamp column" in w for w in files["no_time.csv"]["warnings"])


def test_original_is_hashed_and_intact(case):
    client, cid, files = case
    v = client.get(f"/api/cases/{cid}/files/{files['asa.log']['file_id']}/verify").json()
    assert v["intact"] and v["recorded"] == files["asa.log"]["sha256"]


def test_event_filters_agree_with_summary(case):
    client, cid, _ = case
    s = client.get(f"/api/cases/{cid}").json()
    for cls in ("malicious", "suspicious", "not applicable"):
        assert client.get(f"/api/cases/{cid}/events", params={"cls": cls}).json()["total"] == s["classes"][cls]


def test_event_detail_has_provenance_ml_entities(case):
    client, cid, _ = case
    row = client.get(f"/api/cases/{cid}/events", params={"cls": "suspicious", "limit": 1}).json()["rows"][0]
    d = client.get(f"/api/cases/{cid}/events/{row['event_id']}").json()
    assert d["file"] == "asa.log" and d["source_row"] >= 1
    assert d["ml"]["detail"]["classifiers"]["logreg"]["predicted_class"] in ("suspicious", "malicious", "benign")
    assert any(e["kind"] == "ip" for e in d["entities"])


def test_cross_file_link_through_shared_ip(case):
    client, cid, _ = case
    rows = client.get(f"/api/cases/{cid}/events", params={"entity": "198.51.100.27", "limit": 500}).json()["rows"]
    assert {r["file"] for r in rows} >= {"asa.log", "history.csv"}
    g = client.get(f"/api/cases/{cid}/graph", params={"focus": "198.51.100.27"}).json()
    ids = {n["id"] for n in g["nodes"]}
    assert "ip:198.51.100.27" in ids and any(i.startswith("file:") for i in ids)


def test_reremap_fixes_missing_timestamp(case):
    client, cid, files = case
    fid = files["no_time.csv"]["file_id"]
    assert client.post(f"/api/cases/{cid}/files/{fid}/remap",
                       json={"column_map": {"timestamp": "when", "message_sanitized": "msg"}}).status_code == 202
    f = {x["name"]: x for x in _wait(client, cid)}["no_time.csv"]
    assert f["status"] == "ready" and "missing_required" not in f["parser"] and f["n_applicable"] == 5


def test_assistant_answer_is_grounded(case):
    client, cid, _ = case
    r = client.post(f"/api/cases/{cid}/ask", json={"question": "What happened with 198.51.100.27?"}).json()
    md = r["answer_markdown"]
    for h in ("## Answer", "## Evidence", "## ML assessment", "## Possible links", "## Unknown"):
        assert h in md
    cited = set(re.findall(r"\[(E\d+)\]", md))
    assert cited and cited <= {e["id"] for e in r["citations"]["events"]}
    assert all("198.51.100.27" in (e["message"] + str(e["src_ip"]) + str(e["dst_ip"]))
               for e in r["citations"]["events"] if e["why_retrieved"] == "matches the question's filters")
    assert r["llm"]["provider"] == "builtin" and not r["warnings"]
    assert client.get(f"/api/cases/{cid}/chats").json()[-1]["question"].startswith("What happened")


def test_time_alone_never_links():
    ts = {1: 100.0, 2: 101.0}
    files = {1: 1, 2: 2}
    ents = {1: {("ip", "10.0.0.1")}, 2: {("domain", "example.org")}}
    vecs = mapper.np.array([[1.0, 0.0], [0.0, 1.0]], dtype="float32")
    edges = mapper.build_edges(ts, files, ents, {1: 0, 2: 1}, vecs)
    assert edges == []                     # 1 s apart, nothing shared, unrelated content
    ents[2].add(("ip", "10.0.0.1"))
    assert len(mapper.build_edges(ts, files, ents, {1: 0, 2: 1}, vecs)) == 1


def test_entity_extraction():
    found = extract("Deny tcp src outside:100.64.14.143/57115 dst dmz-1:10.71.234.214/8408 user=alice "
                    "visited https://evil.example.com/a.php hash 978ff3ff4d68cd1084e12aca5914bdfd1797e56173b604d13a1ae7d58909be9b "
                    "at FutureAdapter.java:81")
    kinds = {k for k, _ in found}
    assert {"ip", "url", "domain", "user", "hash"} <= kinds
    assert ("domain", "evil.example.com") in found
    assert not any(v.endswith(".java") for _, v in found)
