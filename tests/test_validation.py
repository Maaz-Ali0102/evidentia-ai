"""Input validation of the API: bad input must get a clear 4xx error, never a 500 and never more data than allowed.

Each test sends one kind of invalid input that the API used to accept (or crash on) before these checks.
Uses a small throw-away case; nothing is sent to an LLM.
"""
import json
import shutil
import time

import pytest
from fastapi.testclient import TestClient

from evidentia.api.main import MAX_UPLOAD, app, store

SSH_LOG = "\n".join(
    f"Nov 13 10:0{i % 10}:1{i % 10} web01 sshd[{100 + i}]: Failed password for root from 10.0.0.{i % 7} port 22 ssh2"
    for i in range(40)
).encode()


@pytest.fixture(scope="module")
def client():
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def cid(client):
    r = client.post("/api/cases", json={"name": "validation test"})
    assert r.status_code == 201
    case_id = r.json()["id"]
    r = client.post(f"/api/cases/{case_id}/files", files={"files": ("auth.log", SSH_LOG)})
    assert r.status_code == 202
    for _ in range(120):                      # wait until the file is processed
        if all(f["status"] in ("ready", "error") for f in client.get(f"/api/cases/{case_id}/files").json()):
            break
        time.sleep(0.5)
    yield case_id
    shutil.rmtree(store.root / case_id, ignore_errors=True)


# ------------------------------------------------------------------ limits and paging
@pytest.mark.parametrize("path, params", [
    ("events", {"limit": -1}), ("events", {"limit": 0}), ("events", {"limit": 501}), ("events", {"offset": -5}),
    ("entities", {"limit": -1}), ("entities", {"limit": 501}),
    ("graph", {"limit": -1}), ("graph", {"limit": 201}),
])
def test_limits_are_bounded(client, cid, path, params):
    # limit=-1 used to return every row (SQLite treats a negative LIMIT as "no limit")
    assert client.get(f"/api/cases/{cid}/{path}", params=params).status_code == 422


def test_valid_paging_still_works(client, cid):
    r = client.get(f"/api/cases/{cid}/events", params={"limit": 5, "offset": 0})
    assert r.status_code == 200 and len(r.json()["rows"]) <= 5


# ------------------------------------------------------------------ fixed choices
@pytest.mark.parametrize("path, params", [
    ("events", {"model": "xyz"}), ("events", {"sort": "hack"}), ("events", {"cls": "evil"}),
    ("timeline", {"model": "xyz"}), ("entities", {"kind": "password"}),
])
def test_unknown_choices_are_rejected(client, cid, path, params):
    assert client.get(f"/api/cases/{cid}/{path}", params=params).status_code == 422


def test_known_choices_are_accepted(client, cid):
    for params in ({"model": "rf", "sort": "risk", "cls": ["malicious", "not applicable"]}, {"sort": "row"}):
        assert client.get(f"/api/cases/{cid}/events", params=params).status_code == 200
    assert client.get(f"/api/cases/{cid}/entities", params={"kind": "ip"}).status_code == 200


# ------------------------------------------------------------------ text inputs
@pytest.mark.parametrize("path, key", [("events", "q"), ("events", "entity"), ("entities", "q"), ("graph", "focus")])
def test_search_text_has_a_max_length(client, cid, path, key):
    assert client.get(f"/api/cases/{cid}/{path}", params={key: "x" * 201}).status_code == 422


def test_like_wildcards_are_literal(client, cid):
    total = client.get(f"/api/cases/{cid}/events").json()["total"]
    assert total > 0
    # "%" used to match every row; now it only matches messages that contain a "%" character
    assert client.get(f"/api/cases/{cid}/events", params={"q": "%"}).json()["total"] == 0
    assert client.get(f"/api/cases/{cid}/events", params={"q": "Failed password"}).json()["total"] > 0


def test_time_range_order(client, cid):
    assert client.get(f"/api/cases/{cid}/events", params={"t0": 200, "t1": 100}).status_code == 400


def test_case_name_and_question_lengths(client, cid):
    assert client.post("/api/cases", json={"name": ""}).status_code == 422
    assert client.post("/api/cases", json={"name": "x" * 121}).status_code == 422
    assert client.post(f"/api/cases/{cid}/ask", json={"question": "x"}).status_code == 422
    assert client.post(f"/api/cases/{cid}/ask", json={"question": "x" * 1001}).status_code == 422


# ------------------------------------------------------------------ uploads
def _upload(client, cid, column_map=None, files=None):
    data = {"column_map": column_map} if column_map is not None else {}
    return client.post(f"/api/cases/{cid}/files", files=files or {"files": ("a.csv", b"time,msg\n1,hello\n")}, data=data)


def _file_count(client, cid):
    return len(client.get(f"/api/cases/{cid}/files").json())


@pytest.mark.parametrize("column_map", ["{not json", "[1, 2]", '"text"', '{"no_such_field": "msg"}',
                                        '{"message_sanitized": 5}', '{"message_sanitized": ""}'])
def test_bad_column_map_is_400_and_stores_nothing(client, cid, column_map):
    # bad JSON used to be a 500, and a JSON list was accepted and then crashed the background job
    before = _file_count(client, cid)
    assert _upload(client, cid, column_map).status_code == 400
    assert _file_count(client, cid) == before


def test_too_many_files(client, cid):
    files = [("files", (f"f{i}.log", b"x")) for i in range(21)]
    before = _file_count(client, cid)
    assert client.post(f"/api/cases/{cid}/files", files=files).status_code == 400
    assert _file_count(client, cid) == before


def test_oversized_file_is_413_and_stores_nothing(client, cid):
    before = _file_count(client, cid)
    big = b"a" * (MAX_UPLOAD + 1)
    assert _upload(client, cid, files={"files": ("big.log", big)}).status_code == 413
    assert _file_count(client, cid) == before


def test_remap_validation(client, cid):
    fid = client.get(f"/api/cases/{cid}/files").json()[0]["file_id"]
    r = client.post(f"/api/cases/{cid}/files/{fid}/remap", json={"column_map": {"no_such_field": "msg"}})
    assert r.status_code == 400
    assert client.post(f"/api/cases/{cid}/files/999/remap", json={"column_map": {}}).status_code == 404


def test_sample_list_is_bounded(client, cid):
    assert client.post(f"/api/cases/{cid}/samples", json={"names": ["x"] * 51}).status_code == 422


# ------------------------------------------------------------------ ids and paths
@pytest.mark.parametrize("bad", ["case.json", "UPPER-case", "a b", "x" * 65, "short"])
def test_bad_case_ids_are_404(client, bad):
    # every endpoint, including the ones that open the case database directly, checks the id the same way
    for path in ("", "/events", "/timeline", "/entities", "/graph", "/files"):
        assert client.get(f"/api/cases/{bad}{path}").status_code == 404


@pytest.mark.parametrize("name", ["..%2F..%2Fconfig", "../registry", "x.json"])
def test_figure_and_metric_paths(client, name):
    assert client.get(f"/api/figures/{name}").status_code == 404
    assert client.get(f"/api/metrics/{name}").status_code == 404


def test_errors_are_json_not_tracebacks(client, cid):
    r = _upload(client, cid, "{not json")
    assert r.headers["content-type"].startswith("application/json")
    assert "Traceback" not in r.text and json.loads(r.text)["detail"]
