"""Tests for the ML subsystem. Run: .venv/Scripts/python -m pytest -q"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from evidentia.ml.config import (BANNED_POST_LABEL, CUTOFFS, MODELS_DIR, NEVER_FEATURES,  # noqa: E402
                                 SIGNALS_PARQUET, SOURCE_FIELDS)
from evidentia.ml.context import add_context_features  # noqa: E402
from evidentia.ml.data import build_dataset, stage2_frame, stage2_splits  # noqa: E402
from evidentia.ml.evaluate import best_f1_threshold, binary_report  # noqa: E402
from evidentia.ml.features import FEATURE_SETS, input_columns, mask_digits, prepare_frame  # noqa: E402
from evidentia.ml.models import make_lr  # noqa: E402


def _events(n=400, seed=0):
    rng = np.random.default_rng(seed)
    return pd.DataFrame({
        "org_id": rng.choice(["o1", "o2"], n),
        "timestamp": np.sort(rng.uniform(0, 20_000, n)).round(1),
        "src_ip": rng.choice(["10.0.0.1", "10.0.0.2", "10.0.0.3", None], n),
        "dst_ip": rng.choice(["10.1.0.1", "10.1.0.2"], n),
        "dst_port": rng.choice(["22", "443", "445"], n),
    })


# ---------------------------------------------------------------- context features
def test_context_matches_brute_force():
    d = _events()
    f = add_context_features(d)
    for i in range(0, len(d), 7):
        r = d.iloc[i]
        if r.src_ip is None:
            assert f.iloc[i]["ctx_src_600s"] == 0
            continue
        m = (d.org_id == r.org_id) & (d.src_ip == r.src_ip) & (d.timestamp < r.timestamp) & \
            (d.timestamp >= r.timestamp - 600)
        assert abs(np.expm1(f.iloc[i]["ctx_src_600s"]) - m.sum()) < 1e-3


def test_context_never_uses_future_rows():
    d = _events()
    cut = 10_000
    early = d[d.timestamp < cut]
    f_all = add_context_features(d).loc[early.index]
    f_early = add_context_features(early)
    pd.testing.assert_frame_equal(f_all, f_early)


def test_context_separates_scopes():
    d = pd.DataFrame({"org_id": ["a", "b"], "timestamp": [0.0, 1.0], "src_ip": ["x", "x"],
                      "dst_ip": ["y", "y"], "dst_port": ["1", "1"]})
    assert add_context_features(d).loc[1, "ctx_src_60s"] == 0  # other org's event not counted


# ---------------------------------------------------------------- leakage guards
@pytest.mark.parametrize("fs", list(FEATURE_SETS))
def test_no_banned_columns_in_any_feature_set(fs):
    cols = set(input_columns(fs))
    assert not cols & set(BANNED_POST_LABEL)
    assert not cols & set(NEVER_FEATURES)
    if fs != "full+source":
        assert not cols & set(SOURCE_FIELDS)


def test_prepare_frame_drops_label_columns():
    raw = pd.DataFrame({"message_sanitized": ["Deny tcp 1.2.3.4"], "label_binary": ["malicious"],
                        "matched_rules": ['["Blocked Action"]'], "suspicion_score": [0.9]})
    X = prepare_frame(raw)
    assert not set(X.columns) & set(BANNED_POST_LABEL)


def test_mask_digits():
    assert mask_digits("Jul 26 2024 11:58:44 port 445") == "Jul 0 0 0:0:0 port 0"


def test_vectorizer_vocabulary_comes_from_training_rows_only():
    tr = pd.DataFrame({"text": ["deny tcp outside"] * 10 + ["permit udp inside"] * 10, "y": [1] * 10 + [0] * 10})
    model = make_lr("text").fit(tr[["text"]], tr["y"])
    vocab = model.named_steps["features"].named_transformers_["text"].vocabulary_
    assert "deny" in vocab and "zebratoken" not in vocab
    model.predict_proba(pd.DataFrame({"text": ["zebratoken zebratoken"]}))  # unseen tokens are ignored
    assert "zebratoken" not in model.named_steps["features"].named_transformers_["text"].vocabulary_


# ---------------------------------------------------------------- splits
def _synthetic_raw():
    c4, c5 = CUTOFFS["ORG-0004"], CUTOFFS["ORG-0005"]
    rows = []
    for org, cut in [("ORG-0004", c4), ("ORG-0005", c5)]:
        for k in range(40):
            t = cut + (k - 20) * 600
            mal = k % 5 == 0
            inc = json.dumps(["inc-cross"]) if (mal and org == "ORG-0005" and k in (15, 25)) else \
                json.dumps([f"inc-{org}-{k}"]) if mal else None
            rows.append({"artifact_id": f"{org}-{k}", "org_id": org, "timestamp": t, "message_type": "fw",
                         "stream_name": "s", "product_name": "p", "vendor_name": "v", "pipeline": "x",
                         "src_ip": f"10.0.0.{k % 3}", "dst_ip": "10.1.1.1", "src_port": "5555", "dst_port": "445",
                         "protocol": "6", "action": "block", "severity": "warning",
                         "message_sanitized": f"Deny tcp {k}", "incident_ids": inc,
                         "label_binary": "malicious" if mal else "suspicious"})
    return pd.DataFrame(rows)


def test_splits_are_temporal_and_incident_disjoint():
    ds = build_dataset(_synthetic_raw())
    s2 = stage2_frame(ds)
    for name, (a, b) in stage2_splits(s2).items():
        assert not set(a) & set(b), name
        if "temporal" in name:
            for org in s2.loc[a, "org_id"].unique():
                assert s2.loc[a][s2.loc[a, "org_id"] == org]["timestamp"].max() < CUTOFFS[org]
            tr_inc = set(s2.loc[a, "incident"].dropna())
            te_inc = set(s2.loc[b, "incident"].dropna())
            assert not tr_inc & te_inc, f"incident leak in {name}"


# ---------------------------------------------------------------- metrics / persistence
def test_threshold_and_report():
    y = np.array([0] * 90 + [1] * 10)
    p = np.r_[np.linspace(0, 0.4, 90), np.linspace(0.6, 1, 10)]
    t = best_f1_threshold(y, p)
    assert 0.4 <= t <= 0.6
    r = binary_report(y, p, t)
    assert r["per_class"]["positive"]["recall"] == 1.0


def test_model_persistence_roundtrip(tmp_path):
    d = _events(300)
    d["message_sanitized"] = np.where(d.index % 2, "deny tcp", "permit udp")
    for c in ["message_type", "action", "protocol", "severity", "src_port"]:
        d[c] = "x"
    X = pd.concat([prepare_frame(d), add_context_features(d)], axis=1)
    y = (d.index % 2).astype(int)
    cols = input_columns("full")
    m = make_lr("full").fit(X[cols], y)
    joblib.dump(m, tmp_path / "m.joblib")
    m2 = joblib.load(tmp_path / "m.joblib")
    np.testing.assert_allclose(m.predict_proba(X[cols]), m2.predict_proba(X[cols]))


# ---------------------------------------------------------------- real artefacts (skip if absent)
@pytest.mark.skipif(not SIGNALS_PARQUET.exists(), reason="dataset not downloaded")
def test_dataset_loads_with_expected_counts():
    import duckdb
    r = duckdb.connect().execute(
        f"SELECT label_binary, count(*) FROM '{SIGNALS_PARQUET.as_posix()}' GROUP BY 1").fetchall()
    assert dict(r) == {"benign": 1_897_153, "suspicious": 106_793, "malicious": 7_728}


needs_models = pytest.mark.skipif(not (MODELS_DIR / "iforest.joblib").exists() or
                                  not (MODELS_DIR / "stage1_logreg.joblib").exists(),
                                  reason="models not trained yet")


@needs_models
def test_orchestrator_on_unseen_records():
    from evidentia.ml.orchestrator import MLOrchestrator
    orch = MLOrchestrator.load()
    ev = pd.DataFrame([
        {"timestamp": 1.9e9, "message_sanitized": '<164>Aug 02 2025 10:00:01: %ASA-4-106023: Deny tcp src '
         'outside:192.0.2.10/51515 dst dmz-1:10.9.9.9/445 by access-group "outside_access_in"',
         "message_type": "firewall_action", "action": "block", "protocol": "6", "severity": "warning",
         "src_ip": "192.0.2.10", "dst_ip": "10.9.9.9", "src_port": "51515", "dst_port": "445"},
        {"timestamp": 1.9e9 + 5, "message_sanitized": "User visited https://example.org/recipes in Chrome"},
        {"timestamp": None, "message_sanitized": "no time here"},
    ])
    out = orch.analyze(ev)
    assert len(out) == 3
    for r in out:
        for m in ("logreg", "random_forest"):
            probs = r["classifiers"][m]["class_probabilities"]
            assert set(probs) == {"benign", "suspicious", "malicious"}
            assert abs(sum(probs.values()) - 1) < 1e-3
            assert "anomaly" not in probs  # anomaly score never merged into class probabilities
        assert r["anomaly"]["score"] is None or isinstance(r["anomaly"]["score"], float)
        if not r["anomaly"]["scored"]:
            assert r["anomaly"]["flagged"] is False
    assert out[2]["applicability"]["applicable"] is False
    assert out[1]["applicability"]["applicable"] is False
