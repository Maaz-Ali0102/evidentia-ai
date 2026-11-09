"""Shared helpers for the Streamlit app (runs locally; no data leaves the machine)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from evidentia.ingestion.upload import parse_upload  # noqa: E402
from evidentia.ml.orchestrator import MLOrchestrator  # noqa: E402

METRICS = ROOT / "reports" / "metrics"
FIGS = ROOT / "reports" / "figures"
SAMPLES = ROOT / "data" / "samples"
CLASS_COLORS = {"benign": "#2a78d6", "suspicious": "#eb6834", "malicious": "#1baf7a",
                "not applicable": "#898781"}
MODEL_NAMES = {"logreg": "Logistic Regression", "random_forest": "Random Forest"}


@st.cache_resource(show_spinner="Loading trained models…")
def orchestrator() -> MLOrchestrator:
    return MLOrchestrator.load()


@st.cache_data(show_spinner=False)
def metrics(name: str) -> dict:
    return json.loads((METRICS / f"{name}.json").read_text(encoding="utf-8"))


@st.cache_data(show_spinner="Parsing file…", max_entries=8)
def parse(file_name: str, data: bytes):
    return parse_upload(file_name, data)


@st.cache_data(show_spinner="Running the models…", max_entries=8)
def analyze(sha256: str, _events: pd.DataFrame) -> pd.DataFrame:
    """Flatten orchestrator output into one row per event. Cached by file hash."""
    res = orchestrator().analyze(_events)
    rows = []
    for r, (_, ev) in zip(res, _events.iterrows()):
        app = r["applicability"]
        row = {
            "row": int(ev["source_row"]),
            "time_utc": pd.to_datetime(ev["timestamp"], unit="s", utc=True) if pd.notna(ev["timestamp"]) else pd.NaT,
            "applicable": app["applicable"],
            "applicability_reason": app["reason"],
            "bigram_coverage": app["token_coverage"],
            "models_agree": r["models_agree"],
            "anomaly_scored": r["anomaly"]["scored"],
            "anomaly_flag": r["anomaly"]["flagged"],
            "anomaly_score": r["anomaly"]["score"],
            "notes": " ".join(r["notes"]),
            "src_ip": ev.get("src_ip"), "dst_ip": ev.get("dst_ip"), "dst_port": ev.get("dst_port"),
            "message": ev.get("message_sanitized"),
            "_detail": r,
        }
        for m in ("logreg", "random_forest"):
            c = r["classifiers"][m]
            row[f"{m}_class"] = c["predicted_class"] if app["applicable"] else "not applicable"
            row[f"{m}_p_alert"] = c["p_alert_stage1"]
            row[f"{m}_p_malicious"] = c["p_malicious_given_alert_stage2"]
            row[f"{m}_threshold"] = c["stage2_threshold"]
        if "reference_label_witfoo" in ev:
            row["reference_label_witfoo"] = ev["reference_label_witfoo"]
        rows.append(row)
    return pd.DataFrame(rows)


def page_header(title: str, subtitle: str) -> None:
    st.title(title)
    st.caption(subtitle)
