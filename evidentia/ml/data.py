"""Load the WitFoo `signals` table and build leakage-safe train/test partitions."""
from __future__ import annotations

import json

import duckdb
import numpy as np
import pandas as pd

from .config import CUTOFFS, SIGNALS_PARQUET, STAGE2_ORGS
from .context import add_context_features
from .features import prepare_frame

LOAD_COLS = ["artifact_id", "org_id", "timestamp", "message_type", "stream_name", "product_name",
             "vendor_name", "pipeline", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
             "action", "severity", "message_sanitized", "label_binary", "incident_ids"]


def load_signals(path=SIGNALS_PARQUET) -> pd.DataFrame:
    """All live signals with the columns we need. `incident_ids` is loaded only to
    build evaluation groups; it is never passed to a model."""
    con = duckdb.connect()
    df = con.execute(f"SELECT {', '.join(LOAD_COLS)} FROM '{path.as_posix()}'").df()
    for c in ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "action", "severity",
              "message_type", "message_sanitized"]:
        df[c] = df[c].replace("", np.nan)
    return df


def first_incident(s: str | None) -> str | None:
    if not s:
        return None
    try:
        v = json.loads(s)
        return v[0] if v else None
    except (ValueError, TypeError):
        return None


def build_dataset(df: pd.DataFrame) -> pd.DataFrame:
    """Add model inputs, context features, split flags and evaluation groups."""
    df = df.sort_values("timestamp", kind="stable").reset_index(drop=True)
    ctx = add_context_features(df, scope_col="org_id")
    X = prepare_frame(df)
    out = pd.concat([df[["artifact_id", "org_id", "timestamp", "label_binary", "incident_ids"]], X, ctx], axis=1)
    out["is_test"] = out["timestamp"] >= out["org_id"].map(CUTOFFS).astype(float)
    out["incident"] = out["incident_ids"].map(first_incident)
    out["raw_text"] = df["message_sanitized"].fillna("")

    # Incidents present in the test period must not appear in training (audit 6).
    all_inc = out.loc[out["label_binary"] == "malicious", ["incident_ids", "is_test"]]
    test_incidents: set[str] = set()
    for s in all_inc.loc[all_inc["is_test"], "incident_ids"]:
        test_incidents.update(json.loads(s))
    def crosses(s):
        return bool(s) and bool(set(json.loads(s)) & test_incidents)
    mal_train = (out["label_binary"] == "malicious") & ~out["is_test"]
    out["drop_from_train"] = False
    out.loc[mal_train, "drop_from_train"] = out.loc[mal_train, "incident_ids"].map(crosses)

    # Groups for cross-validation inside the training window:
    # malicious rows -> their incident; others -> org + 2-hour block.
    block = (out["timestamp"] // 7200).astype(np.int64).astype(str)
    out["cv_group"] = np.where(out["incident"].notna(), "inc:" + out["incident"].fillna(""),
                               out["org_id"] + ":" + block)
    return out


def stage2_frame(ds: pd.DataFrame) -> pd.DataFrame:
    """Non-benign rows of the organisations that have malicious data."""
    m = (ds["label_binary"] != "benign") & ds["org_id"].isin(STAGE2_ORGS)
    s2 = ds.loc[m].copy()
    s2["y"] = (s2["label_binary"] == "malicious").astype(int)
    return s2


def stage2_splits(s2: pd.DataFrame) -> dict[str, tuple[pd.Index, pd.Index]]:
    """name -> (train_index, test_index)."""
    keep = ~s2["drop_from_train"]
    o4, o5 = s2["org_id"] == "ORG-0004", s2["org_id"] == "ORG-0005"
    tr, te = ~s2["is_test"] & keep, s2["is_test"]
    return {
        "A_temporal_ORG-0004": (s2.index[o4 & tr], s2.index[o4 & te]),
        "B_temporal_ORG-0005": (s2.index[o5 & tr], s2.index[o5 & te]),
        "POOLED_temporal": (s2.index[(o4 | o5) & tr], s2.index[(o4 | o5) & te]),
        "C_cross_0004_to_0005": (s2.index[o4], s2.index[o5]),
        "C_cross_0005_to_0004": (s2.index[o5], s2.index[o4]),
    }


def stage1_split(ds: pd.DataFrame, n_benign: int, seed: int) -> tuple[pd.Index, pd.Index]:
    """Benign vs alert. Train: all alerts + a random benign sample from the training
    window. Test: every row of the test window (natural class distribution)."""
    tr = ~ds["is_test"] & ~ds["drop_from_train"]
    benign_tr = ds.index[tr & (ds["label_binary"] == "benign")]
    rng = np.random.default_rng(seed)
    benign_tr = rng.choice(benign_tr, size=min(n_benign, len(benign_tr)), replace=False)
    alerts_tr = ds.index[tr & (ds["label_binary"] != "benign")]
    train_idx = pd.Index(np.sort(np.concatenate([benign_tr, alerts_tr])))
    return train_idx, ds.index[ds["is_test"]]
