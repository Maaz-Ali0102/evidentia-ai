"""Past-only behavioural context features.

For each event and each key (e.g. same source IP) we count how many events with
the same key value happened in the W seconds strictly BEFORE this event.
Rows at the same or later timestamps are never counted, so no information from
the future (including the test period) can leak into a feature.

The same function is used for training and for inference on an uploaded case,
which keeps the two code paths identical.
"""
from __future__ import annotations

import numpy as np
import pandas as pd

from .config import CONTEXT_KEYS, CONTEXT_WINDOWS

NO_PREVIOUS_SECONDS = 86_400.0  # value used when no earlier event exists


def _past_counts(codes: np.ndarray, ts: np.ndarray, valid: np.ndarray, window: float) -> np.ndarray:
    """Count earlier events with the same code in [t - window, t) for every row."""
    out = np.zeros(len(ts), dtype=np.float32)
    idx = np.flatnonzero(valid)
    if idx.size == 0:
        return out
    c, t = codes[idx], ts[idx]
    order = np.lexsort((t, c))
    c_s, t_s = c[order], t[order]
    # Within each code block, timestamps are sorted; search inside the block only.
    starts = np.searchsorted(c_s, c_s, side="left")
    # Position of first element >= t (strictly earlier ones are counted)
    hi = _block_searchsorted(c_s, t_s, t_s, starts)
    lo = _block_searchsorted(c_s, t_s, t_s - window, starts)
    res = np.empty(idx.size, dtype=np.float32)
    res[order] = (hi - lo).astype(np.float32)
    out[idx] = res
    return out


def _block_searchsorted(c_s, t_s, query, starts):
    """Vectorised searchsorted of `query` within each row's code block."""
    # Encode (code, time) into one sortable float key. Times are shifted to start at 0
    # so the composite key keeps sub-millisecond precision.
    t0 = t_s.min()
    span = float(t_s.max() - t0) + 1e6
    key = c_s.astype(np.float64) * span + (t_s - t0)
    qkey = c_s.astype(np.float64) * span + (query - t0)
    return np.searchsorted(key, qkey, side="left")


def _seconds_since_previous(codes, ts, valid) -> np.ndarray:
    out = np.full(len(ts), NO_PREVIOUS_SECONDS, dtype=np.float64)
    idx = np.flatnonzero(valid)
    if idx.size == 0:
        return out.astype(np.float32)
    c, t = codes[idx], ts[idx]
    order = np.lexsort((t, c))
    c_s, t_s = c[order], t[order]
    starts = np.searchsorted(c_s, c_s, side="left")
    first_ge = _block_searchsorted(c_s, t_s, t_s, starts)  # first index with same time
    prev = first_ge - 1
    has_prev = (prev >= starts)
    gap = np.full(idx.size, NO_PREVIOUS_SECONDS)
    gap[has_prev] = t_s[has_prev] - t_s[prev[has_prev]]
    res = np.empty(idx.size)
    res[order] = np.minimum(gap, NO_PREVIOUS_SECONDS)
    out[idx] = res
    return out.astype(np.float32)


def context_feature_names() -> list[str]:
    names = [f"ctx_{k}_{w}s" for k in CONTEXT_KEYS for w in CONTEXT_WINDOWS]
    return names + ["ctx_src_secs_since_prev", "has_src_ip", "has_dst_ip"]


def add_context_features(df: pd.DataFrame, scope_col: str = "org_id") -> pd.DataFrame:
    """Return a DataFrame (same index) of log1p-scaled past-only context features.

    `scope_col` separates independent environments (organisation in training,
    case id at inference) so that counts never mix two networks.
    """
    ts = df["timestamp"].to_numpy(dtype=np.float64)
    scope = df[scope_col].astype(str) if scope_col in df else pd.Series("case", index=df.index)
    feats: dict[str, np.ndarray] = {}
    for name, cols in CONTEXT_KEYS.items():
        parts = [scope] + [df[c].astype("string") for c in cols]
        valid = np.ones(len(df), dtype=bool)
        for c in cols:
            v = df[c]
            valid &= v.notna().to_numpy() & (v.astype("string").str.len().fillna(0) > 0).to_numpy()
        joined = parts[0].str.cat([p.fillna("") for p in parts[1:]], sep="|")
        codes = pd.factorize(joined)[0].astype(np.int64)
        for w in CONTEXT_WINDOWS:
            feats[f"ctx_{name}_{w}s"] = np.log1p(_past_counts(codes, ts, valid, float(w)))
        if name == "src":
            feats["ctx_src_secs_since_prev"] = np.log1p(_seconds_since_previous(codes, ts, valid))
            feats["has_src_ip"] = valid.astype(np.float32)
        if name == "dst":
            feats["has_dst_ip"] = valid.astype(np.float32)
    return pd.DataFrame(feats, index=df.index)[context_feature_names()]
