"""Feature pipeline shared by Logistic Regression and Random Forest.

All learned transforms (TF-IDF vocabulary, one-hot categories, scaler) live inside
one scikit-learn ColumnTransformer, so they are fitted only on the training rows
passed to `.fit()` and merely applied to validation/test rows.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import FunctionTransformer, OneHotEncoder, StandardScaler

from .config import BANNED_POST_LABEL, CAT_COLS, NEVER_FEATURES, SOURCE_FIELDS, TEXT_COL
from .context import context_feature_names

_DIGITS = re.compile(r"\d+")


def mask_digits(text: str) -> str:
    """Replace every digit run with '0' so timestamps/counters do not become tokens."""
    return _DIGITS.sub("0", text or "")


def src_port_bucket(port) -> str:
    try:
        p = int(port)
    except (TypeError, ValueError):
        return "none"
    if p < 1024:
        return "wellknown"
    if p < 49152:
        return "registered"
    return "ephemeral"


def prepare_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Raw event columns -> model input columns (no labels, no post-label fields)."""
    out = pd.DataFrame(index=df.index)
    out["text"] = df[TEXT_COL].fillna("").astype(str).map(mask_digits) if TEXT_COL in df else ""
    for c in CAT_COLS:
        if c == "src_port_bucket":
            out[c] = df["src_port"].map(src_port_bucket) if "src_port" in df else "none"
        else:
            out[c] = df[c].astype(object).fillna("none").astype(str) if c in df else "none"
    for c in SOURCE_FIELDS:
        out[c] = df[c].astype(object).fillna("none").astype(str) if c in df else "none"
    return out


FEATURE_SETS = {
    # name: (use_text, use_categorical, use_context, use_source)
    "text": (True, False, False, False),
    "context": (False, True, True, False),
    "full": (True, True, True, False),
    "full+source": (True, True, True, True),
}


def build_transformer(feature_set: str = "full", max_text_features: int = 20_000) -> ColumnTransformer:
    use_text, use_cat, use_ctx, use_src = FEATURE_SETS[feature_set]
    parts = []
    if use_text:
        parts.append(("text", TfidfVectorizer(ngram_range=(1, 2), min_df=3, max_features=max_text_features,
                                              sublinear_tf=True, dtype=np.float32), "text"))
    if use_cat:
        parts.append(("cat", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=5,
                                           dtype=np.float32), CAT_COLS))
    if use_ctx:
        parts.append(("ctx", StandardScaler(), context_feature_names()))
    if use_src:
        parts.append(("src", OneHotEncoder(handle_unknown="infrequent_if_exist", min_frequency=5,
                                           dtype=np.float32), SOURCE_FIELDS))
    return ColumnTransformer(parts, sparse_threshold=1.0)  # always sparse: never densify TF-IDF


def input_columns(feature_set: str) -> list[str]:
    use_text, use_cat, use_ctx, use_src = FEATURE_SETS[feature_set]
    cols = (["text"] if use_text else []) + (CAT_COLS if use_cat else []) \
        + (context_feature_names() if use_ctx else []) + (SOURCE_FIELDS if use_src else [])
    forbidden = set(BANNED_POST_LABEL) | set(NEVER_FEATURES)
    assert not forbidden & set(cols), f"leakage: {forbidden & set(cols)}"
    return cols
