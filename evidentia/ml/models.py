"""Model factories. LR and RF always receive the same transformer (same features)."""
from __future__ import annotations

from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from .config import SEED
from .features import build_transformer


def make_lr(feature_set: str, C: float = 1.0, multiclass: bool = False) -> Pipeline:
    clf = LogisticRegression(C=C, class_weight="balanced", max_iter=3000,
                             solver="lbfgs" if multiclass else "liblinear", random_state=SEED)
    return Pipeline([("features", build_transformer(feature_set)), ("clf", clf)])


def make_rf(feature_set: str, n_estimators: int = 150, max_depth=None, min_samples_leaf: int = 1,
            max_features="sqrt") -> Pipeline:
    clf = RandomForestClassifier(n_estimators=n_estimators, max_depth=max_depth,
                                 min_samples_leaf=min_samples_leaf, max_features=max_features,
                                 class_weight="balanced_subsample", n_jobs=-1, random_state=SEED)
    return Pipeline([("features", build_transformer(feature_set)), ("clf", clf)])


def make_iforest(contamination: float = 0.01) -> Pipeline:
    """Isolation Forest on context + categorical features (no text, no labels)."""
    return Pipeline([("features", build_transformer("context")),
                     ("iforest", IsolationForest(n_estimators=200, max_samples=4096,
                                                 contamination=contamination, n_jobs=-1,
                                                 random_state=SEED))])
