"""Metric helpers. Every number written to reports/metrics comes from these functions."""
from __future__ import annotations

import numpy as np
from sklearn.metrics import (accuracy_score, average_precision_score, confusion_matrix,
                             f1_score, precision_recall_fscore_support, roc_auc_score)


def binary_report(y_true, proba, threshold: float = 0.5, names=("negative", "positive")) -> dict:
    y_true = np.asarray(y_true)
    pred = (np.asarray(proba) >= threshold).astype(int)
    p, r, f, s = precision_recall_fscore_support(y_true, pred, labels=[0, 1], zero_division=0)
    both = len(np.unique(y_true)) == 2
    return {
        "threshold": round(float(threshold), 4),
        "n": int(len(y_true)), "n_positive": int(y_true.sum()),
        "accuracy": round(accuracy_score(y_true, pred), 4),
        "macro_f1": round(f1_score(y_true, pred, average="macro", zero_division=0), 4),
        "per_class": {names[i]: {"precision": round(p[i], 4), "recall": round(r[i], 4),
                                 "f1": round(f[i], 4), "support": int(s[i])} for i in range(2)},
        "pr_auc_positive": round(average_precision_score(y_true, proba), 4) if both else None,
        "roc_auc": round(roc_auc_score(y_true, proba), 4) if both else None,
        "positive_rate_baseline": round(float(y_true.mean()), 4),
        "confusion_matrix": confusion_matrix(y_true, pred, labels=[0, 1]).tolist(),
    }


def multiclass_report(y_true, y_pred, labels) -> dict:
    p, r, f, s = precision_recall_fscore_support(y_true, y_pred, labels=labels, zero_division=0)
    return {
        "n": int(len(y_true)),
        "accuracy": round(accuracy_score(y_true, y_pred), 4),
        "macro_precision": round(float(np.mean(p)), 4),
        "macro_recall": round(float(np.mean(r)), 4),
        "macro_f1": round(f1_score(y_true, y_pred, labels=labels, average="macro", zero_division=0), 4),
        "per_class": {l: {"precision": round(p[i], 4), "recall": round(r[i], 4), "f1": round(f[i], 4),
                          "support": int(s[i])} for i, l in enumerate(labels)},
        "labels": labels,
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }


def best_f1_threshold(y_true, proba) -> float:
    """Threshold maximising F1 of the positive class (chosen on training OOF scores only)."""
    y_true, proba = np.asarray(y_true), np.asarray(proba)
    best, best_t = -1.0, 0.5
    for t in np.unique(np.quantile(proba, np.linspace(0.5, 0.999, 200))):
        f = f1_score(y_true, (proba >= t).astype(int), zero_division=0)
        if f > best:
            best, best_t = f, float(t)
    return best_t
