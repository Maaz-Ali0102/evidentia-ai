"""ML orchestrator: one entry point that runs every trained model on new events.

It never merges anomaly scores into class probabilities, and it never hides
disagreement between models. It is independent of any UI or chatbot; the
assistant consumes its output through the backend.

    orch = MLOrchestrator.load()
    results = orch.analyze(events_df)   # list[dict], one per event
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .config import FEATURE_VERSION, LABELS, MODELS_DIR
from .context import add_context_features
from .features import prepare_frame

BIGRAM_COVERAGE_MIN = 0.3
DECISION_RULE = ("alert if p_alert_stage1 >= 0.5; then malicious if p_malicious_given_alert_stage2 >= stage2_threshold "
                 "(threshold chosen on training out-of-fold scores to maximise F1), otherwise suspicious. "
                 "Probabilities come from class-balanced training and are NOT calibrated, so the predicted class "
                 "can differ from the largest probability.")
REQUIRED = ["timestamp"]
OPTIONAL = ["message_sanitized", "message_type", "action", "protocol", "severity", "src_ip", "dst_ip",
            "src_port", "dst_port"]


@dataclass
class MLOrchestrator:
    stage1: dict
    stage2: dict
    iforest: dict
    registry: dict = field(default_factory=dict)

    @classmethod
    def load(cls, models_dir: Path = MODELS_DIR) -> "MLOrchestrator":
        s1 = {m: joblib.load(models_dir / f"stage1_{m}.joblib") for m in ("logreg", "random_forest")}
        s2 = {m: joblib.load(models_dir / f"stage2_{m}.joblib") for m in ("logreg", "random_forest")}
        iso = joblib.load(models_dir / "iforest.joblib")
        reg_path = models_dir / "registry.json"
        reg = json.loads(reg_path.read_text()) if reg_path.exists() else {}
        return cls(s1, s2, iso, reg)

    # ------------------------------------------------------------------ helpers
    def _text_vectorizer(self):
        return self.stage1["logreg"]["model"].named_steps["features"].named_transformers_["text"]

    def _known_message_types(self) -> set:
        ct = self.stage1["logreg"]["model"].named_steps["features"]
        enc = ct.named_transformers_["cat"]
        return set(map(str, enc.categories_[0]))

    def _applicability(self, X: pd.DataFrame, events: pd.DataFrame) -> pd.DataFrame:
        # Gate on the share of the record's word BIGRAMS that exist in the training vocabulary.
        # Unigrams are too generic ("user", "https" occur in benign logs too). Calibrated on held-out
        # test rows: 1st percentile 0.333, 5th percentile 0.857; browser/OCR/report text scored 0.0-0.1
        # (reports/ML_RESULTS.md, applicability gate).
        vec = self._text_vectorizer()
        vocab, analyzer = vec.vocabulary_, vec.build_analyzer()
        known_types = self._known_message_types()

        def bigram_coverage(t: str) -> float:
            grams = [g for g in analyzer(t) if " " in g]
            return (sum(g in vocab for g in grams) / len(grams)) if grams else float("nan")

        coverage = X["text"].map(bigram_coverage)
        type_known = X["message_type"].isin(known_types) & (X["message_type"] != "none")
        has_ts = events["timestamp"].notna()
        has_text = coverage.notna()
        ok = has_ts & ((has_text & (coverage >= BIGRAM_COVERAGE_MIN)) | (~has_text & type_known))
        coverage = coverage.fillna(0.0)
        reason = np.where(~has_ts, "no timestamp: context features cannot be computed",
                          np.where(ok, "resembles training data",
                                   "text/fields unlike the WitFoo security logs the models were trained on"))
        return pd.DataFrame({"applicable": ok, "token_coverage": coverage.round(3),
                             "message_type_known": type_known, "reason": reason}, index=X.index)

    # ------------------------------------------------------------------ main API
    def analyze(self, events: pd.DataFrame, scope_col: str = "case_id") -> list[dict]:
        ev = events.copy().reset_index(drop=True)
        for c in REQUIRED + OPTIONAL:
            if c not in ev:
                ev[c] = np.nan
        ev["timestamp"] = pd.to_numeric(ev["timestamp"], errors="coerce")
        if scope_col not in ev:
            ev[scope_col] = "case"
        ev_ctx = ev.copy()
        ev_ctx["timestamp"] = ev_ctx["timestamp"].fillna(-1.0)
        ctx = add_context_features(ev_ctx, scope_col=scope_col)
        X = pd.concat([prepare_frame(ev), ctx], axis=1)
        app = self._applicability(X, ev)

        p1 = {m: d["model"].predict_proba(X[d["columns"]])[:, 1] for m, d in self.stage1.items()}
        p2 = {m: d["model"].predict_proba(X[d["columns"]])[:, 1] for m, d in self.stage2.items()}
        anomaly = -self.iforest["model"].score_samples(X[self.iforest["columns"]])
        # The Isolation Forest was fitted on ALERT rows only (reports/ML_RESULTS.md section 5), so its
        # score is meaningful only for in-domain rows that a classifier routes to the alert stage.
        in_scope = app["applicable"].to_numpy() & np.any(
            [p1[m] >= self.stage1[m]["threshold"] for m in self.stage1], axis=0)
        flag = in_scope & (anomaly >= self.iforest["threshold"])

        out = []
        for i in range(len(ev)):
            per_model = {}
            for m in ("logreg", "random_forest"):
                probs = [1 - p1[m][i], p1[m][i] * (1 - p2[m][i]), p1[m][i] * p2[m][i]]
                if p1[m][i] < self.stage1[m]["threshold"]:
                    cls = "benign"
                else:
                    cls = "malicious" if p2[m][i] >= self.stage2[m]["threshold"] else "suspicious"
                per_model[m] = {"predicted_class": cls,
                                "class_probabilities": dict(zip(LABELS, map(lambda v: round(float(v), 4), probs))),
                                "p_alert_stage1": round(float(p1[m][i]), 4),
                                "p_malicious_given_alert_stage2": round(float(p2[m][i]), 4),
                                "stage2_threshold": round(float(self.stage2[m]["threshold"]), 4)}
            classes = {v["predicted_class"] for v in per_model.values()}
            notes = []
            if len(classes) > 1:
                notes.append("Logistic Regression and Random Forest disagree on the class.")
            if flag[i] and "malicious" not in classes:
                notes.append("Anomaly detector flags this event although no classifier predicts malicious.")
            if not app.loc[i, "applicable"]:
                notes.append("Model output is unreliable for this record: " + app.loc[i, "reason"] + ".")
            out.append({
                "row": i,
                "applicability": {k: (bool(v) if isinstance(v, (bool, np.bool_)) else float(v) if isinstance(v, (float, np.floating)) else v)
                                  for k, v in app.loc[i].to_dict().items()},
                "classifiers": per_model,
                "decision_rule": DECISION_RULE,
                "models_agree": len(classes) == 1,
                "anomaly": {"score": round(float(anomaly[i]), 4) if in_scope[i] else None,
                            "flagged": bool(flag[i]), "scored": bool(in_scope[i]),
                            "threshold": round(float(self.iforest["threshold"]), 4),
                            "meaning": ("unusual context pattern among alert traffic; not evidence of "
                                        "maliciousness by itself") if in_scope[i] else
                                       "not scored: the anomaly model was fitted on alert traffic only"},
                "notes": notes,
                "label_semantics": "Trained to reproduce WitFoo Precinct's automated triage, "
                                   "not analyst-verified ground truth.",
                "versions": {"feature_version": FEATURE_VERSION,
                             "models": {k: v.get("trained") for k, v in self.registry.items()}},
            })
        return out
