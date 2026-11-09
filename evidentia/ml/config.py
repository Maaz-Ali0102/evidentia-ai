"""Central configuration for the ML subsystem.

Every decision here is justified in reports/DATASET_AUDIT.md (section numbers in comments).
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SIGNALS_PARQUET = ROOT / "data" / "raw" / "precinct6" / "signals" / "signals.parquet"
MODELS_DIR = ROOT / "models"
METRICS_DIR = ROOT / "reports" / "metrics"

FEATURE_VERSION = "fv1"  # bump whenever feature engineering changes
SEED = 42

LABELS = ["benign", "suspicious", "malicious"]

# Audit 5.2: produced by (or used to produce) the label -> never model inputs.
BANNED_POST_LABEL = [
    "label_binary", "label_confidence", "attack_techniques", "attack_tactics",
    "defense_techniques", "mo_name", "suspicion_score", "lifecycle_stage", "disposition",
    "disposition_category", "is_false_positive", "status_name", "incident_ids",
    "matched_rules", "set_roles",
]
# Audit 5.3: collection-path fields. Excluded from main models, added back only in ablations.
SOURCE_FIELDS = ["stream_name", "product_name", "vendor_name", "pipeline"]
# Never features: identifiers / evaluation-group keys / constant in signals.
NEVER_FEATURES = ["org_id", "origin", "timestamp_source", "artifact_id"]

# Columns describing the event itself (available at prediction time).
TEXT_COL = "message_sanitized"
CAT_COLS = ["message_type", "action", "protocol", "severity", "dst_port", "src_port_bucket"]

# Past-only behavioural context (audit section 7).
CONTEXT_KEYS = {
    "src": ["src_ip"],
    "dst": ["dst_ip"],
    "dport": ["dst_port"],
    "src_dst": ["src_ip", "dst_ip"],
    "src_dport": ["src_ip", "dst_port"],
}
CONTEXT_WINDOWS = [60, 600, 3600, 21600]  # seconds (1 min, 10 min, 1 h, 6 h)


def _utc(s: str) -> float:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


# Temporal cut-offs (UTC). Rows with timestamp >= cutoff are test rows.
# Chosen so that both sides contain malicious incidents; ORG-0004 has 0 incidents
# crossing its cut-off, ORG-0005 has 44 (their train-side rows are dropped from training).
CUTOFFS = {
    "ORG-0004": _utc("2024-07-29T20:00:00"),
    "ORG-0005": _utc("2024-07-27T00:00:00"),
    "ORG-0003": _utc("2024-07-27T00:00:00"),
    "ORG-0001": _utc("2024-07-27T00:00:00"),
}
STAGE2_ORGS = ["ORG-0004", "ORG-0005"]  # only orgs with enough malicious rows (audit 3)
STAGE1_BENIGN_TRAIN_SAMPLE = 250_000
