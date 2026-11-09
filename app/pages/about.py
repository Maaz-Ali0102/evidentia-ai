import streamlit as st

from common import page_header

page_header("About & limitations", "What the system does, how, and where it must not be trusted.")

st.markdown("""
#### Pipeline
1. **Ingest:** the file is read in memory; its SHA-256 is shown; every event keeps its file and row number.
2. **Parse:** CSV/JSON columns are mapped to event fields; Cisco ASA and AWS VPC flow-log lines are parsed;
   unreadable timestamps stay empty (never invented).
3. **Applicability gate:** an event is scored only if it has a timestamp and ≥30% of its word pairs occur in the
   training vocabulary. Browser history, notes or OCR text are refused instead of guessed.
4. **Context:** for every event, counts of *earlier* events from the same source IP, destination, port and pairs
   over 1 min – 6 h (computed within the uploaded file).
5. **Models:** Stage 1 (benign vs alert) → Stage 2 (suspicious vs malicious), each by Logistic Regression and
   Random Forest; plus an Isolation Forest anomaly score for alert traffic. Disagreements are shown, not hidden.

#### What the labels mean
The models were trained to reproduce **WitFoo Precinct's automated triage** (rule hits and incident leads).
There is no analyst-verified ground truth, so a "malicious" prediction means "resembles events WitFoo's
engine escalated", not "confirmed attack".

#### Measured limits (see Model evaluation)
- Works within an organisation on future incidents (ORG-0005: ROC-AUC ≈ 0.95), but **not** for ORG-0004 and
  **not** across organisations (≈ chance).
- Malicious precision ≈ 0.3: most "malicious" flags still need an analyst.
- Probabilities are not calibrated.
- Context features in an uploaded file only see that file's history.

#### Privacy
Runs on `localhost`; no external API is called; uploaded files are not stored by the app.
""")
