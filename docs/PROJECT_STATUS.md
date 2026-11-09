# Evidentia AI: Project Status

**Last updated:** 2026-11-10
**Repository:** https://github.com/Maaz-Ali0102/evidentia-ai

This page records what is built, what is verified, what is broken or pending, and how the current system compares with the original project vision. For the ML details, see [`reports/ML_REPORT.md`](../reports/ML_REPORT.md).

---

## 1. Summary

The **ML core of the CCA is complete**:

- dataset audit
- train-only EDA
- leakage-safe two-stage classifiers (Logistic Regression, Random Forest)
- Isolation Forest
- tuning and evaluation on future time windows
- a local Streamlit app
- a single-file report

The **forensics-platform extensions** from the original vision are **not built yet**: multi-file cases, other artifact types, a relationship graph, a cross-file timeline and the RAG chatbot.

---

## 2. Original vision vs current state

**Original idea (master prompt).** An investigator creates a *case* and uploads a folder of mixed evidence: browser history, system logs, JSON/CSV security logs, TXT/HTML files, incident reports, network records and screenshots. The system was to preserve and parse the evidence, extract entities, classify events with ML, detect anomalies, link related evidence in a graph, rebuild a timeline, and answer questions through a RAG chatbot. Each answer would separate *evidence*, *ML prediction*, *inferred relationship*, *retrieved context* and *unknown*.

| Capability | Status | Where |
|---|---|---|
| Dataset audit + leakage analysis | ✅ Done | `scripts/audit_dataset.py`, `reports/DATASET_AUDIT.md` |
| Train-only EDA (9 charts) | ✅ Done | `notebooks/01_eda.ipynb`, `reports/eda_summary.md` |
| Preprocessing + features (TF-IDF, one-hot, 23 past-only context features) | ✅ Done | `evidentia/ml/features.py`, `evidentia/ml/context.py` |
| Temporal, incident-aware splits | ✅ Done | `evidentia/ml/data.py` |
| LR / RF (Stage 1 + Stage 2, flat 3-class) + Isolation Forest, GridSearchCV tuning | ✅ Done | `scripts/train_models.py`, `models/` |
| Stage 1 within-product check | ✅ Done | `scripts/stage1_within_product.py` |
| ML orchestrator (both models, disagreement, anomaly flag, applicability gate) | ✅ Done | `evidentia/ml/orchestrator.py` |
| Evidence upload: SHA-256, provenance (file + row), CSV / JSON / ASA / VPC parsing | ✅ Done, **one file at a time** | `evidentia/ingestion/upload.py` |
| Streamlit app: Analyze logs, Model evaluation, Dataset & EDA, About | ✅ Done | `app/` |
| Complete ML report (one file, raw metrics + raw data appendix) | ✅ Done | `reports/ML_REPORT.md` |
| 15 automated tests | ✅ Pass (last run 2026-11-09) | `tests/test_ml.py` |
| Train / validation / test score table (over-fitting check) | ⏳ Script written, **not run** (see §4) | `scripts/train_val_test_scores.py` |
| Cases with many files | ❌ Not built | — |
| Browser history, HTML, screenshots (OCR), incident-report parsing | ❌ Not built (no ML; parsing and rules only) | — |
| Entity extraction (domains, users, paths, processes, hashes) | ❌ Not built | — |
| Relationship engine + evidence graph | ❌ Not built | — |
| Cross-file timeline | ❌ Not built (the app has a per-file alert timeline) | — |
| RAG investigation chatbot | ❌ Not built | — |

---

## 3. How the system takes input and gives output today

**Input.** One file per analysis, on the **Analyze logs** page (http://localhost:8501).

- **Accepted types:** `.csv`, `.json`, `.jsonl`, `.ndjson`, `.log`, `.txt`. Or pick a file from the "…or load a SAMPLE file" drop-down.
- **Required fields:**
  - a timestamp;
  - either a message or a `message_type`.
- **Optional fields:** IPs, ports, protocol, action, severity.
- **Column names** are matched through aliases (e.g. `time`, `ts`, `@timestamp`).
- **Programmatic use:**

  ```python
  parsed = parse_upload(name, data)
  results = MLOrchestrator.load().analyze(parsed.events)
  ```

**Output, per event:**

- class and 3-class probabilities from LR and RF;
- whether the two models agree;
- the Isolation Forest anomaly flag (alert-routed rows only);
- applicability and the reason;
- provenance.

The page shows the file hash, 6 summary metrics, an alert timeline (UTC), filters, an event table, an event inspector and a CSV download.

**Not applicable.** Rows without a timestamp, or whose text is unlike the training logs (< 30% familiar word bigrams), get no prediction by design.

---

## 4. Known issues

| Issue | Effect | Status |
|---|---|---|
| **Windows Smart App Control blocks pandas** (`pandas\_libs\tslibs\ccalendar.cp314-win_amd64.pyd`). Code Integrity events 3033 / 3077. Worked on 2026-11-09, blocked on 2026-11-10. | Nothing that imports pandas runs on this laptop: app, training, tests, `train_val_test_scores.py`. Saved models, metrics and reports are unaffected. | **Open.** Needs a user decision: turn Smart App Control off, or run on another machine. No security setting was changed. |
| Training-score check not run | Over-fitting cannot be fully confirmed or ruled out. Validation and test are known (POOLED LR 0.4633 → 0.2502 PR-AUC). | Blocked by the issue above. After it is fixed, run `scripts/train_val_test_scores.py`, then `scripts/build_report_appendix.py`. |
| Weak feedback when input fields are missing | If no timestamp or message column is recognised, every row becomes "not applicable". The timeline disappears without a message, and the warnings do not name the missing column. | Open (UX). Planned fix: name the missing column, add manual column mapping, show "No alerts in this file". |
| `models/` is not in git | A fresh clone must download the dataset and retrain (~77 min) before the app works. | Open (decision). The models total ~5 MB. |

---

## 5. Measured results (held-out future windows)

| Task | Best result | Chance | Note |
|---|---|---|---|
| Stage 1: benign vs alert | ≈ 1.0 | — | The label is fixed by (product, event type). 0 of 607 pairs are mixed. Reported as log-type routing, not detection. |
| Stage 2 POOLED: suspicious vs malicious | PR-AUC 0.2571 (RF), 0.2502 (LR) | 0.0687 | Context features beat text (ROC-AUC 0.878 vs 0.416). |
| Stage 2 ORG-0005 | PR-AUC 0.3428 (LR); RF malicious F1 0.479, recall 0.762, 90% of incidents | 0.0197 | Best measured model |
| Stage 2 ORG-0004 / cross-org | At chance | — | Validation predicted this (CV PR-AUC 0.16) |
| 3-class macro-F1 | 0.7458 (hierarchical LR) | all-benign accuracy 0.940 | Accuracy (99%+) is not informative |
| Isolation Forest, alerts | PR-AUC 0.2594 | 0.0687 | Catches 987 malicious rows that the RF misses |

**Why precision is low (~0.26–0.36).** There are four reasons:

- Malicious rows are rare (6.9% pooled, 2% in ORG-0005).
- 62% of malicious rows share their exact text with other labels.
- Balanced class weights and an F1-optimal threshold favour recall.
- The test period drifts from the training period.

Full discussion: `reports/ML_REPORT.md` §9 and §11.

**Class imbalance.** Handled with class weighting, undersampling of benign rows (Stage 1), threshold tuning and imbalance-aware metrics. SMOTE was deliberately **not** used: interpolated TF-IDF rows and context counts are unrealistic, malicious rows are near-duplicate templates, and it would add leakage risk.

---

## 6. Next steps (in priority order)

1. **Resolve the pandas block,** then run the train / validation / test check and refresh the report appendix.
2. **Technical report** (10+ pages, PDF) for the CCA, built from `reports/ML_REPORT.md`, plus viva preparation.
3. **Input feedback fixes** (§4), and optionally use the ORG-0005 models for Cisco ASA logs.
4. **Possible ML improvements** (each needs retraining):
   - distinct-count and longer-window context features;
   - session- or incident-level scoring;
   - `HistGradientBoostingClassifier`;
   - per-template sample weights.

   **Do not** use `incident_signals` or graph incident links: they are derived from the labels (leakage).
5. **Bonus phases from the original vision:**
   - RAG chatbot over the ML results (the teacher's suggestion);
   - multi-file cases;
   - entity extraction;
   - relationship graph;
   - cross-file timeline.

---

## 7. Environment

- **Hardware:** Windows 11, i7-8550U (4 cores), 16 GB RAM, no GPU.
- **Python:** 3.14 in `.venv`. Versions are pinned in `requirements.txt` (pandas 3.1.1, numpy 2.5.4, scikit-learn 1.9.1, duckdb 2.0.0, streamlit 1.67.0).
- **Seed:** 42.
- **gstack:** installed globally; `CLAUDE.md` recommends it to teammates (team mode, optional).
