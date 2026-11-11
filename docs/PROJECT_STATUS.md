# Evidentia AI: Project Status

**Last updated:** 2026-11-10 (evening: new frontend, cases, relationship mapper, RAG assistant)
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
- a single-file report

The **investigation platform** from the original vision is now built:

- a React + FastAPI app that replaces Streamlit;
- multi-file cases with read-only, hashed originals;
- indicator extraction;
- a relationship mapper evaluated on WitFoo incidents;
- an evidence graph;
- a RAG assistant: hybrid retrieval with cited answers, written by Gemini when a key is set.

**Still not built:** OCR for screenshots, and a dedicated cross-file timeline view. The Overview has a case-wide activity chart instead.

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
| Evidence upload: SHA-256, provenance (file + row), CSV / JSON / ASA / VPC / text / HTML parsing, manual column mapping | ✅ Done | `evidentia/ingestion/upload.py` |
| Web app (React + FastAPI): Cases, Overview, Evidence, Records + event inspector, Connections graph, Ask, Model evaluation, Training data, How it works | ✅ Done (Streamlit removed) | `frontend/`, `evidentia/api/main.py` |
| Complete ML report (one file, raw metrics + raw data appendix) | ✅ Done | `reports/ML_REPORT.md` |
| 24 automated tests | ✅ Pass (last run 2026-11-10) | `tests/test_ml.py`, `tests/test_api.py` |
| Train / validation / test score table (over-fitting check) | ✅ Done: train 0.56 (LR) / 0.79 (RF) vs validation 0.29 vs test 0.25 PR-AUC, so the models over-fit the training incidents; drift is small | `scripts/train_val_test_scores.py`, `reports/ML_REPORT.md` §9.5 |
| Cases with many files (read-only originals, SQLite per case, background processing) | ✅ Done | `evidentia/cases/` |
| Browser-history CSV, HTML, text files (parsed, indexed, linked; no ML) | ✅ Done | `evidentia/ingestion/upload.py` |
| Screenshots (OCR) | ❌ Not built | — |
| Indicator extraction (IPs, domains, URLs, emails, users, hosts, hashes, paths) | ✅ Done | `evidentia/ingestion/entities.py` |
| Relationship mapper + evaluation on WitFoo incidents + evidence graph | ✅ Done | `evidentia/relations/`, `scripts/train_relations.py` |
| Case-wide activity chart (all files) | ✅ Done; no separate timeline page | Overview |
| RAG assistant (hybrid BM25 + embeddings, ML results, links, rule catalog; Gemini or built-in; citations checked) | ✅ Done | `evidentia/rag/` |

---

## 3. How the system takes input and gives output today

**Input.** Evidence files are added to a **case** on the Evidence page (http://localhost:8000). Several files can be added at once (drag and drop), or a bundled sample can be picked.

- **Accepted types:** `.csv`, `.json`, `.jsonl`, `.ndjson`, `.log`, `.txt`, `.html`, up to 50 MB each.
- **On arrival:**
  - the file is hashed (SHA-256) and stored read-only under `cases/<id>/original/`;
  - processing runs in the background;
  - the page polls the status: processing → linking → ready.
- **Security logs** (Cisco ASA, AWS VPC flow, or CSV/JSON with a timestamp and a log message) get ML triage.
- **Other files** (browser-history CSV, notes, HTML pages) are parsed, indexed and linked, and marked *not scored*.
- **Missing fields:** if no timestamp column is recognised, the file shows a warning naming the accepted column names. **Map columns** lets the investigator pick the columns by hand; the stored original is parsed again and never modified.

**Pipeline per file:** parse → records (file + row kept) → ML once (both classifiers, Isolation Forest) → indicators → embeddings → relationship links for the whole case.

**Questions** are asked on **Ask the case**:

- Retrieval gathers case facts, records matching the question's indicators / class words / time window, hybrid-search hits (BM25 + embeddings), the mapper's links and knowledge notes (model limits, WitFoo rules).
- Gemini, or the built-in fallback, writes the answer under five headings: **Answer, Evidence, ML assessment, Possible links, Unknown**.
- Every claim cites `[E<id>]`, `[K<id>]` or `[S]`. Citations not present in the retrieved material are removed and reported.
- Clicking a citation opens the record.

**Programmatic use:** `evidentia.cases.pipeline.process_file(...)`, `evidentia.rag.answer.answer(store, case_id, question)`. HTTP API: see `evidentia/api/main.py`.

---

## 4. Known issues

| Issue | Effect | Status |
|---|---|---|
| **Windows Smart App Control** blocked pandas (`ccalendar.cp314-win_amd64.pyd`, Code Integrity events 3033 / 3077) on the morning of 2026-11-10. | While blocked, nothing that imports pandas runs (app, training, tests). | **Not blocked since the afternoon of 2026-11-10;** the verdict is cloud-reputation based and may return. No security setting was changed. |
| Template overlap between train and test not measured | The stricter "unseen template" check is missing. | Open |
| ASA timestamps have no time zone | The bundled ASA log's device clock is about 5 h behind WitFoo's UTC ingest time for the same lines. | Warned on upload. A per-file time-zone setting would fix it. |
| `models/` is not in git | A fresh clone must download the dataset and retrain (~77 min) before the app works. | Open (decision). The models total ~5 MB. |
| Gemini answers not yet tested end to end | No API key was available during development. The built-in answers and the citation check are tested. | Set `GEMINI_API_KEY` in `.env` and ask a question to verify. |

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

1. **Try Gemini answers** with your API key (`.env`).
2. **Technical report** (10+ pages, PDF) for the CCA, built from `reports/ML_REPORT.md`, plus viva preparation.
3. Optionally use the ORG-0005 models for Cisco ASA logs, and add a per-file time-zone setting.
4. **Possible ML improvements** (each needs retraining):
   - distinct-count and longer-window context features;
   - session- or incident-level scoring;
   - `HistGradientBoostingClassifier`;
   - per-template sample weights.

   **Do not** use `incident_signals` or graph incident links: they are derived from the labels (leakage).
5. **Remaining from the original vision:**
   - OCR for screenshots;
   - a dedicated cross-file timeline page;
   - a RAG evaluation set (about 20 questions with known answers: retrieval hit@5, citation correctness, refusals).

---

## 7. Environment

- **Hardware:** Windows 11, i7-8550U (4 cores), 16 GB RAM, no GPU.
- **Python:** 3.14 in `.venv`. Versions are pinned in `requirements.txt` (pandas 3.1.1, numpy 2.5.4, scikit-learn 1.9.1, duckdb 2.0.0, fastapi 0.162.2, google-genai 3.0.0, fastembed 0.9.1).
- **Frontend:** Node 24, React 18.3, Vite 5.4, TypeScript 5.6, d3-force 3; fonts bundled locally (Albert Sans, DM Mono).
- **Design:** dealt with the tasteskill `design-taste-frontend` skill (palette stone-blueprint, type albert, radius sharp). Its landing-page structure rules target marketing pages, not an app workspace, so they were not applied.
- **Design gate (tasteskill `gate.mjs`), run on the live Cases page:**
  - Final line: `GATE: OPEN 21 (rounds used up)`.
  - **Fixed after its findings and re-measured in a browser:** body-text contrast (now 9:1), a visible field label, heading order, the sidebar focus ring, full-width card rows, a `<section>` in `<main>`, a one-row mobile nav on the page margin, and no sideways scroll at 1440 / 390 / 320 px on any page.
  - **Why many FAILs still show:** the gate's fingerprint does not see files under `frontend/`, so later runs reused stale results. Its list still names the old `div.page.enter`.
  - **Waived, with reasons in `.taste-skill/waivers.json`:** one-screen hero, scroll moment, equal side margins (sidebar app shell), skip link, React root.
  - **Still open, landing-page rules:** a one-screen hero (`screen-short`, `hero-fold`), "text-only section", and an h1 naming a product category.
- **Seed:** 42.
- **gstack:** installed globally; `CLAUDE.md` recommends it to teammates (team mode, optional).
