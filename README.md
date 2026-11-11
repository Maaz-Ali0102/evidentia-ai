# Evidentia AI

An evidence workspace for security-log triage, built for CT-264 (Programming for AI, CCA).

The system is trained on the WitFoo Precinct6 cybersecurity dataset.

- **Classification:** every security-log record is classified as **benign / suspicious / malicious** by Logistic Regression and Random Forest in two stages.
- **Anomaly score:** an Isolation Forest adds a separate anomaly score.
- **Relationship mapper:** links records across evidence files.
- **Assistant (RAG):** answers questions about a case, citing the records it used.

Everything runs **locally** on a CPU-only Windows laptop. The one exception is when a Gemini key is set (see Assistant below).

## Run it

```
.venv/Scripts/python -m pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..
.venv/Scripts/python -m uvicorn evidentia.api.main:app --port 8000
```

Then open http://localhost:8000 and click **Open the sample case**.

- **Frontend changes:** while working on the frontend, run `npm run dev` in `frontend/` (http://localhost:5173, with the API proxied to port 8000).
- **First run:** the embedding model is downloaded once, about 90 MB, into `data/models_cache/`.
- **Where data is kept:** cases are stored in `cases/` (git-ignored). Each original file is kept read-only with its SHA-256.

### Assistant (RAG) and Gemini

1. Copy `.env.example` to `.env`.
2. Set `GEMINI_API_KEY`. The model is set by `GEMINI_MODEL` (default `gemini-3.8-flash`).

**What gets sent to Google:** with a key set, only the records retrieved for a question are sent to Google's Gemini API, so it can write the answer. The Ask page states this.

**Without a key:** the answer is assembled locally from the same retrieved records, with the same sections and citations.

## What the app does

| Page | What it shows |
|---|---|
| **Cases** | Your investigations; open the bundled sample case in one click |
| **Overview** | Class counts, anomalies, model disagreements, activity over time, the indicators to look at first |
| **Evidence** | Upload (CSV, JSON/JSONL, LOG, TXT, HTML); SHA-256, re-verify, parser details, warnings, manual column mapping when a field is missing |
| **Records** | Filter by class, file, text, indicator, time, anomaly, disagreement; LR/RF switch; the event inspector (raw record, provenance, both models, anomaly, indicators, linked records with reasons) |
| **Connections** | Evidence graph of indicators and files; focus on one IP, domain, user or hash |
| **Ask the case** | Questions answered under Answer / Evidence / ML assessment / Possible links / Unknown, with clickable citations |
| **Model evaluation · Training data · How it works** | Measured results, EDA, pipeline, limits and privacy |

## Reproduce the ML results

```
.venv/Scripts/python scripts/audit_dataset.py        # expects data/raw/precinct6 (see below)
.venv/Scripts/python scripts/eda_figures.py
.venv/Scripts/python -m nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
.venv/Scripts/python scripts/train_models.py         # ~77 min on 4 cores / 16 GB
.venv/Scripts/python scripts/results_figures.py
.venv/Scripts/python scripts/stage1_within_product.py
.venv/Scripts/python scripts/train_relations.py      # relationship mapper weights + evaluation (~2 min)
.venv/Scripts/python scripts/make_samples.py
.venv/Scripts/python -m pytest -q tests              # 24 tests
```

**Dataset download (~170 MB of parquet files):**

```
python -c "from huggingface_hub import snapshot_download; snapshot_download('witfoo/precinct6-cybersecurity', repo_type='dataset', local_dir='data/raw/precinct6', allow_patterns=['README.md','build/*.json','signals/*','graph/*.parquet','graph/metadata.json','reference/*'])"
```

## Where things are

| Path | What |
|---|---|
| `docs/PROJECT_STATUS.md` | **Current status:** what is built, original vision vs now, known issues, next steps |
| `reports/ML_REPORT.md` | **Complete ML report in one file** (all sections + raw metrics, raw data rows, training log) |
| `reports/DATASET_AUDIT.md`, `reports/eda_summary.md`, `reports/ML_RESULTS.md` | Audit, EDA summary, Phase 2 results |
| `docs/ARCHITECTURE.md` | Architecture and roadmap |
| `evidentia/ml/` | Features, past-only context, splits, models, evaluation, ML orchestrator |
| `evidentia/ingestion/` | File parsing with SHA-256 and provenance (`upload.py`), indicator extraction (`entities.py`) |
| `evidentia/cases/` | Case store (`cases/<id>/`: read-only originals + SQLite) and the upload pipeline |
| `evidentia/relations/` | Relationship mapper (time, shared indicators, content) |
| `evidentia/rag/` | Embeddings, hybrid retrieval, Gemini / built-in answers with citations |
| `evidentia/api/main.py` | FastAPI backend; serves the built frontend |
| `frontend/` | React + TypeScript interface (Vite) |
| `models/` | Trained pipelines, `relations.joblib`, `registry.json` |
| `tests/` | 24 tests (leakage guards, splits, context, persistence, orchestrator, case workflow, assistant grounding, mapper) |

## Headline results (held-out future windows)

- **Stage 2, suspicious vs malicious:**
  - ORG-0005: ROC-AUC ≈ 0.955, PR-AUC 0.32–0.34 (chance 0.02).
  - Pooled model: PR-AUC 0.25–0.26 (chance 0.07).
  - ORG-0004 and cross-organisation tests: at chance.
- **3-class macro-F1:** 0.746 (hierarchical Logistic Regression).
- **Stage 1 (benign vs alert):** ≈ 1.0, which reflects log-type recognition, not threat detection.
- **Relationship mapper (WitFoo incidents, test window):** closeness in time ranks same-incident records best.
  - MRR is 0.577 on ORG-0005 and 0.997 on ORG-0004.
  - Shared indicators and content did not improve the ranking.
  - In a case, a link still needs a shared indicator or similar content.
- **Labels:** these are WitFoo's automated triage, not analyst-verified ground truth.

See `reports/ML_REPORT.md` for the full picture.
