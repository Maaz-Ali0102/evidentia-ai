# Evidentia AI

Security-log triage with leakage-aware machine learning, built for CT-264 (Programming for AI, CCA).

The system is trained on the WitFoo Precinct6 cybersecurity dataset. It classifies security-log events as **benign / suspicious / malicious**, using Logistic Regression and Random Forest in two stages, and adds an Isolation Forest anomaly score. Everything runs **locally** on a CPU-only Windows laptop.

## Run the app (local only)

```
.venv/Scripts/python -m streamlit run app/streamlit_app.py
```

Then open http://localhost:8501.

- Files are processed in memory, and no external service is called.
- Try the files in `data/samples/`. They are clearly labelled samples, kept apart from real evidence.

## Reproduce everything

```
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt
.venv/Scripts/python scripts/audit_dataset.py        # downloads nothing; expects data/raw/precinct6 (see below)
.venv/Scripts/python scripts/eda_figures.py
.venv/Scripts/python -m nbconvert --to notebook --execute --inplace notebooks/01_eda.ipynb
.venv/Scripts/python scripts/train_models.py         # ~77 min on 4 cores / 16 GB
.venv/Scripts/python scripts/results_figures.py
.venv/Scripts/python scripts/make_samples.py
.venv/Scripts/python -m pytest -q tests
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
| `reports/DATASET_AUDIT.md` | Phase 1 audit: schema, leakage, splits |
| `notebooks/01_eda.ipynb`, `reports/eda_summary.md` | Train-only EDA (9 charts) |
| `reports/ML_RESULTS.md` | Phase 2 results: every metric, limitation and design choice |
| `docs/ARCHITECTURE.md` | Architecture and roadmap |
| `evidentia/ml/` | Features, past-only context, data splits, models, evaluation, orchestrator |
| `evidentia/ingestion/upload.py` | CSV / JSON / log parsing with SHA-256 and provenance |
| `app/` | Streamlit app |
| `models/` | Trained pipelines + `registry.json` |
| `tests/` | 15 tests (leakage guards, split integrity, context correctness, persistence, orchestrator) |

## Headline results (held-out future windows)

- **Stage 2, suspicious vs malicious:**
  - ORG-0005: ROC-AUC ≈ 0.955, PR-AUC 0.32–0.34 (chance 0.02).
  - Pooled model: PR-AUC 0.25–0.26 (chance 0.07).
  - ORG-0004 and cross-organisation tests: at chance.
- **3-class macro-F1:** 0.746 (hierarchical Logistic Regression).
- **Stage 1 (benign vs alert):** ≈ 1.0, which reflects log-type recognition, not threat detection.
- **Labels:** these are WitFoo's automated triage, not analyst-verified ground truth.

See `reports/ML_REPORT.md` for the full picture.

## Known issue

On the development laptop, Windows Smart App Control currently blocks a pandas DLL (`ccalendar`). Until that is resolved, the app, training and tests cannot run there; saved models and reports are unaffected. Details are in `docs/PROJECT_STATUS.md` §4.
