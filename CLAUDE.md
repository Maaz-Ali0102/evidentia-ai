# Evidentia AI: project instructions

## 1. Project
Evidentia AI, CT-264 Programming for AI (CCA), NED University. Security-log triage on the WitFoo Precinct6 dataset (`signals`, ~2M records).
- **Graded core:** the ML work (audit, EDA, preprocessing, models, evaluation).
- **Bonus layer:** the web app, the relationship mapper and the RAG chat.

## 2. Hard rules
- **Models and metrics.** Never modify `models/` or `reports/metrics/`, and never retrain, without the user's approval.
- **Test window.** It is scored once. Every choice (features, hyper-parameters, thresholds, weights) is made by StratifiedGroupKFold on the training window only.
- **Numbers.** Report only numbers from executed code. Mark anything unverified as "inferred" or "not measured".
- **Keep three outputs separate:** class prediction, anomaly score, and relationship inference. Never merge them.
- **FEATURE FREEZE.** No new features. No more design-gate or UI polish.

## 3. Locked design (do not change)
- **Stages:**
  - Stage 1 (benign vs alert) is a deterministic router; its label is fixed by product + event type.
  - Stage 2 (suspicious vs malicious) is the real task.
- **Models:** Logistic Regression + Random Forest, plus an Isolation Forest (label-free, alert records only).
- **Banned columns:** the 14 leakage columns (`BANNED_POST_LABEL` in `evidentia/ml/config.py`). `incident_signals` is excluded.
- **Splits:** temporal and per organisation, with incident-crossing rows dropped from training:
  - ORG-0004 cut-off: 2024-07-29 20:00 UTC.
  - ORG-0005 cut-off: 2024-07-27 00:00 UTC.
- **App:** FastAPI backend (`evidentia/api/`) + React frontend (`frontend/`).
- **Case store:** SQLite per case under `cases/<id>/`. Every upload gets SHA-256 and a read-only original.
- **Links:** never created from time alone. A link needs a shared indicator or content similarity ≥ 0.6.
- **Gemini:** used only when `GEMINI_API_KEY` is set (in `.env`), and the UI shows a privacy note. Without a key, the built-in answerer is used.

## 4. Where the numbers live
`reports/ML_RESULTS.md` and `reports/ML_REPORT.md`. The appendix of `ML_REPORT.md` is generated from `reports/metrics/*.json`.

Caveats to keep in every write-up:
- **Labels** are WitFoo's automated triage. No live malicious record is analyst-confirmed.
- **Sample:** the 2M-record capture is a downsample, not complete traffic.
- **Overfitting is real.** Pooled PR-AUC: RF train 0.789 vs validation 0.288 (test 0.257); LR train 0.560 vs validation 0.294.
- **Relationship mapper:** ground truth is WitFoo same-incident membership. Time is the strongest signal. Shared indicators and content did not improve the ranking (circularity caveat applies).

## 5. Commands
```bash
.venv/Scripts/python -m uvicorn evidentia.api.main:app --port 8000   # app at http://localhost:8000
.venv/Scripts/python -m pytest -q tests                              # 24 tests pass
.venv/Scripts/python scripts/build_report_appendix.py                # refresh ML_REPORT appendix from metrics
cd frontend && npm run build                                         # rebuild the UI served by FastAPI
```

## 6. Pending
- **Evaluation gaps:**
  - per-org scores;
  - a random baseline;
  - train/test template overlap;
  - bootstrap confidence intervals;
  - the Isolation Forest flag rate.
- **Mapper:** baselines, and the precision of gated links.
- **Gemini:** answers are untested end to end (no key yet).
- **`reports/ML_REPORT.md`:** pending fixes.
- **Teacher:** reply pending on "two datasets vs one large dataset".

## 7. Browsing and gstack
Use the gstack `/browse` skill for all web browsing. Never use `mcp__claude-in-chrome__*` tools.

Teammates install gstack once (team mode, optional):
```bash
git clone --depth 1 https://github.com/garrytan/gstack.git ~/.claude/skills/gstack
cd ~/.claude/skills/gstack && ./setup --team
```
Use `~/.claude/skills/gstack/...` for gstack file paths.
