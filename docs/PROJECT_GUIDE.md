# Evidentia: the complete project guide

A plain-language explanation of the whole project for a team member: what it does, how every part works,
what every chart and number means, and where the code is. Read it top to bottom once; afterwards use the
table of contents to jump.

> Numbers in this guide come from the project's own result files (`reports/metrics/*.json`) and from tests
> run on 12–13 November 2026. If you retrain anything, the numbers can change.

## Contents

1. [What Evidentia is, in one minute](#1-what-evidentia-is-in-one-minute)
2. [The big picture: offline training vs the app](#2-the-big-picture-offline-training-vs-the-app)
3. [The dataset](#3-the-dataset)
4. [EDA: what we learned before training](#4-eda-what-we-learned-before-training)
5. [Leakage and how we prevented it](#5-leakage-and-how-we-prevented-it)
6. [Features: turning a log line into numbers](#6-features-turning-a-log-line-into-numbers)
7. [The models](#7-the-models)
8. [How the models were trained and tested](#8-how-the-models-were-trained-and-tested)
9. [Results, chart by chart](#9-results-chart-by-chart)
10. [The five-model comparison](#10-the-five-model-comparison)
11. [The app, page by page](#11-the-app-page-by-page)
12. [What happens when a file is uploaded](#12-what-happens-when-a-file-is-uploaded)
13. [The chatbot (RAG) and Gemini](#13-the-chatbot-rag-and-gemini)
14. [Working on unseen data](#14-working-on-unseen-data)
15. [Detection rules and the incident story](#15-detection-rules-and-the-incident-story)
16. [Demo cases and which data is real](#16-demo-cases-and-which-data-is-real)
17. [Limitations (say these yourself)](#17-limitations-say-these-yourself)
18. [Likely viva questions](#18-likely-viva-questions)
19. [Code map](#19-code-map)
20. [How to run it](#20-how-to-run-it)
21. [Glossary](#21-glossary)

---

## 1. What Evidentia is, in one minute

Evidentia is a digital-forensics workspace. An investigator uploads evidence files (firewall logs, server
logs, CSV exports, notes). Evidentia then:

1. **Parses** every file into records, keeping the file name and row number of each (provenance).
2. **Hashes** every original file (SHA-256) and keeps it read-only, so you can prove it was not changed.
3. **Classifies** each security record as benign, suspicious or malicious with two ML models
   (Logistic Regression and Random Forest), and flags unusual records with an anomaly detector.
4. **Runs detection rules** that recognise common attack patterns (password guessing, account takeover,
   privilege use, tool downloads, scans) in **any** log, with thresholds learned from each case, plus 22
   community **Sigma** rules from SigmaHQ.
5. **Links related records** (shared IP, user, URL, close in time, similar text): the relationship mapper.
6. **Answers questions** ("What did 203.0.113.45 do?") using only the case's records, with a citation
   for every claim, an assessment of what likely happened, and recommended next steps.

---

## 2. The big picture: offline training vs the app

There are two separate halves. Keep them apart: the teacher may ask about either.

| | Offline (done once) | Online (every time the app is used) |
|---|---|---|
| What | Study the data (EDA), build features, train and evaluate the models | Upload evidence, parse, apply the saved models, run rules, link, answer questions |
| Code | `scripts/`, `notebooks/`, `evidentia/ml/` | `evidentia/api/`, `cases/`, `ingestion/`, `detect/`, `relations/`, `rag/`, `frontend/src/` |
| Output | `models/*.joblib`, `reports/metrics/*.json`, `reports/figures/*.png` | Case database, answers |

**The app never retrains.** It loads the saved models from `models/` and applies them.

```
OFFLINE   WitFoo dataset -> EDA -> features -> train + cross-validation -> saved models (models/)
                                                                                |
ONLINE    upload file -> parse -> run ML (loads models/) -> extract indicators -> detection rules
                                                       -> link records -> answer questions (RAG + Gemini)
```

| Part | Language / library | Folder |
|---|---|---|
| Website (what you click) | TypeScript, React, Vite | `frontend/src/` |
| Server | Python, FastAPI | `evidentia/api/main.py` |
| ML | Python, scikit-learn | `evidentia/ml/` |
| Training, EDA | Python, Jupyter | `scripts/`, `notebooks/01_eda.ipynb` |
| Detection rules | Python | `evidentia/detect/rules.py` |
| Relationship mapper | Python | `evidentia/relations/mapper.py` |
| Chatbot | Python + Google Gemini | `evidentia/rag/` |

---

## 3. The dataset

**WitFoo Precinct6**, public on Hugging Face (`witfoo/precinct6-cybersecurity`). Real security logs from
5 organisations (ORG-0001 … ORG-0005), anonymised.

- **2,011,674 records** in total. Each record is one log line (e.g. a Cisco ASA firewall "Deny") with a
  label: **benign**, **suspicious** or **malicious**.
- Labels come from WitFoo's automated correlation engine, **not** from human analysts.
- File used: `data/raw/precinct6/signals/signals.parquet` (git-ignored; download command in the README).

| Class | Records | Share |
|---|---|---|
| benign | 1,897,153 | 94.31% |
| suspicious | 106,793 | 5.31% |
| malicious | 7,728 | **0.38%** |

This is **severe class imbalance**: a model that says "benign" for everything is ~94% accurate and useless.

Only **ORG-0004** (AWS VPC flow logs) and **ORG-0005** (Cisco ASA firewall) have enough malicious records
(≥ 500) to train on, so the ML for suspicious vs malicious uses those two.

---

## 4. EDA: what we learned before training

**EDA (Exploratory Data Analysis)** = looking at the data before training anything, to find out what is in
it and what could go wrong. Every modelling decision is justified by an EDA finding.

- Notebook: `notebooks/01_eda.ipynb` (sections 1–10, one per chart). Summary: `reports/eda_summary.md`.
  Charts: `reports/figures/eda01_*.png … eda09_*.png`. The app's **Training data** page shows them.
- **Rule:** EDA uses only the **training portion** (1,045,818 rows, before each organisation's cut-off).
  Looking at test data would influence decisions with data we test on.

| Chart | What it shows | Decision it led to |
|---|---|---|
| `eda01_class_distribution` | benign 94.62%, suspicious 5.03%, malicious 0.36% (training part) | Class weighting; judge by PR-AUC, not accuracy |
| `eda02_org_class_mix` | Which organisation has which labels | Only ORG-0004 and ORG-0005 can train Stage 2 |
| `eda03_hourly_daily` | When events happen | Malicious events are bursty (54% in one hour, 11:00 UTC), so split by **time**, never randomly |
| `eda04_message_types` | Log types | 99.77% of alerts come from 2 of 470 log types, so benign vs alert ≈ recognising the log type |
| `eda05_missing_values` | Empty columns per class | Missingness depends on the class (e.g. `dst_port` filled for 97.8% of suspicious, 1.5% of benign) |
| `eda06_message_length` | Message length per class | A first look at the text before choosing text features |
| `eda07_split_coverage` | Days covered per organisation + cut-off | Uneven coverage (0.8 to 5.8 days); the only chart allowed to show test rows (it shows *where* the cut-off is, not what is in the test data) |
| `eda08_duplicates` | Repeated messages | 59% of malicious rows repeat an exact text; 41% share text with another label, so text alone can't separate suspicious from malicious; context is needed |
| `eda09_leakage_evidence` | How well ONE column alone predicts the label | Some columns predict it almost perfectly because the labelling process created them: removed (section 5) |

**The five decisions EDA led to:** (1) class weighting + PR-AUC; (2) drop 14 post-label columns; (3) leave
source fields such as `product_name` out of the main models and admit benign vs alert is log-type
recognition; (4) split by time per organisation; (5) a two-stage model with context features.

---

## 5. Leakage and how we prevented it

**Leakage** = the model sees information it would not have in real life, usually something derived from the
answer. Example: `attack_tactics` is filled in only after an event is judged an attack. A model using it
scores ~100% in testing and is useless in reality.

What the project does:

1. **Drops 14 post-label columns** (`BANNED_POST_LABEL` in `evidentia/ml/config.py`), e.g.
   `attack_tactics`, `attack_techniques`, `lifecycle_stage`, `mo_name`, `suspicion_score`, `incident_ids`.
2. **Splits by time, per organisation** (`CUTOFFS` in `config.py`): ORG-0005 trains before
   2024-07-27 00:00 UTC and tests after; ORG-0004 trains before 2024-07-29 20:00 UTC. A random split would
   put near-copies of the same burst on both sides.
3. **Drops incidents that cross the cut-off** from training (137 rows).
4. **Context features count only earlier events**, never later ones (`evidentia/ml/context.py`).
5. **Chooses settings by cross-validation on training data only**; the test data is scored **once**.

---

## 6. Features: turning a log line into numbers

Models can't read text, so each record becomes a row of numbers (`evidentia/ml/features.py`, `context.py`).

- **Text (TF-IDF):** the message with digits masked (so `10.0.0.5` and `10.0.0.9` look alike), split into
  words and word pairs; the 20,000 most frequent (seen in ≥ 3 records) become columns. TF-IDF weighs rare,
  telling words more than common ones.
- **Categorical (one-hot):** `message_type`, `action`, `protocol`, `severity`, `dst_port`… become yes/no columns.
- **Context (23 features):** how many events the same source IP, destination IP, port or IP pair had in
  the last 1 min, 10 min, 1 h and 6 h, plus time since that IP's previous event. **Past only.**

Feature sets compared: `text`, `context`, `full` (= context + text). Context alone is the strongest on the
pooled data (PR-AUC 0.246 vs 0.134 for text alone), so **the difference between suspicious and malicious
is mostly in the behaviour around a record, not in the record's text**.

---

## 7. The models

| Model | Role | Why |
|---|---|---|
| **Logistic Regression (LR)** | Classifier (main class shown in the app) | Simple, fast, explainable: each feature has a weight |
| **Random Forest (RF)** | Classifier (second opinion) | Many decision trees voting; captures non-linear patterns |
| **Isolation Forest (IF)** | Anomaly detector (no labels) | Flags unusual context patterns among alerts; shown separately, never merged |

### The two stages

- **Stage 1: benign vs alert.** Scores perfectly, but only because in this dataset the log type decides the
  label: of 607 (product, event type) pairs, **0** contain both benign and alert records, and a lookup
  table with no ML gets macro-F1 1.0. So Stage 1 is a **router**, not threat detection.
- **Stage 2: suspicious vs malicious (among alerts).** The real ML task.

**Final class:** benign if Stage 1 says so; otherwise malicious if Stage 2's probability ≥ its threshold,
else suspicious. Code: `analyze` in `evidentia/ml/orchestrator.py`.

**Applicability gate:** if a record doesn't resemble the training data (needs a timestamp, and ≥ 30% of
its word pairs known from training), it is marked **"not applicable"** instead of getting a confident but
meaningless label.

**Why both LR and RF?** Neither wins everywhere (section 9), they are built differently so disagreement is
a useful "look closer" signal, and LR is explainable. The app shows both and flags "models disagree".

---

## 8. How the models were trained and tested

1. **Train** each model on the training period (labels visible).
2. **Tune** settings (e.g. RF depth, LR's C, the feature set) and the **decision threshold** with
   `StratifiedGroupKFold(3)` on the training data. "Group" = records of the same incident stay in the same
   fold, so a model is never tested on part of an incident it trained on.
3. **Predict** on the test period (later dates the model never saw, labels hidden).
4. **Compare** predictions with the true labels → confusion matrices, PR-AUC, recall, precision.
5. **Save** results to `reports/metrics/*.json` and charts to `reports/figures/`. Pages only display them.

**So every number on the Model evaluation page is a test result:** predictions on unseen future records,
checked against the true labels. Code: `scripts/train_models.py`.

### Why we report test, not training, scores (overfitting)

`reports/metrics/train_val_test.json`, Stage 2 pooled, PR-AUC:

| | LR | RF |
|---|---|---|
| Train (data it learned from) | 0.560 | **0.789** |
| Validation (cross-validation) | 0.294 | 0.288 |
| **Test (unseen future)** | **0.250** | **0.257** |

RF scores 0.79 on data it has seen and 0.26 on new data: it memorised (overfitting). Test is the honest number.

---

## 9. Results, chart by chart

### How to read a confusion matrix

Rows = the **true** label; columns = what the model **predicted**. Each box counts test records.
**Diagonal = correct; everything else = mistakes.** Colour = share of the row.

### Metrics in one line each

- **PR-AUC:** sort all records from most to least likely malicious; PR-AUC measures how many real malicious
  records sit near the top. 1.0 = perfect; random guessing = the share of malicious records ("chance").
- **ROC-AUC:** probability that a random malicious record is ranked above a random suspicious one (0.5 = random).
- **Recall (malicious):** of the truly malicious records, how many were caught.
- **Precision (malicious):** of the records called malicious, how many really were.
- **Macro-F1:** average F1 over classes, so the rare class counts equally.
- **Accuracy:** share of all records correct. **Misleading here** because of the imbalance.

### Stage 2: suspicious vs malicious (the main result)

`reports/metrics/stage2.json`, test data, each model's tuned threshold:

| Trained & tested on | Model | PR-AUC | Chance | ROC-AUC | Mal. precision | Mal. recall | Incidents found |
|---|---|---|---|---|---|---|---|
| ORG-0005 (Cisco ASA) | LR | **0.343** | 0.020 | 0.955 | 0.36 | 42% | 301 / 578 |
| ORG-0005 | RF | 0.318 | 0.020 | 0.960 | 0.35 | **76%** | **520 / 578** |
| Both orgs (**deployed in the app**) | LR | 0.250 | 0.069 | 0.880 | 0.26 | 37% | 514 / 622 |
| Both orgs (deployed) | RF | 0.257 | 0.069 | 0.846 | 0.34 | 18% | 545 / 622 |
| ORG-0004 (AWS VPC) | LR | 0.223 | 0.233 | 0.465 | 0 | 0% | 0 / 44 |
| ORG-0004 | RF | 0.275 | 0.233 | 0.556 | 0 | 0% | 0 / 44 |

How to read it:
- **ORG-0005: the models clearly learn.** PR-AUC is ~17× chance, ROC-AUC ~0.96. RF catches 76% of malicious
  records and touches 90% of incidents.
- **ORG-0004: no learnable signal.** Every model is at chance. This comes from the data, not the model.
- **The app uses the pooled models** (both organisations). Mixing in ORG-0004 lowers them to ~0.25.
- **Precision ~0.35** means about 2 of 3 "malicious" flags are wrong: flags need an analyst.

Chart `R1_stage2_prauc_logreg.png`: PR-AUC per feature set and split. Behaviour (context) features beat text
when organisations are mixed.

### The 3-class confusion matrix (the one the teacher asked about)

`R2_three_class_confusion.png`, pooled test data (965,856 records: 907,619 benign, 54,229 suspicious,
4,008 malicious). Four panels = four ways of building a 3-class model:

| Strategy | Model | Macro-F1 | Malicious caught | Accuracy |
|---|---|---|---|---|
| hierarchical (Stage 1 → Stage 2, used by the app) | LR | **0.746** | **37%** | 99.3% |
| hierarchical | RF | 0.731 | 18% | 99.5% |
| flat (one model, 3 classes) | LR | 0.725 | 23% | 99.4% |
| flat | RF | 0.732 | 20% | 99.5% |

**Why is the benign row all zeros?** Because benign vs alert is decided by the log type (Stage 1 = lookup).
The zeros are a property of the dataset, not proof of a smart model. The real result is the bottom-right
2×2 (suspicious vs malicious). Predicting "benign" for everything would already score 94% accuracy here.

**Why does RF catch 76% on ORG-0005 but 18% here?** This matrix is **pooled**: about 3,100 of the 4,008
malicious test records come from ORG-0004, where no model finds a signal. Same models, different test data.

### Stage 1 ablation

`R3_stage1_ablation.png` and `reports/metrics/stage1_within_product.json`: shows benign vs alert is
log-type recognition: a lookup on (product, event type) is already perfect.

### Anomaly detector (Isolation Forest)

`reports/metrics/iforest.json`. Trained on alert records **without labels**.

| Experiment | PR-AUC | Chance | ROC-AUC |
|---|---|---|---|
| Malicious vs suspicious, among alerts | 0.259 | 0.069 | 0.879 |

It flags **987 malicious records that RF misses**, and **no** malicious record is flagged by both, so it
adds a different signal. Its score means "unusual", not "malicious".

### Relationship mapper

`reports/metrics/relations.json`. Ground truth for tuning: two alert events in the same WitFoo incident
(labels used only to evaluate, never as input). Three signals scored per pair: **time closeness**,
**shared indicators** (IDF-weighted, rare ones count more), **text similarity** (sentence embeddings).
On WitFoo training pairs, time alone ranked best (MRR 0.70 vs 0.36 for indicators and 0.37 for text, on
ORG-0005), so the learned mix is time-only. Because a case mixes file types, a link **also** needs a shared
indicator or similar text: **time alone never links two records**.

---

## 10. The five-model comparison

**Why:** to check that our choice of LR and RF is not limited by the algorithm. Script:
`scripts/compare_models.py`; numbers `reports/metrics/model_comparison.json`; write-up
`reports/comparison/COMPARISON.md`; charts `reports/figures/C1…C5`; shown on the **Model evaluation** page.

**Rules (identical for all five):** same Stage 2 records, splits, features and leakage rules; settings and
threshold chosen by grouped CV on training data; test scored once; rare class weighted. All five models
**were trained**; only LR and RF are in the app, because the others were not better.

Test PR-AUC (malicious):

| Model | Pooled | ORG-0005 | ORG-0004 |
|---|---|---|---|
| Logistic Regression | 0.250 | **0.343** | 0.223 |
| Random Forest | **0.257** | 0.318 | 0.275 |
| HistGradientBoosting* | 0.216 | 0.320 | 0.215 |
| XGBoost | 0.234 | 0.322 | 0.265 |
| LightGBM | 0.221 | 0.325 | **0.284** |
| *Random guessing* | *0.069* | *0.020* | *0.233* |

\*HistGradientBoosting used context features only (it can't take the sparse text features).

ORG-0005 confusion matrices (882 malicious among 44,777 test alerts):

| Model | Caught | Missed | False alarms | Accuracy |
|---|---|---|---|---|
| Random Forest | **672 (76%)** | 210 | 1,250 | 96.7% |
| Logistic Regression | 368 (42%) | 514 | 657 | 97.4% |
| XGBoost | 247 (28%) | 635 | 441 | 97.6% |
| HistGradientBoosting | **0** | 882 | 0 | **98.0%** |
| LightGBM | **0** | 882 | 0 | **98.0%** |

**Findings:**
1. **Boosting does not beat LR/RF.** All five land at 0.32–0.34 on ORG-0005, so the limit is the data and
   features, not the algorithm. Improvement must come from better features.
2. **The highest-accuracy models caught zero attacks.** Their threshold (chosen on training data) didn't
   transfer to the test period, so they called everything "suspicious". The best proof that accuracy is useless here.
3. **PR-AUC vs confusion matrix:** PR-AUC judges the *ranking* (no cut-off) and is similar for all; the
   confusion matrix shows one *chosen cut-off*, where models differ a lot.

Charts: `C1_class_imbalance` (class counts, log scale), `C2_prauc_bars` (PR-AUC per model + chance line),
`C3_confusion_*` (2×2 matrices per model), `C4_pr_curves` (precision-recall curves), `C5_metrics_*`
(all metrics side by side, accuracy included).

---

## 11. The app, page by page

Each page is a React file in `frontend/src/pages/`, getting data from `/api/...` in `evidentia/api/main.py`.

| Page | What you see | What happens behind it | Code |
|---|---|---|---|
| **Cases** | List of investigations, "New case", "Open the sample case" | Creates a case; the sample uploads 3 files from `data/samples/` | `Cases.tsx`; `/api/cases` |
| **Overview** | Counters (malicious, suspicious, benign, not scored, anomalies, disagreements, links), **Detections**, activity over time, indicators to look at first | Counts stored ML results; runs detection rules | `Overview.tsx`; `/timeline`, `/entities`, `/findings` |
| **Evidence** | Files, status, SHA-256, warnings, "Hash matches" check | Originals stored read-only; verify recomputes the hash | `Evidence.tsx`; `/files`, `/verify` |
| **Records** | Every record with filters, LR or RF class, detail panel | Detail shows raw line, file:row, both models, anomaly, linked records | `Events.tsx`, `EventInspector.tsx` |
| **Connections** | Graph of records and indicators | Draws mapper links | `Graph.tsx`, `GraphView.tsx` |
| **Ask the case** | Chatbot with cited answers | RAG + detection findings + Gemini (section 13) | `Ask.tsx`; `/ask` |
| **Model evaluation** | All results of sections 9–10 | Displays saved results only | `Model.tsx`; `/api/metrics/*` |
| **Training data** | EDA charts and findings | Displays `reports/eda_summary.md` | `Dataset.tsx` |
| **How it works** | Meaning of outputs, limits, privacy | Static text | `About.tsx` |

**Model evaluation vs Records:** Model evaluation = how good the models were on WitFoo test data (with
true labels). Records = the models' live predictions on *your* uploaded case (no true labels there).

---

## 12. What happens when a file is uploaded

One function runs the chain: `process_file` in `evidentia/cases/pipeline.py`.

1. **Store the original** byte for byte, read-only, record its SHA-256 (`evidentia/cases/store.py`).
2. **Parse into records** (`parse_upload` in `evidentia/ingestion/upload.py`): CSV, JSON, log/text, HTML.
   Special parsers for Cisco ASA and AWS VPC flow lines. Other lines get their time from ISO 8601,
   Apache/nginx, `YYYY/MM/DD` or classic syslog stamps; syslog has no year, so the current year is assumed
   (the previous one if that would be in the future) and a warning says so.
3. **Run the ML** (`orch.analyze`): features → applicability gate → Stage 1 + Stage 2 for LR and RF →
   Isolation Forest (alerts only) → notes like "models disagree".
4. **Extract indicators** (`extract` in `evidentia/ingestion/entities.py`): IPs, domains, URLs, emails,
   hashes, paths, users (including SSH/sudo/PAM users), hosts.
5. **Save** to the case database (tables `events`, `ml`, `entities`).
6. **Link records** (`rebuild_links` → `build_edges` in `evidentia/relations/mapper.py`); save `edges`.
7. **Done:** status "ready" (or "error" with the message; the rest of the case still works).

ML runs once, at upload. Questions later only read stored results.

---

## 13. The chatbot (RAG) and Gemini

**RAG = Retrieval-Augmented Generation:** first *retrieve* the relevant records, then let a language model
*generate* an answer from only those records.

1. `Ask.tsx` sends the question to `/api/cases/{cid}/ask`.
2. `retrieve` (`evidentia/rag/retrieve.py`) collects:
   - **case facts** [S]: counts, time span, rule findings;
   - **focused records**: those matching IPs/users/classes/times named in the question, most severe first,
     **at most 2 per message template** (section 14) with a count;
   - **detection findings** [F]: about the question's indicators (with their whole chain), else the most severe;
   - **search hits**: BM25 keyword search + sentence-embedding search, fused;
   - **links**: mapper edges + **rare-indicator pivot** (records sharing a rare user/IP with a top hit);
   - **knowledge notes** [K]: the models' measured limits.
3. `answer` (`evidentia/rag/answer.py`) sends the material to **Gemini** with strict instructions
   (the `SYSTEM` text): use only this material, cite every sentence, and write these sections:

   | Section | Content |
   |---|---|
   | Answer | Direct answer |
   | Evidence | What records literally say [E..] |
   | ML assessment | What the models predict, as predictions, with limits [K..] |
   | **Assessment** | What most likely happened, in time order, marked as inference [F..][E..] |
   | Possible links | Mapper / pivot links and why |
   | **Recommended actions** | 2–5 concrete next steps for the analyst [F..] |
   | Unknown | What the material can't settle |

4. **Citation check:** any [E..]/[F..]/[K..] that wasn't retrieved is removed and reported. Click a
   citation in the app to open the record or finding.

**Gemini setup** (`evidentia/rag/llm.py`): key in `.env` (`GEMINI_API_KEY`, git-ignored, never commit it).
Free-tier models are often overloaded (503) or slow, so the app tries, within `GEMINI_TIMEOUT_S`
(default 60, 120 recommended): the main model via two API methods, then backups (`GEMINI_FALLBACK_MODELS`,
default `gemini-3.1-flash-lite,gemini-3.5-flash`). On the free tier `gemini-3.5-flash-lite` is the most
reliable main model. If all fail, a **built-in answer** with the same sections is assembled without an
LLM, so the app never depends on Gemini being available.

**Privacy:** free-tier Gemini may use the text sent to it to improve Google products. Fine for public and
synthetic data; never send real company logs through the free tier.

---

## 14. Working on unseen data

Two meanings of "unseen":

| | Unseen **records** of a known type | Unseen **log type** |
|---|---|---|
| Example | Later WitFoo firewall logs (the test period, the sample case) | Linux SSH logs |
| ML | Works; this is what all test scores measure | Says "not applicable" (honest, but detects nothing) |
| What handles it | The models | Parsing + rules + retrieval + Gemini (below) |

The teacher's point "it won't work on unseen data" was about the second meaning. What we added:

1. **Timestamps** in common formats (section 12), so timelines and links work on new log types.
2. **Users** extracted from SSH, sudo and PAM lines.
3. **Message templates:** numbers, times, ports and process ids are masked (IP addresses kept), so
   `Failed password … port 50000` and `… port 50001` are one template. Retrieval takes at most 2 records per
   template and reports "one of 40 similar records, 02:14:00 to 02:15:57", so rare, telling lines (the
   successful login, the sudo command) get a slot instead of 40 copies of a failure.
4. **Rare-indicator pivot:** a retrieved record with a rare user/IP pulls in other records sharing it
   (this found the `sudo` line through `user:deploy`, which the time-driven mapper scored too low).
5. **Detection rules** (section 15).

---

## 15. Detection rules and the incident story

Two kinds of rules run on every case (`evidentia/detect/`). Both work on **any** log, including types the
ML was never trained on. A finding is an inference from records, not proof; ATT&CK tactics are "possible".

### 15.1 Built-in rules with adaptive thresholds (`rules.py`)

| Rule | Fires when | Severity | Possible ATT&CK |
|---|---|---|---|
| `brute_force` | An IP's failed logins in any 10 min are far above this case's normal | medium | Credential Access, T1110 |
| `slow_brute_force` | An IP's failed logins over the whole case are far above normal (spread out to stay under per-minute limits) | medium | Credential Access, T1110 |
| `brute_force_success` | A successful login from that IP within 30 min after the guessing | **high** | Initial Access, T1078 |
| `privilege_after_login` | sudo/su by that account within 60 min | **high** | Privilege Escalation, T1548 |
| `tool_download` | A command line downloads a file (wget, curl, certutil, …) | medium (high in a chain) | Command and Control, T1105 |
| `host_scan` | An IP reaches far more hosts or ports in 10 min than this case's normal | medium | Discovery, T1046 |

**Adaptive thresholds ("far above normal").** Instead of a fixed number, each case learns its own normal.
For every source IP the rule measures its activity (e.g. its peak failed logins in any 10 minutes). The
threshold is **median + 5 × MAD** over all sources (MAD = median absolute deviation, a spread measure that a
few attackers can't inflate), never below a floor (5 failures, 15 for slow guessing, 8 hosts, 15 ports).
With fewer than 5 sources there is nothing to learn from, and a fixed default is used (10, 30, 10, 20).
Each finding says which threshold was used and how far above normal the source was, e.g. on the real LogHub
log: *"279 failed logins … (threshold 10 per 10 min, learned from 25 sources in this case; typical source:
2, 140× the typical source)"*.

Why it matters: a busy server with many normal failures gets a higher bar (fewer false alarms), a quiet one
a lower bar (attacks caught earlier), and slow attackers are caught by the whole-case rule.

### 15.2 Community Sigma rules (`sigma.py`, `sigma_rules/`)

**Sigma** is the open, vendor-neutral rule format SOC teams use to share detections. Evidentia bundles the
22 rules of SigmaHQ's `rules/linux/builtin` folder (reverse shells, malware-dropper commands, hidden root
accounts, log clearing, ld.so.preload injection, network sniffing, suspicious sshd errors, ClamAV
detections, …), copied unchanged under the **Detection Rule License 1.1** (attribution shown with every
match; source commit in `sigma_rules/README.md`).

The engine supports keyword lists, simple field selections, wildcards, the contains / startswith /
endswith / re / all modifiers, and conditions with and / or / not / brackets / "1 of" / "all of". A rule
using anything else is skipped and listed as unsupported (`/api/detection-rules`), never guessed. All 22
bundled rules are supported. More rules can be dropped into `evidentia/detect/sigma_rules/`.

### 15.3 Where they show

The **Detections** panel at the top of Overview (Sigma findings carry a "Sigma" tag), and [F1]…
citations in answers, which include **Assessment** and **Recommended actions**.

**Who decides what:** the rules detect the attack and the playbook suggests actions; the LLM (when on)
connects the findings into a story, prioritises the actions and explains them, from cited evidence only.

### 15.4 Tested on

| Data | Result |
|---|---|
| Synthetic SSH log | Full chain: brute force → login as `deploy` → sudo → download, plus Sigma "Suspicious Activity in Shell Commands" for `wget …; chmod +x` |
| **Real** SSH server log (LogHub `OpenSSH_2k.log`, 2,000 lines) | 6 IPs guessing passwords (learned threshold 10; up to 140× the typical source); the one genuine login not flagged; no Sigma false alarms |
| WitFoo firewall sample (20,357 records) | No findings at all, i.e. no false alarms |

**Covers:** Linux logins (sshd, PAM, sudo, su), Windows logon events exported as text (4625/4624/4672),
download and attack commands, scans in firewall/flow logs, the patterns of the 22 Sigma rules.
**Doesn't cover:** web attacks, phishing, DDoS, lateral movement; `.evtx` binaries (export to CSV/JSON
first); Sigma rules with aggregations or fields Evidentia doesn't store; traffic content (needs an IDS
or packet capture).

## 16. Demo cases and which data is real

| Data | Real or made up | Use |
|---|---|---|
| WitFoo training/test data (all evaluation numbers) | **Real** | Model results |
| `data/samples/witfoo_sample_ORG-0005_test_20min.csv` | **Real** (20 min of ORG-0005's test period, never trained on) | Sample case |
| `data/samples/witfoo_sample_asa_lines.log` | **Real** (raw firewall lines of the same slice) | Sample case |
| `data/samples/synthetic_non_security_notes.txt` | **Made up** (shows non-log files work) | Sample case |
| `demo_unseen_auth.log` | **Made up** by us to imitate a break-in | Unseen-type demo; say it is synthetic |
| `OpenSSH_2k.log` | **Real** (LogHub, logpai/loghub on GitHub) | Real unseen-data demo; cite LogHub |

Suggested demo: (1) sample case → Records, Connections, Ask; (2) LogHub case → Overview shows **0
malicious by ML but 6 detections by rules**; (3) synthetic SSH case → Ask "What happened and what should I
do?" for the full incident story.

---

## 17. Limitations (say these yourself)

- Stage 1 (benign vs alert) is log-type recognition, not threat detection.
- Malicious precision ~0.35: most "malicious" flags still need an analyst.
- ORG-0004 has no learnable signal; models don't transfer across organisations.
- Labels come from WitFoo's automated correlation, not analyst-verified ground truth.
- The ML only applies to WitFoo-style firewall/flow logs; other evidence is "not applicable".
- Detection rules cover a few common patterns; thresholds are learned per case but the patterns are hand-written
  (or community-written, for Sigma).
- Syslog years are assumed when the log has none.
- The relationship mapper's links are inferences, not proof of the same incident.
- Free-tier Gemini can be slow or overloaded and may use sent text; real company logs need a paid/private setup.

---

## 18. Likely viva questions

- **Why not accuracy?** 94% of records are benign; "always benign" is 94% accurate and catches nothing.
- **Why is the benign row all zeros?** The log type decides benign vs alert; a lookup table gets the same.
  The real result is Stage 2.
- **What is leakage, how did you prevent it?** Section 5.
- **Why a time-based split?** Bursts of near-identical lines would land in both train and test.
- **Are these results predictions or training scores?** Predictions on unseen test data, compared with
  true labels. Training scores are inflated (RF 0.79 train vs 0.26 test).
- **Is the test data made by you?** No, it's the later part of the real WitFoo data.
- **Why LR and RF, not just RF?** Neither wins everywhere (RF catches more on ORG-0005; LR ranks better
  there and catches more in the 3-class setup); disagreement is a signal; LR is explainable.
- **Did you try other models?** Yes, three boosting models, all trained and tested the same way; none
  were better, so the limit is the data.
- **Why does RF catch 76% in one chart and 18% in another?** ORG-0005 alone vs pooled (mostly ORG-0004).
- **What does the model output?** A probability; the threshold turns it into a class; the app and RAG turn
  that into a readable, cited answer.
- **Does it work on unseen data?** Unseen records of a known type: yes (all test scores). Unseen log
  types: ML abstains; rules, retrieval and Gemini still reconstruct the attack (LogHub demo).
- **How does the chatbot avoid making things up?** Retrieval first, only retrieved material allowed,
  every sentence cited, invalid citations removed.
- **Are the rules hard-coded?** The patterns are hand-written (like SIEM correlation rules and fail2ban),
  but the thresholds are learned from each case (median + 5 × MAD over all sources), and 22 community Sigma
  rules run alongside ours. Nothing case-specific (IPs, users, dates) is in the code.
- **What makes it intelligent?** It goes from raw logs to "what happened, why, what to do", with evidence
  for each step, on log types it was never trained on.

---

## 19. Code map

| Topic | File | Look for |
|---|---|---|
| EDA | `notebooks/01_eda.ipynb` | sections 1–10 |
| Removed columns, cut-offs | `evidentia/ml/config.py` | `BANNED_POST_LABEL`, `CUTOFFS` |
| Data loading, splits | `evidentia/ml/data.py` | `build_dataset`, `stage2_splits` |
| Features | `evidentia/ml/features.py`, `context.py` | `build_transformer`, `add_context_features` |
| Models | `evidentia/ml/models.py` | `make_lr`, `make_rf`, `make_iforest` |
| Training + CV | `scripts/train_models.py` | `GridSearchCV`, `StratifiedGroupKFold` |
| Train/val/test scores | `scripts/train_val_test_scores.py` | |
| Metrics | `evidentia/ml/evaluate.py` | `binary_report` |
| Model comparison | `scripts/compare_models.py` | |
| Applying models | `evidentia/ml/orchestrator.py` | `analyze`, `_applicability` |
| Upload pipeline | `evidentia/cases/pipeline.py` | `process_file` |
| Evidence hash | `evidentia/cases/store.py` | `sha256` |
| Parsing, timestamps | `evidentia/ingestion/upload.py` | `parse_upload`, `_line_time` |
| Indicators | `evidentia/ingestion/entities.py` | `extract` |
| Detection rules | `evidentia/detect/rules.py` | `detect`, `learned_threshold` |
| Sigma engine + rules | `evidentia/detect/sigma.py`, `evidentia/detect/sigma_rules/` | `run_sigma` |
| Relationship mapper | `evidentia/relations/mapper.py` | `build_edges` |
| Retrieval | `evidentia/rag/retrieve.py` | `retrieve`, `template`, `_diverse` |
| Prompt, citations | `evidentia/rag/answer.py` | `SYSTEM`, `answer`, `builtin_answer` |
| Gemini | `evidentia/rag/llm.py` | `GeminiLLM.generate` |
| Server routes | `evidentia/api/main.py` | `@app.get` / `@app.post` |
| Pages | `frontend/src/pages/*.tsx`, routes in `frontend/src/App.tsx` | |
| Tests | `tests/` (41 tests) | `test_unseen.py` covers the new work |

---

## 20. How to run it

Windows PowerShell (Python 3.13 and Node.js LTS installed):

```powershell
git clone https://github.com/Maaz-Ali0102/evidentia-ai
cd evidentia-ai
py -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
copy .env.example .env        # then put your Gemini key in .env (optional)
.venv\Scripts\python -m uvicorn evidentia.api.main:app --port 8000
```

Open http://localhost:8000. Run tests: `.venv\Scripts\python -m pytest -q tests`.

Notes: `requirements.txt` must have `huggingface_hub<2.0` (fastembed needs it). In old PowerShell, run
commands one per line (`&&` doesn't work). Port 8000 busy = the server is already running somewhere.
The first case downloads a ~90 MB embedding model. To rerun the comparison you also need the dataset
(download command in the README) and `pip install xgboost lightgbm`.

---

## 21. Glossary

| Term | Meaning |
|---|---|
| Benign / suspicious / malicious | WitFoo's labels: normal / an alert / an alert in an incident |
| Prediction | The model's guess for a record it hasn't seen |
| Threshold | Probability cut-off that turns a score into a class |
| Confusion matrix | Table of true vs predicted classes |
| PR-AUC | Ranking quality for the rare class; chance = its share |
| Recall / precision | Share of attacks caught / share of flags that are right |
| Overfitting | Scoring much better on training data than on new data |
| Leakage | The model seeing information derived from the answer |
| Cross-validation (grouped) | Testing settings on parts of the training data, keeping incidents together |
| Stage 1 / Stage 2 | benign vs alert / suspicious vs malicious |
| Applicability gate | Marks records unlike the training data "not applicable" |
| Isolation Forest | Label-free anomaly detector |
| Relationship mapper | Links records by time, shared indicators and text similarity |
| RAG | Retrieve records first, then let an LLM answer only from them |
| Template | A message with numbers masked; groups near-identical lines |
| Finding [F] | Result of a detection rule; an inference, not proof |
| ATT&CK | MITRE's catalogue of attacker tactics and techniques |
| SHA-256 | File fingerprint; same hash = same file |
