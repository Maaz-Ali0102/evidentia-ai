"""Score a blind-test case: compare the app's predictions with the hidden answer key.

    python scripts/score_blind_test.py <case-id> [--url http://127.0.0.1:8000]

Reads every record of the case through the running app's API (so the app is scored exactly as it is used),
matches each to data/blind_test/KEY_DO_NOT_UPLOAD/answer_key.csv by file name and row, and prints, for
Logistic Regression and Random Forest:
  - a confusion matrix (rows = true label, columns = the app's class, including "not applicable");
  - recall and precision per class, accuracy, macro-F1 and balanced accuracy;
  - Stage 1 (benign vs alert) and Stage 2 (malicious among true alerts) separately.
A Markdown copy is written next to the key (blind_test_report_<case-id>.md).
"""
import argparse
import json
import sys
import urllib.request
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
KEY = ROOT / "data" / "blind_test" / "KEY_DO_NOT_UPLOAD" / "answer_key.csv"
TRUE = ["benign", "suspicious", "malicious"]
PRED = TRUE + ["not applicable"]


def fetch(url: str, cid: str, model: str) -> pd.DataFrame:
    rows, offset = [], 0
    while True:
        with urllib.request.urlopen(f"{url}/api/cases/{cid}/events?model={model}&sort=row&limit=500&offset={offset}") as r:
            page = json.load(r)
        rows += page["rows"]
        offset += len(page["rows"])
        if not page["rows"] or offset >= page["total"]:
            return pd.DataFrame(rows)


def report(df: pd.DataFrame, model: str) -> list[str]:
    cm = pd.crosstab(df["true_label"], df["pred"]).reindex(index=[t for t in TRUE if t in set(df.true_label)],
                                                           columns=PRED, fill_value=0)
    out = [f"### {model}", "", "| true \\ predicted | " + " | ".join(PRED) + " | recall |",
           "|---|" + "---|" * (len(PRED) + 1)]
    for t in cm.index:
        n = cm.loc[t].sum()
        out.append(f"| **{t}** ({n}) | " + " | ".join(f"{cm.loc[t, p]}" for p in PRED) + f" | **{cm.loc[t, t] / n:.0%}** |")
    prec = {p: cm.loc[p, p] / cm[p].sum() if p in cm.index and cm[p].sum() else float("nan") for p in TRUE}
    rec = {t: cm.loc[t, t] / cm.loc[t].sum() for t in cm.index}
    f1 = {t: 2 * prec[t] * rec[t] / (prec[t] + rec[t]) if prec[t] + rec[t] else 0.0 for t in cm.index}
    acc = sum(cm.loc[t, t] for t in cm.index) / cm.values.sum()
    out += ["", "| class | precision | recall | F1 |", "|---|---|---|---|"]
    out += [f"| {t} | {prec[t]:.2f} | {rec[t]:.2f} | {f1[t]:.2f} |" for t in cm.index]
    out += ["", f"- Accuracy **{acc:.1%}** · macro-F1 **{sum(f1.values()) / len(f1):.3f}** · "
                f"balanced accuracy **{sum(rec.values()) / len(rec):.1%}**"]
    alert_true = df["true_label"] != "benign"
    alert_pred = df["pred"].isin(["suspicious", "malicious"])
    if "benign" in cm.index:
        s1 = (alert_true == alert_pred).mean()
        out.append(f"- Stage 1 (benign vs alert): {s1:.1%} correct")
    ta = df[alert_true]
    if len(ta):
        mal = ta["true_label"] == "malicious"
        caught = (ta.loc[mal, "pred"] == "malicious").mean() if mal.any() else float("nan")
        fa = (ta.loc[~mal, "pred"] == "malicious").mean() if (~mal).any() else float("nan")
        out.append(f"- Stage 2 (among true alerts): malicious caught {caught:.1%}, "
                   f"suspicious wrongly called malicious {fa:.1%}")
    na = (df["pred"] == "not applicable").mean()
    out.append(f"- Marked not applicable: {na:.1%}")
    return out + [""]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("case_id")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--key", default=str(KEY), help="answer key CSV (file, source_row, true_label[, scored])")
    a = ap.parse_args()
    key = pd.read_csv(a.key)
    if "scored" in key:  # only the rows marked for scoring (e.g. a balanced subset of a full stream)
        key = key[key["scored"].astype(str).str.lower() == "true"]
    lines = [f"# Blind test report: case `{a.case_id}`", ""]
    for model, name in (("lr", "Logistic Regression"), ("rf", "Random Forest")):
        ev = fetch(a.url, a.case_id, model)
        df = ev.merge(key, left_on=["file", "source_row"], right_on=["file", "source_row"], how="inner")
        if df.empty:
            sys.exit("No record of this case is in the answer key: upload the blind-test files unchanged.")
        ok = (df["message_x"].str[:60] == df["message_y"].str[:60]).mean() if "message_x" in df else 1.0
        df = df.rename(columns={"cls": "pred"})
        if model == "lr":
            lines += [f"{len(df)} of {len(ev)} records matched to the key (text check {ok:.0%}); "
                      f"files: {', '.join(sorted(df['file'].unique()))}.", ""]
        lines += report(df, name)
        if model == "lr":
            an = df[df["an_flag"] == 1]["true_label"].value_counts().to_dict()
            lines += [f"Anomaly flags by true label: {an or 'none'}", ""]
    text = "\n".join(lines)
    print(text)
    (Path(a.key).parent / f"blind_test_report_{a.case_id}.md").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
