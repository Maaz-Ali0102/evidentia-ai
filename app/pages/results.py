import pandas as pd
import streamlit as st

from common import FIGS, MODEL_NAMES, metrics, page_header

page_header("Model evaluation",
            "Measured on held-out future time windows. Numbers come from reports/metrics/*.json; "
            "the full write-up is reports/ML_RESULTS.md.")

s2, s1, tc, iso = metrics("stage2"), metrics("stage1"), metrics("three_class"), metrics("iforest")

st.subheader("Stage 2: suspicious vs malicious (tuned)")
st.caption("Feature set, hyper-parameters and threshold chosen by grouped cross-validation on the training window. "
           "Chance PR-AUC = share of malicious rows in the test window.")
rows = []
for split, d in s2["tuned"].items():
    for m, r in d.items():
        t = r["test_at_tuned_threshold"]
        rows.append({"split": split, "model": MODEL_NAMES[m], "features": r["selected_feature_set"],
                     "chance PR-AUC": t["positive_rate_baseline"], "test PR-AUC": t["pr_auc_positive"],
                     "test ROC-AUC": t["roc_auc"], "malicious precision": t["per_class"]["malicious"]["precision"],
                     "malicious recall": t["per_class"]["malicious"]["recall"],
                     "incidents detected": f"{r['incident_level']['detected']} / {r['incident_level']['incidents']}",
                     "size MB": r["model_size_mb"]})
st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
st.image(str(FIGS / "R1_stage2_prauc_logreg.png"),
         caption="Untuned feature ablation (Logistic Regression). Context features generalise better than text when "
                 "organisations are pooled; cross-organisation transfer stays at chance.")

st.subheader("Three classes")
rows = []
for kind in ("hierarchical", "flat"):
    for m, r in tc[kind].items():
        rows.append({"strategy": kind, "model": MODEL_NAMES[m], "macro-F1": r["macro_f1"],
                     "malicious F1": r["per_class"]["malicious"]["f1"],
                     "suspicious F1": r["per_class"]["suspicious"]["f1"], "benign F1": r["per_class"]["benign"]["f1"],
                     "accuracy": r["accuracy"]})
st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
st.caption(f"Test rows: {tc['test_rows']:,}. Accuracy is not informative: predicting 'benign' everywhere scores "
           f"{tc['test_distribution']['benign'] / tc['test_rows']:.1%}.")
st.image(str(FIGS / "R2_three_class_confusion.png"))

st.subheader("Stage 1: benign vs alert")
st.caption("Every feature set scores ≈1.0 because alerts come from distinct log formats. This measures "
           "log-type recognition, not threat detection.")
st.image(str(FIGS / "R3_stage1_ablation.png"))
wp = metrics("stage1_within_product")
lt = wp["label_is_function_of_event_type"]
base = lt["lookup_table_baseline_on_test"]
st.markdown(
    f"**Why it is perfect.** Of {lt['distinct_product_message_type_keys']} distinct (product, event type) pairs, "
    f"**{lt['keys_with_both_benign_and_alert']}** contain both benign and alert rows: the label is fixed by the "
    f"event type. A plain lookup table with no ML scores macro-F1 **{base['macro_f1']}** on "
    f"{base['n']:,} test rows. Training inside one product does not change this either:")
rows = [{"product": p, "test rows": e["test_rows"], "test alerts": e["test_alerts"],
         **{f"{fs} {MODEL_NAMES[m]}": r["pr_auc_positive"]
            for fs, d in e["within_product_model"].items() for m, r in d.items()}}
        for p, e in wp["products"].items() if e["tested"]]
st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
st.caption("PR-AUC inside a single product. Stage 1 therefore acts as a deterministic router; the learning "
           "happens in Stage 2, inside the same event types.")

st.subheader("Isolation Forest (unsupervised)")
rows = []
for k, r in iso["experiments"].items():
    if "pr_auc_positive" in r:
        rows.append({"experiment": k, "PR-AUC": r["pr_auc_positive"], "chance": r["positive_rate_baseline"],
                     "ROC-AUC": r["roc_auc"]})
st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
dis = iso["experiments"]["disagreement_with_random_forest"]["rows"]
st.caption(f"On held-out alerts the anomaly detector flags {dis['malicious']['RF:suspicious & IF:anomaly']:,} malicious "
           f"rows that the Random Forest misses — and {dis['suspicious']['RF:suspicious & IF:anomaly']:,} suspicious rows. "
           "The two signals are shown side by side, never merged.")
