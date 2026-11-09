import streamlit as st

from common import FIGS, ROOT, page_header

page_header("Dataset & EDA",
            "WitFoo Precinct6 cybersecurity dataset (Hugging Face, v2.1.0): 2,011,674 live security-log events "
            "from 4 organisations. Statistics below use the training portion only.")

charts = [
    ("eda01_class_distribution.png", "Class imbalance"),
    ("eda02_org_class_mix.png", "Organisations"),
    ("eda03_hourly_daily.png", "Time patterns"),
    ("eda04_message_types.png", "Message types"),
    ("eda05_missing_values.png", "Missing values"),
    ("eda06_message_length.png", "Message length"),
    ("eda07_split_coverage.png", "Train / test split"),
    ("eda08_duplicates.png", "Duplicates"),
    ("eda09_leakage_evidence.png", "Leakage evidence"),
]
tabs = st.tabs([t for _, t in charts] + ["Summary"])
for tab, (f, _) in zip(tabs, charts):
    with tab:
        st.image(str(FIGS / f), width="stretch")
with tabs[-1]:
    st.markdown((ROOT / "reports" / "eda_summary.md").read_text(encoding="utf-8"))
