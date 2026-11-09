"""Evidentia AI: local investigator app.

Run (from the project folder):
    .venv/Scripts/python -m streamlit run app/streamlit_app.py
It serves on http://localhost:8501 only; uploaded files are processed in memory on this machine.
"""
import streamlit as st

st.set_page_config(page_title="Evidentia AI", page_icon=":material/policy:", layout="wide")

pages = [
    st.Page("pages/analyze.py", title="Analyze logs", icon=":material/search:", default=True),
    st.Page("pages/results.py", title="Model evaluation", icon=":material/monitoring:"),
    st.Page("pages/dataset.py", title="Dataset & EDA", icon=":material/dataset:"),
    st.Page("pages/about.py", title="About & limitations", icon=":material/info:"),
]
nav = st.navigation(pages)
with st.sidebar:
    st.markdown("**Evidentia AI**  \nSecurity-log triage assistant")
    st.caption("Runs locally. Files are processed in memory and are not sent anywhere.")
nav.run()
