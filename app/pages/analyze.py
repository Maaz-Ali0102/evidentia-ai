import altair as alt
import pandas as pd
import streamlit as st

from common import CLASS_COLORS, MODEL_NAMES, SAMPLES, analyze, page_header, parse

page_header("Analyze security logs",
            "Upload firewall / flow / security logs (CSV, JSON, JSONL, LOG, TXT). Each event is classified by two "
            "trained models and checked by an anomaly detector. Outputs are model predictions, not confirmed findings.")

# ------------------------------------------------------------------ input
c_up, c_sample = st.columns([3, 2], gap="large")
with c_up:
    upload = st.file_uploader("Evidence file", type=["csv", "json", "jsonl", "ndjson", "log", "txt"])
with c_sample:
    samples = sorted(p.name for p in SAMPLES.glob("*") if p.is_file())
    choice = st.selectbox("…or load a SAMPLE file", ["(none)"] + samples,
                          help="Samples are clearly separated from real evidence. The WitFoo sample comes from the "
                               "test window, so the models never saw these rows during training.")

if upload is not None:
    name, data = upload.name, upload.getvalue()
elif choice != "(none)":
    name, data = choice, (SAMPLES / choice).read_bytes()
else:
    st.info("Upload a file or pick a sample to start.", icon=":material/upload_file:")
    st.stop()

parsed = parse(name, data)
is_sample = upload is None

# ------------------------------------------------------------------ integrity + parsing
with st.container(border=True):
    st.markdown(f"**{'SAMPLE · ' if is_sample else ''}{parsed.file_name}**")
    a, b, c = st.columns(3)
    a.metric("Events parsed", f"{len(parsed.events):,}")
    b.metric("Size", f"{parsed.size_bytes / 1024:,.1f} KB")
    c.metric("Type", parsed.file_type.upper())
    st.code(f"SHA-256  {parsed.sha256}", language=None)
    pc = parsed.parser_counts
    if "columns_mapped" in pc:
        st.caption(f"Columns mapped ({len(pc['columns_mapped'])}): " +
                   ", ".join(f"{src} → {dst}" if src != dst else dst for dst, src in pc["columns_mapped"].items()))
    if "line_formats" in pc:
        st.caption("Line formats detected: " + ", ".join(f"{k} {v:,}" for k, v in pc["line_formats"].items()))
    for w in parsed.warnings:
        st.warning(w, icon=":material/warning:")

if parsed.events.empty:
    st.stop()

df = analyze(parsed.sha256, parsed.events)

# ------------------------------------------------------------------ summary
model = st.segmented_control("Classifier shown", list(MODEL_NAMES), format_func=MODEL_NAMES.get,
                             default="logreg", key="model")
model = model or "logreg"
other = "random_forest" if model == "logreg" else "logreg"
cls = df[f"{model}_class"]

m1, m2, m3, m4, m5, m6 = st.columns(6)
m1.metric("Events", f"{len(df):,}")
m2.metric("Not applicable", f"{(~df['applicable']).sum():,}",
          help="No timestamp, or text unlike the security logs the models were trained on. These are not scored.")
m3.metric("Suspicious", f"{(cls == 'suspicious').sum():,}")
m4.metric("Malicious", f"{(cls == 'malicious').sum():,}")
m5.metric("Models disagree", f"{(df['applicable'] & ~df['models_agree']).sum():,}")
m6.metric("Anomalies", f"{df['anomaly_flag'].sum():,}",
          help="Isolation Forest flags among alert traffic. Scored separately; never merged into class probabilities.")

if df["applicable"].sum() < len(df) / 2:
    st.warning("Most events in this file do not resemble the training data (firewall / flow / security logs). "
               "Model outputs are withheld for them.", icon=":material/block:")

# ------------------------------------------------------------------ timeline
alerts = df[df["applicable"] & (cls != "benign") & df["time_utc"].notna()].copy()
if not alerts.empty:
    st.subheader("Alert timeline")
    st.caption(f"Each point is an event the {MODEL_NAMES[model]} routes to the alert stage. Height = probability of "
               f"'malicious' given alert (uncalibrated); the dashed line is the decision threshold chosen on training data. "
               f"Ringed points were flagged by the anomaly detector. Context features count only earlier events "
               f"in this file, so the first minutes have little history and scores there are less reliable.")
    alerts["class"] = alerts[f"{model}_class"]
    alerts["p_mal"] = alerts[f"{model}_p_malicious"]
    alerts["time"] = alerts["time_utc"].dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    thr = float(alerts[f"{model}_threshold"].iloc[0])
    base = alt.Chart(alerts)
    pts = base.mark_circle(size=28, opacity=0.75).encode(
        x=alt.X("time_utc:T", title="time (UTC)", scale=alt.Scale(type="utc"), axis=alt.Axis(format="%H:%M")),
        y=alt.Y("p_mal:Q", title="p(malicious | alert)", scale=alt.Scale(domain=[0, 1])),
        color=alt.Color("class:N", title="predicted",
                        scale=alt.Scale(domain=["suspicious", "malicious"],
                                        range=[CLASS_COLORS["suspicious"], CLASS_COLORS["malicious"]])),
        tooltip=["row", "time", "class", alt.Tooltip("p_mal:Q", format=".3f"),
                 "src_ip", "dst_ip", "dst_port", "anomaly_flag"])
    ring = base.transform_filter("datum.anomaly_flag").mark_point(size=120, shape="circle", filled=False,
                                                                  color="#0b0b0b", strokeWidth=1.5).encode(
        x=alt.X("time_utc:T", scale=alt.Scale(type="utc")), y="p_mal:Q")
    rule = alt.Chart(pd.DataFrame({"y": [thr]})).mark_rule(strokeDash=[6, 4], color="#52514e").encode(y="y:Q")
    st.altair_chart((pts + ring + rule).properties(height=320), width="stretch")

# ------------------------------------------------------------------ table
st.subheader("Events")
f1, f2, f3, f4 = st.columns([2, 2, 2, 3])
show_cls = f1.multiselect("Predicted class", ["malicious", "suspicious", "benign", "not applicable"],
                          default=["malicious", "suspicious"])
only_dis = f2.toggle("Only model disagreements")
only_anom = f3.toggle("Only anomalies")
query = f4.text_input("Search message / IP", placeholder="e.g. 10.147.100.191 or 'Deny tcp'")

view = df[cls.isin(show_cls)]
if only_dis:
    view = view[view["applicable"] & ~view["models_agree"]]
if only_anom:
    view = view[view["anomaly_flag"]]
if query:
    q = query.lower()
    view = view[view["message"].fillna("").str.lower().str.contains(q, regex=False)
                | view["src_ip"].fillna("").astype(str).str.contains(q, regex=False)
                | view["dst_ip"].fillna("").astype(str).str.contains(q, regex=False)]

cols = ["row", "time_utc", f"{model}_class", f"{model}_p_malicious", f"{other}_class", "anomaly_flag",
        "anomaly_score", "src_ip", "dst_ip", "dst_port", "message", "notes"]
if "reference_label_witfoo" in df:
    cols.insert(3, "reference_label_witfoo")
st.caption(f"{len(view):,} of {len(df):,} events shown")
st.dataframe(
    view[cols], hide_index=True, width="stretch", height=380,
    column_config={
        "time_utc": st.column_config.DatetimeColumn("time (UTC)", format="YYYY-MM-DD HH:mm:ss"),
        f"{model}_class": st.column_config.TextColumn(f"{MODEL_NAMES[model]}"),
        f"{other}_class": st.column_config.TextColumn(f"{MODEL_NAMES[other]}"),
        f"{model}_p_malicious": st.column_config.ProgressColumn("p(malicious | alert)", min_value=0, max_value=1,
                                                                format="%.3f"),
        "reference_label_witfoo": st.column_config.TextColumn("WitFoo label (sample)"),
        "anomaly_flag": st.column_config.CheckboxColumn("anomaly"),
        "anomaly_score": st.column_config.NumberColumn("anomaly score", format="%.3f"),
        "message": st.column_config.TextColumn("message", width="large"),
    })

# ------------------------------------------------------------------ inspector
with st.expander("Inspect one event (full model output)", icon=":material/manage_search:"):
    rows = view["row"].tolist() or df["row"].tolist()
    pick = st.selectbox("Row", rows, key="inspect_row")
    rec = df.loc[df["row"] == pick].iloc[0]
    st.markdown("**Original line / message**")
    st.code(str(rec["message"]), language=None, wrap_lines=True)
    st.markdown(f"Provenance: `{parsed.file_name}`, row {pick}")
    st.json(rec["_detail"], expanded=2)

# ------------------------------------------------------------------ comparison with reference labels
if "reference_label_witfoo" in df:
    with st.expander("Compare with WitFoo reference labels (sample only)", icon=":material/compare_arrows:"):
        st.caption("Reference labels are WitFoo Precinct's automated triage, not analyst-verified truth. "
                   "Context features here are computed only from this file, so they see less history than in training.")
        ct = pd.crosstab(df["reference_label_witfoo"], df[f"{model}_class"], rownames=["WitFoo label"],
                         colnames=[f"{MODEL_NAMES[model]} prediction"])
        st.dataframe(ct, width="stretch")

# ------------------------------------------------------------------ export
out = df.drop(columns=["_detail"]).copy()
out.insert(0, "source_file", parsed.file_name)
out.insert(1, "source_sha256", parsed.sha256)
st.download_button("Download results (CSV)", out.to_csv(index=False).encode("utf-8"),
                   file_name=f"evidentia_results_{parsed.sha256[:12]}.csv", mime="text/csv",
                   icon=":material/download:")
