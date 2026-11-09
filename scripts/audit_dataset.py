"""Phase 1 dataset audit for witfoo/precinct6-cybersecurity (v2.1.0).

Reads the local parquet files with DuckDB (no full load into pandas) and writes
every number it computes to reports/audit_results.json, so the audit report can
cite measured values instead of assumptions.

Run:  .venv/Scripts/python scripts/audit_dataset.py
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "precinct6"
SIG = (RAW / "signals" / "signals.parquet").as_posix()
INC = (RAW / "signals" / "incident_signals.parquet").as_posix()
REP = (RAW / "graph" / "attack_reports.parquet").as_posix()
EDG = (RAW / "graph" / "edges-00000.parquet").as_posix()
NOD = (RAW / "graph" / "nodes.parquet").as_posix()
OUT = ROOT / "reports" / "audit_results.json"

# Columns the card documents as produced by Precinct's labeling / incident correlation.
POST_LABEL = [
    "label_confidence", "attack_techniques", "attack_tactics", "defense_techniques",
    "mo_name", "suspicion_score", "lifecycle_stage", "disposition",
    "disposition_category", "is_false_positive", "status_name", "incident_ids",
    "matched_rules", "set_roles",
]
# Columns describing where/how a record was collected (possible shortcuts).
SOURCE_META = ["origin", "org_id", "timestamp_source", "stream_name", "pipeline",
               "product_name", "vendor_name", "artifact_id"]
# Columns describing the event itself (candidate model inputs).
EVENT = ["message_type", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
         "src_host", "dst_host", "username", "action", "severity", "vendor_code",
         "message_sanitized", "event_time", "timestamp"]

con = duckdb.connect()
con.execute("SET threads TO 4")
con.execute(f"CREATE VIEW sig AS SELECT * FROM '{SIG}'")
con.execute(f"CREATE VIEW inc AS SELECT * FROM '{INC}'")
con.execute(f"CREATE VIEW rep AS SELECT * FROM '{REP}'")
con.execute(f"CREATE VIEW edg AS SELECT * FROM '{EDG}'")
con.execute(f"CREATE VIEW nod AS SELECT * FROM '{NOD}'")


def rows(sql: str) -> list[dict]:
    cur = con.execute(sql)
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in cur.fetchall()]


def one(sql: str):
    return con.execute(sql).fetchall()[0][0]


R: dict = {}
t0 = time.time()

# 1. Schemas and sizes -------------------------------------------------------
R["schemas"] = {}
for v in ["sig", "inc", "rep", "edg", "nod"]:
    R["schemas"][v] = {
        "rows": one(f"SELECT count(*) FROM {v}"),
        "columns": [{"name": r["column_name"], "type": r["column_type"]}
                    for r in rows(f"DESCRIBE SELECT * FROM {v}")],
    }
sig_cols = [c["name"] for c in R["schemas"]["sig"]["columns"]]

# 2. Label distributions -----------------------------------------------------
R["labels_signals"] = rows("SELECT label_binary, count(*) n FROM sig GROUP BY 1 ORDER BY n DESC")
R["labels_incident_signals"] = rows("SELECT label_binary, count(*) n FROM inc GROUP BY 1")
R["labels_by_org"] = rows("""
  SELECT org_id, count(*) n,
    sum((label_binary='benign')::INT) benign,
    sum((label_binary='suspicious')::INT) suspicious,
    sum((label_binary='malicious')::INT) malicious
  FROM sig GROUP BY 1 ORDER BY n DESC""")
R["labels_by_day"] = rows("""
  SELECT CAST(to_timestamp(timestamp) AS DATE)::VARCHAR AS dt, org_id, label_binary, count(*) n
  FROM sig GROUP BY ALL ORDER BY dt, org_id, label_binary""")

# 3. Missing values (null or empty string) per column, per label -----------
miss = []
for c in sig_cols:
    expr = f"({c} IS NULL OR trim(CAST({c} AS VARCHAR)) IN ('', '[]', 'nan', 'NaN'))"
    r = rows(f"""SELECT
        avg({expr}::INT) all_rows,
        avg(CASE WHEN label_binary='benign' THEN {expr}::INT END) benign,
        avg(CASE WHEN label_binary='suspicious' THEN {expr}::INT END) suspicious,
        avg(CASE WHEN label_binary='malicious' THEN {expr}::INT END) malicious
      FROM sig""")[0]
    miss.append({"column": c, **{k: round(v, 4) for k, v in r.items()}})
R["missing_rate_signals"] = miss

# 4. Leakage: how well does each column ALONE determine the label? ----------
# purity = share of rows whose column value maps (in the whole table) to the
# majority label of that value. 0.943 = majority-class baseline (all benign).
# Also macro-recall of a "lookup table" classifier, which exposes columns that
# perfectly separate the minority classes.
leak = []
for c in POST_LABEL + SOURCE_META + EVENT:
    if c not in sig_cols or c in ("timestamp", "event_time", "message_sanitized", "artifact_id"):
        continue
    r = rows(f"""
      WITH v AS (SELECT CAST({c} AS VARCHAR) val, label_binary y, count(*) n FROM sig GROUP BY 1,2),
      best AS (SELECT val, arg_max(y, n) pred FROM v GROUP BY 1),
      j AS (SELECT v.y, v.n, (v.y = b.pred) ok FROM v JOIN best b ON v.val IS NOT DISTINCT FROM b.val)
      SELECT sum(n*ok::INT)/sum(n) purity,
        sum(CASE WHEN y='benign' AND ok THEN n END)/sum(CASE WHEN y='benign' THEN n END) rec_benign,
        sum(CASE WHEN y='suspicious' AND ok THEN n END)/sum(CASE WHEN y='suspicious' THEN n END) rec_susp,
        sum(CASE WHEN y='malicious' AND ok THEN n END)/sum(CASE WHEN y='malicious' THEN n END) rec_mal,
        (SELECT count(DISTINCT {c}) FROM sig) n_distinct
      FROM j""")[0]
    group = "post_label" if c in POST_LABEL else "source_meta" if c in SOURCE_META else "event"
    leak.append({"column": c, "group": group,
                 **{k: (round(float(v), 4) if v is not None else None) for k, v in r.items()}})
R["single_column_lookup"] = leak

# Post-label columns: are they populated ONLY for some labels? (direct leak)
R["post_label_nonempty_by_label"] = rows(f"""
  SELECT label_binary,
    {", ".join(f"avg(({c} IS NOT NULL AND CAST({c} AS VARCHAR) NOT IN ('', '[]', '0.0', '0', 'false')) ::INT) AS {c}" for c in POST_LABEL)}
  FROM sig GROUP BY 1""")

# 5. Duplicates and label conflicts ----------------------------------------
R["exact_duplicate_messages"] = rows("""
  SELECT count(*) total_rows, count(DISTINCT message_sanitized) distinct_messages,
         1 - count(DISTINCT message_sanitized)/count(*) dup_share FROM sig""")[0]
R["duplicate_share_by_label"] = rows("""
  WITH m AS (SELECT message_sanitized, count(*) c FROM sig GROUP BY 1)
  SELECT s.label_binary, avg((m.c>1)::INT) share_rows_with_duplicate_text
  FROM sig s JOIN m USING (message_sanitized) GROUP BY 1""")
# Identical message text carrying different labels -> ceiling for any text-only model
R["conflicting_labels_same_message"] = rows("""
  WITH m AS (SELECT message_sanitized, count(DISTINCT label_binary) k, count(*) n,
                    sum((label_binary='malicious')::INT) nm
             FROM sig GROUP BY 1)
  SELECT count(*) FILTER (WHERE k>1) messages_with_conflict,
         sum(n) FILTER (WHERE k>1) rows_in_conflict,
         sum(nm) FILTER (WHERE k>1) malicious_rows_whose_text_also_appears_with_other_label,
         (SELECT count(*) FROM sig WHERE label_binary='malicious') malicious_total
  FROM m""")[0]
# Messages after masking digits (timestamps, ports, counters) -> near-duplicates
R["near_duplicate_templates"] = rows("""
  WITH t AS (SELECT regexp_replace(message_sanitized, '[0-9]+', '0', 'g') tpl, label_binary FROM sig)
  SELECT count(DISTINCT tpl) distinct_templates,
         count(DISTINCT tpl) FILTER (WHERE label_binary='malicious') malicious_templates,
         count(DISTINCT tpl) FILTER (WHERE label_binary='suspicious') suspicious_templates
  FROM t""")[0]
R["cross_org_shared_messages"] = one("""
  SELECT count(*) FROM (SELECT message_sanitized FROM sig GROUP BY 1 HAVING count(DISTINCT org_id)>1)""")

# 6. Incident structure of malicious live rows ------------------------------
R["malicious_incident_groups"] = rows("""
  WITH m AS (SELECT org_id, unnest(CAST(json_extract_string(incident_ids, '$[*]') AS VARCHAR[])) inc
             FROM sig WHERE label_binary='malicious')
  SELECT org_id, count(DISTINCT inc) incidents, count(*) memberships,
         max(c) largest_incident, median(c) median_incident_size
  FROM (SELECT org_id, inc, count(*) OVER (PARTITION BY inc) c FROM m) GROUP BY 1""")
R["incidents_spanning_orgs"] = one("""
  WITH m AS (SELECT org_id, unnest(CAST(json_extract_string(incident_ids, '$[*]') AS VARCHAR[])) inc
             FROM sig WHERE label_binary='malicious')
  SELECT count(*) FROM (SELECT inc FROM m GROUP BY 1 HAVING count(DISTINCT org_id)>1)""")
R["malicious_multi_incident_rows"] = one("""
  SELECT count(*) FROM sig WHERE label_binary='malicious'
    AND json_array_length(incident_ids) > 1""")
R["mo_name_malicious_signals"] = rows("""
  SELECT org_id, mo_name, count(*) n FROM sig WHERE label_binary='malicious'
  GROUP BY ALL ORDER BY n DESC LIMIT 20""")

# 7. Domain shift between organizations (org-held-out feasibility) ----------
R["stream_by_org_label"] = rows("""
  SELECT org_id, stream_name, label_binary, count(*) n FROM sig
  GROUP BY ALL HAVING count(*) > 50 ORDER BY org_id, n DESC""")
R["message_type_overlap_0004_0005"] = rows("""
  WITH a AS (SELECT DISTINCT message_type FROM sig WHERE org_id='ORG-0004'),
       b AS (SELECT DISTINCT message_type FROM sig WHERE org_id='ORG-0005')
  SELECT (SELECT count(*) FROM a) types_0004, (SELECT count(*) FROM b) types_0005,
         (SELECT count(*) FROM a JOIN b USING (message_type)) shared""")[0]
R["malicious_message_types_by_org"] = rows("""
  SELECT org_id, message_type, stream_name, count(*) n FROM sig WHERE label_binary='malicious'
  GROUP BY ALL ORDER BY org_id, n DESC""")
R["suspicious_message_types_by_org"] = rows("""
  SELECT org_id, message_type, stream_name, count(*) n FROM sig WHERE label_binary='suspicious'
  GROUP BY org_id, message_type, stream_name QUALIFY row_number() OVER (PARTITION BY org_id ORDER BY count(*) DESC) <= 8
  ORDER BY org_id, n DESC""")

# 8. Live vs incident_lead tables: origin shortcut --------------------------
R["timestamp_source_by_table"] = rows("""
  SELECT 'signals' t, timestamp_source, count(*) n FROM sig GROUP BY ALL
  UNION ALL SELECT 'incident_signals', timestamp_source, count(*) FROM inc GROUP BY ALL""")
R["stream_top_incident_signals"] = rows("""
  SELECT stream_name, count(*) n FROM inc GROUP BY 1 ORDER BY n DESC LIMIT 10""")
R["stream_top_signals_malicious"] = rows("""
  SELECT stream_name, count(*) n FROM sig WHERE label_binary='malicious' GROUP BY 1 ORDER BY n DESC LIMIT 10""")
R["incident_signals_by_org"] = rows("SELECT org_id, count(*) n FROM inc GROUP BY 1 ORDER BY n DESC")
R["incident_signals_year"] = rows("""
  SELECT year(to_timestamp(timestamp)) yr, count(*) n FROM inc GROUP BY 1 ORDER BY 1""")

# 9. Temporal fields --------------------------------------------------------
R["time_range_signals"] = rows("""
  SELECT label_binary, to_timestamp(min(timestamp))::VARCHAR AS t_first, to_timestamp(max(timestamp))::VARCHAR AS t_last,
         avg((event_time IS NOT NULL AND NOT isnan(event_time))::INT) event_time_present
  FROM sig GROUP BY 1""")
R["ingest_vs_event_lag_seconds"] = rows("""
  SELECT label_binary, median(timestamp - event_time) median_lag, quantile_cont(timestamp-event_time, 0.95) p95
  FROM sig WHERE event_time IS NOT NULL AND NOT isnan(event_time) GROUP BY 1""")

# 10. Message length --------------------------------------------------------
R["message_length"] = rows("""
  SELECT label_binary, median(length(message_sanitized)) median_len, max(length(message_sanitized)) max_len
  FROM sig GROUP BY 1""")

# 11. Attack reports + graph ------------------------------------------------
rep_cols = [c["name"] for c in R["schemas"]["rep"]["columns"]]
R["attack_reports"] = rows(f"""
  SELECT count(*) n, count(DISTINCT incident_id) incidents,
         median(length(report_text)) median_chars, max(length(report_text)) max_chars
  FROM rep""")[0]
R["attack_reports_mo"] = rows("SELECT mo_name, count(*) n FROM rep GROUP BY 1 ORDER BY n DESC LIMIT 15")
R["attack_report_example"] = one("SELECT report_text FROM rep WHERE length(report_text) BETWEEN 600 AND 1500 LIMIT 1")
edg_cols = [c["name"] for c in R["schemas"]["edg"]["columns"]]
R["edge_types"] = rows("SELECT type, count(*) n FROM edg GROUP BY 1 ORDER BY n DESC") if "type" in edg_cols else []
R["node_types"] = rows("SELECT type, count(*) n FROM nod GROUP BY 1 ORDER BY n DESC") if "type" in [c["name"] for c in R["schemas"]["nod"]["columns"]] else []

R["_runtime_seconds"] = round(time.time() - t0, 1)
OUT.write_text(json.dumps(R, indent=2, default=str), encoding="utf-8")
print(f"wrote {OUT} in {R['_runtime_seconds']}s")
