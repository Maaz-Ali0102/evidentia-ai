"""Create clearly labelled SAMPLE files for the demo app (data/samples/).

1. witfoo_sample_ORG-0005_test_20min.csv
   A contiguous 20-minute slice of ORG-0005's TEST window (after the 2024-07-27 00:00 UTC cut-off),
   so none of these rows were used for training. Only event columns are exported, plus
   `reference_label_witfoo` (WitFoo's automated label) for comparison in the app; the models never read it.
2. witfoo_sample_asa_lines.log
   The raw Cisco ASA lines from the same slice, as a plain-text log (no labels), to demonstrate line parsing.
3. synthetic_non_security_notes.txt
   A few hand-written, obviously synthetic lines (browser-history / notes style). They demonstrate
   that the applicability gate refuses text the models were not trained on.
"""
from pathlib import Path

import duckdb

ROOT = Path(__file__).resolve().parents[1]
SIG = (ROOT / "data/raw/precinct6/signals/signals.parquet").as_posix()
OUT = ROOT / "data" / "samples"
OUT.mkdir(parents=True, exist_ok=True)

START = 1722045600  # 2024-07-27 02:00:00 UTC, inside ORG-0005's test window (cut-off 2024-07-27 00:00 UTC)
END = START + 20 * 60

con = duckdb.connect()
df = con.execute(f"""
    SELECT timestamp, message_sanitized, message_type, action, protocol, severity,
           src_ip, dst_ip, src_port, dst_port, label_binary AS reference_label_witfoo
    FROM '{SIG}' WHERE org_id = 'ORG-0005' AND timestamp >= {START} AND timestamp < {END}
    ORDER BY timestamp""").df()
df["message_sanitized"] = df["message_sanitized"].fillna("").str.replace("\n", " ", regex=False).str.strip()
df.to_csv(OUT / "witfoo_sample_ORG-0005_test_20min.csv", index=False)
print("csv rows", len(df), df["reference_label_witfoo"].value_counts().to_dict())

asa = df[df["message_sanitized"].str.contains("%ASA-", regex=False)]["message_sanitized"]
(OUT / "witfoo_sample_asa_lines.log").write_text("\n".join(asa) + "\n", encoding="utf-8")
print("asa lines", len(asa))

(OUT / "synthetic_non_security_notes.txt").write_text(
    "SYNTHETIC SAMPLE - not real evidence\n"
    "2024-07-27T02:05:11Z User visited https://example.org/recipes in Chrome\n"
    "2024-07-27T02:06:40Z Downloaded holiday_photos.zip from https://example.net/share\n"
    "2024-07-27T02:07:02Z Meeting notes: discuss quarterly budget with finance team\n"
    "screenshot_ocr: Invoice total due 400 USD\n", encoding="utf-8")
print("wrote", OUT)
