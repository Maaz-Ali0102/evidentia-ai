"""Build a BLIND test of the classifiers from real ORG-0005 records (data/blind_test/).

Every record is REAL WitFoo data from ORG-0005's TEST period (after the 2024-07-27 00:00 UTC cut-off), so none
of it was used for training. The evidence files contain only the columns the app reads from any upload
(time, message, type, action, protocol, severity, IPs, ports): no label and no post-label column. The true
labels go to KEY_DO_NOT_UPLOAD/answer_key.csv, which only the scoring script (score_blind_test.py) reads.

  A  balanced       250 benign + 250 suspicious + 250 malicious, random over the whole test period.
                    Written twice: test_A_balanced.csv (structured) and test_A_balanced_raw.log (message
                    text only), to compare how much the structured columns help.
                    Harder than real use: the records are spread over ~6 hours, so the context features
                    (how active each IP was in the minutes before) see far fewer neighbours than in a full log.
  B  look-alikes    150 malicious + 150 suspicious whose message is the same text pattern (digits masked) as
                    some malicious message: only behaviour/context can separate them. No benign records.
  C  realistic      every record of the 20-minute test-period window with the most malicious records,
                    in its natural mix (mostly benign): real-world conditions, full context.

Upload each test as its own case. Usage:  python scripts/make_blind_test.py
"""
import re
from pathlib import Path

import duckdb
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
SIG = (ROOT / "data/raw/precinct6/signals/signals.parquet").as_posix()
OUT = ROOT / "data" / "blind_test"
KEY = OUT / "KEY_DO_NOT_UPLOAD"
CUTOFF = 1722038400                     # ORG-0005 cut-off, 2024-07-27 00:00 UTC (evidentia/ml/config.py)
SEED = 20261113
COLS = ["timestamp", "message_sanitized", "message_type", "action", "protocol", "severity",
        "src_ip", "dst_ip", "src_port", "dst_port"]


def template(m: str) -> str:
    return re.sub(r"\d+", "#", m or "")


def load() -> pd.DataFrame:
    df = duckdb.connect().execute(
        f"SELECT {', '.join(COLS)}, label_binary FROM '{SIG}' WHERE org_id = 'ORG-0005' AND timestamp >= {CUTOFF}"
    ).df()
    df["message_sanitized"] = df["message_sanitized"].fillna("").str.replace(r"[\r\n]+", " ", regex=True).str.strip()
    return df[df["message_sanitized"] != ""]


def write(name: str, test: str, part: pd.DataFrame, keys: list, raw: bool = False):
    part = part.sort_values("timestamp", kind="stable").reset_index(drop=True)
    if raw:
        (OUT / name).write_text("\n".join(part["message_sanitized"]) + "\n", encoding="utf-8")
    else:
        part[COLS].to_csv(OUT / name, index=False)
    keys.append(pd.DataFrame({"test": test, "file": name, "source_row": range(1, len(part) + 1),
                              "true_label": part["label_binary"], "message": part["message_sanitized"].str[:120]}))
    print(f"{name}: {len(part)} records {part['label_binary'].value_counts().to_dict()}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    KEY.mkdir(exist_ok=True)
    df = load()
    keys: list = []

    a = pd.concat([df[df.label_binary == c].sample(250, random_state=SEED) for c in ("benign", "suspicious", "malicious")])
    write("test_A_balanced.csv", "A", a, keys)
    write("test_A_balanced_raw.log", "A_raw", a, keys, raw=True)

    mal = df[df.label_binary == "malicious"]
    mal_t = set(mal["message_sanitized"].map(template))
    sus_like = df[(df.label_binary == "suspicious") & df["message_sanitized"].map(template).isin(mal_t)]
    b = pd.concat([mal.sample(150, random_state=SEED + 1), sus_like.sample(150, random_state=SEED + 1)])
    write("test_B_lookalikes.csv", "B", b, keys)

    w = (df[df.label_binary == "malicious"]["timestamp"] // 1200).value_counts()
    start = int(w.index[0]) * 1200
    c = df[(df.timestamp >= start) & (df.timestamp < start + 1200)]
    write("test_C_realistic_20min.csv", "C", c, keys)

    pd.concat(keys).to_csv(KEY / "answer_key.csv", index=False)
    (OUT / "README.md").write_text(__doc__.split("Upload each")[0].strip() + f"""

## How to run the test

1. Create one case per test and upload ONLY that test's file(s):
   - `test_A_balanced.csv` and `test_A_balanced_raw.log` (two cases, or one case per file)
   - `test_B_lookalikes.csv`
   - `test_C_realistic_20min.csv` (window starts {pd.to_datetime(start, unit='s', utc=True)}; ~1-2 min to process)
2. Never upload anything from `KEY_DO_NOT_UPLOAD/`.
3. Score a case (server running):  `.venv\\Scripts\\python scripts\\score_blind_test.py <case-id>`
   The case id is the last part of the case's address, e.g. `blind-test-a-1a2b3c`.
""", encoding="utf-8")
    print("answer key:", KEY / "answer_key.csv")


if __name__ == "__main__":
    main()
