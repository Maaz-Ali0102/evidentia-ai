"""Turn an uploaded file into normalised security-log events for the ML orchestrator.

Supported now: CSV, JSON (array or JSON-lines), and plain-text logs (.log/.txt), with
format-specific parsing for Cisco ASA syslog and AWS VPC flow-log lines. Other text lines get their
time from ISO 8601, Apache/nginx, YYYY/MM/DD or classic syslog stamps (_line_time).
Rules:
  * the original bytes are never modified; their SHA-256 is recorded;
  * every event keeps provenance (file name + row/line number);
  * a timestamp that cannot be read is left empty (never invented) and the event is
    reported as "not applicable" by the orchestrator.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

EVENT_COLS = ["timestamp", "message_sanitized", "message_type", "action", "protocol", "severity",
              "src_ip", "dst_ip", "src_port", "dst_port"]

ALIASES = {
    "timestamp": ["timestamp", "time", "ts", "@timestamp", "datetime", "date", "event_time", "eventtime",
                  "visit_time", "last_visit_time", "created", "created_at", "time_generated", "timecreated"],
    "message_sanitized": ["message_sanitized", "message", "msg", "raw", "log", "line", "text"],
    "message_type": ["message_type", "event_type", "type", "category"],
    "action": ["action", "disposition_action", "act"],
    "protocol": ["protocol", "proto"],
    "severity": ["severity", "level", "sev"],
    "src_ip": ["src_ip", "source_ip", "srcaddr", "src", "client_ip"],
    "dst_ip": ["dst_ip", "destination_ip", "dstaddr", "dst", "server_ip"],
    "src_port": ["src_port", "source_port", "srcport", "sport"],
    "dst_port": ["dst_port", "destination_port", "dstport", "dport"],
}
PROTO_NUM = {"tcp": "6", "udp": "17", "icmp": "1", "gre": "47"}
SYSLOG_SEV = {"0": "emergency", "1": "alert", "2": "critical", "3": "error", "4": "warning",
              "5": "notice", "6": "informational", "7": "debug"}

RE_ASA = re.compile(
    r"(?P<ts>[A-Z][a-z]{2} \d{1,2} \d{4} \d{2}:\d{2}:\d{2}).*?%ASA-(?P<sev>\d)-(?P<code>\d+): "
    r"(?P<act>Deny|Permit|Denied|Built|Teardown)\w* (?P<proto>tcp|udp|icmp)\b.*?"
    r"src \S*?:(?P<src>[\d.]+)(?:/(?P<sport>\d+))?.*?dst \S*?:(?P<dst>[\d.]+)(?:/(?P<dport>\d+))?", re.I)
RE_FLOW = re.compile(
    r"^\s*2 \S+ (?P<eni>eni-\S+) (?P<src>[\d.]+) (?P<dst>[\d.]+) (?P<sport>\d+) (?P<dport>\d+) "
    r"(?P<proto>\d+) \d+ \d+ (?P<start>\d{10}) (?P<end>\d{10}) (?P<act>ACCEPT|REJECT)")
RE_ISO = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
# Other common log time formats, tried in this order when a line has no ISO time:
RE_APACHE = re.compile(r"\[?(?P<d>\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2})(?: (?P<z>[+-]\d{4}))?")  # 10/Nov/2026:02:14:00 +0000
RE_SLASH = re.compile(r"\b(?P<d>\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})")                              # 2026/11/10 02:14:00
RE_SYSLOG_Y = re.compile(r"^(?:<\d+>)?(?P<d>[A-Z][a-z]{2} +\d{1,2} \d{4} \d{2}:\d{2}:\d{2})")         # Nov 10 2026 02:14:00
RE_SYSLOG = re.compile(r"^(?:<\d+>)?(?P<d>[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2})\b")              # Nov 10 02:14:00 (no year)
RE_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class ParsedUpload:
    file_name: str
    sha256: str
    size_bytes: int
    file_type: str
    events: pd.DataFrame
    warnings: list[str] = field(default_factory=list)
    parser_counts: dict = field(default_factory=dict)


def _to_epoch(series: pd.Series) -> pd.Series:
    """Numeric epoch (s or ms) or any parseable date string -> epoch seconds (UTC). Unparseable -> NaN."""
    num = pd.to_numeric(series, errors="coerce")
    out = num.where(num < 1e11, num / 1000.0)  # milliseconds -> seconds
    rest = out.isna() & series.notna()
    if rest.any():
        dt = pd.to_datetime(series[rest].astype(str), utc=True, errors="coerce", format="mixed")
        out.loc[rest] = (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()
    return out.astype(float)


def _line_time(line: str, now: pd.Timestamp | None = None) -> tuple[float, bool] | None:
    """Epoch seconds of the first recognised time in a free-text line, and whether its year was assumed.

    Classic syslog (RFC 3164) writes no year. Like rsyslog and journalctl, the year is taken as the
    current one, or the previous one when that would put the line more than a day in the future;
    parse_upload reports how many times were read this way.
    """
    m = RE_ISO.search(line)
    if m:
        t = pd.to_datetime(m.group(0), utc=True, errors="coerce")
        return (t.timestamp(), False) if pd.notna(t) else None
    m = RE_APACHE.search(line)
    if m:
        t = pd.to_datetime(m["d"] + (" " + m["z"] if m["z"] else " +0000"), format="%d/%b/%Y:%H:%M:%S %z", errors="coerce")
        return (t.timestamp(), False) if pd.notna(t) else None
    m = RE_SLASH.search(line)
    if m:
        t = pd.to_datetime(m["d"], format="%Y/%m/%d %H:%M:%S", utc=True, errors="coerce")
        return (t.timestamp(), False) if pd.notna(t) else None
    m = RE_SYSLOG_Y.search(line)
    if m:
        t = pd.to_datetime(re.sub(r" +", " ", m["d"]), format="%b %d %Y %H:%M:%S", utc=True, errors="coerce")
        return (t.timestamp(), False) if pd.notna(t) else None
    m = RE_SYSLOG.search(line)
    if m:
        now = now if now is not None else pd.Timestamp.now(tz="UTC")
        d = re.sub(r" +", " ", m["d"])
        t = pd.to_datetime(f"{now.year} {d}", format="%Y %b %d %H:%M:%S", utc=True, errors="coerce")
        if pd.notna(t) and t > now + pd.Timedelta(days=1):
            t = pd.to_datetime(f"{now.year - 1} {d}", format="%Y %b %d %H:%M:%S", utc=True, errors="coerce")
        return (t.timestamp(), True) if pd.notna(t) else None
    return None


def _parse_line(line: str, now: pd.Timestamp | None = None) -> tuple[dict, str]:
    m = RE_ASA.search(line)
    if m:
        ts = pd.to_datetime(m["ts"], format="%b %d %Y %H:%M:%S", utc=True)
        act = m["act"].lower()
        return {"timestamp": ts.timestamp(), "message_type": "firewall_action",
                "action": "block" if act.startswith("den") else "permit",
                "protocol": PROTO_NUM.get(m["proto"].lower(), m["proto"]), "severity": SYSLOG_SEV.get(m["sev"]),
                "src_ip": m["src"], "dst_ip": m["dst"], "src_port": m["sport"], "dst_port": m["dport"]}, "cisco_asa"
    m = RE_FLOW.search(line)
    if m:
        return {"timestamp": float(m["start"]), "message_type": "network_flow_data",
                "action": "block" if m["act"] == "REJECT" else "permit", "protocol": m["proto"],
                "src_ip": m["src"], "dst_ip": m["dst"], "src_port": m["sport"], "dst_port": m["dport"]}, "aws_vpc_flow"
    out = {}
    t = _line_time(line, now)
    if t is not None:
        out["timestamp"], assumed = t
        if assumed:
            out["_year_assumed"] = True
    ips = RE_IP.findall(line)
    if ips:
        out["src_ip"] = ips[0]
        if len(ips) > 1:
            out["dst_ip"] = ips[1]
    return out, "generic_text"


def _from_table(df: pd.DataFrame, column_map: dict | None = None) -> tuple[pd.DataFrame, dict]:
    lower = {c.lower(): c for c in df.columns}
    out = pd.DataFrame(index=df.index)
    mapping = {}
    for target, src in (column_map or {}).items():
        if target in ALIASES and src in df.columns:
            out[target] = df[src]
            mapping[target] = src
    for target, names in ALIASES.items():
        if target in mapping:
            continue
        src = next((lower[n] for n in names if n in lower and lower[n] not in mapping.values()), None)
        if src is not None:
            out[target] = df[src]
            mapping[target] = src
    # No message column (e.g. a browser-history export): build a searchable message from the
    # other text columns, "column=value | ...". It is marked as composed, never as the raw log line.
    if "message_sanitized" not in out:
        rest = [c for c in df.columns if c not in mapping.values()]
        if rest:
            def compose(r):
                return " | ".join(f"{c}={r[c]}" for c in rest if isinstance(r[c], str) and r[c].strip())
            out["message_sanitized"] = df.apply(compose, axis=1).replace("", np.nan)
            mapping["message_sanitized"] = "composed from: " + ", ".join(rest)
    # If a table only has a raw message column, try line parsing on it to recover fields.
    if "message_sanitized" in out:
        parsed = [_parse_line(str(m)) if isinstance(m, str) else ({}, "empty") for m in out["message_sanitized"]]
        fill = pd.DataFrame([p[0] for p in parsed], index=out.index).drop(columns="_year_assumed", errors="ignore")
        for c in fill.columns:
            if c not in out:
                out[c] = fill[c]
            else:
                out[c] = out[c].where(out[c].notna() & (out[c].astype(str) != ""), fill[c])
    return out, mapping


_RE_TAGS = re.compile(r"<[^>]+>")
_RE_DROP = re.compile(r"<(script|style|noscript)\b.*?</\1>", re.I | re.S)


def _html_lines(text: str) -> list[str]:
    import html as _html
    body = _RE_DROP.sub(" ", text)
    body = re.sub(r"<(br|p|div|li|tr|h\d)\b[^>]*>", "\n", body, flags=re.I)
    body = _html.unescape(_RE_TAGS.sub(" ", body))
    return [re.sub(r"\s+", " ", ln).strip() for ln in body.splitlines() if ln.strip()]


def parse_upload(file_name: str, data: bytes, column_map: dict | None = None) -> ParsedUpload:
    sha = hashlib.sha256(data).hexdigest()
    ext = file_name.rsplit(".", 1)[-1].lower() if "." in file_name else ""
    warnings: list[str] = []
    counts: dict = {}
    text = data.decode("utf-8", errors="replace")
    if "�" in text:
        warnings.append("Some bytes were not valid UTF-8 and were replaced.")
    if not text.strip():
        return ParsedUpload(file_name, sha, len(data), ext or "unknown", pd.DataFrame(columns=EVENT_COLS),
                            ["The file is empty."], {})

    if ext == "csv":
        raw = pd.read_csv(io.StringIO(text), dtype=str, keep_default_na=False, na_values=[""])
        ev, mapping = _from_table(raw, column_map)
        counts["columns_mapped"] = mapping
        counts["columns_available"] = list(raw.columns)
        extra = raw[[c for c in raw.columns if c not in mapping.values()]]
    elif ext in ("json", "jsonl", "ndjson"):
        try:
            obj = json.loads(text)
            records = obj if isinstance(obj, list) else obj.get("events") or obj.get("records") or [obj]
        except json.JSONDecodeError:
            records, bad = [], 0
            for ln in text.splitlines():
                if ln.strip():
                    try:
                        records.append(json.loads(ln))
                    except json.JSONDecodeError:
                        bad += 1
            if bad:
                warnings.append(f"{bad} JSON lines could not be parsed and were skipped.")
        raw = pd.json_normalize(records).astype(str).replace({"nan": np.nan, "None": np.nan})
        ev, mapping = _from_table(raw, column_map)
        counts["columns_mapped"] = mapping
        counts["columns_available"] = list(raw.columns)
        extra = raw[[c for c in raw.columns if c not in mapping.values()]]
    elif ext in ("log", "txt", "", "html", "htm"):
        rows, kinds = [], []
        lines = _html_lines(text) if ext in ("html", "htm") else text.splitlines()
        for ln in lines:
            if not ln.strip():
                continue
            fields, kind = _parse_line(ln)
            rows.append({"message_sanitized": ln, **fields})
            kinds.append(kind)
        ev = pd.DataFrame(rows)
        counts["line_formats"] = pd.Series(kinds).value_counts().to_dict()
        if "_year_assumed" in ev:
            n_assumed = int(ev.pop("_year_assumed").fillna(False).astype(bool).sum())
            if n_assumed:
                counts["year_assumed"] = n_assumed
                warnings.append(f"{n_assumed} syslog times carry no year; the current year was assumed "
                                "(the previous one where that would be in the future), as syslog tools do.")
        if "cisco_asa" in counts["line_formats"]:
            warnings.append("Cisco ASA syslog timestamps carry no time zone; they are the device's own clock and "
                            "are interpreted as UTC. Times may be offset from other sources.")
        extra = pd.DataFrame(index=ev.index)
    else:
        return ParsedUpload(file_name, sha, len(data), ext, pd.DataFrame(columns=EVENT_COLS),
                            [f"Unsupported file type '.{ext}'. Supported: csv, json, jsonl, ndjson, log, txt, html."], {})

    for c in EVENT_COLS:
        if c not in ev:
            ev[c] = np.nan
    ev["timestamp"] = _to_epoch(ev["timestamp"])
    missing_ts = int(ev["timestamp"].isna().sum())
    if "columns_mapped" in counts and "timestamp" not in counts["columns_mapped"]:
        warnings.append("No timestamp column was found, so no event can be scored. Accepted names: "
                        + ", ".join(ALIASES["timestamp"]) + ". Map a column by hand to fix this.")
        counts["missing_required"] = ["timestamp"]
    elif missing_ts:
        warnings.append(f"{missing_ts} of {len(ev)} events have no readable timestamp; they are kept but not scored.")
    ev = ev[EVENT_COLS].copy()
    ev.insert(0, "source_row", np.arange(1, len(ev) + 1))
    ev.insert(0, "source_file", file_name)
    # keep any extra columns (e.g. a reference label in the sample file) for display only
    for c in extra.columns:
        if c not in ev:
            ev[c] = extra[c].values
    return ParsedUpload(file_name, sha, len(data), ext or "txt", ev.reset_index(drop=True), warnings, counts)
