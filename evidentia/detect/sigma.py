"""A small Sigma rule engine: run community detection rules (https://github.com/SigmaHQ/sigma) on a case.

Sigma is the open, vendor-neutral format SOC teams use to share detection rules. This engine supports the
subset that fits Evidentia's records (see sigma_rules/README.md): keyword lists and simple field selections
with wildcards and the contains / startswith / endswith / re / all modifiers, combined with and / or / not /
brackets / "1 of x*" / "all of x*" / "them". Anything else makes the rule "unsupported": it is skipped and
reported, never guessed.

Every rule that matches becomes one finding: the rule's title, level, ATT&CK tags, author and id, how many
records matched and when, with the first and last matching records as evidence.
"""
from __future__ import annotations

import fnmatch
import re
from functools import lru_cache
from pathlib import Path

import pandas as pd
import yaml

RULES_DIR = Path(__file__).with_name("sigma_rules")
LEVEL = {"critical": "high", "high": "high", "medium": "medium", "low": "low", "informational": "low"}
FIELDS = {  # Sigma field name (lower case) -> Evidentia column
    "message": "message", "keywords": "message", "commandline": "message", "command": "message",
    "src_ip": "src_ip", "sourceip": "src_ip", "source.ip": "src_ip", "src": "src_ip",
    "dst_ip": "dst_ip", "destinationip": "dst_ip", "destination.ip": "dst_ip", "dst": "dst_ip",
    "dst_port": "dst_port", "destinationport": "dst_port", "destination.port": "dst_port",
    "action": "action", "protocol": "protocol", "severity": "severity", "message_type": "message_type",
}
TACTICS = {"reconnaissance", "resource-development", "initial-access", "execution", "persistence",
           "privilege-escalation", "defense-evasion", "credential-access", "discovery", "lateral-movement",
           "collection", "command-and-control", "exfiltration", "impact"}


class Unsupported(ValueError):
    pass


def _body(value, modifier: str | None) -> str:
    """A Sigma value as a regex body for an unanchored, case-insensitive search. Sigma wildcards: * and ?.
    Leading/trailing * are dropped (a search already matches anywhere); keeping them as .* makes every
    search scan the whole line from each position, which is very slow on large cases."""
    v = str(value)
    if modifier == "re":
        return v
    parts = []
    for ch in v:
        parts.append(".*?" if ch == "*" else "." if ch == "?" else re.escape(ch))
    body = "".join(parts)
    while body.startswith(".*?"):
        body = body[3:]
    while body.endswith(".*?"):
        body = body[:-3]
    if modifier == "startswith":
        body = "^" + body
    elif modifier == "endswith":
        body = body + "$"
    return body


def _match_values(series: pd.Series, values, modifiers: list[str]) -> pd.Series:
    values = values if isinstance(values, list) else [values]
    mod = next((m for m in modifiers if m in ("contains", "startswith", "endswith", "re")), None)
    if any(m not in ("contains", "startswith", "endswith", "re", "all") for m in modifiers):
        raise Unsupported(f"modifier {modifiers}")
    if not values:
        return pd.Series(False, index=series.index)
    bodies = [_body(v, mod) for v in values]
    if "all" not in modifiers:  # any value: one combined search per item
        return series.str.contains(re.compile("|".join(f"(?:{b})" for b in bodies), re.I | re.S), na=False)
    out = pd.Series(True, index=series.index)
    for b in bodies:
        out &= series.str.contains(re.compile(b, re.I | re.S), na=False)
    return out


def _item(ev: pd.DataFrame, text: pd.Series, item) -> pd.Series:
    """One named detection item: a keyword list, an {'|all': [...]} keyword block, or a field map."""
    if isinstance(item, (list, str, int)):
        return _match_values(text, item, [])
    if isinstance(item, dict):
        out = pd.Series(True, index=ev.index)
        for key, values in item.items():
            name, *mods = str(key).split("|")
            if name == "":  # keyword block with modifiers, e.g. '|all'
                out &= _match_values(text, values, mods)
                continue
            col = FIELDS.get(name.lower())
            if col is None:
                raise Unsupported(f"field {name}")
            if col != "message" and col not in ev:
                raise Unsupported(f"field {name} is not stored for these records")
            series = text if col == "message" else ev[col].fillna("").astype(str)
            out &= _match_values(series, values, mods)
        return out
    raise Unsupported(f"detection item of type {type(item).__name__}")


_TOKEN = re.compile(r"\(|\)|\band\b|\bor\b|\bnot\b|\b1 of\b|\ball of\b|[A-Za-z0-9_*\-]+", re.I)


def _condition(cond: str, items: dict[str, pd.Series]) -> pd.Series:
    """Evaluate a Sigma condition over the boolean series of the named items (recursive descent)."""
    toks = _TOKEN.findall(cond)
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def group(pattern: str) -> list[pd.Series]:
        names = list(items) if pattern == "them" else [n for n in items if fnmatch.fnmatch(n, pattern)]
        if not names:
            raise Unsupported(f"no detection item matches '{pattern}'")
        return [items[n] for n in names]

    def atom():
        t = peek()
        if t == "(":
            take()
            v = expr()
            if take() != ")":
                raise Unsupported("unbalanced brackets")
            return v
        if t == "not":
            take()
            return ~atom()
        if t in ("1 of", "all of"):
            take()
            parts = group(take())
            out = parts[0]
            for p in parts[1:]:
                out = (out | p) if t == "1 of" else (out & p)
            return out
        name = take()
        if name not in items:
            raise Unsupported(f"condition uses '{name}'")
        return items[name]

    def conj():
        v = atom()
        while peek() == "and":
            take()
            v = v & atom()
        return v

    def expr():
        v = conj()
        while peek() == "or":
            take()
            v = v | conj()
        return v

    if "|" in cond or "count(" in cond or " by " in cond:
        raise Unsupported("aggregation conditions")
    result = expr()
    if pos != len(toks):
        raise Unsupported(f"could not read condition '{cond}'")
    return result


@lru_cache(maxsize=1)
def load_rules() -> tuple:
    rules = []
    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
                if isinstance(doc, dict) and "detection" in doc:
                    rules.append({**doc, "_file": path.relative_to(RULES_DIR).as_posix()})
        except yaml.YAMLError as e:
            rules.append({"title": path.name, "_file": path.name, "_error": f"invalid YAML: {e}"})
    return tuple(rules)


def _attack(tags: list) -> tuple[str, str]:
    tactics, techniques = [], []
    for t in tags or []:
        t = str(t).lower()
        if not t.startswith("attack."):
            continue
        v = t[7:]
        if v in TACTICS:
            tactics.append(v.replace("-", " ").title().replace("And", "and"))
        elif re.fullmatch(r"t\d{4}(\.\d{3})?", v):
            techniques.append(v.upper())
    return ", ".join(tactics) or "Not tagged", "; ".join(techniques) or "Not tagged"


def rules_status() -> dict:
    """What the Sigma engine has loaded (for the API / UI)."""
    probe = pd.DataFrame([{**{c: "" for c in set(FIELDS.values())}, "event_id": 0, "ts": 0.0}])
    _, bad = run_sigma(probe, {})
    rules = load_rules()
    return {"folder": str(RULES_DIR), "loaded": len(rules), "unsupported": bad,
            "rules": [{"title": r.get("title"), "level": r.get("level"), "file": r["_file"]} for r in rules]}


def run_sigma(ev: pd.DataFrame, ents: dict) -> tuple[list[dict], list[dict]]:
    """Findings for every bundled rule that matches, and the list of rules that could not be run."""
    if ev.empty:
        return [], []
    ev = ev[ev["ts"].notna()].sort_values("ts", kind="stable") if ev["ts"].notna().any() else ev
    text = ev["message"].fillna("").astype(str)
    findings, unsupported = [], []
    for rule in load_rules():
        if "_error" in rule:
            unsupported.append({"rule": rule["title"], "file": rule["_file"], "reason": rule["_error"]})
            continue
        det = dict(rule["detection"])
        cond = det.pop("condition", None)
        try:
            if not isinstance(cond, str):
                raise Unsupported("missing or multiple conditions")
            items = {name: _item(ev, text, item) for name, item in det.items() if name != "timeframe"}
            hit = _condition(cond, items)
        except (Unsupported, KeyError, re.error) as e:
            unsupported.append({"rule": rule.get("title"), "file": rule["_file"], "reason": str(e)})
            continue
        m = ev[hit]
        if m.empty:
            continue
        tactic, technique = _attack(rule.get("tags"))
        ips = pd.concat([m["src_ip"], m["dst_ip"]]).dropna().value_counts().index[:3].tolist()
        first, last = m.iloc[0], m.iloc[-1]
        fp = [str(x) for x in (rule.get("falsepositives") or []) if str(x).lower() != "unknown"]
        refs = [str(r) for r in (rule.get("references") or [])][:1]
        findings.append({
            "rule": f"sigma:{rule.get('id', rule['_file'])}", "source": "sigma",
            "severity": LEVEL.get(str(rule.get("level", "medium")).lower(), "medium"),
            "title": f"Sigma: {rule.get('title', rule['_file'])}",
            "tactic": tactic, "technique": technique,
            "summary": f"{len(m)} record(s) match the community Sigma rule \"{rule.get('title')}\": "
                       f"{str(rule.get('description', '')).strip().rstrip('.')}. Rule by {rule.get('author', 'unknown')} "
                       f"(SigmaHQ, DRL 1.1).",
            "event_ids": sorted({int(first["event_id"]), int(last["event_id"])}), "n_events": int(len(m)),
            "first_utc": _utc(first["ts"]), "last_utc": _utc(last["ts"]),
            "indicators": [f"ip:{i}" for i in ips],
            "actions": [f"Review the {len(m)} matching record(s) and confirm whether the activity was authorised."]
                       + ([f"Known false positives for this rule: {'; '.join(fp)}."] if fp else [])
                       + ([f"Rule background: {refs[0]}"] if refs else []),
        })
    return findings, unsupported


def _utc(t) -> str | None:
    return None if t is None or pd.isna(t) else pd.to_datetime(t, unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S")
