"""Deterministic detection rules: findings that work on ANY log, including log types the ML never saw.

The classifiers only know WitFoo-style firewall/flow records. These rules look for well-known attack
patterns in the text and indicators of every record, with fixed, documented thresholds, so each
finding can be explained and checked by hand:

  brute_force             an IP's failed logins within 10 minutes are far above this case's normal
  slow_brute_force        an IP's failed logins over the whole case are far above normal (spread out)
  brute_force_success     a successful login from that IP after the failures (within 30 minutes)
  privilege_after_login   sudo/su by the account that logged in that way (within 60 minutes)
  tool_download           a command line that downloads a file (wget, curl, certutil, ...)
  host_scan               an IP reaching far more hosts or ports in 10 minutes than this case's normal

Adaptive thresholds: "far above normal" is learned from each case. For every source IP the rule measures
its activity (e.g. its peak failed logins in any 10 minutes); the threshold is median + 5 x MAD over all
sources (MAD = median absolute deviation, a spread measure that a few attackers cannot inflate), never
below a fixed floor. With fewer than 5 sources there is nothing to learn from and a fixed default is used.
Each finding states the threshold, how it was set, and how far above normal the source was.

Community Sigma rules (evidentia/detect/sigma.py, sigma_rules/) run alongside these and add their findings.

A finding is an inference from records, not proof. ATT&CK tactics are given as "possible" labels.
Recommended actions are a fixed playbook per rule, filled with the finding's own indicators.
"""
from __future__ import annotations

import re

import numpy as np
import pandas as pd

# One failed attempt often writes several lines (sshd: "Invalid user", "authentication failure", "Failed
# password"). Attempts are counted from the primary line; the secondary lines only count for a source
# that has no primary line at all.
FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive|none)\b|Login failed|logon failure|"
                  r"An account failed to log on|\bEventID[=: ]+4625\b|failed login", re.I)
FAIL_SECONDARY = re.compile(r"authentication failure|\bInvalid user\b", re.I)
SUCCESS = re.compile(r"Accepted (?:password|publickey|keyboard-interactive)|session opened for user|Successful login|"
                     r"An account was successfully logged on|\bEventID[=: ]+4624\b|Login succeeded", re.I)
PRIV = re.compile(r"\bsudo\b.*\bCOMMAND=|\bsu\b.*(?:session opened|Successful su)|Special privileges assigned|"
                  r"\bEventID[=: ]+4672\b", re.I)
DOWNLOAD = re.compile(r"\b(?:wget|curl|Invoke-WebRequest|iwr|bitsadmin|tftp)\b|certutil\b.*urlcache", re.I)

BRUTE_WINDOW = 600                         # seconds
BRUTE = {"floor": 5, "default": 10}        # peak failed logins per source in BRUTE_WINDOW
SLOW = {"floor": 15, "default": 30}        # failed logins per source over the whole case
MIN_SOURCES, MAD_K = 5, 5.0
SUCCESS_AFTER = 1800                       # seconds after the last failure
PRIV_AFTER = 3600                          # seconds after the successful login
SCAN_WINDOW = 600
SCAN_HOSTS = {"floor": 8, "default": 10}   # peak distinct hosts per source in SCAN_WINDOW
SCAN_PORTS = {"floor": 15, "default": 20}  # peak distinct ports per source in SCAN_WINDOW
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def _utc(t: float | None) -> str | None:
    return None if t is None or pd.isna(t) else pd.to_datetime(t, unit="s", utc=True).strftime("%Y-%m-%d %H:%M:%S")


NOT_USERS = {"root", "invalid", "unknown", "user", "none", "illegal"}


def _users(ents: dict, eid: int) -> list[str]:
    return sorted(v for k, v in ents.get(eid, ()) if k == "user" and v.lower() not in NOT_USERS)


def learned_threshold(values, limits: dict) -> dict:
    """Threshold for 'far above this case's normal': median + MAD_K x MAD over all sources (MAD at least 1),
    never below limits['floor']; limits['default'] when there are fewer than MIN_SOURCES sources."""
    v = np.asarray(list(values), float)
    if len(v) < MIN_SOURCES:
        return {"value": limits["default"], "how": "default", "sources": int(len(v)), "typical": None}
    med = float(np.median(v))
    mad = float(np.median(np.abs(v - med))) * 1.4826
    return {"value": int(max(limits["floor"], np.ceil(med + MAD_K * max(mad, 1.0)))), "how": "learned",
            "sources": int(len(v)), "typical": med}


def _explain(t: dict, observed: float, unit: str) -> str:
    if t["how"] == "default":
        return (f" (threshold {t['value']} {unit}: fixed default, because only {t['sources']} source(s) are in this "
                "case, too few to learn what is normal)")
    times = f", {observed / t['typical']:.0f}x the typical source" if t["typical"] else ""
    return (f" (threshold {t['value']} {unit}, learned from {t['sources']} sources in this case; typical source: "
            f"{t['typical']:g}{times})")


def _peak_count(times: np.ndarray, window: float) -> int:
    best, i = 0, 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        best = max(best, j - i + 1)
    return best


def _burst(times: np.ndarray, n_min: int, window: float) -> tuple[int, int] | None:
    """Indexes (i, j) of the longest run of sorted times with >= n_min items inside `window` seconds."""
    best, i = None, 0
    for j in range(len(times)):
        while times[j] - times[i] > window:
            i += 1
        if j - i + 1 >= n_min and (best is None or j - i > best[1] - best[0]):
            best = (i, j)
    return best


def detect(ev: pd.DataFrame, ents: dict) -> list[dict]:
    """ev: event_id, ts, message, src_ip, dst_ip, dst_port. ents: event_id -> {(kind, value)}."""
    if ev.empty:
        return []
    ev = ev[ev["ts"].notna()].sort_values("ts", kind="stable")
    msg = ev["message"].fillna("")
    fail, ok, priv, dl = (msg.str.contains(p) for p in (FAIL, SUCCESS, PRIV, DOWNLOAD))
    fail2 = msg.str.contains(FAIL_SECONDARY) & ~fail
    with_primary = set(ev.loc[fail, "src_ip"].dropna())
    fail = fail | (fail2 & ~ev["src_ip"].isin(with_primary))
    findings: list[dict] = []

    def add(**f):
        findings.append(f)
        return f

    # Learn this case's normal login behaviour: every source that took part in logins, failures or not.
    auth_ips = set(ev.loc[(fail | fail2 | ok) & ev["src_ip"].notna(), "src_ip"])
    fails_by_ip = {ip: g["ts"].to_numpy(float) for ip, g in ev[fail & ev["src_ip"].notna()].groupby("src_ip")}
    peak = {ip: _peak_count(fails_by_ip.get(ip, np.array([])), BRUTE_WINDOW) for ip in auth_ips}
    t_burst = learned_threshold(peak.values(), BRUTE)
    t_slow = learned_threshold([len(fails_by_ip.get(ip, ())) for ip in auth_ips], SLOW)

    # 1-3: brute force -> success -> privilege use, followed per source IP
    for ip, g in ev[fail & ev["src_ip"].notna()].groupby("src_ip"):
        b = _burst(g["ts"].to_numpy(float), t_burst["value"], BRUTE_WINDOW)
        if b is None:
            if len(g) >= t_slow["value"]:  # spread out over time: no burst, but far more failures than normal
                t0, t1 = float(g["ts"].iloc[0]), float(g["ts"].iloc[-1])
                targets = sorted({u for e in g["event_id"] for u in _users(ents, int(e))})
                add(rule="slow_brute_force", severity="medium", title=f"Slow password guessing from {ip}",
                    tactic="Credential Access", technique="T1110 Brute Force",
                    summary=f"{len(g)} failed logins from {ip} spread over {(t1 - t0) / 60:.0f} min"
                            + (f", against {', '.join(targets[:5])}" if targets else "")
                            + _explain(t_slow, len(g), "failures per source") + ".",
                    event_ids=[int(g["event_id"].iloc[0]), int(g["event_id"].iloc[-1])], n_events=len(g),
                    first_utc=_utc(t0), last_utc=_utc(t1), indicators=[f"ip:{ip}"] + [f"user:{u}" for u in targets[:5]],
                    threshold=t_slow,
                    actions=[f"Block {ip}; slow guessing is designed to stay under per-minute limits.",
                             "Use lockout over longer periods (e.g. failures per day), not only per minute."])
            continue
        burst = g.iloc[b[0]:b[1] + 1]
        t0, t1 = float(burst["ts"].iloc[0]), float(burst["ts"].iloc[-1])
        targets = sorted({u for e in burst["event_id"] for u in _users(ents, int(e))})
        bf = add(rule="brute_force", severity="medium", title=f"Password guessing from {ip}",
                 tactic="Credential Access", technique="T1110 Brute Force",
                 summary=f"{len(burst)} failed logins from {ip} in {int(t1 - t0)} s"
                         + (f", against {', '.join(targets[:5])}" if targets else "")
                         + _explain(t_burst, len(burst), "per 10 min") + ".",
                 threshold=t_burst,
                 event_ids=[int(burst["event_id"].iloc[0]), int(burst["event_id"].iloc[-1])], n_events=len(burst),
                 first_utc=_utc(t0), last_utc=_utc(t1), indicators=[f"ip:{ip}"] + [f"user:{u}" for u in targets[:5]],
                 actions=[f"Block or rate-limit {ip} at the firewall.",
                          "Enable account lockout or fail2ban for the targeted service.",
                          "Check whether the targeted accounts exist and use strong passwords or keys."])
        wins = ev[ok & (ev["src_ip"] == ip) & (ev["ts"] > t0) & (ev["ts"] <= t1 + SUCCESS_AFTER)]
        if wins.empty:
            continue
        w = wins.iloc[0]
        users = _users(ents, int(w["event_id"]))
        who = users[0] if users else "an account"
        bs = add(rule="brute_force_success", severity="high", title=f"Login succeeded after password guessing: {who}",
                 tactic="Initial Access", technique="T1078 Valid Accounts",
                 summary=f"{ip} logged in as {who} {int(w['ts'] - t1)} s after {len(burst)} failed attempts. "
                         "The account is likely compromised.",
                 event_ids=[int(w["event_id"])], n_events=len(wins), first_utc=_utc(w["ts"]), last_utc=_utc(w["ts"]),
                 indicators=[f"ip:{ip}"] + [f"user:{u}" for u in users], related=[bf],
                 actions=[f"Treat {who} as compromised: disable it or reset its credentials and end its sessions.",
                          f"Block {ip}.",
                          f"Review everything {who} did after {_utc(w['ts'])} UTC."])
        for u in users:
            after = ev[priv & (ev["ts"] >= w["ts"]) & (ev["ts"] <= w["ts"] + PRIV_AFTER)]
            after = after[[u in _users(ents, int(e)) for e in after["event_id"]]]
            if after.empty:
                continue
            downloads = after[dl.loc[after.index]]
            p = after.iloc[0]
            add(rule="privilege_after_login", severity="high",
                title=f"{u} used admin rights right after the suspicious login",
                tactic="Privilege Escalation" + (", Command and Control" if len(downloads) else ""),
                technique="T1548 Abuse Elevation Control" + ("; T1105 Ingress Tool Transfer" if len(downloads) else ""),
                summary=f"{u} ran {len(after)} privileged command(s), the first {int(p['ts'] - w['ts'])} s after "
                        f"logging in from {ip}" + (", including a file download" if len(downloads) else "") + ".",
                event_ids=[int(e) for e in after["event_id"].iloc[:3]], n_events=len(after),
                first_utc=_utc(p["ts"]), last_utc=_utc(after["ts"].iloc[-1]),
                indicators=[f"user:{u}", f"ip:{ip}"], related=[bs],
                actions=["Preserve the host's logs and shell history before changing anything.",
                         "Check the host for new accounts, SSH keys, cron jobs or services (persistence).",
                         "Isolate the host if the commands cannot be explained."])

    # 4: file downloads from a command line (anywhere; marked when already part of a chain above)
    in_chain = {e for f in findings if f["rule"] == "privilege_after_login" for e in f["event_ids"]}
    for _, r in ev[dl].iterrows():
        urls = sorted(v for k, v in ents.get(int(r["event_id"]), ()) if k == "url")
        what = urls[0] if urls else "a remote file"
        add(rule="tool_download", severity="high" if int(r["event_id"]) in in_chain else "medium",
            title=f"File downloaded from the command line: {what}",
            tactic="Command and Control", technique="T1105 Ingress Tool Transfer",
            summary=f"A command downloaded {what}" + (" with admin rights" if PRIV.search(r["message"] or "") else "") + ".",
            event_ids=[int(r["event_id"])], n_events=1, first_utc=_utc(r["ts"]), last_utc=_utc(r["ts"]),
            indicators=[f"url:{u}" for u in urls],
            actions=[f"Do not run it; collect {what} (or its hash) for analysis.",
                     "Block the download host and search other hosts for the same URL or IP."])

    # 5: one source reaching many hosts or ports (network scans in firewall / flow logs)
    net = ev[ev["src_ip"].notna() & ev["dst_ip"].notna()]
    spread = {}
    for ip, g in net.groupby("src_ip"):
        ts_, h_, p_ = g["ts"].to_numpy(float), g["dst_ip"].to_numpy(), g["dst_port"].to_numpy()
        bh = bp = i = 0
        for j in range(len(ts_)):
            while ts_[j] - ts_[i] > SCAN_WINDOW:
                i += 1
            bh = max(bh, len(set(h_[i:j + 1])))
            bp = max(bp, len({x for x in p_[i:j + 1] if x is not None and x == x}))
        spread[ip] = (bh, bp)
    t_hosts = learned_threshold([v[0] for v in spread.values()], SCAN_HOSTS)
    t_ports = learned_threshold([v[1] for v in spread.values()], SCAN_PORTS)
    scans = []
    for ip, g in net.groupby("src_ip"):
        if spread[ip][0] < t_hosts["value"] and spread[ip][1] < t_ports["value"]:
            continue
        ts = g["ts"].to_numpy(float)
        hosts, ports = g["dst_ip"].to_numpy(), g["dst_port"].to_numpy()
        best = None
        i = 0
        for j in range(len(ts)):
            while ts[j] - ts[i] > SCAN_WINDOW:
                i += 1
            nh, npt = len(set(hosts[i:j + 1])), len({p for p in ports[i:j + 1] if p is not None and p == p})
            if (nh >= t_hosts["value"] or npt >= t_ports["value"]) and (best is None or nh + npt > best[2]):
                best = (i, j, nh + npt, nh, npt)
        if best:
            w = g.iloc[best[0]:best[1] + 1]
            scans.append((best[2], ip, w, best[3], best[4]))
    for _, ip, w, nh, npt in sorted(scans, key=lambda x: -x[0])[:5]:
        add(rule="host_scan", severity="medium", title=f"{ip} reached {nh} hosts / {npt} ports",
            tactic="Discovery", technique="T1046 Network Service Discovery",
            summary=f"{ip} contacted {nh} different hosts on {npt} different ports in "
                    f"{int(w['ts'].iloc[-1] - w['ts'].iloc[0])} s ({len(w)} records)"
                    + (_explain(t_hosts, nh, "hosts per 10 min") if nh >= t_hosts["value"]
                       else _explain(t_ports, npt, "ports per 10 min")) + ".",
            threshold=t_hosts if nh >= t_hosts["value"] else t_ports,
            event_ids=[int(w["event_id"].iloc[0]), int(w["event_id"].iloc[-1])], n_events=len(w),
            first_utc=_utc(w["ts"].iloc[0]), last_utc=_utc(w["ts"].iloc[-1]), indicators=[f"ip:{ip}"],
            actions=[f"If {ip} is external, block it; if internal, check that host for compromise.",
                     "Check whether any scanned host accepted the connection."])

    # community Sigma rules (evidentia/detect/sigma_rules), run on the same records
    from .sigma import run_sigma
    sig, _ = run_sigma(ev, ents)
    findings.extend(sig)

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["first_utc"] or ""))
    for n, f in enumerate(findings, 1):
        f["id"] = f"F{n}"
    for f in findings:  # replace object links by ids now that ids exist
        f["related"] = [r["id"] for r in f.get("related", [])]
    return findings
