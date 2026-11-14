# All-in-one demo case

One case that shows every part of Evidentia: the ML models, anomalies, model disagreement, detection rules
with learned thresholds, community Sigma rules, cross-file links, unseen log types, and the assistant.

## What to upload (one case, 4 files)

| File | Real or synthetic | Shows |
|---|---|---|
| `data/samples/witfoo_sample_asa_lines.log` | **Real** (WitFoo test period, never trained on) | ML predictions, anomalies, LR/RF disagreement |
| `data/demo_case/web01_auth.log` | **Synthetic** | A log type the models never saw; brute force, takeover, sudo, Sigma hits |
| `data/demo_case/firewall_dmz_extra.log` | **Synthetic** (real ASA format) | The compromised server scanning the internal network; the reverse-shell connection |
| `data/demo_case/analyst_notes.txt` | **Synthetic** | Non-log evidence linked to the logs |

The synthetic files are written by `scripts/make_demo_case.py`. They reuse two addresses that really appear in
the WitFoo log, so the case links across files: **100.64.37.4** (an outside address the real firewall shows
probing the DMZ) and **10.187.253.125** (a real DMZ server it probed, playing "web01" here).

Suggested case name: **DEMO: full attack story**

## The story (26 July 2024, UTC)

1. 20:57: 100.64.37.4 probes DMZ servers (real firewall records; ML: malicious).
2. 20:50–23:45: 203.0.113.77 guesses SSH passwords slowly, one try every 5 minutes.
3. 21:30–21:32: 100.64.37.4 guesses 40 SSH passwords on web01 in 2 minutes…
4. 21:32:05: …and logs in as `deploy`.
5. 21:32:20: `deploy` uses sudo to download and `chmod +x` a script from 198.51.100.7.
6. 21:33: web01 opens a reverse shell to 198.51.100.7:4444 (also allowed by the firewall).
7. 21:35: a hidden root account `backup2` is created.
8. 21:40: web01 scans 20 internal servers on port 22, looking for the next target.
9. 22:15–22:30: analyst notes: helpdesk ticket from `deploy`; 198.51.100.7 is a known malware server.

Normal noise: alice, bob, carol and dave log in from the office; bob mistypes his password once.

## Expected results

- **Overview:** 185 malicious and 2,822 suspicious (ML, real firewall data), 1 anomaly, 43 model
  disagreements, 10 detections.
- **Detections:** login after guessing, admin rights after login, file download, Sigma: shell commands,
  Sigma: reverse shell, Sigma: privileged user created, slow password guessing (203.0.113.77), password
  guessing (100.64.37.4, learned threshold), Sigma: /dev/tcp, internal scan from 10.187.253.125.
- **Records:** the SSH lines are mostly "not scored" or "benign": the models don't know this log type.
  This is where the rules take over.

## Demo script (about 5 minutes)

1. **Evidence:** 4 files, each with a SHA-256 hash; "Hash matches" proves nothing changed.
2. **Overview:** counters, then **Detections** from top to bottom. Point out a learned threshold
   ("typical source …") and a **Sigma** tag.
3. **Records:** filter *Malicious* → the real firewall records of 100.64.37.4; open one to show both
   models, the anomaly score and its links. Then search `deploy` → the SSH lines, "not scored".
4. **Connections:** focus on `100.64.37.4` → links from the real firewall log to the SSH log and the notes.
5. **Ask the case**:
   - `What did 100.64.37.4 do?`
   - `What happened on web01 and what should I do?`
   - `Is 198.51.100.7 involved?` (links the download, the reverse shell, the firewall and the notes)
6. **Model evaluation:** the five-model comparison, and why accuracy is misleading.

Say once, clearly: *"The firewall log is real WitFoo data; the SSH log, extra firewall lines and notes are
synthetic, written to show a full attack across several sources."*
