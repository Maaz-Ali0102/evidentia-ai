"""Answer an investigator's question from retrieved case material, with citations.

Answer layout (both for Gemini and the built-in fallback):
  ## Answer               the direct answer
  ## Evidence             what the records themselves say            -> cites [E..]
  ## ML assessment        what the models predict (not proof)        -> cites [E..], [K..]
  ## Assessment           what most likely happened: the incident story, an inference from the
                          records and the detection-rule findings  -> cites [F..], [E..]
  ## Possible links       what the relationship mapper infers        -> cites [E..]
  ## Recommended actions  next steps for the analyst                 -> cites [F..], [E..]
  ## Unknown              what the retrieved material cannot settle
Citation ids that are not in the retrieved material are removed and reported.
"""
from __future__ import annotations

import json
import re
import time

from ..cases.store import CaseStore
from .llm import get_llm, llm_status
from .retrieve import retrieve

SYSTEM = """You are Evidentia, an assistant for digital-forensics investigators. You answer ONLY from the
case material in the prompt: case facts [S], evidence records [E<number>], detection-rule findings
[F<number>], relationship links, and knowledge notes [K<number>]. Never use outside knowledge about the case, never invent events, IPs,
times, counts or files.

Write in plain English for an investigator, in markdown, with exactly these sections:
## Answer
## Evidence
## ML assessment
## Assessment
## Possible links
## Recommended actions
## Unknown

Rules:
- Cite every factual sentence with the ids it rests on, e.g. [E12] or [E12][E40] or [S] or [K2].
- "Evidence" states only what records literally contain (times are UTC, file:row provenance).
- "ML assessment" reports model predictions as predictions, never as facts; mention their limits [K..].
- "Assessment" tells what most likely happened as a short story in time order (e.g. password guessing, then a
  successful login, then admin commands), naming the likely attack stage. It is an inference: use words like
  "likely" or "consistent with", and cite the findings [F..] and records [E..] it rests on. Findings come from
  fixed detection rules, not from the ML models. If nothing points to an attack, say so.
- "Possible links" are inferences of the relationship mapper; say why (shared indicator, time gap).
- "Recommended actions": 2 to 5 concrete next steps for the analyst, most urgent first, based on the findings'
  suggested actions and the records; cite what each rests on. They are suggestions, not actions taken.
- "Unknown" lists what the material cannot answer. If nothing relevant was retrieved, say so.
- Numbers for the whole case come from [S]; never count records yourself unless asked about the listed ones.
- A record marked "stands for N similar records" represents N records with the same text apart from numbers
  and addresses; report the count and time span (e.g. "40 failed logins in 2 minutes [E1][E40]").
- Records the models mark "not applicable" are still evidence: read their text and say what it shows,
  but never present that reading as a model prediction.
- Keep it under 350 words. Use short bullets."""

CITE = re.compile(r"\[(E\d+|K\d+|F\d+|S)\]")


def _context(r: dict) -> str:
    lines = ["CASE FACTS [S]:", json.dumps(r["facts"], indent=1, default=str), "", "EVIDENCE RECORDS:"]
    for e in r["events"]:
        ml = e["ml"]
        lines.append(f"[{e['id']}] {e['file']}:{e['row']} | {e['time_utc'] or 'no time'} UTC | type {e['artifact_type']} | "
                     + (f"LR={ml['class_lr']}" + (f" (p_mal {ml['p_malicious_lr']})" if ml["p_malicious_lr"] is not None else "")
                        + f" RF={ml['class_rf']} anomaly={ml['anomaly_flag']} | "
                        if ml["class_lr"] != "not applicable" else "models: not applicable (no score) | ")
                     + f"src {e['src_ip']} dst {e['dst_ip']}:{e['dst_port']} | {e['message']}"
                     + (f" | stands for {e['similar_events']} similar records, {e['similar_first_utc']} to "
                        f"{e['similar_last_utc']} UTC" if e.get("similar_events") else ""))
    if not r["events"]:
        lines.append("(no matching records)")
    lines += ["", "FINDINGS (fixed detection rules; inferences from the records, not ML predictions):"]
    for f in r.get("findings", []):
        lines.append(f"[{f['id']}] {f['severity'].upper()} {f['title']}: {f['summary']} Evidence: "
                     + " ".join(f"[E{e}]" for e in f["event_ids"]) + f" ({f['n_events']} records, {f['first_utc']} to "
                     f"{f['last_utc']} UTC). Possible ATT&CK: {f['tactic']}, {f['technique']}. "
                     + (f"Related: {', '.join(f['related'])}. " if f["related"] else "")
                     + "Suggested actions: " + " ".join(f["actions"]))
    if not r.get("findings"):
        lines.append("(no rule fired for this question)")
    lines += ["", "RELATIONSHIP LINKS (inferred by the mapper):"]
    for l in r["links"]:
        how = f"score {l['score']}" if l.get("score") is not None else "shares a rare indicator"
        lines.append(f"{l['from']} <-> {l['to']} {how} shared {', '.join(l['shared']) or 'none'} "
                     f"time gap {l['dt_seconds']} s")
    if not r["links"]:
        lines.append("(none)")
    lines += ["", "KNOWLEDGE:"] + [f"[{k['id']}] {k['title']}: {k['text']}" for k in r["knowledge"]]
    return "\n".join(lines)


def builtin_answer(question: str, r: dict, llm_failed: bool = False) -> str:
    f, qa, evs = r["facts"], r["analysis"], r["events"]
    c = f["classes"]
    focus = [e for e in evs if e["why_retrieved"] == "matches the question's filters"]
    lead = []
    if qa["intent"] == "count" or not evs:
        if "focus_matches" in r:
            lead.append(f"{r['focus_matches']:,} events match the question's filters [S].")
        lead.append(f"The case holds {f['events']:,} events: {c['malicious']:,} predicted malicious, "
                    f"{c['suspicious']:,} suspicious, {c['benign']:,} benign and {c['not applicable']:,} not scored [S].")
    if focus:
        lead.append(f"The most relevant matches are {' '.join('[' + e['id'] + ']' for e in focus[:5])}.")
    elif evs:
        lead.append(f"The closest records found are {' '.join('[' + e['id'] + ']' for e in evs[:5])}.")
    if f["top_ips_in_malicious_events"] and qa["intent"] in ("list", "general"):
        top = ", ".join(f"{t['ip']} ({t['malicious_events']})" for t in f["top_ips_in_malicious_events"][:5])
        lead.append(f"IPs most often seen in predicted-malicious events: {top} [S].")
    ev_lines, seen_templates = [], set()
    for e in evs:
        if len(ev_lines) >= 8:
            break
        if e.get("template_id") in seen_templates:
            continue  # another record with the same text pattern is already listed
        seen_templates.add(e.get("template_id"))
        line = f"- [{e['id']}] `{e['file']}:{e['row']}`, {e['time_utc'] or 'no time'} UTC: {e['message'][:160]}"
        if e.get("similar_events"):
            line += (f" (one of {e['similar_events']} similar records, {e['similar_first_utc'] or '?'} to "
                     f"{e['similar_last_utc'] or '?'} UTC)")
        ev_lines.append(line)
    ev_lines = ev_lines or ["- No record matched."]
    ml_lines = [f"- [{e['id']}]: Logistic Regression says **{e['ml']['class_lr']}**"
                + (f" (p={e['ml']['p_malicious_lr']})" if e['ml']['p_malicious_lr'] is not None else "")
                + f", Random Forest says {e['ml']['class_rf']}" + (", anomaly flag" if e["ml"]["anomaly_flag"] else "")
                for e in evs[:6] if e["ml"]["class_lr"] != "not applicable"]
    ml_lines.append("- These are predictions of WitFoo-style triage, not proof; malicious precision is about 0.3 [K1][K2].")
    link_lines = [f"- [{l['from']}] ↔ [{l['to']}]: shared {', '.join(l['shared']) or 'similar content'}, "
                  f"{l['dt_seconds']} s apart" + (f" (score {l['score']})" if l.get("score") is not None
                                                  else " (shared rare indicator)")
                  for l in r["links"][:5]] or ["- No links among the retrieved records."]
    unknown = ["- Whether any flagged activity succeeded or caused harm: the records show events, not outcomes.",
               ("- The language model did not answer in time, so this answer lists retrieved records instead of a "
                "written summary; ask again for a written one." if llm_failed else
                "- No language model is configured, so this answer lists retrieved records instead of a written summary.")]
    fs = r.get("findings", [])
    order = sorted(fs, key=lambda f: f["first_utc"] or "")
    assess = [f"- **{f['title']}** [{f['id']}]: {f['summary']} " + " ".join(f"[E{e}]" for e in f["event_ids"])
              + f" (possible ATT&CK: {f['tactic']})" for f in order] or \
             ["- No detection rule fired on the retrieved records, so nothing here points to a known attack pattern."]
    if any(f["severity"] == "high" for f in fs):
        assess.append("- Taken together, the records are consistent with an attack in progress; this is an inference "
                      "from fixed detection rules, not a confirmed incident.")
    actions, seen = [], set()
    for f in fs:  # most severe first
        for a in f["actions"]:
            if a not in seen and len(actions) < 5:
                seen.add(a)
                actions.append(f"- {a} [{f['id']}]")
    actions = actions or ["- Nothing specific: review the listed records and widen the question if needed."]
    if fs and not focus:
        lead.insert(0, f"Detection rules flagged {len(fs)} finding(s), most severe first: "
                    + " ".join(f"[{f['id']}]" for f in fs[:3]) + ".")
    return "\n".join(["## Answer", " ".join(lead) or "Nothing relevant was retrieved [S].", "", "## Evidence", *ev_lines, "",
                      "## ML assessment", *ml_lines, "", "## Assessment", *assess, "", "## Possible links", *link_lines, "",
                      "## Recommended actions", *actions, "", "## Unknown", *unknown])


def answer(store: CaseStore, case_id: str, question: str) -> dict:
    t0 = time.time()
    question = (question or "").strip()[:1000]
    r = retrieve(store, case_id, question)
    status = llm_status()
    warnings = []
    text = None
    if status["provider"] != "builtin":
        try:
            llm = get_llm()
            text = llm.generate(SYSTEM, f"QUESTION: {question}\n\nCASE MATERIAL:\n{_context(r)}")
            if llm.last_model and llm.last_model != status.get("model"):
                warnings.append(f"{status.get('model')} was busy; {llm.last_model} wrote this answer.")
                status = {**status, "model": llm.last_model}
        except Exception as e:
            warnings.append(f"Gemini call failed ({type(e).__name__}: {str(e)[:200]}); showing the built-in answer.")
            status = {**llm_status(), "provider": "builtin", "model": None, "external": False}
    if text is None:
        text = builtin_answer(question, r, llm_failed=bool(warnings))
    known = {e["id"] for e in r["events"]} | {k["id"] for k in r["knowledge"]} | {f["id"] for f in r["findings"]} | {"S"}
    bad = sorted({c for c in CITE.findall(text) if c not in known})
    if bad:
        text = CITE.sub(lambda m: m.group(0) if m.group(1) in known else "", text)
        warnings.append(f"Removed citations not present in the retrieved material: {', '.join(bad)}.")
    cited = set(CITE.findall(text))
    result = {
        "question": question, "answer_markdown": text,
        "citations": {"events": [e for e in r["events"] if e["id"] in cited],
                      "knowledge": [k for k in r["knowledge"] if k["id"] in cited],
                      "findings": [f for f in r["findings"] if f["id"] in cited]},
        "retrieved": {"events": len(r["events"]), "links": len(r["links"]), "knowledge": len(r["knowledge"]),
                      "findings": len(r["findings"]),
                      "focus_matches": r.get("focus_matches")},
        "analysis": r["analysis"], "llm": status, "warnings": warnings, "seconds": round(time.time() - t0, 2)}
    with store.db(case_id) as con:
        cur = con.execute("INSERT INTO chats(ts, question, answer) VALUES (?,?,?)",
                          (time.time(), question, json.dumps(result, default=str)))
        result["chat_id"] = cur.lastrowid
    return result
