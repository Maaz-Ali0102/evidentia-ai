"""Answer an investigator's question from retrieved case material, with citations.

Answer layout (both for Gemini and the built-in fallback):
  ## Answer             the direct answer
  ## Evidence           what the records themselves say            -> cites [E..]
  ## ML assessment      what the models predict (not proof)        -> cites [E..], [K..]
  ## Possible links     what the relationship mapper infers        -> cites [E..]
  ## Unknown            what the retrieved material cannot settle
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
case material in the prompt: case facts [S], evidence records [E<number>], relationship links, and
knowledge notes [K<number>]. Never use outside knowledge about the case, never invent events, IPs,
times, counts or files.

Write in plain English for an investigator, in markdown, with exactly these sections:
## Answer
## Evidence
## ML assessment
## Possible links
## Unknown

Rules:
- Cite every factual sentence with the ids it rests on, e.g. [E12] or [E12][E40] or [S] or [K2].
- "Evidence" states only what records literally contain (times are UTC, file:row provenance).
- "ML assessment" reports model predictions as predictions, never as facts; mention their limits [K..].
- "Possible links" are inferences of the relationship mapper; say why (shared indicator, time gap).
- "Unknown" lists what the material cannot answer. If nothing relevant was retrieved, say so.
- Numbers for the whole case come from [S]; never count records yourself unless asked about the listed ones.
- Keep it under 250 words. Use short bullets."""

CITE = re.compile(r"\[(E\d+|K\d+|S)\]")


def _context(r: dict) -> str:
    lines = ["CASE FACTS [S]:", json.dumps(r["facts"], indent=1, default=str), "", "EVIDENCE RECORDS:"]
    for e in r["events"]:
        ml = e["ml"]
        lines.append(f"[{e['id']}] {e['file']}:{e['row']} | {e['time_utc'] or 'no time'} UTC | type {e['artifact_type']} | "
                     f"LR={ml['class_lr']} (p_mal {ml['p_malicious_lr']}) RF={ml['class_rf']} anomaly={ml['anomaly_flag']} | "
                     f"src {e['src_ip']} dst {e['dst_ip']}:{e['dst_port']} | {e['message']}")
    if not r["events"]:
        lines.append("(no matching records)")
    lines += ["", "RELATIONSHIP LINKS (inferred by the mapper):"]
    for l in r["links"]:
        lines.append(f"{l['from']} <-> {l['to']} score {l['score']} shared {', '.join(l['shared']) or 'none'} "
                     f"time gap {l['dt_seconds']} s")
    if not r["links"]:
        lines.append("(none)")
    lines += ["", "KNOWLEDGE:"] + [f"[{k['id']}] {k['title']}: {k['text']}" for k in r["knowledge"]]
    return "\n".join(lines)


def builtin_answer(question: str, r: dict) -> str:
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
    ev_lines = [f"- [{e['id']}] `{e['file']}:{e['row']}`, {e['time_utc'] or 'no time'} UTC: {e['message'][:160]}"
                for e in evs[:6]] or ["- No record matched."]
    ml_lines = [f"- [{e['id']}]: Logistic Regression says **{e['ml']['class_lr']}**"
                + (f" (p={e['ml']['p_malicious_lr']})" if e['ml']['p_malicious_lr'] is not None else "")
                + f", Random Forest says {e['ml']['class_rf']}" + (", anomaly flag" if e["ml"]["anomaly_flag"] else "")
                for e in evs[:6] if e["ml"]["class_lr"] != "not applicable"]
    ml_lines.append("- These are predictions of WitFoo-style triage, not proof; malicious precision is about 0.3 [K1][K2].")
    link_lines = [f"- [{l['from']}] ↔ [{l['to']}]: shared {', '.join(l['shared']) or 'similar content'}, "
                  f"{l['dt_seconds']} s apart (score {l['score']})" for l in r["links"][:5]] or ["- No links among the retrieved records."]
    unknown = ["- Whether any flagged activity succeeded or caused harm: the records show events, not outcomes.",
               "- No language model is configured, so this answer lists retrieved records instead of a written summary."]
    return "\n".join(["## Answer", " ".join(lead) or "Nothing relevant was retrieved [S].", "", "## Evidence", *ev_lines, "",
                      "## ML assessment", *ml_lines, "", "## Possible links", *link_lines, "", "## Unknown", *unknown])


def answer(store: CaseStore, case_id: str, question: str) -> dict:
    t0 = time.time()
    question = (question or "").strip()[:1000]
    r = retrieve(store, case_id, question)
    status = llm_status()
    warnings = []
    text = None
    if status["provider"] != "builtin":
        try:
            text = get_llm().generate(SYSTEM, f"QUESTION: {question}\n\nCASE MATERIAL:\n{_context(r)}")
        except Exception as e:
            warnings.append(f"Gemini call failed ({type(e).__name__}: {str(e)[:200]}); showing the built-in answer.")
            status = {**llm_status(), "provider": "builtin", "model": None, "external": False}
    if text is None:
        text = builtin_answer(question, r)
    known = {e["id"] for e in r["events"]} | {k["id"] for k in r["knowledge"]} | {"S"}
    bad = sorted({c for c in CITE.findall(text) if c not in known})
    if bad:
        text = CITE.sub(lambda m: m.group(0) if m.group(1) in known else "", text)
        warnings.append(f"Removed citations not present in the retrieved material: {', '.join(bad)}.")
    cited = set(CITE.findall(text))
    result = {
        "question": question, "answer_markdown": text,
        "citations": {"events": [e for e in r["events"] if e["id"] in cited],
                      "knowledge": [k for k in r["knowledge"] if k["id"] in cited]},
        "retrieved": {"events": len(r["events"]), "links": len(r["links"]), "knowledge": len(r["knowledge"]),
                      "focus_matches": r.get("focus_matches")},
        "analysis": r["analysis"], "llm": status, "warnings": warnings, "seconds": round(time.time() - t0, 2)}
    with store.db(case_id) as con:
        cur = con.execute("INSERT INTO chats(ts, question, answer) VALUES (?,?,?)",
                          (time.time(), question, json.dumps(result, default=str)))
        result["chat_id"] = cur.lastrowid
    return result
