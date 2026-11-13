import { CloudUpload, HardDrive, Loader2, SendHorizontal } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, type AskResult, type LlmStatus } from "../api";
import { Markdown } from "../components/Markdown";
import { ErrorNote, Spinner } from "../components/ui";
import { useCase } from "./CaseLayout";

const SUGGEST = [
  "Which IPs look malicious, and why?",
  "How many malicious events are there in each file?",
  "What happened after 21:05?",
  "Which events do the two models disagree on?",
  "Show the anomalies and what they are linked to.",
  "How far can I trust a 'malicious' prediction?",
];

export function Ask() {
  const { caseId, files, openEvent } = useCase();
  const [thread, setThread] = useState<AskResult[] | null>(null);
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [llm, setLlm] = useState<LlmStatus | null>(null);
  const end = useRef<HTMLDivElement>(null);
  const processing = files.some((f) => f.status === "processing" || f.status === "linking");

  useEffect(() => { api.chats(caseId).then(setThread).catch(setErr); api.llm().then(setLlm).catch(() => null); }, [caseId]);
  useEffect(() => { end.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [thread?.length, busy]);

  const ask = async (question: string) => {
    if (!question.trim() || busy) return;
    setBusy(true); setErr(null); setQ("");
    try { const r = await api.ask(caseId, question.trim()); setThread((t) => [...(t ?? []), r]); }
    catch (x) { setErr(x); setQ(question); }
    finally { setBusy(false); }
  };
  const cite = (r: AskResult) => (id: string) => {
    const e = r.citations.events.find((x) => x.id === id);
    if (e) openEvent(e.event_id);
    else if (id.startsWith("F")) {
      const f = r.citations.findings?.find((x) => x.id === id);
      if (f) {
        const go = window.confirm(`${f.id} · ${f.severity.toUpperCase()} · ${f.title}\n\n${f.summary}\n\nPossible ATT&CK: ${f.tactic} (${f.technique})\n\nSuggested actions:\n- ${f.actions.join("\n- ")}\n\nOpen its first record?`);
        if (go && f.event_ids.length) openEvent(f.event_ids[0]);
      }
    } else if (id.startsWith("K")) {
      const k = r.citations.knowledge.find((x) => x.id === id);
      if (k) alert(`${k.title}\n\n${k.text}`);
    }
  };

  return (
    <div className="chat">
      <div>
        <div className="thread" aria-live="polite">
          {!thread && <Spinner />}
          {thread?.length === 0 && (
            <div className="panel"><div className="panel-body">
              <h2>Ask about this case</h2>
              <p className="muted" style={{ marginTop: 6 }}>
                Answers come only from this case's records, the model results stored at upload, the links between records and notes on the models' limits.
                Each answer separates what the records show, what the models predict and what is only inferred, and cites the records it uses. Click a citation to open the record.
              </p>
            </div></div>
          )}
          {thread?.map((r) => (
            <div key={r.chat_id} className="grid" style={{ gap: 10 }}>
              <div className="q">{r.question}</div>
              <article className="a md">
                <Markdown text={r.answer_markdown} onCite={cite(r)} />
                <div className="small muted" style={{ marginTop: 14, display: "flex", gap: 12, flexWrap: "wrap" }}>
                  <span>{r.llm.provider === "gemini" ? `Written by ${r.llm.model}` : "Assembled from records (no LLM)"}</span>
                  <span>{r.retrieved.events} records · {r.retrieved.links} links · {r.retrieved.knowledge} notes retrieved</span>
                  {r.retrieved.focus_matches != null && <span>{r.retrieved.focus_matches.toLocaleString()} records match the question's filters</span>}
                  <span>{r.seconds}s</span>
                </div>
                {r.warnings.map((w) => <div key={w} className="warn">{w}</div>)}
              </article>
            </div>
          ))}
          {busy && <div className="loading"><Loader2 className="spin" size={18} />Retrieving records and writing the answer</div>}
          <div ref={end} />
        </div>
        <ErrorNote error={err} />
        <form className="composer" onSubmit={(e) => { e.preventDefault(); ask(q); }}>
          <label className="sr" htmlFor="ask-q">Question</label>
          <textarea id="ask-q" className="input" rows={2} value={q} disabled={processing}
                    placeholder={processing ? "Wait until every file is processed" : "Ask a question about this case, e.g. what did 100.64.37.4 do?"}
                    onChange={(e) => setQ(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); ask(q); } }} />
          <button className="btn primary" disabled={busy || processing || q.trim().length < 2} aria-label="Ask"><SendHorizontal size={17} />Ask</button>
        </form>
      </div>
      <aside className="grid" style={{ position: "sticky", top: 16 }}>
        {llm && (
          <div className={`provider ${llm.external ? "ext" : "local"}`}>
            {llm.external ? <CloudUpload size={18} style={{ flex: "none" }} /> : <HardDrive size={18} style={{ flex: "none" }} />}
            <div><b>{llm.provider === "gemini" ? `Gemini · ${llm.model}` : "Built-in answers"}</b><div style={{ marginTop: 3 }}>{llm.note}</div></div>
          </div>
        )}
        <div className="panel">
          <div className="panel-head"><h3>Try asking</h3></div>
          <div className="panel-body suggest">
            {SUGGEST.map((s) => <button key={s} onClick={() => ask(s)} disabled={busy || processing}>{s}</button>)}
          </div>
        </div>
      </aside>
    </div>
  );
}
