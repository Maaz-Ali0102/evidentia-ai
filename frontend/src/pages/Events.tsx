import { ChevronLeft, ChevronRight, Search, Sparkles, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, fmtNum, fmtTime, type Cls, type EventRow } from "../api";
import { AnomalyBadge, ClassBadge, ErrorNote, Spinner } from "../components/ui";
import { useCase } from "./CaseLayout";

const CLASSES: { v: Cls; label: string }[] = [
  { v: "malicious", label: "Malicious" }, { v: "suspicious", label: "Suspicious" }, { v: "benign", label: "Benign" }, { v: "not applicable", label: "Not scored" }];
const PAGE = 100;

export function Events() {
  const { caseId, files, openEvent, summary } = useCase();
  const [sp, setSp] = useSearchParams();
  const [data, setData] = useState<{ total: number; rows: EventRow[] } | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [q, setQ] = useState(sp.get("q") ?? "");

  const cls = sp.getAll("cls");
  const model = sp.get("model") ?? "lr";
  const offset = Number(sp.get("offset") ?? 0);
  const set = (k: string, v: string | string[] | null) => {
    const n = new URLSearchParams(sp);
    n.delete(k);
    if (Array.isArray(v)) v.forEach((x) => n.append(k, x)); else if (v) n.set(k, v);
    if (k !== "offset") n.delete("offset");
    setSp(n, { replace: true });
  };

  useEffect(() => {
    setData(null);
    api.events(caseId, {
      model, cls, file_id: sp.get("file_id") ?? undefined, q: sp.get("q") ?? undefined, entity: sp.get("entity") ?? undefined,
      anomaly: sp.get("anomaly") === "1", disagree: sp.get("disagree") === "1", t0: sp.get("t0") ?? undefined, t1: sp.get("t1") ?? undefined,
      sort: sp.get("sort") ?? "time", offset, limit: PAGE,
    }).then(setData).catch(setErr);
  }, [caseId, sp.toString(), summary.events]);

  const toggle = (v: string) => set("cls", cls.includes(v) ? cls.filter((c) => c !== v) : [...cls, v]);
  const active = ["file_id", "entity", "anomaly", "disagree", "t0", "q"].some((k) => sp.get(k)) || cls.length > 0;
  return (
    <section className="panel">
      <div className="filters" role="group" aria-label="Filters">
        {CLASSES.map((c) => <button key={c.v} className="chip" aria-pressed={cls.includes(c.v)} onClick={() => toggle(c.v)}>{c.label}</button>)}
        <button className="chip" aria-pressed={sp.get("anomaly") === "1"} onClick={() => set("anomaly", sp.get("anomaly") === "1" ? null : "1")}><Sparkles size={14} />Anomalies</button>
        <button className="chip" aria-pressed={sp.get("disagree") === "1"} onClick={() => set("disagree", sp.get("disagree") === "1" ? null : "1")}>Models disagree</button>
        <form onSubmit={(e) => { e.preventDefault(); set("q", q.trim() || null); }} style={{ display: "flex", gap: 6, flex: "1 1 200px", minWidth: 0 }}>
          <label className="sr" htmlFor="ev-q">Search record text</label>
          <input id="ev-q" className="input" placeholder="Search text, e.g. 106023 or a port" value={q} onChange={(e) => setQ(e.target.value)} style={{ minHeight: 32, padding: "4px 10px" }} />
          <button className="btn ghost small" aria-label="Search"><Search size={15} /></button>
        </form>
      </div>
      <div className="filters">
        <label className="sr" htmlFor="ev-file">File</label>
        <select id="ev-file" className="input" style={{ width: "auto", maxWidth: "100%", minHeight: 32, padding: "4px 8px" }} value={sp.get("file_id") ?? ""} onChange={(e) => set("file_id", e.target.value || null)}>
          <option value="">All files</option>
          {files.map((f) => <option key={f.file_id} value={f.file_id}>{f.name}</option>)}
        </select>
        <label className="sr" htmlFor="ev-sort">Sort</label>
        <select id="ev-sort" className="input" style={{ width: "auto", minHeight: 32, padding: "4px 8px" }} value={sp.get("sort") ?? "time"} onChange={(e) => set("sort", e.target.value)}>
          <option value="time">Oldest first</option><option value="risk">Riskiest first</option><option value="row">File order</option>
        </select>
        <div className="seg" role="group" aria-label="Classifier shown">
          <button aria-pressed={model === "lr"} onClick={() => set("model", null)}>Logistic Regression</button>
          <button aria-pressed={model === "rf"} onClick={() => set("model", "rf")}>Random Forest</button>
        </div>
        {sp.get("entity") && <span className="pill">{sp.get("entity")}<button className="icon-btn" aria-label="Remove indicator filter" onClick={() => set("entity", null)}><X size={13} /></button></span>}
        {sp.get("t0") && <span className="pill">{fmtTime(Number(sp.get("t0")))}–{fmtTime(Number(sp.get("t1")))} UTC
          <button className="icon-btn" aria-label="Remove time filter" onClick={() => { const n = new URLSearchParams(sp); n.delete("t0"); n.delete("t1"); setSp(n); }}><X size={13} /></button></span>}
        {active && <button className="link-btn small" onClick={() => { setQ(""); setSp(new URLSearchParams(model === "rf" ? { model: "rf" } : {})); }}>Clear filters</button>}
        <span className="small muted" style={{ marginLeft: "auto" }}>{data ? `${fmtNum(data.total)} records` : ""}</span>
      </div>
      <ErrorNote error={err} />
      {!data ? <Spinner /> : data.rows.length === 0 ? <div className="empty">No record matches these filters.</div> : (
        <div className="table-wrap">
          <table>
            <thead><tr><th>Time (UTC)</th><th>Prediction</th><th className="num">p(mal)</th><th>Connection</th><th>Record</th><th>Source</th></tr></thead>
            <tbody>
              {data.rows.map((r) => (
                <tr key={r.event_id} className="click" tabIndex={0} onClick={() => openEvent(r.event_id)} onKeyDown={(e) => e.key === "Enter" && openEvent(r.event_id)}>
                  <td className="mono small">{fmtTime(r.ts)}</td>
                  <td><div style={{ display: "flex", gap: 4, flexWrap: "wrap" }}><ClassBadge cls={r.cls} />{r.an_flag ? <AnomalyBadge /> : null}
                    {r.applicable === 1 && !r.agree && <span className="badge b-plain" title="The other classifier predicts a different class">≠</span>}</div></td>
                  <td className="num mono small">{r.applicable === 1 ? (model === "rf" ? r.rf_p_mal : r.lr_p_mal)?.toFixed(2) : "–"}</td>
                  <td className="mono small" style={{ whiteSpace: "nowrap" }}>{r.src_ip || r.dst_ip ? `${r.src_ip ?? "?"} → ${r.dst_ip ?? "?"}${r.dst_port ? `:${r.dst_port}` : ""}` : "–"}</td>
                  <td><div className="msg">{r.message}</div></td>
                  <td className="mono small muted" style={{ whiteSpace: "nowrap" }}>{r.file}:{r.source_row}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && data.total > PAGE && (
        <div className="pager">
          <span>{fmtNum(offset + 1)}–{fmtNum(Math.min(offset + PAGE, data.total))} of {fmtNum(data.total)}</span>
          <div style={{ display: "flex", gap: 6 }}>
            <button className="btn ghost small" disabled={offset === 0} onClick={() => set("offset", String(Math.max(0, offset - PAGE)))}><ChevronLeft size={15} />Previous</button>
            <button className="btn ghost small" disabled={offset + PAGE >= data.total} onClick={() => set("offset", String(offset + PAGE))}>Next<ChevronRight size={15} /></button>
          </div>
        </div>
      )}
    </section>
  );
}
