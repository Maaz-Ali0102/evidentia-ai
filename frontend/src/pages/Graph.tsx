import { ListFilter, Search, X } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api, fmtNum, fmtTime, type EventRow, type GraphData, type GraphNode } from "../api";
import { GraphView } from "../components/GraphView";
import { CLASS_FILL, ClassBadge, ErrorNote, Spinner } from "../components/ui";
import { useCase } from "./CaseLayout";

export function Graph() {
  const { caseId, openEvent, summary } = useCase();
  const nav = useNavigate();
  const [sp, setSp] = useSearchParams();
  const focus = sp.get("focus");
  const [data, setData] = useState<GraphData | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [sel, setSel] = useState<GraphNode | null>(null);
  const [rows, setRows] = useState<EventRow[] | null>(null);
  const [q, setQ] = useState(focus ?? "");

  useEffect(() => {
    setData(null); setErr(null);
    api.graph(caseId, focus ?? undefined).then((g) => {
      setData(g);
      setSel(focus ? g.nodes.find((n) => n.label === focus) ?? null : null);
    }).catch(setErr);
  }, [caseId, focus, summary.links]);
  useEffect(() => {
    setRows(null);
    if (sel?.type === "entity") api.events(caseId, { entity: sel.label, sort: "risk", limit: 25 }).then((r) => setRows(r.rows)).catch(setErr);
    if (sel?.type === "file") api.events(caseId, { file_id: sel.id.split(":")[1], sort: "risk", limit: 25 }).then((r) => setRows(r.rows)).catch(setErr);
  }, [sel, caseId]);

  return (
    <div className="grid">
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <form onSubmit={(e) => { e.preventDefault(); setSp(q.trim() ? { focus: q.trim() } : {}); }} style={{ display: "flex", gap: 6, flex: "1 1 360px", maxWidth: 520 }}>
          <label className="sr" htmlFor="g-q">Focus on an indicator</label>
          <input id="g-q" className="input" placeholder="Focus on an IP, domain, user or hash" value={q} onChange={(e) => setQ(e.target.value)} />
          <button className="btn"><Search size={15} />Focus</button>
        </form>
        {focus && <button className="btn ghost small" onClick={() => { setQ(""); setSp({}); }}><X size={14} />Show the whole case</button>}
        <div className="legend" style={{ marginLeft: "auto" }}>
          <span><i style={{ background: CLASS_FILL.malicious, borderRadius: "50%" }} />worst record malicious</span>
          <span><i style={{ background: CLASS_FILL.suspicious, borderRadius: "50%" }} />suspicious</span>
          <span><i style={{ background: CLASS_FILL.benign, borderRadius: "50%" }} />benign</span>
          <span><i style={{ background: CLASS_FILL["not applicable"], borderRadius: "50%" }} />not scored</span>
          <span><i style={{ background: "var(--p-ink)" }} />evidence file</span>
        </div>
      </div>
      <p className="small muted" style={{ marginTop: -6 }}>
        {focus ? <>Everything connected to <b className="mono">{focus}</b>: the records that contain it, the records the relationship mapper links to them, and the other indicators they carry.</>
               : <>The case's riskiest indicators, the files they appear in (dashed) and how often they occur together (solid, thicker = more often). Click a node to see its records; drag to rearrange; scroll to zoom.</>}
      </p>
      <ErrorNote error={err} />
      <div className="graph-layout">
        <div className="graph-wrap" style={{ flex: 1 }}>
          {!data ? <Spinner label="Laying out connections" /> : data.nodes.length === 0 ? <div className="empty">No indicators to connect yet.</div> :
            <GraphView data={data} selected={sel?.id ?? null} onSelect={setSel} />}
        </div>
        <aside className="panel graph-side" aria-live="polite">
          {!sel ? (
            <div className="panel-body">
              <h3>Select a node</h3>
              <p className="small muted" style={{ marginTop: 6 }}>An indicator's panel lists its records, riskiest first. Open any record to see its own links and the reasons for them.</p>
              {data && <p className="small" style={{ marginTop: 14 }}>{fmtNum(data.nodes.filter((n) => n.type === "entity").length)} indicators · {fmtNum(data.nodes.filter((n) => n.type === "file").length)} files · {fmtNum(data.edges.length)} connections shown</p>}
            </div>
          ) : (
            <>
              <div className="panel-head">
                <div style={{ minWidth: 0 }}>
                  <span className="eyebrow">{sel.type === "file" ? "evidence file" : sel.kind}</span>
                  <h3 className="mono" style={{ overflowWrap: "anywhere" }}>{sel.label}</h3>
                  {sel.type === "entity" && <p>{fmtNum(sel.events)} records · {sel.files} file{sel.files === 1 ? "" : "s"} · {fmtNum(sel.malicious)} malicious · {sel.anomalies} anomalies</p>}
                </div>
              </div>
              <div className="panel-body" style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {sel.type === "entity" && focus !== sel.label && <button className="btn small" onClick={() => { setQ(sel.label); setSp({ focus: sel.label }); }}>Focus here</button>}
                <button className="btn ghost small" onClick={() => nav(`/cases/${caseId}/events?${sel.type === "file" ? `file_id=${sel.id.split(":")[1]}` : `entity=${encodeURIComponent(sel.label)}`}&sort=risk`)}>
                  <ListFilter size={14} />All records</button>
              </div>
              {!rows ? <Spinner /> : (
                <div style={{ maxHeight: 460, overflowY: "auto" }}>
                  {rows.map((r) => (
                    <button key={r.event_id} className="link-item" style={{ borderLeft: 0, borderRight: 0, marginBottom: 0 }} onClick={() => openEvent(r.event_id)}>
                      <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                        <span className="mono small">{fmtTime(r.ts)} · {r.file}:{r.source_row}</span><ClassBadge cls={r.cls} />
                      </div>
                      <div className="msg" style={{ marginTop: 4, maxWidth: "100%" }}>{r.message}</div>
                    </button>
                  ))}
                </div>
              )}
            </>
          )}
        </aside>
      </div>
    </div>
  );
}
