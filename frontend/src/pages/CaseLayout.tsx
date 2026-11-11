import { FileUp, GitFork, LayoutDashboard, ListFilter, Loader2, MessageSquareText, Trash2 } from "lucide-react";
import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { NavLink, Outlet, useNavigate, useParams } from "react-router-dom";
import { api, fmtNum, fmtTime, type CaseSummary, type EvidenceFile } from "../api";
import { EventInspector } from "../components/EventInspector";
import { ErrorNote, Spinner } from "../components/ui";

interface Ctx {
  caseId: string; summary: CaseSummary; files: EvidenceFile[]; refresh: () => void;
  openEvent: (id: number) => void; showEntity: (value: string) => void;
}
const CaseCtx = createContext<Ctx | null>(null);
export const useCase = () => useContext(CaseCtx)!;

export function CaseLayout() {
  const { caseId = "" } = useParams();
  const nav = useNavigate();
  const [summary, setSummary] = useState<CaseSummary | null>(null);
  const [files, setFiles] = useState<EvidenceFile[]>([]);
  const [err, setErr] = useState<unknown>(null);
  const [eventId, setEventId] = useState<number | null>(null);

  const refresh = useCallback(() => {
    Promise.all([api.case(caseId), api.files(caseId)]).then(([s, f]) => { setSummary(s); setFiles(f); }).catch(setErr);
  }, [caseId]);
  useEffect(() => { refresh(); }, [refresh]);
  const busy = files.some((f) => f.status === "processing" || f.status === "linking");
  useEffect(() => {
    if (!busy) return;
    const t = setInterval(refresh, 1500);
    return () => clearInterval(t);
  }, [busy, refresh]);

  if (err) return <div className="page"><ErrorNote error={err} /></div>;
  if (!summary) return <Spinner label="Opening case" />;

  const ctx: Ctx = {
    caseId, summary, files, refresh, openEvent: setEventId,
    showEntity: (v) => { setEventId(null); nav(`/cases/${caseId}/graph?focus=${encodeURIComponent(v)}`); },
  };
  const del = async () => {
    if (!confirm(`Delete the case "${summary.name}" and its stored evidence copies? This cannot be undone.`)) return;
    await api.deleteCase(caseId);
    nav("/");
  };
  const [t0, t1] = summary.time_span;
  return (
    <CaseCtx.Provider value={ctx}>
      <header className="case-head">
        <div className="inner">
          <div className="case-top">
            <div>
              <span className="eyebrow">Case</span>
              <h1>{summary.name}</h1>
              <div className="case-meta">
                <span>{fmtNum(summary.files)} evidence files</span>
                <span>{fmtNum(summary.events)} records</span>
                {t0 != null && <span className="mono">{fmtTime(t0, true)} → {fmtTime(t1, true)} UTC</span>}
                {busy && <span style={{ color: "var(--c-anomaly)", display: "inline-flex", gap: 6, alignItems: "center" }}><Loader2 size={14} className="spin" />Processing evidence</span>}
              </div>
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button className="btn primary" onClick={() => nav(`/cases/${caseId}/evidence`)}><FileUp size={16} />Add evidence</button>
              <button className="icon-btn" onClick={del} aria-label="Delete case" title="Delete case"><Trash2 size={17} /></button>
            </div>
          </div>
          <nav className="tabs" aria-label="Case sections">
            <NavLink to="" end><LayoutDashboard size={16} />Overview</NavLink>
            <NavLink to="evidence"><FileUp size={16} />Evidence <span className="count">{summary.files}</span></NavLink>
            <NavLink to="events"><ListFilter size={16} />Records <span className="count">{fmtNum(summary.events)}</span></NavLink>
            <NavLink to="graph"><GitFork size={16} />Connections <span className="count">{fmtNum(summary.links)}</span></NavLink>
            <NavLink to="ask"><MessageSquareText size={16} />Ask the case</NavLink>
          </nav>
        </div>
      </header>
      <section className="page wrap enter" key={caseId}>
        <Outlet />
      </section>
      {eventId != null && (
        <EventInspector caseId={caseId} eventId={eventId} onClose={() => setEventId(null)} onOpen={setEventId} onEntity={ctx.showEntity} />
      )}
    </CaseCtx.Provider>
  );
}
