import { AlertOctagon, AlertTriangle, CircleDashed, GitFork, Shuffle, Sparkles } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, fmtNum } from "../api";
import { TimelineChart } from "../components/TimelineChart";
import { CLASS_FILL, ErrorNote, Spinner, Stat } from "../components/ui";
import { useCase } from "./CaseLayout";

export function Overview() {
  const { caseId, summary, files } = useCase();
  const nav = useNavigate();
  const [tl, setTl] = useState<Awaited<ReturnType<typeof api.timeline>> | null>(null);
  const [ents, setEnts] = useState<Awaited<ReturnType<typeof api.entities>> | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [benign, setBenign] = useState(false);
  const span = summary.time_span[0] != null ? (summary.time_span[1]! - summary.time_span[0]) : 0;
  const bucket = span > 86400 * 2 ? 3600 : span > 7200 ? 300 : 60;

  useEffect(() => {
    api.timeline(caseId, "lr", bucket).then(setTl).catch(setErr);
    api.entities(caseId, "", 12).then(setEnts).catch(setErr);
  }, [caseId, summary.events, summary.links, bucket]);

  const go = (q: string) => nav(`/cases/${caseId}/events?${q}`);
  if (summary.events === 0) {
    return (
      <div className="panel"><div className="empty">
        <h3>This case has no records yet</h3>
        <p>Add evidence files to start. Processing a 20,000-line log takes about a minute.</p>
        <button className="btn primary" onClick={() => nav(`/cases/${caseId}/evidence`)}>Add evidence</button>
      </div></div>
    );
  }
  const c = summary.classes;
  return (
    <div className="grid">
      <div className="stats">
        <Stat label="Predicted malicious" icon={<AlertOctagon size={14} color="var(--c-malicious)" />} value={fmtNum(c.malicious)}
              note="open the list" onClick={() => go("cls=malicious&sort=risk")} />
        <Stat label="Suspicious" icon={<AlertTriangle size={14} color="var(--c-suspicious)" />} value={fmtNum(c.suspicious)} onClick={() => go("cls=suspicious&sort=risk")} />
        <Stat label="Benign" value={fmtNum(c.benign)} onClick={() => go("cls=benign")} />
        <Stat label="Not scored" icon={<CircleDashed size={14} />} value={fmtNum(c["not applicable"])} note="not a security log" onClick={() => go("cls=not+applicable")} />
        <Stat label="Anomalies" icon={<Sparkles size={14} color="var(--c-anomaly)" />} value={fmtNum(summary.anomalies)} onClick={() => go("anomaly=1")} />
        <Stat label="Models disagree" icon={<Shuffle size={14} />} value={fmtNum(summary.disagreements)} onClick={() => go("disagree=1")} />
        <Stat label="Links between records" icon={<GitFork size={14} />} value={fmtNum(summary.links)} onClick={() => nav(`/cases/${caseId}/graph`)} />
      </div>
      <ErrorNote error={err} />
      <div className="grid cols-2">
        <section className="panel">
          <div className="panel-head">
            <div>
              <h2>Activity over time</h2>
              <p>Records per {bucket >= 3600 ? "hour" : bucket >= 300 ? "5 minutes" : "minute"} (UTC), coloured by the Logistic Regression's prediction. Triangles mark anomalies.</p>
            </div>
            <div className="seg" role="group" aria-label="Classes shown">
              <button aria-pressed={!benign} onClick={() => setBenign(false)}>Alerts</button>
              <button aria-pressed={benign} onClick={() => setBenign(true)}>All</button>
            </div>
          </div>
          <div className="panel-body">
            {!tl ? <Spinner /> : (
              <>
                <TimelineChart histogram={tl.histogram} bucket={tl.bucket} showBenign={benign}
                               anomalies={tl.alerts.filter((a) => a.an_flag).map((a) => a.ts)}
                               onPick={(t0, t1) => go(`t0=${t0}&t1=${t1}&sort=risk`)} />
                <div className="legend" style={{ marginTop: 8 }}>
                  {benign && <span><i style={{ background: CLASS_FILL.benign }} />Benign</span>}
                  <span><i style={{ background: CLASS_FILL.suspicious }} />Suspicious</span>
                  <span><i style={{ background: CLASS_FILL.malicious }} />Malicious</span>
                  <span><i style={{ background: "var(--c-anomaly)" }} />Anomaly</span>
                </div>
              </>
            )}
          </div>
        </section>
        <section className="panel">
          <div className="panel-head"><div><h2>Indicators to look at first</h2><p>Ranked by malicious predictions, anomalies and alerts.</p></div></div>
          {!ents ? <Spinner /> : ents.length === 0 ? <div className="empty">No indicators extracted.</div> : (
            <div className="table-wrap"><table>
              <thead><tr><th>Indicator</th><th className="num">Malicious</th><th className="num">Records</th><th className="num">Files</th></tr></thead>
              <tbody>{ents.map((e) => (
                <tr key={e.kind + e.value} className="click" onClick={() => nav(`/cases/${caseId}/graph?focus=${encodeURIComponent(e.value)}`)}>
                  <td><span className="tag">{e.kind}</span> <span className="mono">{e.value}</span></td>
                  <td className="num" style={{ color: e.malicious ? "var(--c-malicious)" : undefined }}>{fmtNum(e.malicious)}</td>
                  <td className="num">{fmtNum(e.events)}</td>
                  <td className="num">{e.files}</td>
                </tr>))}
              </tbody>
            </table></div>
          )}
        </section>
      </div>
      <section className="panel">
        <div className="panel-head"><div><h2>Evidence files</h2><p>What each file contributed.</p></div>
          <button className="btn ghost small" onClick={() => nav(`/cases/${caseId}/evidence`)}>Manage evidence</button></div>
        <div className="table-wrap"><table>
          <thead><tr><th>File</th><th>Type</th><th>Status</th><th className="num">Records</th><th className="num">Scored</th></tr></thead>
          <tbody>{files.map((f) => (
            <tr key={f.file_id} className="click" onClick={() => go(`file_id=${f.file_id}`)}>
              <td className="mono">{f.name}</td><td>{f.artifact_type?.replace("_", " ") ?? "…"}</td><td>{f.status}</td>
              <td className="num">{fmtNum(f.n_events)}</td>
              <td className="num">{f.n_events ? `${Math.round((f.n_applicable / f.n_events) * 100)}%` : "–"}</td>
            </tr>))}
          </tbody>
        </table></div>
      </section>
    </div>
  );
}
