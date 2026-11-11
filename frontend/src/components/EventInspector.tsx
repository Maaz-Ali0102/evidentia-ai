import { ArrowUpRight, FileText, Link2, X } from "lucide-react";
import { Fragment, useEffect, useRef, useState } from "react";
import { api, fmtTime, type EventDetail } from "../api";
import { AnomalyBadge, ClassBadge, ErrorNote, ProbBar, Spinner } from "./ui";

const MODEL_LABEL = { logreg: "Logistic Regression", random_forest: "Random Forest" } as const;

export function EventInspector({ caseId, eventId, onClose, onOpen, onEntity }: {
  caseId: string; eventId: number; onClose: () => void; onOpen: (id: number) => void; onEntity: (value: string) => void;
}) {
  const [d, setD] = useState<EventDetail | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    setD(null); setErr(null);
    api.event(caseId, eventId).then(setD).catch(setErr);
  }, [caseId, eventId]);
  useEffect(() => {
    closeRef.current?.focus();
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", k);
    return () => window.removeEventListener("keydown", k);
  }, [onClose]);

  const ml = d?.ml;
  const scored = ml?.applicable === 1;
  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-label={`Event E${eventId}`}>
        <div className="drawer-head">
          <div>
            <span className="eyebrow">Event E{eventId}</span>
            {d && <h2 style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <ClassBadge cls={scored ? ml!.detail.classifiers.logreg.predicted_class : "not applicable"} />
              {ml?.an_flag ? <AnomalyBadge /> : null}
              <span className="mono muted" style={{ fontSize: 13 }}>{fmtTime(d.ts, true)} UTC</span>
            </h2>}
          </div>
          <button ref={closeRef} className="icon-btn" onClick={onClose} aria-label="Close event"><X size={18} /></button>
        </div>
        <ErrorNote error={err} />
        {!d && !err && <Spinner />}
        {d && (
          <>
            <section>
              <h3>Raw record</h3>
              <div className="raw">{d.message ?? "(no message text)"}</div>
              <dl className="kv" style={{ marginTop: 12 }}>
                <dt>Source</dt><dd className="mono"><FileText size={13} style={{ verticalAlign: -2 }} /> {d.file} : row {d.source_row}</dd>
                <dt>File SHA-256</dt><dd className="hash">{d.sha256}</dd>
                <dt>Evidence type</dt><dd>{d.artifact_type?.replace("_", " ")}</dd>
                {d.message_type && <><dt>Event type</dt><dd className="mono">{d.message_type}{d.action ? ` · ${d.action}` : ""}</dd></>}
                {(d.src_ip || d.dst_ip) && <><dt>Connection</dt><dd className="mono">{d.src_ip ?? "?"}{d.src_port ? `:${d.src_port}` : ""} → {d.dst_ip ?? "?"}{d.dst_port ? `:${d.dst_port}` : ""}{d.protocol ? ` (proto ${d.protocol})` : ""}</dd></>}
                {Object.entries(d.extra).map(([k, v]) => <Fragment key={k}><dt>{k.replace(/_/g, " ")}</dt><dd>{String(v)}</dd></Fragment>)}
              </dl>
            </section>

            <section>
              <h3>What the models say</h3>
              {!ml && <p className="muted">No model output stored.</p>}
              {ml && !scored && <p className="muted">Not scored: {ml.reason}. The models only judge records that look like the security logs they were trained on.</p>}
              {ml && scored && (
                <>
                  <div className="models">
                    {(["logreg", "random_forest"] as const).map((m) => {
                      const c = ml.detail.classifiers[m];
                      return (
                        <div className="model-card" key={m}>
                          <h4>{MODEL_LABEL[m]}</h4>
                          <ClassBadge cls={c.predicted_class} />
                          <div className="small muted" style={{ margin: "10px 0 4px" }}>Alert (stage 1) {c.p_alert_stage1.toFixed(3)}</div>
                          <ProbBar value={c.p_alert_stage1} threshold={0.5} color="var(--c-suspicious-fill)" />
                          <div className="small muted" style={{ margin: "10px 0 4px" }}>Malicious given alert {c.p_malicious_given_alert_stage2.toFixed(3)}</div>
                          <ProbBar value={c.p_malicious_given_alert_stage2} threshold={c.stage2_threshold} color="var(--c-malicious)" />
                        </div>
                      );
                    })}
                  </div>
                  <p className="small muted" style={{ marginTop: 10 }}>
                    Black tick = decision threshold. {ml.agree ? "Both models agree." : "The models disagree; treat this event with extra care."}{" "}
                    Probabilities are not calibrated. {ml.detail.label_semantics}
                  </p>
                  <div style={{ marginTop: 12 }}>
                    <span className="small"><b>Anomaly detector:</b> </span>
                    <span className="small muted">
                      {ml.detail.anomaly.scored ? `score ${ml.detail.anomaly.score?.toFixed(3)} (flag at ${ml.detail.anomaly.threshold.toFixed(3)}) ${ml.detail.anomaly.flagged ? "· flagged" : ""}` : "not scored"} · {ml.detail.anomaly.meaning}
                    </span>
                  </div>
                  {ml.detail.notes.length > 0 && <ul className="small" style={{ marginTop: 10, paddingLeft: 18 }}>{ml.detail.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
                </>
              )}
            </section>

            <section>
              <h3>Indicators in this record</h3>
              {d.entities.length === 0 && <p className="muted small">No IPs, domains, users, hashes or paths found.</p>}
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {d.entities.map((e) => (
                  <button key={e.kind + e.value} className="chip" onClick={() => onEntity(e.value)} title={`Seen in ${e.seen} records. Open in the graph.`}>
                    <span className="tag">{e.kind}</span><span className="mono">{e.value}</span><span className="muted small">{e.seen}</span>
                  </button>
                ))}
              </div>
            </section>

            <section>
              <h3><Link2 size={15} style={{ verticalAlign: -2 }} /> Linked records</h3>
              <p className="small muted" style={{ marginBottom: 10 }}>Inferred by the relationship mapper from a shared indicator or similar content, ranked by closeness in time. A link is a lead, not proof.</p>
              {d.links.length === 0 && <p className="muted small">No links for this record.</p>}
              {d.links.map((l) => l.event && (
                <button key={l.other} className="link-item" onClick={() => onOpen(l.other)}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 8, alignItems: "center" }}>
                    <span className="mono small">E{l.other} · {l.event.file}:{l.event.source_row}</span>
                    <span style={{ display: "flex", gap: 6, alignItems: "center" }}><ClassBadge cls={l.event.cls} /><ArrowUpRight size={14} /></span>
                  </div>
                  <div className="msg" style={{ marginTop: 6, maxWidth: "100%" }}>{l.event.message}</div>
                  <div className="signals">
                    <span>score {l.score.toFixed(2)}</span>
                    <span>{l.dt == null ? "no time" : `${l.dt.toFixed(0)} s apart`}</span>
                    <span>content {l.semantic.toFixed(2)}</span>
                    {l.shared.length > 0 && <span>shared {l.shared.join(", ")}</span>}
                  </div>
                </button>
              ))}
            </section>
          </>
        )}
      </aside>
    </>
  );
}
