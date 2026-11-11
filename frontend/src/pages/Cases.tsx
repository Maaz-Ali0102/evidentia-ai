import { ArrowRight, FlaskConical, Plus } from "lucide-react";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, fmtNum, type CaseSummary } from "../api";
import { ErrorNote, Spinner } from "../components/ui";

export function Cases() {
  const nav = useNavigate();
  const [cases, setCases] = useState<CaseSummary[] | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [name, setName] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.cases().then(setCases).catch(setErr); }, []);

  const create = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;
    setBusy(true);
    try { const c = await api.createCase(name.trim()); nav(`/cases/${c.id}/evidence`); } catch (x) { setErr(x); setBusy(false); }
  };
  const sample = async () => {
    setBusy(true);
    try {
      const c = await api.createCase("Sample investigation: firewall + browser notes", "Bundled WitFoo test-window samples and a synthetic notes file.");
      await api.addSamples(c.id);
      nav(`/cases/${c.id}`);
    } catch (x) { setErr(x); setBusy(false); }
  };

  return (
    <section className="page wrap enter">
      <div className="page-head">
        <div>
          <span className="eyebrow">Investigate</span>
          <h1>Cases</h1>
          <p>A case holds the evidence files of one investigation. Each file is hashed and kept read-only; every record keeps its file and row.</p>
        </div>
        <form onSubmit={create} style={{ display: "flex", gap: 8, flex: "0 1 440px", minWidth: 0 }}>
          <div className="field" style={{ flex: 1 }}>
            <label htmlFor="case-name">New case</label>
            <div style={{ display: "flex", gap: 8 }}>
              <input id="case-name" className="input" placeholder="e.g. Finance server, July" value={name} onChange={(e) => setName(e.target.value)} />
              <button className="btn primary" disabled={busy || !name.trim()}><Plus size={16} />Create case</button>
            </div>
          </div>
        </form>
      </div>
      <ErrorNote error={err} />
      {!cases && !err && <Spinner />}
      {cases && cases.length === 0 && (
        <section className="hero-empty">
          <div className="copy">
            <span className="eyebrow">No cases yet</span>
            <h2>Triage a firewall log in about two minutes</h2>
            <p className="lead">Open the sample case: 20,357 records from WitFoo's held-out test window, a raw Cisco ASA log and a notes file the models must refuse. Nothing leaves this machine.</p>
            <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
              <button className="btn primary" onClick={sample} disabled={busy}><FlaskConical size={16} />Open the sample case</button>
            </div>
          </div>
          <div className="steps">
            <ol>
              <li><b>01</b><span><strong>Add evidence.</strong> CSV, JSON, log, text or HTML. Hashed with SHA-256 on arrival.</span></li>
              <li><b>02</b><span><strong>Read the triage.</strong> Two classifiers and an anomaly detector score every security-log record.</span></li>
              <li><b>03</b><span><strong>Follow connections.</strong> Shared IPs, domains and users link records across files.</span></li>
              <li><b>04</b><span><strong>Ask the case.</strong> Answers cite the exact records they rest on.</span></li>
            </ol>
          </div>
        </section>
      )}
      {cases && cases.length > 0 && (
        <>
          <div className="case-list">
            {cases.map((c) => {
              const tot = Math.max(1, c.events);
              return (
                <Link key={c.id} to={`/cases/${c.id}`} className="case-card">
                  <div className="row">
                    <h2>{c.name}</h2>
                    <ArrowRight size={17} className="muted" />
                  </div>
                  <div className="mini-bar" aria-label={`${c.classes.malicious} malicious, ${c.classes.suspicious} suspicious of ${c.events} records`}>
                    <span style={{ width: `${(c.classes.malicious / tot) * 100}%`, background: "var(--c-malicious)", minWidth: c.classes.malicious ? 3 : 0 }} />
                    <span style={{ width: `${(c.classes.suspicious / tot) * 100}%`, background: "var(--c-suspicious-fill)" }} />
                    <span style={{ width: `${(c.classes.benign / tot) * 100}%`, background: "var(--c-benign-fill)" }} />
                  </div>
                  <div className="row small">
                    <span><b>{fmtNum(c.classes.malicious)}</b> <span className="muted">malicious</span></span>
                    <span><b>{fmtNum(c.classes.suspicious)}</b> <span className="muted">suspicious</span></span>
                    <span><b>{fmtNum(c.events)}</b> <span className="muted">records</span></span>
                    <span><b>{c.files}</b> <span className="muted">files</span></span>
                  </div>
                  <div className="small muted">Opened {new Date(c.created * 1000).toLocaleString()}{c.processing ? " · processing" : ""}</div>
                </Link>
              );
            })}
          </div>
          <div style={{ marginTop: 18 }}>
            <button className="btn ghost" onClick={sample} disabled={busy}><FlaskConical size={16} />Open another sample case</button>
          </div>
        </>
      )}
    </section>
  );
}
