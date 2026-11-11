import { CheckCircle2, FileUp, FlaskConical, Loader2, ShieldAlert, ShieldCheck, TriangleAlert, Upload } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, fmtBytes, fmtNum, type EvidenceFile } from "../api";
import { ErrorNote } from "../components/ui";
import { useCase } from "./CaseLayout";

const TARGETS: [string, string][] = [["timestamp", "Time"], ["message_sanitized", "Message"], ["src_ip", "Source IP"], ["dst_ip", "Destination IP"], ["dst_port", "Destination port"], ["message_type", "Event type"]];

export function Evidence() {
  const { caseId, files, refresh } = useCase();
  const [over, setOver] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [sending, setSending] = useState(false);
  const [samples, setSamples] = useState<{ name: string; size: number }[]>([]);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => { api.samples().then(setSamples).catch(() => setSamples([])); }, []);

  const send = async (list: File[]) => {
    if (!list.length) return;
    setSending(true); setErr(null);
    try { await api.upload(caseId, list); refresh(); } catch (x) { setErr(x); } finally { setSending(false); }
  };
  const addSample = async (name: string) => {
    setErr(null);
    try { await api.addSamples(caseId, [name]); refresh(); } catch (x) { setErr(x); }
  };

  return (
    <div className="grid">
      <section className="panel">
        <div className="panel-head"><div><h2>Add evidence</h2><p>Files are read once, hashed with SHA-256 and stored read-only. Analysis runs in the background.</p></div></div>
        <div className="panel-body grid">
          <div className={`drop ${over ? "over" : ""}`} role="button" tabIndex={0}
               onClick={() => input.current?.click()} onKeyDown={(e) => (e.key === "Enter" || e.key === " ") && input.current?.click()}
               onDragOver={(e) => { e.preventDefault(); setOver(true); }} onDragLeave={() => setOver(false)}
               onDrop={(e) => { e.preventDefault(); setOver(false); send([...e.dataTransfer.files]); }}>
            <span className="drop-icon">{sending ? <Loader2 className="spin" /> : <Upload />}</span>
            <div>
              <h3>Drop files here, or choose files</h3>
              <p className="muted small" style={{ marginTop: 4 }}>
                CSV, JSON / JSONL, LOG, TXT, HTML · up to 50 MB each. Firewall and flow logs get ML triage; other files are parsed, indexed and linked.
              </p>
            </div>
            <input ref={input} type="file" multiple hidden accept=".csv,.json,.jsonl,.ndjson,.log,.txt,.html,.htm"
                   onChange={(e) => { send([...(e.target.files ?? [])]); e.target.value = ""; }} />
          </div>
          {samples.length > 0 && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <span className="small muted"><FlaskConical size={14} style={{ verticalAlign: -2 }} /> Or add a bundled sample:</span>
              {samples.map((s) => <button key={s.name} className="chip" onClick={() => addSample(s.name)}><span className="mono">{s.name}</span><span className="muted small">{fmtBytes(s.size)}</span></button>)}
            </div>
          )}
          <ErrorNote error={err} />
        </div>
      </section>

      <section className="panel">
        <div className="panel-head"><div><h2>Evidence files <span className="muted">({files.length})</span></h2>
          <p>Re-check a file's hash at any time; a mismatch means the stored copy changed.</p></div></div>
        {files.length === 0 && <div className="empty"><FileUp /><p>No files yet.</p></div>}
        {files.map((f) => <FileRow key={f.file_id} f={f} />)}
      </section>
    </div>
  );
}

function FileRow({ f }: { f: EvidenceFile }) {
  const { caseId, refresh } = useCase();
  const [check, setCheck] = useState<{ intact: boolean } | null>(null);
  const [mapOpen, setMapOpen] = useState(false);
  const cols = f.parser.columns_available ?? [];
  const mapped = f.parser.columns_mapped ?? {};
  const [map, setMap] = useState<Record<string, string>>({});
  const busy = f.status === "processing" || f.status === "linking";
  const pct = f.n_events ? Math.round((f.n_applicable / f.n_events) * 100) : 0;
  const needsMap = cols.length > 0 && (f.parser.missing_required?.length || (f.n_events > 0 && pct < 50));

  const remap = async () => {
    const m = Object.fromEntries(Object.entries(map).filter(([, v]) => v));
    await api.remap(caseId, f.file_id, m);
    setMapOpen(false); refresh();
  };
  return (
    <div className="file-row">
      <div style={{ minWidth: 0 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <h3 className="mono" style={{ fontSize: 14.5 }}>{f.name}</h3>
          {f.artifact_type && <span className="badge b-plain">{f.artifact_type.replace("_", " ")}</span>}
          {busy && <span className="badge b-anomaly"><Loader2 size={13} className="spin" />{f.status === "linking" ? "Linking" : "Processing"}</span>}
          {f.status === "ready" && <span className="badge b-benign"><CheckCircle2 size={13} />Ready</span>}
          {f.status === "error" && <span className="badge b-malicious"><TriangleAlert size={13} />Error</span>}
        </div>
        <div className="small muted" style={{ marginTop: 4 }}>
          {fmtBytes(f.size)} · {fmtNum(f.n_events)} records · {pct}% scored by the models · added {new Date(f.uploaded * 1000).toLocaleString()}
        </div>
        <div className="hash" style={{ marginTop: 4 }}>SHA-256 {f.sha256}</div>
        {Object.keys(mapped).length > 0 && (
          <div className="small muted" style={{ marginTop: 6 }}>Columns used: {Object.entries(mapped).map(([k, v]) => `${v} → ${k.replace("_sanitized", "")}`).join(" · ")}</div>
        )}
        {f.parser.line_formats && <div className="small muted" style={{ marginTop: 6 }}>Line formats: {Object.entries(f.parser.line_formats).map(([k, v]) => `${k.replace(/_/g, " ")} ${fmtNum(v)}`).join(" · ")}</div>}
        {f.error && <div className="warn"><TriangleAlert size={15} />{f.error}</div>}
        {f.warnings.map((w) => <div key={w} className="warn"><TriangleAlert size={15} style={{ flex: "none", marginTop: 2 }} />{w}</div>)}
        {mapOpen && (
          <div className="panel" style={{ marginTop: 10, padding: 14 }}>
            <p className="small" style={{ marginBottom: 10 }}>Tell Evidentia which column holds what. The stored original is not changed; the file is parsed again.</p>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(200px, 1fr))", gap: 10 }}>
              {TARGETS.map(([k, label]) => (
                <div className="field" key={k}>
                  <label htmlFor={`m-${f.file_id}-${k}`}>{label}</label>
                  <select id={`m-${f.file_id}-${k}`} className="input" value={map[k] ?? (mapped[k] && cols.includes(mapped[k]) ? mapped[k] : "")}
                          onChange={(e) => setMap({ ...map, [k]: e.target.value })}>
                    <option value="">(none)</option>
                    {cols.map((c) => <option key={c} value={c}>{c}</option>)}
                  </select>
                </div>
              ))}
            </div>
            <div style={{ display: "flex", gap: 8, marginTop: 12 }}>
              <button className="btn primary small" onClick={remap}>Parse again with these columns</button>
              <button className="btn ghost small" onClick={() => setMapOpen(false)}>Cancel</button>
            </div>
          </div>
        )}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 6, alignItems: "flex-end" }}>
        <button className="btn ghost small" disabled={busy} onClick={async () => setCheck(await api.verify(caseId, f.file_id))}>
          {check ? (check.intact ? <><ShieldCheck size={15} className="ok" />Hash matches</> : <><ShieldAlert size={15} color="var(--c-malicious)" />Hash changed</>) : "Verify hash"}
        </button>
        {cols.length > 0 && !busy && (
          <button className={`btn small ${needsMap ? "primary" : "ghost"}`} onClick={() => setMapOpen(!mapOpen)}>Map columns</button>
        )}
      </div>
    </div>
  );
}
