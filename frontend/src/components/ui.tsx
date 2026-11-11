import { AlertOctagon, AlertTriangle, CircleDashed, Loader2, ShieldCheck, Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import type { Cls } from "../api";

const CLS: Record<Cls, { cls: string; icon: ReactNode; label: string }> = {
  malicious: { cls: "b-malicious", icon: <AlertOctagon size={13} aria-hidden />, label: "Malicious" },
  suspicious: { cls: "b-suspicious", icon: <AlertTriangle size={13} aria-hidden />, label: "Suspicious" },
  benign: { cls: "b-benign", icon: <ShieldCheck size={13} aria-hidden />, label: "Benign" },
  "not applicable": { cls: "b-na", icon: <CircleDashed size={13} aria-hidden />, label: "Not scored" },
};

export const CLASS_FILL: Record<Cls, string> = {
  malicious: "var(--c-malicious)", suspicious: "var(--c-suspicious-fill)", benign: "var(--c-benign-fill)",
  "not applicable": "var(--c-na-fill)",
};

export function ClassBadge({ cls }: { cls: Cls | string | null | undefined }) {
  const c = CLS[(cls as Cls) ?? "not applicable"] ?? CLS["not applicable"];
  return <span className={`badge ${c.cls}`}>{c.icon}{c.label}</span>;
}

export function AnomalyBadge() {
  return <span className="badge b-anomaly" title="Isolation Forest: unusual pattern among alert traffic"><Sparkles size={13} aria-hidden />Anomaly</span>;
}

export function Spinner({ label = "Loading" }: { label?: string }) {
  return <div className="loading" role="status"><Loader2 size={18} className="spin" aria-hidden />{label}</div>;
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return <div className="empty"><h3>{title}</h3>{children}</div>;
}

export function ErrorNote({ error }: { error: unknown }) {
  if (!error) return null;
  return <div className="error" role="alert">{error instanceof Error ? error.message : String(error)}</div>;
}

export function Stat({ label, value, note, icon, onClick }: { label: string; value: ReactNode; note?: string; icon?: ReactNode; onClick?: () => void }) {
  const body = (<><div className="stat-label">{icon}{label}</div><div className="stat-value">{value}</div>{note && <div className="stat-note">{note}</div>}</>);
  return onClick ? <button type="button" className="stat" onClick={onClick}>{body}</button> : <div className="stat">{body}</div>;
}

export function ProbBar({ value, threshold, color }: { value: number; threshold?: number; color: string }) {
  return (
    <div className="bar" role="img" aria-label={`probability ${value.toFixed(3)}${threshold != null ? `, threshold ${threshold.toFixed(3)}` : ""}`}>
      <span style={{ width: `${Math.max(1, value * 100)}%`, background: color }} />
      {threshold != null && <i className="thr" style={{ left: `calc(${threshold * 100}% - 1px)` }} />}
    </div>
  );
}
