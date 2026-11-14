export type Cls = "benign" | "suspicious" | "malicious" | "not applicable";

export interface CaseSummary {
  id: string; name: string; description: string; created: number; files: number; processing: number;
  events: number; classes: Record<Cls, number>; anomalies: number; disagreements: number; links: number;
  time_span: [number | null, number | null];
}

export interface EvidenceFile {
  file_id: number; name: string; sha256: string; size: number; uploaded: number; file_type: string;
  artifact_type: string | null; status: "processing" | "linking" | "ready" | "error"; error: string | null;
  n_events: number; n_applicable: number; warnings: string[];
  parser: { columns_mapped?: Record<string, string>; columns_available?: string[]; line_formats?: Record<string, number>; missing_required?: string[] };
}

export interface EventRow {
  event_id: number; file_id: number; file: string; source_row: number; ts: number | null; message: string | null;
  message_type: string | null; action: string | null; src_ip: string | null; dst_ip: string | null; dst_port: string | null;
  cls: Cls; lr_class: string; rf_class: string; lr_p_mal: number | null; rf_p_mal: number | null; applicable: number;
  agree: number; an_flag: number; an_score: number | null; reference_label: string | null;
}

export interface Link {
  other: number; score: number; temporal: number; entity: number; semantic: number; shared: string[]; dt: number | null;
  event: { event_id: number; file: string; source_row: number; ts: number | null; message: string; cls: Cls } | null;
}

export interface EventDetail {
  event_id: number; file_id: number; file: string; sha256: string; artifact_type: string; source_row: number; ts: number | null;
  message: string | null; message_type: string | null; action: string | null; protocol: string | null; severity: string | null;
  src_ip: string | null; dst_ip: string | null; src_port: string | null; dst_port: string | null; extra: Record<string, unknown>;
  ml: null | {
    applicable: number; reason: string; coverage: number; agree: number; an_scored: number; an_flag: number; an_score: number | null;
    detail: {
      classifiers: Record<"logreg" | "random_forest", { predicted_class: Cls; class_probabilities: Record<string, number>;
        p_alert_stage1: number; p_malicious_given_alert_stage2: number; stage2_threshold: number }>;
      anomaly: { score: number | null; flagged: boolean; scored: boolean; threshold: number; meaning: string };
      notes: string[]; decision_rule: string; label_semantics: string;
    };
  };
  entities: { kind: string; value: string; seen: number }[];
  links: Link[];
}

export interface Finding {
  id: string; rule: string; severity: "high" | "medium" | "low"; title: string; summary: string;
  tactic: string; technique: string; event_ids: number[]; n_events: number; first_utc: string | null;
  last_utc: string | null; indicators: string[]; actions: string[]; related: string[];
}

export interface AskResult {
  chat_id: number; question: string; answer_markdown: string; seconds: number; warnings: string[];
  citations: { events: { id: string; event_id: number; file: string; row: number; time_utc: string | null; message: string }[];
    knowledge: { id: string; title: string; text: string }[]; findings?: Finding[] };
  retrieved: { events: number; links: number; knowledge: number; focus_matches: number | null };
  llm: { provider: string; model: string | null; external: boolean; note: string };
}

export interface LlmStatus { provider: string; model: string | null; external: boolean; note: string }

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(path, init);
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`;
    try { const j = await r.json(); if (j.detail) msg = typeof j.detail === "string" ? j.detail : JSON.stringify(j.detail); } catch { /* not json */ }
    throw new Error(msg);
  }
  return r.status === 204 ? (undefined as T) : r.json();
}

const json = (body: unknown): RequestInit => ({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export const api = {
  cases: () => req<CaseSummary[]>("/api/cases"),
  createCase: (name: string, description = "") => req<CaseSummary>("/api/cases", json({ name, description })),
  deleteCase: (id: string) => req<void>(`/api/cases/${id}`, { method: "DELETE" }),
  case: (id: string) => req<CaseSummary>(`/api/cases/${id}`),
  files: (id: string) => req<EvidenceFile[]>(`/api/cases/${id}/files`),
  upload: (id: string, files: File[]) => {
    const fd = new FormData();
    files.forEach((f) => fd.append("files", f));
    return req<unknown>(`/api/cases/${id}/files`, { method: "POST", body: fd });
  },
  addSamples: (id: string, names: string[] = []) => req<unknown>(`/api/cases/${id}/samples`, json({ names })),
  samples: () => req<{ name: string; size: number }[]>("/api/samples"),
  verify: (id: string, fid: number) => req<{ intact: boolean; recorded: string; current: string }>(`/api/cases/${id}/files/${fid}/verify`),
  remap: (id: string, fid: number, column_map: Record<string, string>) => req<unknown>(`/api/cases/${id}/files/${fid}/remap`, json({ column_map })),
  events: (id: string, params: Record<string, string | number | boolean | string[] | undefined>) => {
    const u = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v === undefined || v === "" || v === false) return;
      if (Array.isArray(v)) v.forEach((x) => u.append(k, x)); else u.set(k, String(v));
    });
    return req<{ total: number; offset: number; rows: EventRow[] }>(`/api/cases/${id}/events?${u}`);
  },
  event: (id: string, eid: number) => req<EventDetail>(`/api/cases/${id}/events/${eid}`),
  timeline: (id: string, model: string, bucket: number) =>
    req<{ bucket: number; histogram: { t: number; cls: Cls; n: number }[]; alerts: { event_id: number; ts: number; cls: Cls; p_mal: number; an_flag: number; src_ip: string; dst_ip: string }[]; threshold: number | null }>(
      `/api/cases/${id}/timeline?model=${model}&bucket=${bucket}`),
  entities: (id: string, q = "", limit = 30) =>
    req<{ kind: string; value: string; events: number; files: number; malicious: number; suspicious: number; anomalies: number }[]>(
      `/api/cases/${id}/entities?limit=${limit}${q ? `&q=${encodeURIComponent(q)}` : ""}`),
  graph: (id: string, focus?: string) => req<GraphData>(`/api/cases/${id}/graph${focus ? `?focus=${encodeURIComponent(focus)}` : ""}`),
  findings: (id: string) => req<Finding[]>(`/api/cases/${id}/findings`),
  detectionRules: () => req<{ builtin: string[]; sigma: { loaded: number; unsupported: { rule: string; reason: string }[] } }>("/api/detection-rules"),
  ask: (id: string, question: string) => req<AskResult>(`/api/cases/${id}/ask`, json({ question })),
  chats: (id: string) => req<AskResult[]>(`/api/cases/${id}/chats`),
  llm: () => req<LlmStatus>("/api/llm"),
  health: () => req<{ relations: { source: string; mix: number[] | null; tau: number } }>("/api/health"),
  metric: <T = any>(name: string) => req<T>(`/api/metrics/${name}`),
  edaSummary: () => req<{ markdown: string }>("/api/reports/eda-summary"),
};

export interface GraphNode {
  id: string; type: "entity" | "file"; kind: string; label: string; events?: number; malicious?: number; anomalies?: number;
  files?: number; worst?: Cls; artifact_type?: string;
  x?: number; y?: number; vx?: number; vy?: number; fx?: number | null; fy?: number | null;
}
export interface GraphEdge { source: string | GraphNode; target: string | GraphNode; type: string; weight: number }
export interface GraphData { nodes: GraphNode[]; edges: GraphEdge[]; focus: string | null }

export const fmtTime = (ts: number | null | undefined, withDate = false) => {
  if (ts == null) return "no time";
  const d = new Date(ts * 1000).toISOString();
  return withDate ? `${d.slice(0, 10)} ${d.slice(11, 19)}` : d.slice(11, 19);
};
export const fmtNum = (n: number | null | undefined) => (n == null ? "–" : n.toLocaleString("en-US"));
export const fmtBytes = (b: number) => (b < 1024 ? `${b} B` : b < 1048576 ? `${(b / 1024).toFixed(1)} KB` : `${(b / 1048576).toFixed(1)} MB`);
