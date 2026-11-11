import { useEffect, useMemo, useRef, useState } from "react";
import type { Cls } from "../api";
import { fmtTime } from "../api";
import { CLASS_FILL } from "./ui";

type Hist = { t: number; cls: Cls; n: number }[];
const ORDER: Cls[] = ["benign", "suspicious", "malicious"];

/** Stacked bars of events per time bucket (UTC). One y-axis; benign optional so alerts stay readable. */
export function TimelineChart({ histogram, bucket, showBenign, anomalies, onPick }: {
  histogram: Hist; bucket: number; showBenign: boolean; anomalies: number[]; onPick?: (t0: number, t1: number) => void;
}) {
  const wrap = useRef<HTMLDivElement>(null);
  const [w, setW] = useState(900);
  const [tip, setTip] = useState<{ x: number; y: number; t: number; counts: Record<string, number> } | null>(null);
  useEffect(() => {
    const ro = new ResizeObserver(([e]) => setW(Math.max(320, e.contentRect.width)));
    if (wrap.current) ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const cls = showBenign ? ORDER : ORDER.slice(1);
  const { buckets, max, t0, t1 } = useMemo(() => {
    const m = new Map<number, Record<string, number>>();
    histogram.forEach((h) => { const r = m.get(h.t) ?? {}; r[h.cls] = (r[h.cls] ?? 0) + h.n; m.set(h.t, r); });
    const ts = [...m.keys()].sort((a, b) => a - b);
    const t0 = ts[0] ?? 0, t1 = (ts[ts.length - 1] ?? 0) + bucket;
    let max = 1;
    m.forEach((r) => { max = Math.max(max, cls.reduce((s, c) => s + (r[c] ?? 0), 0)); });
    return { buckets: m, max, t0, t1 };
  }, [histogram, bucket, showBenign]);

  const H = 220, padL = 44, padR = 12, padT = 12, padB = 40;
  const iw = w - padL - padR, ih = H - padT - padB;
  const n = Math.max(1, Math.round((t1 - t0) / bucket));
  const bw = Math.max(1, iw / n - (iw / n > 6 ? 2 : 0));
  const x = (t: number) => padL + ((t - t0) / Math.max(1, t1 - t0)) * iw;
  const y = (v: number) => padT + ih - (v / max) * ih;
  const ticks = [0, 0.5, 1].map((f) => Math.round(max * f));
  const xt = Array.from({ length: 6 }, (_, i) => t0 + ((t1 - t0) * i) / 5);

  return (
    <div ref={wrap} style={{ position: "relative" }}>
      <svg className="chart" width={w} height={H} role="img" aria-label="Events per time bucket, stacked by predicted class">
        {ticks.map((v) => (
          <g key={v}>
            <line x1={padL} x2={w - padR} y1={y(v)} y2={y(v)} stroke="var(--line-soft)" />
            <text x={padL - 8} y={y(v) + 4} textAnchor="end">{v.toLocaleString()}</text>
          </g>
        ))}
        {[...buckets.entries()].map(([t, r]) => {
          let acc = 0;
          return (
            <g key={t} onMouseMove={(e) => setTip({ x: e.clientX, y: e.clientY, t, counts: r })} onMouseLeave={() => setTip(null)}
               onClick={() => onPick?.(t, t + bucket)} style={{ cursor: onPick ? "pointer" : "default" }}>
              <rect x={x(t)} y={padT} width={bw} height={ih} fill="transparent" />
              {cls.map((c) => {
                const v = r[c] ?? 0;
                if (!v) return null;
                const y0 = y(acc), y1 = y(acc + v);
                acc += v;
                return <rect key={c} x={x(t)} y={y1} width={bw} height={Math.max(1, y0 - y1 - (acc > v ? 1 : 0))} fill={CLASS_FILL[c]} rx={1} />;
              })}
            </g>
          );
        })}
        {anomalies.map((t, i) => (
          <path key={i} d={`M${x(t)} ${H - padB + 10} l4 7 h-8z`} fill="var(--c-anomaly)" stroke="var(--panel)" strokeWidth={1}>
            <title>Anomaly at {fmtTime(t)} UTC</title>
          </path>
        ))}
        <line x1={padL} x2={w - padR} y1={padT + ih} y2={padT + ih} stroke="var(--p-muted)" />
        {xt.map((t) => <text key={t} x={x(t)} y={H - 6} textAnchor="middle">{fmtTime(t).slice(0, 5)}</text>)}
      </svg>
      {tip && (
        <div className="tooltip" style={{ left: tip.x + 12, top: tip.y + 12 }}>
          <b>{fmtTime(tip.t)}–{fmtTime(tip.t + bucket)} UTC</b>
          {ORDER.concat(["not applicable"]).map((c) => tip.counts[c] ? <div key={c}>{c === "not applicable" ? "not scored" : c}: {tip.counts[c].toLocaleString()}</div> : null)}
          {onPick && <div style={{ opacity: .7, marginTop: 4 }}>Click to list these events</div>}
        </div>
      )}
    </div>
  );
}
