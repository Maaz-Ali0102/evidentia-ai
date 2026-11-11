import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type Simulation } from "d3-force";
import { Minus, Plus, RotateCcw } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import type { GraphData, GraphEdge, GraphNode } from "../api";
import { CLASS_FILL } from "./ui";

const KIND_SHORT: Record<string, string> = { ip: "IP", domain: "DOM", url: "URL", email: "@", hash: "#", path: "/", user: "USR", host: "HST", file: "FILE" };

export function GraphView({ data, selected, onSelect }: { data: GraphData; selected: string | null; onSelect: (n: GraphNode) => void }) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [, setTick] = useState(0);
  const [view, setView] = useState({ x: 0, y: 0, k: 1 });
  const [hover, setHover] = useState<{ n: GraphNode; x: number; y: number } | null>(null);
  const sim = useRef<Simulation<GraphNode, GraphEdge> | null>(null);
  const size = useRef({ w: 900, h: 600 });

  const { nodes, edges, maxW, labelled } = useMemo(() => {
    const nodes = data.nodes.map((n) => ({ ...n }));
    const edges = data.edges.map((e) => ({ ...e }));
    // Always label only the riskiest indicators; the rest show on zoom, hover or selection.
    const top = nodes.filter((n) => n.type === "entity")
      .sort((a, b) => (b.malicious ?? 0) - (a.malicious ?? 0) || (b.events ?? 0) - (a.events ?? 0)).slice(0, 12);
    return { nodes, edges, maxW: Math.max(1, ...edges.map((e) => e.weight)), labelled: new Set(top.map((n) => n.id)) };
  }, [data]);

  useEffect(() => {
    const el = svgRef.current;
    if (el) size.current = { w: el.clientWidth || 900, h: el.clientHeight || 600 };
    const { w, h } = size.current;
    const s = forceSimulation<GraphNode>(nodes)
      .force("link", forceLink<GraphNode, GraphEdge>(edges).id((d) => d.id)
        .distance((e) => (e.type === "appears_in" ? 120 : 70)).strength((e) => (e.type === "appears_in" ? 0.15 : 0.5)))
      .force("charge", forceManyBody().strength(-340))
      .force("collide", forceCollide<GraphNode>().radius((d) => radius(d) + 8))
      .force("center", forceCenter(w / 2, h / 2))
      .alphaDecay(0.035)
      .on("tick", () => setTick((t) => t + 1));
    sim.current = s;
    setView({ x: 0, y: 0, k: 1 });
    return () => { s.stop(); };
  }, [nodes, edges]);

  // pan with background drag, zoom with wheel
  const drag = useRef<{ mode: "pan" | "node"; sx: number; sy: number; vx: number; vy: number; node?: GraphNode } | null>(null);
  const toGraph = (cx: number, cy: number) => {
    const r = svgRef.current!.getBoundingClientRect();
    return { x: (cx - r.left - view.x) / view.k, y: (cy - r.top - view.y) / view.k };
  };
  const onDown = (e: React.PointerEvent, node?: GraphNode) => {
    e.stopPropagation();
    (e.target as Element).setPointerCapture?.(e.pointerId);
    drag.current = { mode: node ? "node" : "pan", sx: e.clientX, sy: e.clientY, vx: view.x, vy: view.y, node };
    if (node) { sim.current?.alphaTarget(0.25).restart(); node.fx = node.x; node.fy = node.y; }
  };
  const onMove = (e: React.PointerEvent) => {
    const d = drag.current;
    if (!d) return;
    if (d.mode === "pan") setView((v) => ({ ...v, x: d.vx + e.clientX - d.sx, y: d.vy + e.clientY - d.sy }));
    else if (d.node) { const p = toGraph(e.clientX, e.clientY); d.node.fx = p.x; d.node.fy = p.y; }
  };
  const onUp = (e: React.PointerEvent) => {
    const d = drag.current;
    drag.current = null;
    if (d?.node) {
      sim.current?.alphaTarget(0);
      d.node.fx = null; d.node.fy = null;
      if (Math.abs(e.clientX - d.sx) + Math.abs(e.clientY - d.sy) < 4) onSelect(d.node);
    }
  };
  const zoom = (f: number, cx?: number, cy?: number) => setView((v) => {
    const k = Math.min(4, Math.max(0.3, v.k * f));
    const r = svgRef.current!.getBoundingClientRect();
    const px = cx == null ? r.width / 2 : cx - r.left, py = cy == null ? r.height / 2 : cy - r.top;
    return { k, x: px - ((px - v.x) * k) / v.k, y: py - ((py - v.y) * k) / v.k };
  });
  useEffect(() => {
    const el = svgRef.current;
    if (!el) return;
    const wheel = (e: WheelEvent) => { e.preventDefault(); zoom(e.deltaY < 0 ? 1.12 : 1 / 1.12, e.clientX, e.clientY); };
    el.addEventListener("wheel", wheel, { passive: false });
    return () => el.removeEventListener("wheel", wheel);
  });

  const focusNbr = useMemo(() => {
    if (!selected) return null;
    const s = new Set([selected]);
    edges.forEach((e) => {
      const a = typeof e.source === "string" ? e.source : e.source.id, b = typeof e.target === "string" ? e.target : e.target.id;
      if (a === selected) s.add(b); if (b === selected) s.add(a);
    });
    return s;
  }, [selected, edges, nodes]);

  return (
    <>
      <div className="graph-tools">
        <button className="btn ghost small" onClick={() => zoom(1.25)} aria-label="Zoom in"><Plus size={15} /></button>
        <button className="btn ghost small" onClick={() => zoom(0.8)} aria-label="Zoom out"><Minus size={15} /></button>
        <button className="btn ghost small" onClick={() => { setView({ x: 0, y: 0, k: 1 }); sim.current?.alpha(0.6).restart(); }} aria-label="Reset layout"><RotateCcw size={15} /></button>
      </div>
      <svg ref={svgRef} onPointerDown={(e) => onDown(e)} onPointerMove={onMove} onPointerUp={onUp} role="img"
           aria-label={`Evidence graph with ${nodes.length} nodes and ${edges.length} connections`}>
        <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
          {edges.map((e, i) => {
            const s = e.source as GraphNode, t = e.target as GraphNode;
            if (s.x == null || t.x == null) return null;
            const dim = focusNbr && !(focusNbr.has(s.id) && focusNbr.has(t.id));
            return <line key={i} x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                         stroke={e.type === "appears_in" ? "var(--line)" : "var(--p-muted)"} strokeDasharray={e.type === "appears_in" ? "3 3" : undefined}
                         strokeWidth={e.type === "appears_in" ? 1 : 1 + 3 * (e.weight / maxW)} opacity={dim ? 0.12 : 0.7} />;
          })}
          {nodes.map((n) => {
            if (n.x == null) return null;
            const r = radius(n);
            const dim = focusNbr && !focusNbr.has(n.id);
            const sel = n.id === selected;
            return (
              <g key={n.id} transform={`translate(${n.x},${n.y})`} opacity={dim ? 0.25 : 1} style={{ cursor: "pointer" }}
                 onPointerDown={(e) => onDown(e, n)}
                 onPointerEnter={(e) => setHover({ n, x: e.clientX, y: e.clientY })} onPointerLeave={() => setHover(null)}>
                {n.type === "file"
                  ? <rect x={-r} y={-r} width={2 * r} height={2 * r} fill="var(--p-ink)" stroke={sel ? "var(--c-anomaly)" : "var(--panel-2)"} strokeWidth={sel ? 3 : 2} />
                  : <circle r={r} fill={CLASS_FILL[n.worst ?? "not applicable"]} stroke={sel ? "var(--p-ink)" : "var(--panel-2)"} strokeWidth={sel ? 3 : 2} />}
                {n.type === "entity" && (n.anomalies ?? 0) > 0 && <circle r={r + 4} fill="none" stroke="var(--c-anomaly)" strokeWidth={1.5} strokeDasharray="2 2" />}
                <text y={4} textAnchor="middle" style={{ font: "500 9px var(--font-mono)", fill: n.type === "file" ? "var(--p-bg)" : "#fff", pointerEvents: "none" }}>
                  {KIND_SHORT[n.kind] ?? n.kind.slice(0, 3).toUpperCase()}
                </text>
                {(view.k > 1.6 || sel || n.type === "file" || labelled.has(n.id) || (focusNbr?.has(n.id) && view.k > 1.1)) && (
                  <text className="node-label" x={r + 5} y={4}>{n.label.length > 34 ? n.label.slice(0, 33) + "…" : n.label}</text>
                )}
              </g>
            );
          })}
        </g>
      </svg>
      {hover && (
        <div className="tooltip" style={{ left: hover.x + 14, top: hover.y + 14 }}>
          <b className="mono">{hover.n.label}</b>
          {hover.n.type === "file" ? <div>evidence file · {hover.n.artifact_type?.replace("_", " ")}</div> : (
            <>
              <div>{hover.n.kind} · in {hover.n.events} records across {hover.n.files} file{hover.n.files === 1 ? "" : "s"}</div>
              <div>{hover.n.malicious} predicted malicious · {hover.n.anomalies} anomalies</div>
            </>
          )}
        </div>
      )}
    </>
  );
}

function radius(n: GraphNode) {
  if (n.type === "file") return 15;
  return 9 + Math.min(12, Math.sqrt(n.events ?? 1) * 1.4);
}
