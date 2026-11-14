import type { ReactNode } from "react";

/** Small markdown renderer for the app's own text (assistant answers, EDA summary).
 *  Supports headings, bullet/numbered lists, tables, **bold**, `code`, links and citation
 *  tags [E12] / [K3] / [F1] / [S], which become buttons when `onCite` is given. Raw HTML is never rendered. */
export function Markdown({ text, onCite }: { text: string; onCite?: (id: string) => void }) {
  const lines = text.replace(/\r/g, "").split("\n");
  const out: ReactNode[] = [];
  let i = 0;
  let key = 0;
  while (i < lines.length) {
    const ln = lines[i];
    if (!ln.trim()) { i++; continue; }
    const h = /^(#{1,4})\s+(.*)$/.exec(ln);
    if (h) {
      const level = Math.min(h[1].length + 1, 4);
      const H = (`h${level}`) as "h2" | "h3" | "h4";
      out.push(<H key={key++}>{inline(h[2], onCite)}</H>);
      i++; continue;
    }
    if (/^\s*\|/.test(ln)) {
      const rows: string[][] = [];
      while (i < lines.length && /^\s*\|/.test(lines[i])) {
        const cells = lines[i].trim().replace(/^\||\|$/g, "").split("|").map((c) => c.trim());
        if (!cells.every((c) => /^:?-{2,}:?$/.test(c))) rows.push(cells);
        i++;
      }
      const [head, ...body] = rows;
      out.push(
        <div className="table-wrap" key={key++}><table>
          <thead><tr>{head.map((c, j) => <th key={j}>{inline(c, onCite)}</th>)}</tr></thead>
          <tbody>{body.map((r, k) => <tr key={k}>{r.map((c, j) => <td key={j}>{inline(c, onCite)}</td>)}</tr>)}</tbody>
        </table></div>);
      continue;
    }
    if (/^\s*([-*]|\d+\.)\s+/.test(ln)) {
      const ordered = /^\s*\d+\./.test(ln);
      const items: string[] = [];
      while (i < lines.length && /^\s*([-*]|\d+\.)\s+/.test(lines[i])) {
        let item = lines[i].replace(/^\s*([-*]|\d+\.)\s+/, "");
        i++;
        while (i < lines.length && /^\s{2,}\S/.test(lines[i]) && !/^\s*([-*]|\d+\.)\s+/.test(lines[i])) { item += " " + lines[i].trim(); i++; }
        items.push(item);
      }
      const L = ordered ? "ol" : "ul";
      out.push(<L key={key++}>{items.map((t, j) => <li key={j}>{inline(t, onCite)}</li>)}</L>);
      continue;
    }
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() && !/^(#{1,4}\s|\s*\||\s*([-*]|\d+\.)\s+)/.test(lines[i])) { para.push(lines[i].trim()); i++; }
    out.push(<p key={key++}>{inline(para.join(" "), onCite)}</p>);
  }
  return <>{out}</>;
}

const TOKEN = /(\*\*[^*]+\*\*|`[^`]+`|\[(?:E\d+|K\d+|F\d+|S)\]|\[[^\]]+\]\([^)]+\))/g;

function inline(s: string, onCite?: (id: string) => void): ReactNode[] {
  return s.split(TOKEN).filter(Boolean).map((part, j) => {
    if (part.startsWith("**")) return <strong key={j}>{part.slice(2, -2)}</strong>;
    if (part.startsWith("`")) return <code key={j}>{part.slice(1, -1)}</code>;
    const cite = /^\[(E\d+|K\d+|F\d+|S)\]$/.exec(part);
    if (cite) {
      const id = cite[1];
      const label = id === "S" ? "case facts" : id;
      if (!onCite || id === "S") return <span key={j} className={`cite ${id.startsWith("E") ? "" : "k"}`} title={id === "S" ? "Counts computed from the whole case" : undefined}>{label}</span>;
      return <button type="button" key={j} className={`cite ${id.startsWith("E") ? "" : "k"}`} onClick={() => onCite(id)} aria-label={`Open ${id}`}>{label}</button>;
    }
    const link = /^\[([^\]]+)\]\(([^)]+)\)$/.exec(part);
    if (link && /^(https?:|\/|#)/.test(link[2])) return <a key={j} href={link[2]} target={link[2].startsWith("http") ? "_blank" : undefined} rel="noreferrer">{link[1]}</a>;
    return <span key={j}>{part}</span>;
  });
}
