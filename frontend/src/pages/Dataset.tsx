import { useEffect, useState } from "react";
import { api } from "../api";
import { Markdown } from "../components/Markdown";
import { Spinner } from "../components/ui";

const FIGS: [string, string][] = [
  ["eda01_class_distribution.png", "Malicious is 0.36% of training records"],
  ["eda02_org_class_mix.png", "Only two organisations carry alerts"],
  ["eda03_hourly_daily.png", "Malicious activity comes in bursts"],
  ["eda04_message_types.png", "Alerts come from two event types"],
  ["eda05_missing_values.png", "Missing fields differ by class"],
  ["eda06_message_length.png", "Message length by class"],
  ["eda07_split_coverage.png", "Train and test windows per organisation"],
  ["eda08_duplicates.png", "Repeated texts and conflicting labels"],
  ["eda09_leakage_evidence.png", "Columns removed because they leak the label"],
];

export function Dataset() {
  const [md, setMd] = useState<string | null>(null);
  useEffect(() => { api.edaSummary().then((r) => setMd(r.markdown)).catch(() => setMd("")); }, []);
  return (
    <section className="page wrap enter grid" style={{ gap: 20 }}>
      <div className="page-head">
        <div>
          <span className="eyebrow">Under the hood</span>
          <h1>Training data</h1>
          <p>WitFoo Precinct6 (Hugging Face, v2.1.0): 2,011,674 live security-log records from four organisations, July 2024.
            Every statistic below uses the training window only.</p>
        </div>
      </div>
      <div className="figure-grid">
        {FIGS.map(([f, t]) => (
          <figure key={f} className="figure" style={{ margin: 0 }}>
            <img src={`/api/figures/${f}`} alt={t} loading="lazy" />
            <figcaption className="figure-title">{t}</figcaption>
          </figure>
        ))}
      </div>
      <section className="panel"><div className="panel-body md">{md == null ? <Spinner /> : <Markdown text={md} />}</div></section>
    </section>
  );
}
