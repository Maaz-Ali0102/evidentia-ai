import { useEffect, useState } from "react";
import { api } from "../api";
import { ErrorNote, Spinner } from "../components/ui";

const MN: Record<string, string> = { logreg: "Logistic Regression", random_forest: "Random Forest" };
const SPLIT: Record<string, string> = { POOLED_temporal: "Both organisations (deployed)", "B_temporal_ORG-0005": "ORG-0005 · Cisco ASA", "A_temporal_ORG-0004": "ORG-0004 · AWS VPC" };
const f = (v: number | null | undefined, d = 3) => (v == null ? "–" : v.toFixed(d));

export function Model() {
  const [m, setM] = useState<Record<string, any> | null>(null);
  const [err, setErr] = useState<unknown>(null);
  useEffect(() => {
    Promise.all(["stage2", "three_class", "iforest", "stage1_within_product", "relations"].map((n) => api.metric(n).catch(() => null)))
      .then(([stage2, three, iso, s1, rel]) => setM({ stage2, three, iso, s1, rel })).catch(setErr);
  }, []);
  if (err) return <div className="page"><ErrorNote error={err} /></div>;
  if (!m) return <Spinner />;
  const lt = m.s1?.label_is_function_of_event_type;
  return (
    <section className="page wrap enter grid" style={{ gap: 20 }}>
      <div className="page-head">
        <div>
          <span className="eyebrow">Under the hood</span>
          <h1>Model evaluation</h1>
          <p>Every number is measured on a later time window with incidents the models never saw, and read live from <code>reports/metrics/*.json</code>.
            Labels reproduce WitFoo's automated triage, not analyst-verified ground truth.</p>
        </div>
      </div>

      <section className="panel">
        <div className="panel-head"><div><h2>Suspicious vs malicious</h2><p>The task that needs learning. Chance PR-AUC equals the share of malicious records in the test window.</p></div></div>
        <div className="table-wrap"><table>
          <thead><tr><th>Trained and tested on</th><th>Model</th><th>Features</th><th className="num">PR-AUC</th><th className="num">chance</th><th className="num">ROC-AUC</th><th className="num">precision</th><th className="num">recall</th><th className="num">incidents found</th></tr></thead>
          <tbody>{Object.entries(m.stage2.tuned).flatMap(([split, d]: [string, any]) => Object.entries(d).map(([mn, r]: [string, any]) => {
            const t = r.test_at_tuned_threshold;
            return (<tr key={split + mn}><td>{SPLIT[split] ?? split}</td><td>{MN[mn]}</td><td>{r.selected_feature_set}</td>
              <td className="num"><b>{f(t.pr_auc_positive)}</b></td><td className="num muted">{f(t.positive_rate_baseline)}</td><td className="num">{f(t.roc_auc)}</td>
              <td className="num">{f(t.per_class.malicious.precision, 2)}</td><td className="num">{f(t.per_class.malicious.recall, 2)}</td>
              <td className="num">{r.incident_level.detected} / {r.incident_level.incidents}</td></tr>);
          }))}</tbody>
        </table></div>
        <div className="panel-body figure-grid">
          <figure className="figure" style={{ margin: 0 }}><img src="/api/figures/R1_stage2_prauc_logreg.png" alt="PR-AUC of Logistic Regression by feature set and split" /><figcaption className="figure-title">Behaviour features beat text when organisations are mixed</figcaption></figure>
          <figure className="figure" style={{ margin: 0 }}><img src="/api/figures/R2_three_class_confusion.png" alt="Confusion matrices for the three-class models" /><figcaption className="figure-title">Three classes: where the errors fall</figcaption></figure>
        </div>
      </section>

      <div className="grid cols-even">
        <section className="panel">
          <div className="panel-head"><div><h2>Three classes</h2><p>Accuracy is not informative here; macro-F1 weighs the rare class equally.</p></div></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Strategy</th><th>Model</th><th className="num">macro-F1</th><th className="num">malicious F1</th><th className="num">accuracy</th></tr></thead>
            <tbody>{["hierarchical", "flat"].flatMap((k) => Object.entries(m.three[k]).map(([mn, r]: [string, any]) => (
              <tr key={k + mn}><td>{k}</td><td>{MN[mn]}</td><td className="num"><b>{f(r.macro_f1)}</b></td><td className="num">{f(r.per_class.malicious.f1)}</td><td className="num muted">{f(r.accuracy)}</td></tr>)))}
            </tbody>
          </table></div>
          <p className="small muted panel-body">Predicting "benign" for everything scores {((m.three.test_distribution.benign / m.three.test_rows) * 100).toFixed(1)}% accuracy on this test set.</p>
        </section>
        <section className="panel">
          <div className="panel-head"><div><h2>Why benign vs alert is perfect</h2><p>Stage 1 routes records; it does not detect threats.</p></div></div>
          <div className="panel-body">
            {lt && <p>Of {lt.distinct_product_message_type_keys} (product, event type) pairs in the 2,011,674 records, <b>{lt.keys_with_both_benign_and_alert}</b> contain both benign and alert records.
              A lookup table with no machine learning reaches macro-F1 <b>{lt.lookup_table_baseline_on_test.macro_f1}</b> on {lt.lookup_table_baseline_on_test.n.toLocaleString()} test records.
              The label is fixed by the event type, so the learning claim rests on suspicious vs malicious.</p>}
          </div>
        </section>
      </div>

      <section className="panel">
        <div className="panel-head"><div><h2>Anomaly detector</h2><p>Isolation Forest fitted on alert traffic without labels; shown next to the classifiers, never merged into them.</p></div></div>
        <div className="table-wrap"><table>
          <thead><tr><th>Experiment</th><th className="num">PR-AUC</th><th className="num">chance</th><th className="num">ROC-AUC</th></tr></thead>
          <tbody>{Object.entries(m.iso.experiments).filter(([, r]: any) => r.pr_auc_positive != null).map(([k, r]: [string, any]) => (
            <tr key={k}><td>{k.replace(/_/g, " ")}</td><td className="num"><b>{f(r.pr_auc_positive)}</b></td><td className="num muted">{f(r.positive_rate_baseline)}</td><td className="num">{f(r.roc_auc)}</td></tr>))}
          </tbody>
        </table></div>
        <p className="small muted panel-body">On held-out alerts it flags {m.iso.experiments.disagreement_with_random_forest.rows.malicious["RF:suspicious & IF:anomaly"].toLocaleString()} malicious records the Random Forest misses, and no malicious record is flagged by both.</p>
      </section>

      {m.rel && (
        <section className="panel">
          <div className="panel-head"><div><h2>Relationship mapper</h2>
            <p>Ground truth: two alert records belong to the same WitFoo incident. Queries are malicious records of the test window; MRR = how high the first true link ranks.</p></div></div>
          <div className="table-wrap"><table>
            <thead><tr><th>Organisation</th><th>Scorer</th><th className="num">MRR</th><th className="num">P@5</th><th className="num">recall@10</th></tr></thead>
            <tbody>{Object.entries(m.rel.results).flatMap(([org, d]: [string, any]) =>
              ["temporal_only", "entity_only", "semantic_only", "equal_average", "combined_learned"].map((s) => (
                <tr key={org + s}><td>{org}</td><td>{s.replace(/_/g, " ")}{s === "combined_learned" ? " (used)" : ""}</td>
                  <td className="num"><b>{f(d.test[s].mrr)}</b></td><td className="num">{f(d.test[s].p_at_5)}</td><td className="num">{f(d.test[s].recall_at_10)}</td></tr>)))}
            </tbody>
          </table></div>
          <p className="small muted panel-body">
            The non-negative mix chosen on the training window is {m.rel.weights.mix?.map((v: number, i: number) => `${["time", "shared indicators", "content"][i]} ${v}`).join(", ")}: inside WitFoo incidents, closeness in time ranks links best.
            {" "}{m.rel.caveat} In a case, time alone never creates a link: a link also needs a shared indicator or similar content.
          </p>
        </section>
      )}
    </section>
  );
}
