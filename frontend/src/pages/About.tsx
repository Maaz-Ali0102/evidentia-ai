export function About() {
  return (
    <section className="page wrap enter grid" style={{ gap: 20 }}>
      <div className="page-head">
        <div>
          <span className="eyebrow">Under the hood</span>
          <h1>How Evidentia works</h1>
          <p>What happens to a file from upload to answer, what each output means, and where not to trust it.</p>
        </div>
      </div>
      <div className="flow" role="list">
        {[["01 Preserve", "SHA-256 on arrival; the original is stored read-only and can be re-hashed at any time."],
          ["02 Parse", "CSV, JSON, Cisco ASA and AWS VPC lines, text and HTML become records that keep file and row."],
          ["03 Triage", "Two classifiers judge security-log records once, at upload; others are marked not scored."],
          ["04 Extract", "IPs, domains, URLs, users, hashes, hosts and paths are pulled from every record."],
          ["05 Connect", "Records sharing an indicator or content are linked and ranked by closeness in time."],
          ["06 Answer", "Questions retrieve records, model results, links and notes; answers cite them."]].map(([t, d]) => (
          <div key={t} role="listitem"><b>{t}</b><span className="small">{d}</span></div>
        ))}
      </div>
      <div className="grid cols-even">
        <section className="panel md"><div className="panel-body">
          <h2>What the outputs mean</h2>
          <ul>
            <li><b>Malicious / suspicious / benign</b> reproduce WitFoo Precinct's automated triage. "Malicious" means the record resembles records WitFoo's engine put into an incident, not a confirmed attack.</li>
            <li><b>Not scored</b> means the record does not look like the firewall and flow logs the models learned from. The models refuse rather than guess.</li>
            <li><b>Anomaly</b> is a separate, label-free signal for alert traffic. It catches different records than the classifiers and is never merged into their probabilities.</li>
            <li><b>Links</b> are leads: two records share an indicator or similar content and are close in time.</li>
            <li><b>Answers</b> separate what the records show, what the models predict, what is inferred and what is unknown.</li>
          </ul>
        </div></section>
        <section className="panel md"><div className="panel-body">
          <h2>Where not to trust it</h2>
          <ul>
            <li>Malicious precision is about 0.26–0.36 on future incidents: most flags still need an analyst.</li>
            <li>It works within the organisation it learned from (ROC-AUC about 0.955 on ORG-0005); it does not transfer to other organisations or log products.</li>
            <li>Probabilities are not calibrated.</li>
            <li>Behaviour features count earlier records inside the uploaded file only, so the first minutes of a file score less reliably.</li>
            <li>Cisco ASA timestamps carry no time zone; they are read as UTC.</li>
          </ul>
        </div></section>
      </div>
      <section className="panel md"><div className="panel-body">
        <h2>Privacy</h2>
        <p>Evidentia runs on this machine. Uploaded files, records and model results stay in the local <code>cases/</code> folder. The only exception is the assistant: when a Gemini API key is configured, the records retrieved for a question are sent to Google's Gemini API to write the answer, and the Ask page says so. Without a key, answers are assembled locally.</p>
      </div></section>
    </section>
  );
}
