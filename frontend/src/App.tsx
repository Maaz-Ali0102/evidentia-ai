import { BarChart3, Database, FolderOpen, Info } from "lucide-react";
import { useEffect, useState } from "react";
import { BrowserRouter, NavLink, Navigate, Route, Routes } from "react-router-dom";
import { api, type LlmStatus } from "./api";
import { About } from "./pages/About";
import { Ask } from "./pages/Ask";
import { CaseLayout } from "./pages/CaseLayout";
import { Cases } from "./pages/Cases";
import { Dataset } from "./pages/Dataset";
import { Evidence } from "./pages/Evidence";
import { Events } from "./pages/Events";
import { Graph } from "./pages/Graph";
import { Model } from "./pages/Model";
import { Overview } from "./pages/Overview";

export function App() {
  const [llm, setLlm] = useState<LlmStatus | null>(null);
  useEffect(() => { api.llm().then(setLlm).catch(() => setLlm(null)); }, []);
  return (
    <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <div className="shell">
        <nav className="side" aria-label="Main">
          <NavLink to="/" className="brand" end>
            <span className="brand-mark" aria-hidden>E</span>
            <span className="brand-name">Evidentia</span>
          </NavLink>
          <div className="nav">
            <span className="nav-label">Investigate</span>
            <NavLink to="/" end><FolderOpen size={17} />Cases</NavLink>
            <span className="nav-label">Under the hood</span>
            <NavLink to="/model"><BarChart3 size={17} />Model evaluation</NavLink>
            <NavLink to="/dataset"><Database size={17} />Training data</NavLink>
            <NavLink to="/about"><Info size={17} />How it works</NavLink>
          </div>
          <div className="side-foot">
            <div><span className="dot" style={{ background: "#7fb08f" }} /><b>Local</b> · files stay on this machine</div>
            <div style={{ marginTop: 6 }}>
              <span className="dot" style={{ background: llm?.external ? "#d08a24" : "#9e9d99" }} />
              Answers: <b>{llm ? (llm.provider === "gemini" ? `Gemini (${llm.model})` : "built-in, offline") : "…"}</b>
            </div>
          </div>
        </nav>
        <main id="main">
          <Routes>
            <Route path="/" element={<Cases />} />
            <Route path="/cases/:caseId" element={<CaseLayout />}>
              <Route index element={<Overview />} />
              <Route path="evidence" element={<Evidence />} />
              <Route path="events" element={<Events />} />
              <Route path="graph" element={<Graph />} />
              <Route path="ask" element={<Ask />} />
            </Route>
            <Route path="/model" element={<Model />} />
            <Route path="/dataset" element={<Dataset />} />
            <Route path="/about" element={<About />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
