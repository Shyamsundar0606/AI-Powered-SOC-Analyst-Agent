import { useEffect, useState } from "react";

const emptyAnalysis = null;

function App() {
  const [samples, setSamples] = useState([]);
  const [selectedSample, setSelectedSample] = useState("");
  const [rawInput, setRawInput] = useState("");
  const [analysis, setAnalysis] = useState(emptyAnalysis);
  const [history, setHistory] = useState([]);
  const [chatHistory, setChatHistory] = useState([]);
  const [question, setQuestion] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");

  useEffect(() => {
    fetch("/api/samples")
      .then((res) => res.json())
      .then((data) => setSamples(data.samples ?? []))
      .catch(() => setSamples([]));

    refreshHistory();
  }, []);

  async function refreshHistory() {
    try {
      const res = await fetch("/api/history");
      const data = await res.json();
      setHistory(data.investigations ?? []);
    } catch {
      setHistory([]);
    }
  }

  async function loadSample() {
    if (!selectedSample) {
      setMessage("Choose a sample first.");
      return;
    }
    const res = await fetch(`/api/samples/${selectedSample}`);
    const data = await res.json();
    setRawInput(data.content ?? "");
    setMessage("");
  }

  async function analyzeAlert(file) {
    setLoading(true);
    setMessage("");
    setChatHistory([]);
    try {
      let data;
      if (file) {
        const formData = new FormData();
        formData.append("file", file);
        const res = await fetch("/api/analyze-file", { method: "POST", body: formData });
        data = await res.json();
      } else {
        const res = await fetch("/api/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ raw_text: rawInput, source_label: selectedSample }),
        });
        data = await res.json();
      }
      setAnalysis(data);
      refreshHistory();
    } catch {
      setMessage("Analysis failed. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  async function askQuestion() {
    if (!question.trim()) return;
    const userMessage = { role: "user", content: question };
    setChatHistory((current) => [...current, userMessage]);
    const asked = question;
    setQuestion("");
    try {
      const res = await fetch("/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ question: asked, analysis }),
      });
      const data = await res.json();
      setChatHistory((current) => [...current, { role: "assistant", content: data.answer }]);
    } catch {
      setChatHistory((current) => [...current, { role: "assistant", content: "I could not process that question." }]);
    }
  }

  async function clearHistory() {
    await fetch("/api/history", { method: "DELETE" });
    setHistory([]);
  }

  const severityClass = analysis ? `severity-${analysis.severity.toLowerCase()}` : "";

  return (
    <div className="page-shell">
      <aside className="sidebar">
        <h2>Project Controls</h2>
        <label htmlFor="sample-select">Load a sample dataset</label>
        <select id="sample-select" value={selectedSample} onChange={(e) => setSelectedSample(e.target.value)}>
          <option value="">None</option>
          {samples.map((sample) => (
            <option key={sample.id} value={sample.id}>
              {sample.name}
            </option>
          ))}
        </select>
        <button onClick={loadSample}>Load sample</button>
        <button className="ghost" onClick={clearHistory}>Clear history</button>
      </aside>

      <main className="main-content">
        <section className="hero">
          <div>
            <div className="eyebrow">SOC Operations Console</div>
            <h1>AI-Powered SOC Analyst Agent</h1>
            <p>
              Ingest alerts, triage suspicious activity, explain analyst reasoning, and recommend
              next investigation steps through a modern web dashboard built with React and FastAPI.
            </p>
          </div>
          <div className="hero-metrics">
            <div className="metric-card"><span>Primary Mission</span><strong>Threat Triage</strong></div>
            <div className="metric-card"><span>Frontend</span><strong>React + HTML/CSS</strong></div>
            <div className="metric-card"><span>Backend</span><strong>FastAPI</strong></div>
          </div>
        </section>

        <section className="workspace-grid">
          <div className="panel">
            <h3>Alert Intake</h3>
            <p>Load sample telemetry, upload alerts, or paste raw evidence for triage.</p>
            <input
              type="file"
              accept=".txt,.log,.json"
              onChange={(e) => e.target.files?.[0] && analyzeAlert(e.target.files[0])}
            />
            <textarea
              value={rawInput}
              onChange={(e) => setRawInput(e.target.value)}
              placeholder="Paste auth logs, suspicious alerts, JSON events, or free-text case notes here..."
            />
            <button disabled={loading} onClick={() => analyzeAlert()}>
              {loading ? "Analyzing..." : "Analyze alert"}
            </button>
            {message && <div className="status-message">{message}</div>}
          </div>

          <div className="panel">
            <h3>Investigation Chat</h3>
            <p>Ask for severity justification, evidence, MITRE hints, or next response steps.</p>
            <div className="chat-suggestions">
              <strong>Suggested questions</strong>
              <ul>
                <li>Why is this alert suspicious?</li>
                <li>What should the analyst do first?</li>
                <li>What evidence should be checked next?</li>
              </ul>
            </div>
            <div className="chat-log">
              {chatHistory.map((item, index) => (
                <div key={`${item.role}-${index}`} className={`chat-bubble ${item.role}`}>
                  <span>{item.role === "user" ? "You" : "Agent"}</span>
                  <pre>{item.content}</pre>
                </div>
              ))}
            </div>
            <div className="chat-input-row">
              <input
                value={question}
                onChange={(e) => setQuestion(e.target.value)}
                placeholder="Ask about the current alert, severity, or next actions"
              />
              <button onClick={askQuestion}>Send</button>
            </div>
          </div>
        </section>

        {analysis && (
          <section className="results">
            <h2>Triage Result</h2>
            <div className="metrics-row">
              <div><span>Severity</span><strong>{analysis.severity}</strong></div>
              <div><span>Confidence</span><strong>{analysis.confidence}</strong></div>
              <div><span>Source Type</span><strong>{analysis.source_type}</strong></div>
            </div>

            <div className={`severity-banner ${severityClass}`}>
              <div>
                <div className={`severity-chip ${severityClass}`}>{analysis.severity} Severity</div>
                <h3>{analysis.title}</h3>
                <p>Confidence: {analysis.confidence} | Source: {analysis.source_type}</p>
              </div>
              <p className="banner-copy">SOC-ready output designed to explain what happened and what the analyst should do next.</p>
            </div>

            <div className="summary-card">
              <h4>Executive Summary</h4>
              <p>{analysis.summary}</p>
            </div>

            <div className="card-grid">
              <div className="info-card">
                <h4>Why it is suspicious</h4>
                <ul>{analysis.reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>
              </div>
              <div className="info-card">
                <h4>Suggested next actions</h4>
                <ul>{analysis.suggested_actions.map((action) => <li key={action}>{action}</li>)}</ul>
              </div>
            </div>

            <div className="card-grid">
              <div className="info-card">
                <h4>MITRE ATT&CK hints</h4>
                {analysis.mitre_attack.length ? (
                  <ul>{analysis.mitre_attack.map((item) => <li key={item}>{item}</li>)}</ul>
                ) : (
                  <p>No strong MITRE mapping was inferred from the current evidence.</p>
                )}
              </div>
              <div className="info-card">
                <h4>Normalized evidence</h4>
                <pre>{analysis.normalized_context}</pre>
              </div>
            </div>

            <div className="card-grid">
              <div className="info-card">
                <h4>RAG Knowledge Context</h4>
                {analysis.retrieved_knowledge?.length ? (
                  <div className="stacked-list">
                    {analysis.retrieved_knowledge.map((item, index) => (
                      <article key={`${item.title}-${index}`} className="stacked-item">
                        <span>{item.category}</span>
                        <strong>{item.title}</strong>
                        <p>{item.content}</p>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p>No additional local knowledge was retrieved for this alert.</p>
                )}
              </div>
              <div className="info-card">
                <h4>Threat Intelligence Enrichment</h4>
                {analysis.threat_intelligence?.length ? (
                  <div className="stacked-list">
                    {analysis.threat_intelligence.map((item, index) => (
                      <article key={`${item.indicator}-${index}`} className="stacked-item">
                        <span>{item.type} | {item.severity}</span>
                        <strong>{item.indicator}</strong>
                        <p>{item.note}</p>
                      </article>
                    ))}
                  </div>
                ) : (
                  <p>No enrichment data is available.</p>
                )}
              </div>
            </div>

            {analysis.incident_report && (
              <div className="summary-card report-card">
                <h4>Generated Incident Report</h4>
                <div className="report-grid">
                  <div>
                    <span>Executive Summary</span>
                    <p>{analysis.incident_report.executive_summary}</p>
                  </div>
                  <div>
                    <span>Affected Scope</span>
                    <p>{analysis.incident_report.affected_scope}</p>
                  </div>
                  <div>
                    <span>Containment Priority</span>
                    <p>{analysis.incident_report.containment_priority}</p>
                  </div>
                  <div>
                    <span>Report Status</span>
                    <p>{analysis.incident_report.report_status}</p>
                  </div>
                </div>
              </div>
            )}
          </section>
        )}

        <section className="history-panel">
          <h3>Recent Investigations</h3>
          <p>Local case tracking for your latest alert triage sessions.</p>
          <div className="history-list">
            {history.map((item, index) => (
              <article className="history-item" key={`${item.title}-${index}`}>
                <div className="history-head">
                  <div>
                    <strong>{item.title}</strong>
                    <p>{item.source_type} | {item.timestamp}</p>
                  </div>
                  <div className={`severity-chip severity-${String(item.severity).toLowerCase()}`}>{item.severity}</div>
                </div>
                <p>{item.summary}</p>
              </article>
            ))}
            {!history.length && <div className="history-empty">No investigations yet. Analyze an alert to start building history.</div>}
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
