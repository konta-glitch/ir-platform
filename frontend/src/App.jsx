import { useState, useEffect, useCallback, useRef } from "react";

const API = "/api";

// ── Palette ──
const C = {
  bg: "#0f0f0f",
  surface: "#1a1a1a",
  surface2: "#222",
  border: "#2a2a2a",
  border2: "#3a3a3a",
  text: "#e4e4e4",
  muted: "#888",
  dim: "#555",
  accent: "#7f77dd",
  accentDim: "#534AB7",
  teal: "#1D9E75",
  tealDim: "#0F6E56",
  coral: "#D85A30",
  amber: "#EF9F27",
  red: "#E24B4A",
  blue: "#378ADD",
  green: "#5DCAA5",
};

const SEVERITY = {
  critical: { bg: "#501313", fg: "#F7C1C1", b: "#A32D2D" },
  high:     { bg: "#4A1B0C", fg: "#F5C4B3", b: "#993C1D" },
  medium:   { bg: "#412402", fg: "#FAC775", b: "#854F0B" },
  low:      { bg: "#042C53", fg: "#B5D4F4", b: "#185FA5" },
  info:     { bg: "#2C2C2A", fg: "#D3D1C7", b: "#5F5E5A" },
};

const ARTIFACT_TYPES = [
  "processes", "network", "filesystem", "registry",
  "eventlog", "prefetch", "autoruns", "browser", "timeline",
];

// ── Primitives ──

const Badge = ({ severity }) => {
  const s = SEVERITY[severity] || SEVERITY.info;
  return (
    <span style={{
      padding: "2px 10px", borderRadius: 20, fontSize: 10, fontWeight: 700,
      letterSpacing: .8, background: s.bg, color: s.fg,
      border: `1px solid ${s.b}`, textTransform: "uppercase",
    }}>{severity}</span>
  );
};

const Tag = ({ children, active, onClick }) => (
  <button onClick={onClick} style={{
    padding: "4px 12px", borderRadius: 20, fontSize: 12, cursor: "pointer",
    border: `1px solid ${active ? C.accent : C.border2}`,
    background: active ? C.accentDim : "transparent",
    color: active ? "#fff" : C.muted, fontWeight: active ? 600 : 400,
    transition: "all .15s",
  }}>{children}</button>
);

const Card = ({ children, style, ...rest }) => (
  <div style={{
    background: C.surface, border: `1px solid ${C.border}`,
    borderRadius: 10, padding: 20, ...style,
  }} {...rest}>{children}</div>
);

const Btn = ({ children, variant = "default", disabled, style, ...rest }) => {
  const base = {
    padding: "7px 16px", borderRadius: 8, fontSize: 13, fontWeight: 500,
    cursor: disabled ? "not-allowed" : "pointer", opacity: disabled ? .5 : 1,
    transition: "all .15s", border: "none", ...style,
  };
  const variants = {
    primary: { background: C.accent, color: "#fff" },
    teal: { background: C.tealDim, color: "#fff" },
    danger: { background: "#791F1F", color: "#F7C1C1" },
    default: { background: "transparent", color: C.text, border: `1px solid ${C.border2}` },
    ghost: { background: "transparent", color: C.muted, border: "none", padding: "4px 8px" },
  };
  return <button style={{ ...base, ...variants[variant] }} disabled={disabled} {...rest}>{children}</button>;
};

const Input = ({ label, ...rest }) => (
  <div style={{ marginBottom: 12 }}>
    {label && <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 4, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label>}
    <input style={{
      width: "100%", padding: "8px 12px", borderRadius: 8,
      border: `1px solid ${C.border}`, background: C.bg,
      color: C.text, fontSize: 14, boxSizing: "border-box",
    }} {...rest} />
  </div>
);

const TextArea = ({ label, ...rest }) => (
  <div style={{ marginBottom: 12 }}>
    {label && <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 4, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>{label}</label>}
    <textarea style={{
      width: "100%", padding: "8px 12px", borderRadius: 8,
      border: `1px solid ${C.border}`, background: C.bg,
      color: C.text, fontSize: 13, fontFamily: "monospace",
      minHeight: 100, resize: "vertical", boxSizing: "border-box",
    }} {...rest} />
  </div>
);

// ── Health ──

function HealthBar({ health }) {
  const items = [
    { label: "LM Studio", ok: health?.lm_studio_reachable, detail: health?.lm_studio_model },
    { label: "Claude API", ok: health?.claude_api_configured, detail: "standby" },
  ];
  return (
    <div style={{ display: "flex", gap: 8, marginBottom: 20 }}>
      {items.map(s => (
        <div key={s.label} style={{
          flex: 1, padding: "10px 14px", borderRadius: 8,
          background: C.surface, border: `1px solid ${C.border}`,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{
              width: 8, height: 8, borderRadius: "50%",
              background: s.ok ? C.green : C.red,
            }} />
            <span style={{ fontSize: 12, color: C.text }}>{s.label}</span>
          </div>
          {s.detail && (
            <div style={{ fontSize: 11, color: C.dim, marginTop: 4, fontFamily: "monospace" }}>
              {s.detail}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Manual Analysis ──

function ManualPanel({ onResult }) {
  const [rawData, setRawData] = useState("");
  const [title, setTitle] = useState("");
  const [context, setContext] = useState("");
  const [dataType, setDataType] = useState("processes");
  const [allowCloud, setAllowCloud] = useState(true);
  const [loading, setLoading] = useState(false);
  const [step, setStep] = useState("");

  const analyze = async () => {
    if (!rawData) return;
    setLoading(true); setStep("Anonymizing...");
    try {
      const r = await fetch(`${API}/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          title: title || "Manual analysis", raw_data: rawData,
          data_type: dataType, context, allow_cloud: allowCloud,
        }),
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      setStep(data.stats?.cloud_used ? "Done (local + cloud)" : "Done (100% local)");
      onResult?.(data);
    } catch (e) { setStep(`Error: ${e.message}`); }
    finally { setLoading(false); }
  };

  return (
    <Card>
      <h3 style={{ margin: "0 0 16px", fontSize: 15, fontWeight: 500 }}>Paste forensic data</h3>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <Input label="Title" value={title} onChange={e => setTitle(e.target.value)} />
        <div style={{ marginBottom: 12 }}>
          <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 4, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>Data type</label>
          <select value={dataType} onChange={e => setDataType(e.target.value)} style={{
            width: "100%", padding: "8px 12px", borderRadius: 8,
            border: `1px solid ${C.border}`, background: C.bg, color: C.text, fontSize: 14,
          }}>
            {ARTIFACT_TYPES.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
        </div>
      </div>
      <TextArea label="Raw data" value={rawData} onChange={e => setRawData(e.target.value)} rows={6}
        placeholder='Paste JSON, CSV, or text output...' />
      <TextArea label="Context" value={context} onChange={e => setContext(e.target.value)} rows={2} />
      <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
        <label style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12, color: C.muted }}>
          <input type="checkbox" checked={allowCloud} onChange={e => setAllowCloud(e.target.checked)}
            style={{ accentColor: C.accent }} />
          Allow cloud
        </label>
        <Btn variant="primary" onClick={analyze} disabled={loading || !rawData}>
          {loading ? "Analyzing..." : "Analyze"}
        </Btn>
        {step && <span style={{ fontSize: 12, color: C.muted }}>{step}</span>}
      </div>
    </Card>
  );
}

// ── Stats Bar ──

function StatsBar({ stats, escalation }) {
  if (!stats) return null;
  return (
    <div style={{
      display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
      gap: 8, marginBottom: 16,
    }}>
      {[
        { label: "Analyzed by", value: escalation?.sent_to_cloud > 0 ? "Local + Cloud" : "100% Local", color: escalation?.sent_to_cloud > 0 ? C.blue : C.green },
        { label: "Confidence", value: `${Math.round(stats.local_analysis_confidence * 100)}%`, color: stats.local_analysis_confidence >= .7 ? C.green : C.amber },
        { label: "PII redacted", value: stats.pii_items_redacted, color: C.coral },
        { label: "Knowledge gaps", value: `${stats.gaps_found} found`, color: stats.gaps_found > 0 ? C.amber : C.green },
        { label: "Resolved locally", value: stats.gaps_resolved_locally, color: C.teal },
        { label: "Sent to cloud", value: stats.gaps_sent_to_cloud, color: stats.gaps_sent_to_cloud > 0 ? C.blue : C.dim },
      ].map(s => (
        <div key={s.label} style={{ padding: "10px 12px", borderRadius: 8, background: C.surface2 }}>
          <div style={{ fontSize: 10, color: C.dim, textTransform: "uppercase", letterSpacing: .5, marginBottom: 4 }}>{s.label}</div>
          <div style={{ fontSize: 16, fontWeight: 600, color: s.color }}>{s.value}</div>
        </div>
      ))}
    </div>
  );
}

// ── Escalation Details ──

function EscalationView({ escalation, incidentId }) {
  if (!escalation?.items?.length) return null;

  const [approving, setApproving] = useState(false);
  const [approveResult, setApproveResult] = useState(null);

  const approve = async () => {
    setApproving(true); setApproveResult(null);
    try {
      const r = await fetch(`${API}/incidents/${incidentId}/escalation/approve`, { method: "POST" });
      const d = await r.json();
      if (!r.ok) {
        setApproveResult({ error: d.detail || `Error ${r.status}` });
      } else {
        setApproveResult(d);
      }
    } catch (e) { setApproveResult({ error: e.message }); }
    finally { setApproving(false); }
  };

  const unresolved = escalation.items.filter(i => !i.resolved_by_cloud && !i.resolved_locally);

  return (
    <Card style={{ borderLeft: `3px solid ${C.amber}` }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
        <h3 style={{ margin: 0, fontSize: 14, fontWeight: 500 }}>Knowledge gaps</h3>
        {unresolved.length > 0 && (
          <Btn variant="teal" onClick={approve} disabled={approving}>
            {approving ? "Sending to Claude..." : `Approve cloud escalation (${unresolved.length} items)`}
          </Btn>
        )}
      </div>
      {approveResult && (
        <div style={{
          marginBottom: 12, padding: "10px 14px", borderRadius: 8, fontSize: 12,
          background: approveResult.error ? "#501313" : "#04342C",
          borderLeft: `3px solid ${approveResult.error ? C.red : C.green}`,
        }}>
          {approveResult.error ? (
            <span style={{ color: "#F7C1C1" }}>{approveResult.error}</span>
          ) : (
            <div>
              <div style={{ color: C.green, fontWeight: 500 }}>
                Claude resolved {approveResult.cloud_resolved}/{approveResult.escalated} items
              </div>
              {approveResult.enrichments?.map((e, i) => (
                <div key={i} style={{
                  marginTop: 8, padding: "8px 10px", borderRadius: 6, background: C.bg,
                  fontFamily: "monospace", color: C.muted, whiteSpace: "pre-wrap",
                }}>
                  <div style={{ fontWeight: 500, color: C.text, marginBottom: 4 }}>{e.question}</div>
                  {e.answer}
                </div>
              ))}
            </div>
          )}
        </div>
      )}
      <div style={{ fontSize: 12, color: C.dim, marginBottom: 12 }}>{escalation.escalation_reason}</div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {escalation.items.map((item, i) => (
          <div key={i} style={{
            padding: "10px 14px", borderRadius: 8, background: C.surface2,
            borderLeft: `3px solid ${
              item.resolved_by_cloud ? C.blue :
              item.resolved_locally ? C.green : C.amber
            }`,
          }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
              <span style={{ fontSize: 12, fontWeight: 500 }}>{item.question}</span>
              <span style={{
                fontSize: 10, padding: "2px 8px", borderRadius: 10,
                background: item.resolved_by_cloud ? "#042C53" : item.resolved_locally ? "#04342C" : "#412402",
                color: item.resolved_by_cloud ? "#85B7EB" : item.resolved_locally ? "#5DCAA5" : "#FAC775",
              }}>
                {item.resolved_by_cloud ? "cloud" : item.resolved_locally ? "local" : "pending"}
              </span>
            </div>
            <div style={{ fontSize: 11, color: C.dim }}>[{item.category}] priority: {item.priority}</div>
            {(item.cloud_answer || item.local_answer) && (
              <div style={{
                marginTop: 8, padding: "8px 10px", borderRadius: 6, background: C.bg,
                fontSize: 12, color: C.muted, lineHeight: 1.5, fontFamily: "monospace",
                whiteSpace: "pre-wrap",
              }}>
                {item.cloud_answer || item.local_answer}
              </div>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Analysis Results ──

function AnalysisView({ result }) {
  const a = result?.analysis;
  if (!a) return null;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <StatsBar stats={result.stats} escalation={result.escalation} />

      {/* Summary */}
      <Card>
        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 500 }}>Summary</h3>
          <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
            <Badge severity={a.severity} />
            <span style={{
              fontSize: 10, padding: "2px 8px", borderRadius: 10,
              background: a.analyzed_by === "local" ? "#04342C" : "#042C53",
              color: a.analyzed_by === "local" ? C.green : C.blue,
            }}>{a.analyzed_by}</span>
          </div>
        </div>
        <p style={{ margin: 0, fontSize: 13, lineHeight: 1.7, color: C.muted }}>{a.summary}</p>
        {a.confidence_explanation && (
          <div style={{ marginTop: 10, fontSize: 12, color: C.dim, fontStyle: "italic" }}>
            {a.confidence_explanation}
          </div>
        )}
      </Card>

      {/* Cloud enrichments */}
      {a.cloud_enrichments?.length > 0 && (
        <Card style={{ borderLeft: `3px solid ${C.blue}` }}>
          <h3 style={{ margin: "0 0 10px", fontSize: 14, fontWeight: 500 }}>Cloud enrichments</h3>
          {a.cloud_enrichments.map((e, i) => (
            <div key={i} style={{
              padding: "8px 12px", borderRadius: 6, background: C.surface2,
              marginBottom: 6, fontSize: 12, color: C.muted, lineHeight: 1.5,
              fontFamily: "monospace", whiteSpace: "pre-wrap",
            }}>{e}</div>
          ))}
        </Card>
      )}

      {/* IOCs */}
      {a.iocs?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 10px", fontSize: 14, fontWeight: 500 }}>
            IOCs ({a.iocs.length})
          </h3>
          <div style={{ display: "grid", gap: 6 }}>
            {a.iocs.map((ioc, i) => (
              <div key={i} style={{
                display: "grid", gridTemplateColumns: "70px 1fr auto", gap: 8,
                padding: "8px 12px", borderRadius: 6, alignItems: "center",
                background: ioc.malicious ? "rgba(226,75,74,.08)" : C.surface2,
              }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: "uppercase", color: C.dim }}>{ioc.type}</span>
                <code style={{ fontSize: 12, color: C.text }}>{ioc.value}</code>
                <span style={{
                  fontSize: 10, padding: "2px 8px", borderRadius: 10,
                  background: ioc.malicious ? "#501313" : "transparent",
                  color: ioc.malicious ? "#F7C1C1" : C.dim,
                }}>
                  {Math.round(ioc.confidence * 100)}%
                </span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* MITRE */}
      {a.mitre_techniques?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 10px", fontSize: 14, fontWeight: 500 }}>MITRE ATT&CK</h3>
          <div style={{ display: "grid", gap: 6 }}>
            {a.mitre_techniques.map((t, i) => (
              <div key={i} style={{
                padding: "10px 14px", borderRadius: 6, background: C.surface2,
                borderLeft: `3px solid ${t.confidence >= .7 ? C.accent : C.amber}`,
              }}>
                <div style={{ display: "flex", justifyContent: "space-between" }}>
                  <span style={{ fontSize: 13, fontWeight: 500 }}>
                    <code style={{ fontSize: 11 }}>{t.technique_id}</code>{" "}{t.technique_name}
                  </span>
                  <span style={{ fontSize: 11, color: C.dim }}>{t.tactic} · {Math.round(t.confidence * 100)}%</span>
                </div>
                {t.evidence && <p style={{ margin: "4px 0 0", fontSize: 12, color: C.dim }}>{t.evidence}</p>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Timeline */}
      {a.timeline?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 10px", fontSize: 14, fontWeight: 500 }}>Timeline</h3>
          <div style={{ paddingLeft: 16, position: "relative" }}>
            <div style={{ position: "absolute", left: 5, top: 4, bottom: 4, width: 2, background: C.border2 }} />
            {a.timeline.map((e, i) => (
              <div key={i} style={{ position: "relative", marginBottom: 14, paddingLeft: 20 }}>
                <div style={{
                  position: "absolute", left: -13, top: 5, width: 8, height: 8,
                  borderRadius: "50%", background: C.accent,
                  border: `2px solid ${C.surface}`,
                }} />
                <div style={{ fontSize: 11, color: C.dim, fontFamily: "monospace" }}>{e.timestamp}</div>
                <div style={{ fontSize: 13, fontWeight: 500, margin: "2px 0" }}>{e.event}</div>
                {e.significance && <div style={{ fontSize: 12, color: C.dim }}>{e.significance}</div>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Recommendations */}
      {a.recommendations?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 10px", fontSize: 14, fontWeight: 500 }}>Recommendations</h3>
          {a.recommendations.map((r, i) => (
            <div key={i} style={{ display: "flex", gap: 10, marginBottom: 8, fontSize: 13, color: C.muted, lineHeight: 1.5 }}>
              <span style={{
                flexShrink: 0, width: 20, height: 20, borderRadius: "50%",
                background: C.tealDim, color: C.green,
                display: "flex", alignItems: "center", justifyContent: "center",
                fontSize: 10, fontWeight: 700,
              }}>{i + 1}</span>
              <span>{r}</span>
            </div>
          ))}
        </Card>
      )}

      {/* Escalation details */}
      <EscalationView escalation={result.escalation} incidentId={result.incident_id || result.incident?.id} />
    </div>
  );
}

// ── Report View ──

function ReportView({ incidentId, onBack }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);
  const [approving, setApproving] = useState(false);
  const [approveResult, setApproveResult] = useState(null);

  // Investigation agent state
  const [investigation, setInvestigation] = useState(null);
  const [investigating, setInvestigating] = useState(false);
  const [agentSteps, setAgentSteps] = useState([]);
  const [question, setQuestion] = useState("");

  // Conversational chat state
  const [chatMessages, setChatMessages] = useState([]); // {role, content, steps}
  const [chatInput, setChatInput] = useState("");
  const [chatBusy, setChatBusy] = useState(false);

  const sendChat = async () => {
    const q = chatInput.trim();
    if (!q || chatBusy) return;
    setChatInput("");
    setChatMessages(prev => [...prev, { role: "user", content: q }]);
    setChatBusy(true);
    try {
      const form = new FormData();
      form.append("question", q);
      const r = await fetch(`${API}/incidents/${incidentId}/chat`, { method: "POST", body: form });
      const d = await r.json();
      if (!r.ok) {
        setChatMessages(prev => [...prev, { role: "agent", content: d.detail || `Error ${r.status}`, error: true }]);
      } else {
        setChatMessages(prev => [...prev, { role: "agent", content: d.answer, steps: d.steps || [] }]);
      }
    } catch (e) {
      setChatMessages(prev => [...prev, { role: "agent", content: e.message, error: true }]);
    } finally {
      setChatBusy(false);
    }
  };

  const clearChat = async () => {
    try { await fetch(`${API}/incidents/${incidentId}/chat/clear`, { method: "POST" }); } catch {}
    setChatMessages([]);
  };

  // ── Finding triage ──
  // Verdict map keyed by finding id, seeded from the report and updated
  // optimistically so marking a finding feels instant.
  const [triage, setTriage] = useState({});
  const [triageFilter, setTriageFilter] = useState("all");
  const [noteDraft, setNoteDraft] = useState({}); // finding_id -> in-progress note text

  const markFinding = async (findingId, verdict) => {
    // Optimistic update; reconcile with server response.
    setTriage(prev => {
      const next = { ...prev };
      if (verdict === "clear") delete next[findingId];
      else next[findingId] = { ...(next[findingId] || {}), verdict };
      return next;
    });
    try {
      const form = new FormData();
      form.append("verdict", verdict);
      const r = await fetch(`${API}/incidents/${incidentId}/findings/${findingId}/triage`,
        { method: "POST", body: form });
      const d = await r.json();
      if (r.ok) setTriage(prev => ({ ...prev, [findingId]: d.triage }));
    } catch { /* keep optimistic state */ }
  };

  const saveNote = async (findingId) => {
    const note = (noteDraft[findingId] ?? "").trim();
    try {
      const form = new FormData();
      form.append("note", note);
      const r = await fetch(`${API}/incidents/${incidentId}/findings/${findingId}/triage`,
        { method: "POST", body: form });
      const d = await r.json();
      if (r.ok) {
        setTriage(prev => ({ ...prev, [findingId]: d.triage }));
        setNoteDraft(prev => { const n = { ...prev }; delete n[findingId]; return n; });
      }
    } catch { /* ignore */ }
  };

  const loadReport = () => {
    fetch(`${API}/incidents/${incidentId}/report`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setReport(d); if (d?.finding_triage) setTriage(d.finding_triage); setLoading(false); })
      .catch(() => setLoading(false));
  };
  useEffect(loadReport, [incidentId]);

  // Load any previously-run investigation
  useEffect(() => {
    fetch(`${API}/incidents/${incidentId}/investigation`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setInvestigation(d); })
      .catch(() => {});
  }, [incidentId]);

  const runInvestigation = async () => {
    setInvestigating(true);
    setInvestigation(null);
    setAgentSteps([]);
    try {
      const form = new FormData();
      form.append("question", question);
      form.append("max_steps", "12");
      const r = await fetch(`${API}/incidents/${incidentId}/investigate`, { method: "POST", body: form });
      if (!r.ok) throw new Error(await r.text());
      const { job_id } = await r.json();

      // Poll for progress + result
      const poll = async () => {
        try {
          const sr = await fetch(`${API}/investigations/${job_id}`);
          if (sr.ok) {
            const job = await sr.json();
            setAgentSteps(job.steps || []);
            if (job.done) {
              setInvestigating(false);
              if (job.error) setInvestigation({ error: job.error });
              else setInvestigation(job.result);
              return;
            }
          }
        } catch {}
        setTimeout(poll, 1500);
      };
      poll();
    } catch (e) {
      setInvestigating(false);
      setInvestigation({ error: e.message });
    }
  };

  const approveEscalation = async () => {
    setApproving(true); setApproveResult(null);
    try {
      const r = await fetch(`${API}/incidents/${incidentId}/escalation/approve`, { method: "POST" });
      const d = await r.json();
      if (!r.ok) setApproveResult({ error: d.detail || `Error ${r.status}` });
      else { setApproveResult(d); loadReport(); }
    } catch (e) { setApproveResult({ error: e.message }); }
    finally { setApproving(false); }
  };

  if (loading) return <Card style={{ textAlign: "center", padding: 40, color: C.muted }}>Loading report...</Card>;
  if (!report) return <Card style={{ textAlign: "center", padding: 40, color: C.red }}>Report not found</Card>;

  const m = report.metadata;
  const sevColors = { CRITICAL: C.red, HIGH: C.coral, MEDIUM: C.amber, LOW: C.blue, INFORMATIONAL: C.dim };
  const sevColor = sevColors[m.severity] || C.dim;
  const pendingGaps = (report.knowledge_gaps || []).filter(g => g.status === "pending");

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      {/* Header (full width) */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <Btn variant="ghost" onClick={onBack}>← Back</Btn>
        <a href={`${API}/incidents/${incidentId}/report/download`} download
          style={{ padding: "6px 14px", borderRadius: 8, fontSize: 12, background: C.accentDim, color: "#fff", textDecoration: "none" }}>
          Download report (.md)
        </a>
      </div>

      {/* Two-column workspace: report on the left, sticky agent chat on the
          right so the analyst can read findings and ask the agent without
          scrolling between them. Collapses to one column on narrow screens. */}
      <div className="ir-workspace" style={{
        display: "grid", gridTemplateColumns: "minmax(0, 1fr) 380px",
        gap: 16, alignItems: "start",
      }}>
        {/* LEFT: report content */}
        <div style={{ display: "flex", flexDirection: "column", gap: 16, minWidth: 0 }}>

      {/* Cover */}
      <Card style={{ borderTop: `3px solid ${sevColor}` }}>
        <div style={{ fontSize: 11, color: C.dim, textTransform: "uppercase", letterSpacing: 1 }}>Incident Response Report</div>
        <h2 style={{ margin: "8px 0 4px", fontSize: 20, fontWeight: 500 }}>{m.report_id}: {m.title}</h2>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginTop: 12 }}>
          <span style={{ padding: "3px 12px", borderRadius: 20, fontSize: 11, fontWeight: 600, background: sevColor + "22", color: sevColor, border: `1px solid ${sevColor}44` }}>{m.severity}</span>
          <span style={{ padding: "3px 12px", borderRadius: 20, fontSize: 11, background: C.surface2, color: C.muted }}>Confidence: {m.confidence}</span>
          <span style={{ padding: "3px 12px", borderRadius: 20, fontSize: 11, background: C.surface2, color: C.muted }}>Status: {m.status}</span>
          <span style={{ padding: "3px 12px", borderRadius: 20, fontSize: 11, background: m.analyzed_by === "local" ? "#04342C" : "#042C53", color: m.analyzed_by === "local" ? C.green : C.blue }}>{m.analyzed_by}</span>
        </div>
        <div style={{ fontSize: 11, color: C.dim, marginTop: 10 }}>Generated: {m.generated_at}</div>
      </Card>

      {/* Executive Summary */}
      <Card>
        <h3 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 500 }}>Executive summary</h3>
        {report.executive_summary.bottom_line && (
          <div style={{ padding: "12px 16px", borderRadius: 8, background: sevColor + "11", borderLeft: `3px solid ${sevColor}`, marginBottom: 12 }}>
            <div style={{ fontSize: 11, fontWeight: 600, color: sevColor, textTransform: "uppercase", letterSpacing: .5, marginBottom: 4 }}>Bottom line</div>
            <div style={{ fontSize: 13, color: C.text, lineHeight: 1.6 }}>{report.executive_summary.bottom_line}</div>
          </div>
        )}
        {report.executive_summary.key_metrics && (
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(90px, 1fr))", gap: 8, marginBottom: 12 }}>
            {[
              { label: "Findings", value: report.executive_summary.key_metrics.total_findings, color: C.text },
              { label: "Critical", value: report.executive_summary.key_metrics.critical, color: C.red },
              { label: "High", value: report.executive_summary.key_metrics.high, color: C.coral },
              { label: "IOCs", value: report.executive_summary.key_metrics.iocs, color: C.text },
              { label: "Tactics", value: report.executive_summary.key_metrics.mitre_tactics, color: C.accent },
              { label: "Techniques", value: report.executive_summary.key_metrics.mitre_techniques, color: C.accent },
            ].map((m, i) => (
              <div key={i} style={{ padding: "10px 8px", borderRadius: 8, background: C.surface2, textAlign: "center" }}>
                <div style={{ fontSize: 20, fontWeight: 500, color: m.color }}>{m.value}</div>
                <div style={{ fontSize: 10, color: C.dim, textTransform: "uppercase", letterSpacing: .5 }}>{m.label}</div>
              </div>
            ))}
          </div>
        )}
        <p style={{ margin: 0, fontSize: 14, lineHeight: 1.7, color: C.muted }}>{report.executive_summary.summary}</p>
        {report.executive_summary.confidence_explanation && (
          <p style={{ margin: "10px 0 0", fontSize: 12, color: C.dim, fontStyle: "italic" }}>{report.executive_summary.confidence_explanation}</p>
        )}
      </Card>

      {/* Attack Narrative (LLM-generated) */}
      {report.attack_narrative?.attack_narrative && (
        <Card style={{ borderLeft: `3px solid ${C.accent}` }}>
          <h3 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 500 }}>Attack narrative</h3>
          <p style={{ margin: "0 0 12px", fontSize: 13, lineHeight: 1.7, color: C.muted, whiteSpace: "pre-wrap" }}>
            {report.attack_narrative.attack_narrative}
          </p>
          {report.attack_narrative.threat_assessment && (
            <div style={{ padding: "10px 14px", borderRadius: 8, background: C.surface2, marginBottom: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: C.coral, textTransform: "uppercase", letterSpacing: .5, marginBottom: 4 }}>Threat assessment</div>
              <div style={{ fontSize: 13, color: C.text, lineHeight: 1.6 }}>{report.attack_narrative.threat_assessment}</div>
            </div>
          )}
          {report.attack_narrative.key_findings?.length > 0 && (
            <div>
              <div style={{ fontSize: 12, fontWeight: 500, color: C.text, marginBottom: 8 }}>Key findings triage</div>
              {report.attack_narrative.key_findings.map((kf, i) => (
                <div key={i} style={{ padding: "8px 12px", marginBottom: 6, borderRadius: 6, background: C.surface2 }}>
                  <div style={{ fontSize: 12 }}>
                    <code style={{ color: C.accent, fontSize: 11 }}>{kf.finding_id}</code>
                    <span style={{ color: C.muted, marginLeft: 8 }}>{kf.why_it_matters}</span>
                  </div>
                  {kf.recommended_action && (
                    <div style={{ fontSize: 11, color: C.green, marginTop: 4 }}>→ {kf.recommended_action}</div>
                  )}
                </div>
              ))}
            </div>
          )}
        </Card>
      )}

      {/* Investigation Agent */}
      <Card style={{ borderLeft: `3px solid ${C.accent}` }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>AI investigation agent</h3>
          {investigation && !investigation.error && (
            <span style={{ fontSize: 11, padding: "2px 10px", borderRadius: 12, background: C.surface2, color: C.dim }}>
              {investigation.step_count} steps
            </span>
          )}
        </div>
        <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim, lineHeight: 1.6 }}>
          The agent queries the actual collected data with tools — searching IOCs, inspecting findings,
          tracing process trees — and reasons step by step until it reaches a verdict. Every claim is
          grounded in a tool result, never guessed.
        </p>

        {!investigating && (
          <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
            <input
              value={question}
              onChange={e => setQuestion(e.target.value)}
              placeholder="Optional: focus the investigation (e.g. 'check for lateral movement')"
              style={{ flex: 1, padding: "8px 12px", borderRadius: 8, border: `1px solid ${C.border}`,
                       background: C.bg, color: C.text, fontSize: 12 }}
            />
            <Btn onClick={runInvestigation}>
              {investigation ? "Re-investigate" : "Investigate"}
            </Btn>
          </div>
        )}

        {/* Live steps */}
        {(investigating || agentSteps.length > 0) && (
          <div style={{ marginBottom: investigation ? 12 : 0 }}>
            {agentSteps.map((s, i) => (
              <div key={i} style={{ display: "flex", gap: 10, padding: "6px 0", borderBottom: `1px solid ${C.border}22` }}>
                <span style={{ fontSize: 10, color: C.dim, fontFamily: "monospace", minWidth: 20 }}>{s.step}</span>
                <div style={{ flex: 1 }}>
                  <code style={{ fontSize: 11, color: s.action === "conclude" ? C.green : C.accent }}>{s.action}</code>
                  {s.thought && <span style={{ fontSize: 11, color: C.muted, marginLeft: 8 }}>{s.thought}</span>}
                </div>
              </div>
            ))}
            {investigating && (
              <div style={{ display: "flex", alignItems: "center", gap: 8, padding: "8px 0", fontSize: 12, color: C.accent }}>
                <span className="pulse" style={{ width: 6, height: 6, borderRadius: "50%", background: C.accent }} />
                Agent investigating...
              </div>
            )}
          </div>
        )}

        {/* Verdict */}
        {investigation?.error && (
          <div style={{ fontSize: 12, color: C.coral, padding: "8px 12px", borderRadius: 8, background: C.red + "11" }}>
            {investigation.error}
          </div>
        )}
        {investigation?.verdict && investigation.verdict.compromised !== null && (
          <div style={{ padding: "12px 16px", borderRadius: 8, background: C.surface2 }}>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: investigation.verdict.compromised ? C.red : C.green }}>
                {investigation.verdict.compromised ? "COMPROMISED" : "NO COMPROMISE FOUND"}
              </span>
              <span style={{ fontSize: 11, color: C.dim }}>
                confidence {Math.round((investigation.verdict.confidence || 0) * 100)}%
              </span>
            </div>
            <p style={{ margin: "0 0 10px", fontSize: 13, color: C.text, lineHeight: 1.6 }}>
              {investigation.verdict.summary}
            </p>
            {investigation.verdict.attack_chain?.length > 0 && (
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: C.dim, marginBottom: 4 }}>Attack chain</div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 6, alignItems: "center" }}>
                  {investigation.verdict.attack_chain.map((step, i) => (
                    <span key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11, padding: "3px 10px", borderRadius: 6, background: C.bg, color: C.muted }}>{step}</span>
                      {i < investigation.verdict.attack_chain.length - 1 && <span style={{ color: C.dim }}>→</span>}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {investigation.verdict.recommended_actions?.length > 0 && (
              <div>
                <div style={{ fontSize: 11, color: C.dim, marginBottom: 4 }}>Recommended actions</div>
                {investigation.verdict.recommended_actions.map((a, i) => (
                  <div key={i} style={{ fontSize: 12, color: C.green, marginBottom: 2 }}>→ {a}</div>
                ))}
              </div>
            )}
          </div>
        )}
      </Card>

      {/* Conversational chat moved to the right panel (see below) */}

      {/* Entity connectivity graph */}
      <EntityGraph incidentId={incidentId} />

      {/* MITRE ATT&CK Coverage */}
      {report.mitre_coverage?.coverage?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>
            MITRE ATT&CK coverage
          </h3>
          <p style={{ margin: "0 0 14px", fontSize: 12, color: C.dim }}>
            {report.mitre_coverage.tactics_observed} tactics · {report.mitre_coverage.total_techniques} techniques observed across the kill chain
          </p>
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {report.mitre_coverage.coverage.map((tac, i) => (
              <div key={i} style={{ display: "flex", gap: 12, alignItems: "flex-start" }}>
                <div style={{ width: 140, flexShrink: 0, fontSize: 12, fontWeight: 500, color: C.text, paddingTop: 4 }}>
                  {tac.tactic}
                  <span style={{ fontSize: 10, color: C.dim, fontWeight: 400 }}> ({tac.total_detections})</span>
                </div>
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4, flex: 1 }}>
                  {tac.techniques.map((t, j) => {
                    const tc = { critical: C.red, high: C.coral, medium: C.amber, low: C.blue, info: C.dim }[t.severity] || C.dim;
                    return (
                      <span key={j} title={t.examples?.join("; ")} style={{
                        fontSize: 11, padding: "3px 8px", borderRadius: 6,
                        background: tc + "22", color: tc, border: `1px solid ${tc}44`,
                        fontFamily: "monospace", cursor: "default",
                      }}>{t.id}{t.count > 1 ? ` ×${t.count}` : ""}</span>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Anonymization */}
      <Card>
        <h3 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 500 }}>Data anonymization</h3>
        <div style={{ fontSize: 13, color: C.muted, marginBottom: 10 }}>{report.anonymization.total_redacted} identifiers redacted before analysis</div>
        {Object.keys(report.anonymization.by_category || {}).length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
            {Object.entries(report.anonymization.by_category).sort((a,b) => b[1]-a[1]).map(([cat, count]) => (
              <span key={cat} style={{ padding: "2px 10px", borderRadius: 20, fontSize: 11, background: C.surface2, color: C.muted }}>
                {cat}: {count}
              </span>
            ))}
          </div>
        )}
      </Card>

      {/* IOCs */}
      {report.iocs.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 12px", fontSize: 15, fontWeight: 500 }}>Indicators of compromise ({report.iocs.length})</h3>
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12 }}>
              <thead>
                <tr style={{ borderBottom: `1px solid ${C.border}` }}>
                  <th style={{ padding: "8px 6px", textAlign: "left", color: C.dim, fontWeight: 500 }}>Type</th>
                  <th style={{ padding: "8px 6px", textAlign: "left", color: C.dim, fontWeight: 500 }}>Value</th>
                  <th style={{ padding: "8px 6px", textAlign: "center", color: C.dim, fontWeight: 500 }}>Malicious</th>
                  <th style={{ padding: "8px 6px", textAlign: "center", color: C.dim, fontWeight: 500 }}>Confidence</th>
                  <th style={{ padding: "8px 6px", textAlign: "left", color: C.dim, fontWeight: 500 }}>Context</th>
                </tr>
              </thead>
              <tbody>
                {report.iocs.map((ioc, i) => (
                  <tr key={i} style={{ borderBottom: `1px solid ${C.border}22`, background: ioc.malicious ? C.red + "08" : "transparent" }}>
                    <td style={{ padding: "6px", fontSize: 10, fontWeight: 600, textTransform: "uppercase", color: C.dim }}>{ioc.type}</td>
                    <td style={{ padding: "6px", fontFamily: "monospace", fontSize: 11, color: C.text }}>{ioc.value}</td>
                    <td style={{ padding: "6px", textAlign: "center" }}>
                      {ioc.malicious ? <span style={{ color: C.red, fontWeight: 600 }}>YES</span> : <span style={{ color: C.dim }}>No</span>}
                    </td>
                    <td style={{ padding: "6px", textAlign: "center" }}>
                      <span style={{ padding: "1px 6px", borderRadius: 8, fontSize: 10, background: ioc.confidence_raw >= 0.7 ? "#04342C" : ioc.confidence_raw >= 0.4 ? "#412402" : "#501313", color: ioc.confidence_raw >= 0.7 ? C.green : ioc.confidence_raw >= 0.4 ? C.amber : "#F7C1C1" }}>{ioc.confidence}</span>
                    </td>
                    <td style={{ padding: "6px", fontSize: 11, color: C.dim, maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{ioc.context}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {/* MITRE ATT&CK */}
      {report.mitre_techniques.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 12px", fontSize: 15, fontWeight: 500 }}>MITRE ATT&CK mapping ({report.mitre_techniques.length})</h3>
          <div style={{ display: "grid", gap: 8 }}>
            {report.mitre_techniques.map((t, i) => (
              <div key={i} style={{ padding: "12px 16px", borderRadius: 8, background: C.surface2, borderLeft: `3px solid ${t.confidence_raw >= 0.7 ? C.accent : C.amber}` }}>
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <div>
                    <code style={{ fontSize: 11, color: C.accent }}>{t.id}</code>
                    <span style={{ fontSize: 13, fontWeight: 500, marginLeft: 8 }}>{t.name}</span>
                  </div>
                  <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                    <span style={{ fontSize: 10, color: C.dim, padding: "2px 8px", borderRadius: 8, background: C.bg }}>{t.tactic}</span>
                    <span style={{ fontSize: 10, color: C.muted }}>{t.confidence}</span>
                  </div>
                </div>
                {t.evidence && <div style={{ fontSize: 12, color: C.dim, marginTop: 6, lineHeight: 1.5 }}>{t.evidence}</div>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Timeline */}
      {report.timeline.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 12px", fontSize: 15, fontWeight: 500 }}>Attack timeline ({report.timeline.length} events)</h3>
          <div style={{ paddingLeft: 16, position: "relative" }}>
            <div style={{ position: "absolute", left: 5, top: 4, bottom: 4, width: 2, background: C.border2 }} />
            {report.timeline.map((e, i) => (
              <div key={i} style={{ position: "relative", marginBottom: 16, paddingLeft: 24 }}>
                <div style={{ position: "absolute", left: -13, top: 6, width: 10, height: 10, borderRadius: "50%", background: C.accent, border: `2px solid ${C.surface}` }} />
                <div style={{ fontSize: 11, fontFamily: "monospace", color: C.dim }}>{e.timestamp}</div>
                <div style={{ fontSize: 13, fontWeight: 500, margin: "2px 0" }}>{e.event}</div>
                {e.source && <div style={{ fontSize: 11, color: C.dim }}>Source: {e.source}</div>}
                {e.significance && <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>{e.significance}</div>}
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Recommendations */}
      {report.recommendations.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 12px", fontSize: 15, fontWeight: 500 }}>Recommendations ({report.recommendations.length})</h3>
          {report.recommendations.map((rec, i) => (
            <div key={i} style={{ display: "flex", gap: 12, marginBottom: 10, fontSize: 13, color: C.muted, lineHeight: 1.6 }}>
              <span style={{ flexShrink: 0, width: 24, height: 24, borderRadius: "50%", background: C.tealDim, color: C.green, display: "flex", alignItems: "center", justifyContent: "center", fontSize: 11, fontWeight: 600 }}>{i + 1}</span>
              <span>{rec}</span>
            </div>
          ))}
        </Card>
      )}

      {/* Knowledge Gaps */}
      {report.knowledge_gaps.length > 0 && (
        <Card style={{ borderLeft: `3px solid ${C.amber}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>Knowledge gaps ({report.knowledge_gaps.length})</h3>
            {pendingGaps.length > 0 && (
              <Btn variant="teal" onClick={approveEscalation} disabled={approving}>
                {approving ? "Sending to Claude..." : `Send ${pendingGaps.length} to Anthropic Claude →`}
              </Btn>
            )}
          </div>
          {approveResult && (
            <div style={{ marginBottom: 12, padding: "10px 14px", borderRadius: 8, fontSize: 12,
              background: approveResult.error ? "#501313" : "#04342C",
              borderLeft: `3px solid ${approveResult.error ? C.red : C.green}` }}>
              {approveResult.error ? (
                <span style={{ color: "#F7C1C1" }}>{approveResult.error}</span>
              ) : (
                <span style={{ color: C.green }}>Claude resolved {approveResult.cloud_resolved}/{approveResult.escalated} gaps. Report updated.</span>
              )}
            </div>
          )}
          {report.knowledge_gaps.map((gap, i) => (
            <div key={i} style={{ padding: "8px 12px", marginBottom: 6, borderRadius: 6, background: C.surface2, borderLeft: `3px solid ${gap.status === "resolved_cloud" ? C.blue : gap.status === "resolved_local" ? C.green : C.amber}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12 }}>
                <span style={{ fontWeight: 500 }}>{gap.question}</span>
                <span style={{ fontSize: 10, padding: "1px 6px", borderRadius: 8, background: gap.status === "pending" ? "#412402" : "#04342C", color: gap.status === "pending" ? C.amber : C.green }}>{gap.status}</span>
              </div>
              <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>[{gap.category}] priority: {gap.priority}</div>
              {gap.answer && <div style={{ fontSize: 11, color: C.muted, marginTop: 6, padding: "6px 8px", background: C.bg, borderRadius: 4, fontFamily: "monospace", whiteSpace: "pre-wrap" }}>{gap.answer}</div>}
            </div>
          ))}
        </Card>
      )}

      {/* Detection Engine Findings */}
      {report.detection_findings?.length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>
            Automated detection findings ({report.detection_findings.length})
          </h3>
          <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim }}>
            Every row of collected data was scanned by the detection engine. Findings below include evidence pointers.
          </p>

          {report.detection_summary?.attack_chains?.length > 0 && (
            <div style={{ marginBottom: 14, padding: "10px 14px", borderRadius: 8, background: C.red + "11", borderLeft: `3px solid ${C.red}` }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: C.coral, marginBottom: 4 }}>Attack chains identified</div>
              {report.detection_summary.attack_chains.map((chain, i) => (
                <div key={i} style={{ fontSize: 12, color: C.muted }}>• {chain}</div>
              ))}
            </div>
          )}

          {/* Triage filter — work through findings by verdict */}
          {(() => {
            const counts = { all: report.detection_findings.length, untriaged: 0,
              true_positive: 0, false_positive: 0, benign: 0, needs_review: 0 };
            for (const f of report.detection_findings) {
              const v = triage[f.id]?.verdict;
              if (!v) counts.untriaged++; else if (counts[v] != null) counts[v]++;
            }
            const filters = [
              ["all", "All", C.muted], ["untriaged", "Untriaged", C.dim],
              ["true_positive", "True positive", C.red],
              ["false_positive", "False positive", C.green],
              ["benign", "Benign", C.blue], ["needs_review", "Needs review", C.amber],
            ];
            return (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 12 }}>
                {filters.map(([key, label, col]) => (
                  <button key={key} onClick={() => setTriageFilter(key)} style={{
                    padding: "4px 11px", borderRadius: 20, fontSize: 11, cursor: "pointer",
                    fontWeight: triageFilter === key ? 600 : 400,
                    border: `1px solid ${triageFilter === key ? col : C.border2}`,
                    background: triageFilter === key ? col + "22" : "transparent",
                    color: triageFilter === key ? col : C.muted,
                  }}>{label} <span style={{ opacity: .7 }}>{counts[key]}</span></button>
                ))}
              </div>
            );
          })()}

          <div style={{ display: "grid", gap: 6 }}>
            {report.detection_findings.slice(0, 100).filter((f) => {
              if (triageFilter === "all") return true;
              const v = triage[f.id]?.verdict;
              if (triageFilter === "untriaged") return !v;
              return v === triageFilter;
            }).map((f) => {
              const sevColor = { critical: C.red, high: C.coral, medium: C.amber, low: C.blue, info: C.dim }[f.severity] || C.dim;
              return (
                <details key={f.id} style={{ padding: "10px 14px", borderRadius: 8, background: C.surface2, borderLeft: `3px solid ${sevColor}` }}>
                  <summary style={{ cursor: "pointer", fontSize: 13, display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                    <span>
                      <code style={{ fontSize: 10, color: C.dim, marginRight: 8 }}>{f.id}</code>
                      <span style={{ fontWeight: 500 }}>{f.title}</span>
                      {f.category === "sigma_detection" && (
                        <span style={{ fontSize: 9, marginLeft: 6, padding: "1px 6px", borderRadius: 8, background: "#26215C", color: "#CECBF6" }}>SIGMA</span>
                      )}
                    </span>
                    <span style={{ display: "flex", gap: 6, alignItems: "center", flexShrink: 0 }}>
                      {triage[f.id]?.verdict && (() => {
                        const v = triage[f.id].verdict;
                        const vc = { true_positive: C.red, false_positive: C.green, benign: C.blue, needs_review: C.amber }[v] || C.dim;
                        const vl = { true_positive: "TP", false_positive: "FP", benign: "benign", needs_review: "review" }[v] || v;
                        return <span style={{ fontSize: 9, padding: "1px 7px", borderRadius: 10, fontWeight: 700, textTransform: "uppercase", background: vc + "22", color: vc, border: `1px solid ${vc}55` }}>{vl}</span>;
                      })()}
                      {f.mitre && <code style={{ fontSize: 10, color: C.accent }}>{f.mitre}</code>}
                      <span style={{ fontSize: 9, padding: "1px 8px", borderRadius: 10, textTransform: "uppercase", fontWeight: 600, background: sevColor + "22", color: sevColor }}>{f.severity}</span>
                    </span>
                  </summary>
                  <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${C.border}`, fontSize: 12, color: C.muted }}>
                    <div style={{ marginBottom: 6 }}>{f.description}</div>
                    <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>
                      Category: {f.category}
                    </div>
                    <div style={{ fontSize: 11, marginBottom: 8, padding: "5px 8px", borderRadius: 4, background: C.accent + "11", border: `1px solid ${C.accent}33` }}>
                      <span style={{ color: C.dim }}>Evidence: </span>
                      <span style={{ color: C.accent, fontFamily: "monospace", wordBreak: "break-all" }}>
                        {f.evidence?.locator || `${f.artifact} (row ${f.evidence?.row_index ?? "N/A"})`}
                      </span>
                    </div>
                    {(() => {
                      const skip = ["row_index", "locator", "source_file"];
                      const entries = Object.entries(f.evidence || {}).filter(([k, v]) => !skip.includes(k) && v);
                      if (!entries.length && !f.evidence?.source_file) return null;
                      return (
                        <div style={{ padding: "8px 10px", borderRadius: 6, background: C.bg, fontFamily: "monospace", fontSize: 11 }}>
                          {f.evidence?.source_file && (
                            <div style={{ marginBottom: 2 }}>
                              <span style={{ color: C.green }}>file</span>
                              <span style={{ color: C.dim }}>: </span>
                              <span style={{ color: C.text, wordBreak: "break-all" }}>{f.evidence.source_file}</span>
                            </div>
                          )}
                          {entries.map(([k, v]) => (
                            <div key={k} style={{ marginBottom: 2 }}>
                              <span style={{ color: C.accent }}>{k}</span>
                              <span style={{ color: C.dim }}>: </span>
                              <span style={{ color: C.text }}>{String(v).slice(0, 200)}</span>
                            </div>
                          ))}
                        </div>
                      );
                    })()}
                    {/* Triage controls */}
                    <div style={{ marginTop: 12, paddingTop: 10, borderTop: `1px solid ${C.border}` }}>
                      <div style={{ fontSize: 10, color: C.dim, textTransform: "uppercase", letterSpacing: .5, marginBottom: 6 }}>Analyst verdict</div>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 8 }}>
                        {[["true_positive", "True positive", C.red],
                          ["false_positive", "False positive", C.green],
                          ["benign", "Benign", C.blue],
                          ["needs_review", "Needs review", C.amber]].map(([v, label, col]) => {
                          const active = triage[f.id]?.verdict === v;
                          return (
                            <button key={v} onClick={() => markFinding(f.id, active ? "clear" : v)} style={{
                              padding: "4px 11px", borderRadius: 6, fontSize: 11, cursor: "pointer",
                              fontWeight: active ? 600 : 400,
                              border: `1px solid ${active ? col : C.border2}`,
                              background: active ? col + "22" : "transparent",
                              color: active ? col : C.muted,
                            }}>{label}</button>
                          );
                        })}
                      </div>
                      <div style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
                        <textarea
                          value={noteDraft[f.id] ?? triage[f.id]?.note ?? ""}
                          onChange={e => setNoteDraft(prev => ({ ...prev, [f.id]: e.target.value }))}
                          placeholder="Add a note (what you checked, why this verdict)…"
                          style={{ flex: 1, minHeight: 38, padding: "7px 10px", borderRadius: 6,
                            border: `1px solid ${C.border}`, background: C.bg, color: C.text,
                            fontSize: 12, fontFamily: "inherit", resize: "vertical", boxSizing: "border-box" }}
                        />
                        {noteDraft[f.id] != null && noteDraft[f.id] !== (triage[f.id]?.note ?? "") && (
                          <Btn variant="primary" onClick={() => saveNote(f.id)} style={{ fontSize: 11, padding: "6px 12px" }}>Save</Btn>
                        )}
                      </div>
                      {triage[f.id]?.updated_at && (
                        <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>
                          Marked {new Date(triage[f.id].updated_at).toLocaleString()}
                        </div>
                      )}
                    </div>
                  </div>
                </details>
              );
            })}
            {report.detection_findings.length > 100 && (
              <div style={{ fontSize: 11, color: C.dim, textAlign: "center", padding: 8 }}>
                Showing top 100 of {report.detection_findings.length} findings. Download report for full list.
              </div>
            )}
          </div>
        </Card>
      )}

      {/* Timeline Activity Bursts */}
      {report.timeline_clusters?.length > 0 && (
        <Card style={{ borderLeft: `3px solid ${C.coral}` }}>
          <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>
            Timeline activity bursts ({report.timeline_clusters.length})
          </h3>
          <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim }}>
            Tight clusters of cross-artifact activity — often coordinated attacker actions in a short window.
          </p>
          {report.timeline_clusters.map((c, i) => (
            <details key={i} style={{ padding: "10px 14px", marginBottom: 6, borderRadius: 8, background: C.surface2 }}>
              <summary style={{ cursor: "pointer", fontSize: 13, display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontWeight: 500 }}>{c.event_count} events in &lt;5 min</span>
                <span style={{ fontSize: 11, color: C.dim }}>{c.artifacts_involved?.length} artifact types</span>
              </summary>
              <div style={{ marginTop: 8, paddingTop: 8, borderTop: `1px solid ${C.border}` }}>
                <div style={{ fontSize: 11, color: C.dim, marginBottom: 6 }}>{c.start} → {c.end}</div>
                {c.events?.slice(0, 10).map((ev, j) => (
                  <div key={j} style={{ fontSize: 11, fontFamily: "monospace", color: C.muted, padding: "2px 0", display: "flex", gap: 8 }}>
                    <span style={{ color: C.dim, flexShrink: 0 }}>{ev.time?.split("T")[1]?.slice(0,8) || ev.time}</span>
                    <span style={{ color: C.accent, flexShrink: 0 }}>[{ev.artifact}]</span>
                    <span>{ev.description}</span>
                  </div>
                ))}
              </div>
            </details>
          ))}
        </Card>
      )}

      {/* Suspicious Process Chains */}
      {report.suspicious_chains?.length > 0 && (
        <Card style={{ borderLeft: `3px solid ${C.red}` }}>
          <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>
            Suspicious process chains ({report.suspicious_chains.length})
          </h3>
          <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim }}>
            Reconstructed process ancestry matching known attack patterns.
          </p>
          {report.suspicious_chains.map((c, i) => (
            <div key={i} style={{ padding: "10px 14px", marginBottom: 6, borderRadius: 8, background: C.surface2, fontFamily: "monospace", fontSize: 12 }}>
              <div style={{ color: C.text, lineHeight: 1.6 }}>
                {c.chain.split(" → ").map((proc, j, arr) => (
                  <span key={j}>
                    <span style={{ color: j === arr.length - 1 ? C.coral : C.muted }}>{proc}</span>
                    {j < arr.length - 1 && <span style={{ color: C.dim }}> → </span>}
                  </span>
                ))}
              </div>
              <div style={{ fontSize: 10, color: C.dim, marginTop: 4 }}>depth {c.depth}</div>
            </div>
          ))}
        </Card>
      )}

      {/* Frequency Analysis */}
      {report.frequency_summary && Object.keys(report.frequency_summary).length > 0 && (
        <Card>
          <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>Frequency analysis</h3>
          <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim }}>
            Stack counting — rare artifacts are statistically suspicious.
          </p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            <span style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: C.surface2, color: C.muted }}>
              Unique processes: <strong style={{ color: C.text }}>{report.frequency_summary.unique_process_names || 0}</strong>
            </span>
            <span style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: C.surface2, color: C.muted }}>
              Unique paths: <strong style={{ color: C.text }}>{report.frequency_summary.unique_paths || 0}</strong>
            </span>
            <span style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: C.surface2, color: C.muted }}>
              Unique hashes: <strong style={{ color: C.text }}>{report.frequency_summary.unique_hashes || 0}</strong>
            </span>
            <span style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: report.frequency_summary.rare_suspicious_paths > 0 ? "#412402" : C.surface2, color: report.frequency_summary.rare_suspicious_paths > 0 ? C.amber : C.muted }}>
              Rare suspicious paths: <strong>{report.frequency_summary.rare_suspicious_paths || 0}</strong>
            </span>
          </div>
        </Card>
      )}

      {/* Pipeline Execution Trace */}
      {report.pipeline_trace?.stages?.length > 0 && (
        <Card>
          <details>
            <summary style={{ cursor: "pointer", fontSize: 15, fontWeight: 500, color: C.text }}>
              Pipeline execution trace
              <span style={{ fontSize: 12, color: C.dim, fontWeight: 400, marginLeft: 8 }}>
                {report.pipeline_trace.total_duration_s}s · {report.pipeline_trace.stage_count} stages
              </span>
            </summary>
            <div style={{ marginTop: 12, display: "flex", flexDirection: "column", gap: 4 }}>
              {report.pipeline_trace.stages.map((s, i) => {
                const maxDur = Math.max(...report.pipeline_trace.stages.map(x => x.duration_s || 0), 0.1);
                const pct = ((s.duration_s || 0) / maxDur) * 100;
                return (
                  <div key={i} style={{ fontSize: 12 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 2 }}>
                      <span style={{ color: s.error ? C.red : C.text }}>{s.stage}</span>
                      <span style={{ color: C.dim, fontFamily: "monospace" }}>{s.duration_s}s</span>
                    </div>
                    <div style={{ height: 4, borderRadius: 2, background: C.bg, marginBottom: 4 }}>
                      <div style={{ height: "100%", borderRadius: 2, background: s.error ? C.red : C.accent, width: `${pct}%` }} />
                    </div>
                    {Object.keys(s.metrics || {}).length > 0 && (
                      <div style={{ fontSize: 10, color: C.dim, fontFamily: "monospace", marginBottom: 6 }}>
                        {Object.entries(s.metrics).map(([k, v]) => `${k}=${v}`).join("  ")}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </details>
        </Card>
      )}

      {/* Data Coverage — IR completeness proof */}
      {report.coverage?.per_artifact?.length > 0 ? (
        <Card>
          <h3 style={{ margin: "0 0 6px", fontSize: 15, fontWeight: 500 }}>Data coverage</h3>
          <div style={{ padding: "10px 14px", borderRadius: 8, background: C.green + "11", border: `1px solid ${C.green}33`, marginBottom: 12 }}>
            <div style={{ fontSize: 13, color: C.text }}>
              <strong style={{ color: C.green }}>100% scanned</strong> — every row examined, no sampling.
            </div>
            <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>
              {Number(report.coverage.total_rows_scanned).toLocaleString()} rows across {report.coverage.artifacts_scanned} artifacts
            </div>
          </div>
          <div style={{ maxHeight: 300, overflowY: "auto" }}>
            <table style={{ width: "100%", fontSize: 12, borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ color: C.dim, textAlign: "left" }}>
                  <th style={{ padding: "4px 8px", position: "sticky", top: 0, background: C.surface }}>Artifact</th>
                  <th style={{ padding: "4px 8px", textAlign: "right", position: "sticky", top: 0, background: C.surface }}>Rows</th>
                  <th style={{ padding: "4px 8px", textAlign: "center", position: "sticky", top: 0, background: C.surface }}>✓</th>
                </tr>
              </thead>
              <tbody>
                {report.coverage.per_artifact.map((a, i) => (
                  <tr key={i} style={{ borderTop: `1px solid ${C.border}22` }}>
                    <td style={{ padding: "4px 8px", color: C.muted, fontFamily: "monospace", wordBreak: "break-all" }}>{a.artifact}</td>
                    <td style={{ padding: "4px 8px", textAlign: "right", color: C.text }}>{Number(a.rows_scanned).toLocaleString()}</td>
                    <td style={{ padding: "4px 8px", textAlign: "center", color: C.green }}>{a.fully_scanned ? "✓" : "✗"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      ) : report.detection_statistics && Object.keys(report.detection_statistics).some(k => k.endsWith("_total_rows")) && (
        <Card>
          <h3 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 500 }}>Data coverage</h3>
          <p style={{ margin: "0 0 10px", fontSize: 12, color: C.dim }}>Complete dataset analyzed — not sampled.</p>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {Object.entries(report.detection_statistics)
              .filter(([k]) => k.endsWith("_total_rows"))
              .map(([k, v]) => (
                <span key={k} style={{ padding: "4px 12px", borderRadius: 8, fontSize: 12, background: C.surface2, color: C.muted }}>
                  {k.replace("_total_rows", "")}: <strong style={{ color: C.text }}>{Number(v).toLocaleString()}</strong> rows
                </span>
              ))}
          </div>
        </Card>
      )}

      {/* Cloud Enrichments */}
      {report.cloud_enrichments?.length > 0 && (
        <Card style={{ borderLeft: `3px solid ${C.blue}` }}>
          <h3 style={{ margin: "0 0 10px", fontSize: 15, fontWeight: 500 }}>Cloud enrichments</h3>
          {report.cloud_enrichments.map((e, i) => (
            <div key={i} style={{ padding: "6px 10px", marginBottom: 4, borderRadius: 4, background: C.surface2, fontSize: 12, color: C.muted, fontFamily: "monospace", whiteSpace: "pre-wrap" }}>{e}</div>
          ))}
        </Card>
      )}
        </div>{/* end LEFT column */}

        {/* RIGHT: sticky agent chat panel */}
        <div className="ir-chat-rail" style={{ position: "sticky", top: 16, alignSelf: "start" }}>
          <Card style={{ display: "flex", flexDirection: "column", maxHeight: "calc(100vh - 32px)" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>Ask the agent</h3>
              {chatMessages.length > 0 && (
                <button onClick={clearChat}
                  style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", fontSize: 11 }}>
                  Clear chat
                </button>
              )}
            </div>
            <p style={{ margin: "0 0 12px", fontSize: 12, color: C.dim, lineHeight: 1.6 }}>
              Plain-language questions. The agent queries the real data and remembers
              context, so you can follow up ("what about that IP?", "more on F0003").
            </p>

            {/* Message thread — grows to fill the panel, scrolls internally */}
            <div style={{ display: "flex", flexDirection: "column", gap: 10, marginBottom: 12,
                          flex: 1, overflowY: "auto", minHeight: chatMessages.length ? 120 : 0,
                          padding: "4px 2px" }}>
              {chatMessages.map((msg, i) => (
                <div key={i} style={{
                  alignSelf: msg.role === "user" ? "flex-end" : "flex-start",
                  maxWidth: "90%",
                }}>
                  <div style={{
                    padding: "8px 14px", borderRadius: 12, fontSize: 13, lineHeight: 1.6,
                    background: msg.role === "user" ? C.accent + "22" : (msg.error ? C.red + "15" : C.surface2),
                    color: msg.error ? C.coral : C.text,
                    border: msg.role === "user" ? `1px solid ${C.accent}33` : `1px solid ${C.border}33`,
                    whiteSpace: "pre-wrap",
                  }}>
                    {msg.content}
                  </div>
                  {msg.steps?.length > 0 && (
                    <div style={{ marginTop: 4, marginLeft: 4 }}>
                      {msg.steps.map((s, j) => (
                        <span key={j} title={s.thought} style={{
                          display: "inline-block", marginRight: 4, marginTop: 2,
                          fontSize: 10, padding: "1px 7px", borderRadius: 5,
                          background: C.bg, color: C.dim, fontFamily: "monospace", cursor: "default",
                        }}>{s.action}({s.result_summary})</span>
                      ))}
                    </div>
                  )}
                </div>
              ))}
              {chatBusy && (
                <div style={{ alignSelf: "flex-start", display: "flex", alignItems: "center", gap: 8,
                              fontSize: 12, color: C.accent, padding: "4px 8px" }}>
                  <span className="pulse" style={{ width: 6, height: 6, borderRadius: "50%", background: C.accent }} />
                  Agent querying the data...
                </div>
              )}
            </div>

            {/* Input (pinned at the bottom of the panel) */}
            <div style={{ display: "flex", gap: 8 }}>
              <input
                value={chatInput}
                onChange={e => setChatInput(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); } }}
                placeholder="Ask about findings, IOCs..."
                disabled={chatBusy}
                style={{ flex: 1, padding: "9px 14px", borderRadius: 8, border: `1px solid ${C.border}`,
                         background: C.bg, color: C.text, fontSize: 13, minWidth: 0 }}
              />
              <Btn onClick={sendChat} disabled={chatBusy || !chatInput.trim()}>Send</Btn>
            </div>

            {/* Suggested starters (only before the first message) */}
            {chatMessages.length === 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginTop: 10 }}>
                {[
                  "Most critical findings?",
                  "Evidence of lateral movement?",
                  "Were credentials accessed?",
                  "Walk me through the timeline",
                ].map((q, i) => (
                  <button key={i} onClick={() => setChatInput(q)}
                    style={{ fontSize: 11, padding: "4px 10px", borderRadius: 14, cursor: "pointer",
                             background: C.surface2, color: C.muted, border: `1px solid ${C.border}33` }}>
                    {q}
                  </button>
                ))}
              </div>
            )}
          </Card>
        </div>{/* end RIGHT chat rail */}
      </div>{/* end workspace grid */}
    </div>
  );
}

// ── Entity Connectivity Graph ──
// Force-directed graph of processes, IPs, users, and files and how they
// relate. Self-contained SVG + a lightweight force simulation (no external
// graph library), themed to match the dark IR aesthetic.

const NODE_STYLE = {
  process: { color: "#7f77dd", shape: "circle", label: "Process" },
  ip:      { color: "#378ADD", shape: "diamond", label: "IP address" },
  user:    { color: "#5DCAA5", shape: "circle", label: "User" },
  file:    { color: "#EF9F27", shape: "square", label: "File" },
};

function EntityGraph({ incidentId }) {
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [positions, setPositions] = useState({});
  const svgRef = useRef(null);
  const W = 760, H = 460;

  useEffect(() => {
    fetch(`${API}/incidents/${incidentId}/graph`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setGraph(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [incidentId]);

  // Simple force simulation: repulsion between nodes + spring along edges,
  // run for a fixed number of ticks, then render static (cheap + stable).
  useEffect(() => {
    if (!graph?.nodes?.length) return;
    const nodes = graph.nodes.map((n, i) => ({
      ...n,
      x: W / 2 + Math.cos(i) * 120 + (Math.random() - 0.5) * 40,
      y: H / 2 + Math.sin(i) * 120 + (Math.random() - 0.5) * 40,
      vx: 0, vy: 0,
    }));
    const idx = Object.fromEntries(nodes.map((n, i) => [n.id, i]));
    const edges = graph.edges.filter(e => idx[e.source] != null && idx[e.target] != null);

    for (let tick = 0; tick < 280; tick++) {
      // Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          let dx = nodes[i].x - nodes[j].x, dy = nodes[i].y - nodes[j].y;
          let dist = Math.sqrt(dx * dx + dy * dy) || 1;
          let force = 1800 / (dist * dist);
          let fx = (dx / dist) * force, fy = (dy / dist) * force;
          nodes[i].vx += fx; nodes[i].vy += fy;
          nodes[j].vx -= fx; nodes[j].vy -= fy;
        }
      }
      // Spring along edges
      for (const e of edges) {
        const a = nodes[idx[e.source]], b = nodes[idx[e.target]];
        let dx = b.x - a.x, dy = b.y - a.y;
        let dist = Math.sqrt(dx * dx + dy * dy) || 1;
        let force = (dist - 90) * 0.02;
        let fx = (dx / dist) * force, fy = (dy / dist) * force;
        a.vx += fx; a.vy += fy; b.vx -= fx; b.vy -= fy;
      }
      // Center gravity + integrate
      for (const n of nodes) {
        n.vx += (W / 2 - n.x) * 0.004;
        n.vy += (H / 2 - n.y) * 0.004;
        n.x += n.vx * 0.5; n.y += n.vy * 0.5;
        n.vx *= 0.85; n.vy *= 0.85;
        n.x = Math.max(30, Math.min(W - 30, n.x));
        n.y = Math.max(30, Math.min(H - 30, n.y));
      }
    }
    setPositions(Object.fromEntries(nodes.map(n => [n.id, { x: n.x, y: n.y }])));
  }, [graph]);

  if (loading) return null;
  if (!graph?.nodes?.length) return null;

  const sevColor = (s) => s === "critical" ? C.red : s === "high" ? C.coral
    : s === "medium" ? C.amber : null;

  const nodeRadius = (n) => 6 + Math.min(n.finding_count || 0, 4) * 2
    + (n.type === "user" ? 2 : 0);

  const renderShape = (n, pos) => {
    const style = NODE_STYLE[n.type] || NODE_STYLE.process;
    const r = nodeRadius(n);
    const ring = sevColor(n.max_severity);
    const isSel = selected?.id === n.id;
    const common = {
      stroke: ring || (isSel ? "#fff" : "transparent"),
      strokeWidth: ring ? 2.5 : (isSel ? 2 : 0),
      fill: style.color,
      style: { cursor: "pointer", transition: "all .15s" },
      onClick: () => setSelected(isSel ? null : n),
    };
    if (style.shape === "diamond")
      return <rect x={pos.x - r} y={pos.y - r} width={r * 2} height={r * 2}
        transform={`rotate(45 ${pos.x} ${pos.y})`} rx={2} {...common} />;
    if (style.shape === "square")
      return <rect x={pos.x - r} y={pos.y - r} width={r * 2} height={r * 2} rx={2} {...common} />;
    return <circle cx={pos.x} cy={pos.y} r={r} {...common} />;
  };

  return (
    <Card>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>Entity connectivity</h3>
        <span style={{ fontSize: 11, color: C.dim }}>
          {graph.nodes.length} entities · {graph.edges.length} links
          {graph.truncated && " (trimmed)"}
        </span>
      </div>
      <p style={{ margin: "0 0 10px", fontSize: 12, color: C.dim, lineHeight: 1.6 }}>
        How processes, IP addresses, users, and files connect. Ring color marks
        entities tied to findings. Click a node for detail.
      </p>

      {/* Legend */}
      <div style={{ display: "flex", gap: 14, marginBottom: 8, flexWrap: "wrap" }}>
        {Object.entries(NODE_STYLE).map(([type, s]) => (
          <span key={type} style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color: C.muted }}>
            <span style={{ width: 10, height: 10, background: s.color,
              borderRadius: s.shape === "circle" ? "50%" : 2,
              transform: s.shape === "diamond" ? "rotate(45deg)" : "none",
              display: "inline-block" }} />
            {s.label}
          </span>
        ))}
      </div>

      <div style={{ position: "relative", background: C.bg, borderRadius: 8, border: `1px solid ${C.border}` }}>
        <svg ref={svgRef} viewBox={`0 0 ${W} ${H}`} style={{ width: "100%", height: "auto", display: "block" }}>
          {/* Edges */}
          {graph.edges.map((e, i) => {
            const a = positions[e.source], b = positions[e.target];
            if (!a || !b) return null;
            const dim = selected && selected.id !== e.source && selected.id !== e.target;
            return (
              <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke={dim ? C.border : C.border2} strokeWidth={1}
                opacity={dim ? 0.3 : 0.7} />
            );
          })}
          {/* Nodes */}
          {graph.nodes.map((n) => {
            const pos = positions[n.id];
            if (!pos) return null;
            const dim = selected && selected.id !== n.id
              && !graph.edges.some(e =>
                (e.source === selected.id && e.target === n.id) ||
                (e.target === selected.id && e.source === n.id));
            return (
              <g key={n.id} opacity={dim ? 0.3 : 1}>
                {renderShape(n, pos)}
              </g>
            );
          })}
        </svg>

        {/* Detail popover */}
        {selected && (
          <div style={{ position: "absolute", top: 8, right: 8, maxWidth: 260,
            background: C.surface, border: `1px solid ${C.border2}`, borderRadius: 8,
            padding: "10px 12px", fontSize: 12 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 4 }}>
              <span style={{ color: (NODE_STYLE[selected.type] || {}).color, fontWeight: 600, fontSize: 11, textTransform: "uppercase" }}>
                {(NODE_STYLE[selected.type] || {}).label}
              </span>
              <button onClick={() => setSelected(null)}
                style={{ background: "none", border: "none", color: C.dim, cursor: "pointer", fontSize: 14 }}>×</button>
            </div>
            <div style={{ color: C.text, fontWeight: 500, wordBreak: "break-all", marginBottom: 4 }}>
              {selected.full_name || selected.label}
            </div>
            {selected.finding_count > 0 && (
              <div style={{ color: sevColor(selected.max_severity) || C.muted, fontSize: 11 }}>
                {selected.finding_count} finding{selected.finding_count > 1 ? "s" : ""}
                {selected.max_severity && ` · ${selected.max_severity}`}
              </div>
            )}
            <div style={{ color: C.dim, fontSize: 11, marginTop: 4 }}>
              {graph.edges.filter(e => e.source === selected.id || e.target === selected.id).length} connection(s)
            </div>
          </div>
        )}
      </div>
    </Card>
  );
}

// ── Incident List ──

function IncidentList({ incidents, onSelect, onDelete }) {
  const [deleting, setDeleting] = useState(null);

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm("Delete this incident permanently? This cannot be undone.")) return;
    setDeleting(id);
    try {
      const r = await fetch(`${API}/incidents/${id}`, { method: "DELETE" });
      if (r.ok) onDelete?.(id);
    } catch {}
    finally { setDeleting(null); }
  };

  if (!incidents?.length) return (
    <Card style={{ textAlign: "center", padding: 40, color: C.dim }}>
      No incidents yet. Analyze data or upload collector results to create one.
    </Card>
  );
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
      {incidents.map(inc => (
        <Card key={inc.id} style={{ cursor: "pointer", padding: "12px 16px" }}
          onClick={() => onSelect(inc)}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 500 }}>{inc.title}</div>
              <div style={{ display: "flex", gap: 10, marginTop: 4, alignItems: "center", fontSize: 11, color: C.dim }}>
                <code>{inc.id}</code>
                <span style={{
                  width: 6, height: 6, borderRadius: "50%",
                  background: inc.status === "closed" ? C.dim : C.green,
                }} />
                <span>{inc.status}</span>
                {inc.analysis?.analyzed_by && (
                  <span style={{
                    padding: "1px 6px", borderRadius: 8, fontSize: 9,
                    background: inc.analysis.analyzed_by === "local" ? "#04342C" : "#042C53",
                    color: inc.analysis.analyzed_by === "local" ? C.green : C.blue,
                  }}>{inc.analysis.analyzed_by}</span>
                )}
              </div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <Badge severity={inc.severity} />
              <button
                onClick={(e) => handleDelete(e, inc.id)}
                disabled={deleting === inc.id}
                title="Delete incident"
                style={{ background: "none", border: "none", color: C.dim, cursor: "pointer",
                         fontSize: 16, padding: "2px 6px", borderRadius: 4, lineHeight: 1 }}
                onMouseEnter={e => e.currentTarget.style.color = C.red}
                onMouseLeave={e => e.currentTarget.style.color = C.dim}
              >×</button>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ── Collector Panel ──

function CollectorPanel({ onResult }) {
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [collections, setCollections] = useState([]);
  const [selectedPath, setSelectedPath] = useState("");
  const [pathAnalyzing, setPathAnalyzing] = useState(false);

  const fetchCollections = () => {
    fetch(`${API}/collections`).then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setCollections(d.collections || []); }).catch(() => {});
  };
  useEffect(fetchCollections, []);

  const upload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true); setUploadResult(null);
    const form = new FormData();
    form.append("file", file);
    form.append("title", `Upload: ${file.name}`);
    form.append("allow_cloud", "false");
    try {
      const r = await fetch(`${API}/collector/upload`, { method: "POST", body: form });
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      setUploadResult(d);
      if (d.analysis) onResult?.(d);
    } catch (e) { setUploadResult({ error: e.message }); }
    finally { setUploading(false); e.target.value = ""; }
  };

  const [progress, setProgress] = useState(null);

  const analyzeFromPath = async () => {
    if (!selectedPath) return;
    setPathAnalyzing(true); setUploadResult(null); setProgress(null);
    try {
      // Start the job
      const form = new FormData();
      form.append("collection_path", selectedPath);
      form.append("title", `Collection: ${selectedPath.split("/").pop()}`);
      form.append("allow_cloud", "false");
      const startRes = await fetch(`${API}/collections/analyze`, { method: "POST", body: form });
      if (!startRes.ok) throw new Error(await startRes.text());
      const { job_id } = await startRes.json();

      // Stream progress via SSE, with a polling fallback if the stream drops.
      let finished = false;
      let errorCount = 0;
      let es = null;

      const finish = (data) => {
        if (finished) return;
        finished = true;
        if (es) es.close();
        setPathAnalyzing(false);
        if (data?.error) {
          setUploadResult({ error: data.error });
        } else if (data?.result) {
          setUploadResult(data.result);
          if (data.result.analysis) onResult?.(data.result);
        }
        setProgress(null);
      };

      // Polling fallback: if SSE fails, poll the job status endpoint.
      const pollStatus = async () => {
        if (finished) return;
        try {
          const r = await fetch(`${API}/jobs/${job_id}/status`);
          if (r.ok) {
            const data = await r.json();
            setProgress(data);
            if (data.done) {
              finish(data);
              return;
            }
          }
        } catch { /* keep polling */ }
        if (!finished) setTimeout(pollStatus, 2000);
      };

      const connectSSE = () => {
        es = new EventSource(`${API}/jobs/${job_id}/progress`);
        es.onmessage = (ev) => {
          if (!ev.data) return;
          let data;
          try { data = JSON.parse(ev.data); } catch { return; }
          errorCount = 0; // healthy message resets error counter
          setProgress(data);
          if (data.done) finish(data);
        };
        es.onerror = () => {
          es.close();
          if (finished) return;
          errorCount++;
          // EventSource dropped. After a couple of quick retries, fall back
          // to polling so a long blocking stage never looks like a failure.
          if (errorCount <= 2) {
            setTimeout(connectSSE, 1000);
          } else {
            pollStatus();
          }
        };
      };
      connectSSE();
    } catch (e) {
      setUploadResult({ error: e.message });
      setPathAnalyzing(false);
    }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>

      {/* Step 1: Download */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
          <span style={{ background: C.accent, color: "#fff", width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, flexShrink: 0 }}>1</span>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>Download Collector Script</h3>
        </div>
        <p style={{ margin: "0 0 16px 34px", fontSize: 12, color: C.dim }}>
          Standalone scripts — no install, no dependencies, no Velociraptor needed.
          Run on target machine to collect forensic artifacts.
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginLeft: 34 }}>
          <a href={`${API}/collector/download/windows`} download style={{
            display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
            padding: "20px 16px", borderRadius: 10, textDecoration: "none",
            background: C.surface2, border: `1px solid ${C.border}`,
            cursor: "pointer", transition: "border-color .2s",
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = C.accent}
            onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
          >
            <span style={{ fontSize: 28 }}>🪟</span>
            <span style={{ fontSize: 14, fontWeight: 500, color: C.text }}>Windows Collector</span>
            <span style={{ fontSize: 11, color: C.dim }}>ir_collect.ps1 — PowerShell</span>
            <span style={{
              fontSize: 11, padding: "3px 10px", borderRadius: 6,
              background: C.accentDim, color: "#fff",
            }}>Download .ps1</span>
          </a>

          <a href={`${API}/collector/download/linux`} download style={{
            display: "flex", flexDirection: "column", alignItems: "center", gap: 8,
            padding: "20px 16px", borderRadius: 10, textDecoration: "none",
            background: C.surface2, border: `1px solid ${C.border}`,
            cursor: "pointer", transition: "border-color .2s",
          }}
            onMouseEnter={e => e.currentTarget.style.borderColor = C.accent}
            onMouseLeave={e => e.currentTarget.style.borderColor = C.border}
          >
            <span style={{ fontSize: 28 }}>🐧</span>
            <span style={{ fontSize: 14, fontWeight: 500, color: C.text }}>Linux / Mac Collector</span>
            <span style={{ fontSize: 11, color: C.dim }}>ir_collect.sh — Bash</span>
            <span style={{
              fontSize: 11, padding: "3px 10px", borderRadius: 6,
              background: C.accentDim, color: "#fff",
            }}>Download .sh</span>
          </a>
        </div>

        <div style={{ marginTop: 14, marginLeft: 34, padding: "10px 14px", borderRadius: 8, background: C.bg, fontSize: 12, color: C.dim }}>
          <div style={{ fontWeight: 500, color: C.muted, marginBottom: 4 }}>How to run:</div>
          <div><b>Windows:</b> Right-click → Run as Administrator, or: <code style={{ color: C.text }}>powershell -ExecutionPolicy Bypass -File ir_collect.ps1</code></div>
          <div style={{ marginTop: 4 }}><b>Linux/Mac:</b> <code style={{ color: C.text }}>chmod +x ir_collect.sh && sudo ./ir_collect.sh</code></div>
          <div style={{ marginTop: 4 }}><b>Quick mode:</b> Add <code style={{ color: C.text }}>-Quick</code> (Win) or <code style={{ color: C.text }}>--quick</code> (Linux) to skip heavy artifacts</div>
        </div>
      </Card>

      {/* Step 2: Analyze from path (large files) */}
      <Card>
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 4 }}>
          <span style={{ background: C.tealDim, color: "#fff", width: 24, height: 24, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontSize: 12, fontWeight: 700, flexShrink: 0 }}>2</span>
          <h3 style={{ margin: 0, fontSize: 15, fontWeight: 500 }}>Analyze Collection</h3>
        </div>
        <p style={{ margin: "0 0 16px 34px", fontSize: 12, color: C.dim }}>
          Upload small files via browser, or place large collections (60GB+) in <code style={{ color: C.text }}>./collections/</code> folder
        </p>

        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginLeft: 34, marginBottom: 16 }}>
          {/* Browser upload (small files) */}
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 8, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>
              Browser upload (small files)
            </label>
            <div style={{
              border: `2px dashed ${C.border2}`, borderRadius: 8, padding: "20px 12px",
              textAlign: "center", position: "relative", cursor: "pointer",
            }}
              onDragOver={e => { e.preventDefault(); e.currentTarget.style.borderColor = C.accent; }}
              onDragLeave={e => { e.currentTarget.style.borderColor = C.border2; }}
              onDrop={e => {
                e.preventDefault(); e.currentTarget.style.borderColor = C.border2;
                const file = e.dataTransfer.files[0];
                if (file) { const dt = new DataTransfer(); dt.items.add(file); const inp = e.currentTarget.querySelector("input"); if (inp) { inp.files = dt.files; inp.dispatchEvent(new Event("change", { bubbles: true })); } }
              }}
            >
              <input type="file" accept=".zip,.tar.gz,.json,.jsonl,.csv" onChange={upload}
                style={{ position: "absolute", inset: 0, opacity: 0, cursor: "pointer" }} />
              <div style={{ fontSize: 20, marginBottom: 4 }}>{uploading ? "⏳" : "📂"}</div>
              <div style={{ fontSize: 12, color: C.muted }}>{uploading ? "Processing..." : "Drop or click"}</div>
              <div style={{ fontSize: 10, color: C.dim, marginTop: 2 }}>ZIP · tar.gz · JSON · CSV</div>
              <div style={{ fontSize: 10, color: C.dim }}>Velociraptor (pwd: infected)</div>
            </div>
          </div>

          {/* Path-based (large files) */}
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 8, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>
              From ./collections/ folder (large files)
            </label>
            <select value={selectedPath} onChange={e => setSelectedPath(e.target.value)} style={{
              width: "100%", padding: "8px 12px", borderRadius: 8,
              border: `1px solid ${C.border}`, background: C.bg, color: C.text, fontSize: 13,
            }}>
              <option value="">Select collection...</option>
              {collections.map(c => (
                <option key={c.path} value={c.path}>
                  {c.filename} ({c.size_gb > 1 ? `${c.size_gb}GB` : `${c.size_mb}MB`}, {c.format})
                </option>
              ))}
            </select>
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <Btn variant="primary" onClick={analyzeFromPath}
                disabled={pathAnalyzing || !selectedPath}
                style={{ flex: 1, fontSize: 12 }}>
                {pathAnalyzing ? "Analyzing..." : "Analyze"}
              </Btn>
              <button onClick={fetchCollections} style={{
                background: "transparent", border: "none", color: C.accent, fontSize: 12, cursor: "pointer",
              }}>↻</button>
            </div>
          </div>
        </div>

        {progress && (
          <div style={{ marginLeft: 34, marginTop: 4, padding: "16px 18px", borderRadius: 10, background: C.surface2, border: `1px solid ${C.border}` }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
              <span style={{ fontSize: 13, fontWeight: 500, color: C.text }}>{progress.stage_label}</span>
              <span style={{ fontSize: 12, color: C.accent, fontWeight: 600 }}>{progress.percent}%</span>
            </div>
            <div style={{ height: 6, borderRadius: 3, background: C.bg, overflow: "hidden" }}>
              <div style={{ height: "100%", borderRadius: 3, background: `linear-gradient(90deg, ${C.accent}, ${C.tealDim})`, width: `${progress.percent}%`, transition: "width .4s ease" }} />
            </div>
            {progress.detail && (
              <div style={{ fontSize: 12, color: C.muted, marginTop: 8 }}>{progress.detail}</div>
            )}
            {progress.total_rows > 0 && (
              <div style={{ fontSize: 11, color: C.dim, marginTop: 4 }}>
                {progress.total_rows.toLocaleString()} rows in dataset
                {progress.findings_count > 0 && ` · ${progress.findings_count} findings so far`}
              </div>
            )}
            {/* Stage dots */}
            <div style={{ display: "flex", gap: 4, marginTop: 12 }}>
              {["upload","extract","binary_parse","detection","anonymize","llm_analysis","report"].map((s) => (
                <div key={s} style={{
                  flex: 1, height: 3, borderRadius: 2,
                  background: progress.stage === s ? C.accent
                    : ["upload","extract","binary_parse","detection","anonymize","llm_analysis","report"].indexOf(progress.stage) > ["upload","extract","binary_parse","detection","anonymize","llm_analysis","report"].indexOf(s) ? C.tealDim
                    : C.border,
                }} />
              ))}
            </div>
          </div>
        )}

        {uploadResult && (
          <div style={{
            marginTop: 12, marginLeft: 34, padding: "12px 16px", borderRadius: 8,
            background: uploadResult.error ? "#501313" : "#04342C",
            borderLeft: `3px solid ${uploadResult.error ? C.red : C.green}`,
          }}>
            {uploadResult.error ? (
              <div style={{ fontSize: 12, color: "#F7C1C1" }}>{uploadResult.error}</div>
            ) : (
              <div>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 6 }}>
                  <span style={{ fontSize: 13, fontWeight: 500, color: C.green }}>
                    Analyzed — incident {uploadResult.incident_id}
                  </span>
                  {uploadResult.upload_summary?.source_type && (
                    <span style={{
                      fontSize: 10, padding: "2px 8px", borderRadius: 10,
                      background: uploadResult.upload_summary.source_type === "velociraptor"
                        ? "#042C53" : "#04342C",
                      color: uploadResult.upload_summary.source_type === "velociraptor"
                        ? "#85B7EB" : "#5DCAA5",
                    }}>
                      {uploadResult.upload_summary.source_type === "velociraptor"
                        ? "Velociraptor collector" : uploadResult.upload_summary.source_type}
                    </span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: C.muted }}>
                  {uploadResult.upload_summary?.total_items} items
                  · {uploadResult.stats?.pii_items_redacted} PII redacted
                  · Severity: {uploadResult.analysis?.severity}
                </div>
                {uploadResult.upload_summary?.data_types?.length > 0 && (
                  <div style={{
                    marginTop: 6, display: "flex", flexWrap: "wrap", gap: 4,
                  }}>
                    {uploadResult.upload_summary.data_types.filter(d => d !== "_metadata").slice(0, 12).map((dt, i) => (
                      <span key={i} style={{
                        fontSize: 10, padding: "1px 6px", borderRadius: 8,
                        background: C.surface2, color: C.dim,
                      }}>{dt}</span>
                    ))}
                    {uploadResult.upload_summary.data_types.length > 12 && (
                      <span style={{ fontSize: 10, color: C.dim }}>
                        +{uploadResult.upload_summary.data_types.length - 12} more
                      </span>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── Disk Image Panel ──

function ImagePanel({ onResult }) {
  const [images, setImages] = useState([]);
  const [selectedImage, setSelectedImage] = useState("");
  const [analyzing, setAnalyzing] = useState(false);
  const [imgResult, setImgResult] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadPct, setUploadPct] = useState(0);

  const fetchImages = () => {
    fetch(`${API}/images`).then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setImages(d.images || []); }).catch(() => {});
  };
  useEffect(fetchImages, []);

  const analyzeImage = async () => {
    if (!selectedImage) return;
    setAnalyzing(true); setImgResult(null);
    const form = new FormData();
    form.append("image_path", selectedImage);
    form.append("title", `Image: ${selectedImage.split("/").pop()}`);
    form.append("allow_cloud", "false");
    try {
      const r = await fetch(`${API}/images/analyze`, { method: "POST", body: form });
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      setImgResult(d);
      if (d.analysis) onResult?.(d);
    } catch (e) { setImgResult({ error: e.message }); }
    finally { setAnalyzing(false); }
  };

  const uploadImage = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true); setUploadPct(0);
    const form = new FormData();
    form.append("file", file);
    try {
      const xhr = new XMLHttpRequest();
      xhr.upload.onprogress = (ev) => { if (ev.lengthComputable) setUploadPct(Math.round(ev.loaded / ev.total * 100)); };
      await new Promise((resolve, reject) => {
        xhr.onload = () => { if (xhr.status === 200) { const d = JSON.parse(xhr.responseText); setSelectedImage(d.path); fetchImages(); resolve(); } else reject(new Error(xhr.responseText)); };
        xhr.onerror = () => reject(new Error("Upload failed"));
        xhr.open("POST", `${API}/images/upload`);
        xhr.send(form);
      });
    } catch (e) { setImgResult({ error: e.message }); }
    finally { setUploading(false); setUploadPct(0); e.target.value = ""; }
  };

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <Card>
        <h3 style={{ margin: "0 0 4px", fontSize: 15, fontWeight: 500 }}>Forensic Disk Image Analysis</h3>
        <p style={{ margin: "0 0 16px", fontSize: 12, color: C.dim }}>
          Analyze FTK Imager, EnCase (E01), raw/dd, VMDK, or VHD disk images.
          Extracts registry, event logs, prefetch, services, autoruns, timeline, and more.
        </p>

        {/* Upload or select image */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12, marginBottom: 16 }}>
          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 8, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>
              Upload image file
            </label>
            <div style={{
              border: `2px dashed ${C.border2}`, borderRadius: 8, padding: "16px 12px",
              textAlign: "center", position: "relative", cursor: "pointer",
            }}>
              <input type="file" accept=".e01,.E01,.raw,.dd,.img,.vmdk,.vhd,.vhdx"
                onChange={uploadImage}
                style={{ position: "absolute", inset: 0, opacity: 0, cursor: "pointer" }} />
              {uploading ? (
                <div>
                  <div style={{ fontSize: 12, color: C.muted }}>Uploading... {uploadPct}%</div>
                  <div style={{ height: 4, borderRadius: 2, background: C.border, marginTop: 8 }}>
                    <div style={{ height: "100%", borderRadius: 2, background: C.accent, width: `${uploadPct}%`, transition: "width .3s" }} />
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: 12, color: C.muted }}>Drop E01/raw/VMDK or click</div>
              )}
            </div>
          </div>

          <div>
            <label style={{ display: "block", fontSize: 11, fontWeight: 600, marginBottom: 8, color: C.muted, textTransform: "uppercase", letterSpacing: .5 }}>
              Or select from ./images/ folder
            </label>
            <select value={selectedImage} onChange={e => setSelectedImage(e.target.value)} style={{
              width: "100%", padding: "8px 12px", borderRadius: 8,
              border: `1px solid ${C.border}`, background: C.bg, color: C.text, fontSize: 13,
            }}>
              <option value="">Select image...</option>
              {images.map(img => (
                <option key={img.path} value={img.path}>
                  {img.filename} ({img.size_gb}GB, {img.format})
                </option>
              ))}
            </select>
            <button onClick={fetchImages} style={{
              marginTop: 6, background: "transparent", border: "none", color: C.accent, fontSize: 11, cursor: "pointer",
            }}>↻ Refresh list</button>
          </div>
        </div>

        <div style={{ padding: "10px 14px", borderRadius: 8, background: C.bg, fontSize: 12, color: C.dim, marginBottom: 16 }}>
          <div style={{ fontWeight: 500, color: C.muted, marginBottom: 4 }}>For large images (&gt;2GB):</div>
          <div>Copy the image to <code style={{ color: C.text }}>./images/</code> folder in the project directory, then select it from the dropdown. The folder is mounted into the Docker container.</div>
        </div>

        <Btn variant="primary" onClick={analyzeImage} disabled={analyzing || !selectedImage}>
          {analyzing ? "Extracting & analyzing..." : "Analyze Disk Image"}
        </Btn>
        {analyzing && (
          <div style={{ marginTop: 8, fontSize: 12, color: C.muted }}>
            Extracting artifacts from image (registry, event logs, prefetch, timeline...). This may take several minutes for large images.
          </div>
        )}

        {imgResult && (
          <div style={{
            marginTop: 12, padding: "12px 16px", borderRadius: 8,
            background: imgResult.error ? "#501313" : "#04342C",
            borderLeft: `3px solid ${imgResult.error ? C.red : C.green}`,
          }}>
            {imgResult.error ? (
              <div style={{ fontSize: 12, color: "#F7C1C1" }}>{imgResult.error}</div>
            ) : (
              <div>
                <div style={{ fontSize: 13, fontWeight: 500, color: C.green }}>
                  Image analyzed — incident {imgResult.incident_id}
                </div>
                <div style={{ fontSize: 12, color: C.muted, marginTop: 4 }}>
                  {imgResult.image_info?.filename} · {imgResult.image_info?.total_artifacts_extracted} artifacts extracted
                  {imgResult.system_info?.hostname && ` · Host: ${imgResult.system_info.hostname}`}
                  {imgResult.system_info?.os && ` · OS: ${imgResult.system_info.os}`}
                </div>
                <div style={{ fontSize: 12, color: C.muted, marginTop: 2 }}>
                  Severity: {imgResult.analysis?.severity} · PII redacted: {imgResult.stats?.pii_items_redacted}
                </div>
              </div>
            )}
          </div>
        )}
      </Card>
    </div>
  );
}

// ── App ──

const TABS = ["Analyze", "Collector", "Disk Image", "Incidents"];

export default function App() {
  const [tab, setTab] = useState(0);
  const [health, setHealth] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selected, setSelected] = useState(null);
  const [result, setResult] = useState(null);

  const fetchHealth = useCallback(async () => {
    try { const r = await fetch(`${API}/health`); if (r.ok) setHealth(await r.json()); }
    catch { setHealth(null); }
  }, []);

  const fetchIncidents = useCallback(async () => {
    try {
      const r = await fetch(`${API}/incidents`);
      if (r.ok) { const d = await r.json(); setIncidents(d.incidents || []); }
    } catch {}
  }, []);

  useEffect(() => {
    fetchHealth();
    fetchIncidents();
    const iv = setInterval(fetchHealth, 30000);
    return () => clearInterval(iv);
  }, []);

  const handleResult = (data) => { setResult(data); fetchIncidents(); };

  return (
    <div style={{ maxWidth: 1400, margin: "0 auto", padding: "12px 24px", minHeight: "100vh" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 16 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600, letterSpacing: -.5 }}>
            IR Platform
          </h1>
          <span style={{ fontSize: 11, color: C.dim }}>local-first · LM Studio + Claude (standby) + standalone collectors</span>
        </div>
        <Btn variant="ghost" onClick={() => { fetchHealth(); fetchIncidents(); }}>↻ Refresh</Btn>
      </div>

      <HealthBar health={health} />

      <div style={{ display: "flex", gap: 0, marginBottom: 20, borderBottom: `1px solid ${C.border}` }}>
        {TABS.map((t, i) => (
          <button key={t} onClick={() => { setTab(i); setSelected(null); }} style={{
            padding: "8px 20px", fontSize: 13, background: "transparent", border: "none",
            cursor: "pointer", marginBottom: -1,
            fontWeight: tab === i ? 600 : 400,
            color: tab === i ? C.text : C.dim,
            borderBottom: tab === i ? `2px solid ${C.accent}` : "2px solid transparent",
          }}>{t}{i === 3 && incidents.length > 0 ? ` (${incidents.length})` : ""}</button>
        ))}
      </div>

      {tab === 0 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <ManualPanel onResult={handleResult} />
          {result && <AnalysisView result={result} />}
        </div>
      )}

      {tab === 1 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <CollectorPanel onResult={handleResult} />
          {result?.analysis && result?.incident_id && <AnalysisView result={result} />}
        </div>
      )}

      {tab === 2 && (
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          <ImagePanel onResult={handleResult} />
          {result?.analysis && result?.incident_id && <AnalysisView result={result} />}
        </div>
      )}

      {tab === 3 && (
        selected ? (
          <ReportView incidentId={selected.id} onBack={() => setSelected(null)} />
        ) : (
          <IncidentList incidents={incidents} onSelect={setSelected} onDelete={() => fetchIncidents()} />
        )
      )}
    </div>
  );
}
