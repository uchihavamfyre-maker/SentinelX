import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import {
  Activity, AlertOctagon, AlertTriangle, ArrowDownRight, ArrowUpRight,
  CheckCircle2, ChevronDown, CircleHelp, Clock3, Download, ExternalLink,
  FileSearch, Filter, Gauge, Github, LockKeyhole, RefreshCw, Search,
  Settings2, Shield, ShieldAlert, ShieldCheck, SlidersHorizontal, Terminal,
  Wifi, WifiOff, X
} from "lucide-react";
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis,
  BarChart, Bar
} from "recharts";

type EventType = "login_success" | "login_failure";
type Label = "normal" | "suspicious";
type AuthEvent = {
  event_id: string; timestamp: string; source_ip: string; username: string;
  event_type: EventType; label: Label;
};
type Alert = {
  alert_id: string; rule_id: string; title: string;
  severity: "low" | "medium" | "high" | "critical";
  source_ip: string; username: string; first_seen: string; last_seen: string;
  event_count: number; evidence_event_ids: string[]; explanation: string;
};
type Metrics = {
  total_events: number; labeled_events: number; true_positive: number;
  false_positive: number; true_negative: number; false_negative: number;
  precision: number; recall: number; f1: number; false_positive_rate: number;
};

const BASE_TIME = Date.parse("2026-01-01T10:00:00Z");
function buildDemoEvents(): AuthEvent[] {
  const rows: AuthEvent[] = [];
  let n = 0;
  const add = (offset: number, ip: string, username: string, type: EventType, label: Label) => {
    n += 1;
    rows.push({
      event_id: `evt-${String(n).padStart(4, "0")}`,
      timestamp: new Date(BASE_TIME + offset * 1000).toISOString(),
      source_ip: ip, username, event_type: type, label,
    });
  };
  for (let i = 0; i < 24; i++) {
    const offset = i * 47;
    if (i % 4 === 0) add(offset, `192.0.2.${10 + (i % 8)}`, `user-${1 + (i % 6)}`, "login_failure", "normal");
    add(offset + 3, `192.0.2.${10 + (i % 8)}`, `user-${1 + (i % 6)}`, "login_success", "normal");
  }
  for (let i = 0; i < 8; i++) add(120 + i * 18, "198.51.100.23", "demo-admin", "login_failure", "suspicious");
  for (let i = 0; i < 3; i++) add(900 + i * 40, "198.51.100.44", "demo-operator", "login_failure", "suspicious");
  for (let i = 0; i < 8; i++) add(1100 + i * 61, `192.0.2.${40 + i}`, `staff-${i}`, "login_failure", "normal");
  return rows.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
}

function detect(events: AuthEvent[], threshold: number, windowSeconds: number): Alert[] { const groups = new Map<string, AuthEvent[]>(); events.filter(e => e.event_type === "login_failure").forEach(e => { const k = e.source_ip + "|" + e.username; groups.set(k, [...(groups.get(k) ?? []), e]); }); const result: Alert[] = []; groups.forEach(group => { const sorted = [...group].sort((x,y) => x.timestamp.localeCompare(y.timestamp)); let left = 0; let latest: AuthEvent[] = []; for (let right=0; right<sorted.length; right++) { const t=Date.parse(sorted[right].timestamp); while(left<=right && Date.parse(sorted[left].timestamp)<t-windowSeconds*1000) left++; const batch=sorted.slice(left,right+1); if(batch.length>=threshold) latest=batch; } if(!latest.length) return; const last=latest[latest.length-1]; const count=latest.length; result.push({ alert_id: "incident-"+hash(last.source_ip+"|"+last.username+"|AUTH-001"), rule_id:"AUTH-001", title:"Repeated authentication failures", severity:count>=threshold*3?"critical":count>=threshold*2?"high":"medium", source_ip:last.source_ip, username:last.username, first_seen:latest[0].timestamp, last_seen:last.timestamp, event_count:count, evidence_event_ids:latest.map(e=>e.event_id), explanation:count+" failed logins for "+last.username+" from "+last.source_ip+" within "+windowSeconds+"s." }); }); return result.sort((x,y)=>y.last_seen.localeCompare(x.last_seen)); }
function hash(value: string) {
  let h = 2166136261;
  for (let i = 0; i < value.length; i++) h = Math.imul(h ^ value.charCodeAt(i), 16777619);
  return (h >>> 0).toString(16).padStart(8, "0");
}
function evaluate(events: AuthEvent[], alerts: Alert[]): Metrics {
  const predicted = new Set(alerts.flatMap(a => a.evidence_event_ids));
  let tp = 0, fp = 0, tn = 0, fn = 0;
  events.forEach(e => {
    const p = predicted.has(e.event_id);
    const actual = e.label === "suspicious";
    if (actual && p) tp++; else if (!actual && p) fp++; else if (!actual && !p) tn++; else fn++;
  });
  const div = (a: number, b: number) => b ? a / b : 0;
  const precision = div(tp, tp + fp), recall = div(tp, tp + fn);
  return {
    total_events: events.length, labeled_events: events.length, true_positive: tp,
    false_positive: fp, true_negative: tn, false_negative: fn, precision, recall,
    f1: div(2 * precision * recall, precision + recall),
    false_positive_rate: div(fp, fp + tn),
  };
}
const pct = (v: number) => `${(v * 100).toFixed(1)}%`;
const time = (s: string) => new Date(s).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });

export default function App() {
  const [events, setEvents] = useState<AuthEvent[]>(buildDemoEvents);
  const [threshold, setThreshold] = useState(5);
  const [windowSeconds, setWindowSeconds] = useState(300);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("all");
  const [tab, setTab] = useState<"incidents" | "events" | "research">("incidents");
  const [apiUrl, setApiUrl] = useState("/api/sentinelx");
  const [apiState, setApiState] = useState<"demo" | "connected" | "error">("demo");
  const [busy, setBusy] = useState(false);
  const [apiSnapshot, setApiSnapshot] = useState<{ threshold: number; windowSeconds: number; alerts: Alert[]; metrics: Metrics } | null>(null);
  const [selected, setSelected] = useState<Alert | null>(null);
  const [liveMode, setLiveMode] = useState(false);
  const [simulationCount, setSimulationCount] = useState(0);
  const [notice, setNotice] = useState("Synthetic lab dataset loaded. No external systems contacted.");

  const localAlerts = useMemo(() => detect(events, threshold, windowSeconds), [events, threshold, windowSeconds]);
  const localMetrics = useMemo(() => evaluate(events, localAlerts), [events, localAlerts]);
  const snapshotMatches = !!apiSnapshot && apiSnapshot.threshold === threshold && apiSnapshot.windowSeconds === windowSeconds;
  const alerts = snapshotMatches ? apiSnapshot!.alerts : localAlerts;
  const metrics = snapshotMatches ? apiSnapshot!.metrics : localMetrics;
  const filteredAlerts = alerts.filter(a => {
    const q = search.toLowerCase();
    return (!q || [a.username, a.source_ip, a.rule_id, a.title].some(v => v.toLowerCase().includes(q)))
      && (severity === "all" || a.severity === severity);
  });
  const eventRows = events.filter(e => {
    const q = search.toLowerCase();
    return !q || [e.event_id, e.source_ip, e.username, e.event_type, e.label].some(v => v.toLowerCase().includes(q));
  }).slice().reverse();
  const timeline = useMemo(() => {
    const buckets = new Map<string, { time: string; successful: number; failed: number }>();
    events.forEach(e => {
      const label = new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      const row = buckets.get(label) ?? { time: label, successful: 0, failed: 0 };
      if (e.event_type === "login_success") row.successful++; else row.failed++;
      buckets.set(label, row);
    });
    return [...buckets.values()].slice(0, 12);
  }, [events]);
  const severityRows = [
    { name: "Critical", value: alerts.filter(a => a.severity === "critical").length, color: "#fb7185" },
    { name: "High", value: alerts.filter(a => a.severity === "high").length, color: "#fb923c" },
    { name: "Medium", value: alerts.filter(a => a.severity === "medium").length, color: "#facc15" },
    { name: "Low", value: alerts.filter(a => a.severity === "low").length, color: "#60a5fa" },
  ];

  async function refreshFromApi() {
    if (!apiUrl.trim()) {
      setApiState("demo");
      setApiSnapshot(null);
      setNotice("Using local synthetic demo mode. Enter an API base URL to connect a running SentinelX API.");
      return;
    }
    setBusy(true);
    let stage = "health check";
    try {
      const base = apiUrl.trim().replace(/\/$/, "");
      const health = await fetch(`${base}/health`);
      if (!health.ok) throw new Error(`Health check returned HTTP ${health.status}`);
      stage = "authentication-event analysis";
      const analyzeResponse = await fetch(`${base}/analyze`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events, threshold, window_seconds: windowSeconds }),
      });
      if (!analyzeResponse.ok) {
        const detail = await analyzeResponse.text();
        throw new Error(`Analyze returned HTTP ${analyzeResponse.status}: ${detail.slice(0, 240)}`);
      }
      const data = await analyzeResponse.json();
      stage = "detector evaluation";
      const evalResponse = await fetch(`${base}/evaluate`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ events, threshold, window_seconds: windowSeconds }),
      });
      if (!evalResponse.ok) {
        const detail = await evalResponse.text();
        throw new Error(`Evaluate returned HTTP ${evalResponse.status}: ${detail.slice(0, 240)}`);
      }
      const evaluated = await evalResponse.json();
      setApiSnapshot({ threshold, windowSeconds, alerts: data.alerts as Alert[], metrics: evaluated as Metrics });
      setApiState("connected");
      setNotice(`Connected to SentinelX API. Backend analyzed ${data.event_count} events and returned ${data.alert_count} alerts. Changing the rule settings requires reconnecting to refresh the backend snapshot.`);
    } catch (err) {
      setApiState("error");
      setApiSnapshot(null);
      const detail = err instanceof Error ? err.message : String(err);
      const likelyCors = detail.includes("Failed to fetch") || detail.includes("NetworkError") || detail.includes("Load failed");
      setNotice(`API connection failed during ${stage}: ${detail}.${likelyCors ? " This may be a browser CORS or network block; check the API CORS allowlist." : ""} Dashboard remains in local demo mode.`);
    } finally { setBusy(false); }
  }

  useEffect(() => {
    void refreshFromApi();
    // Re-run backend analysis whenever events or detector configuration changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [events, threshold, windowSeconds]);

  useEffect(() => {
    if (!liveMode) return;
    const timer = window.setInterval(() => {
      const now = new Date().toISOString();
      const failed = Math.random() < 0.38;
      const event: AuthEvent = {
        event_id: "live-" + Date.now() + "-" + Math.random().toString(16).slice(2, 7),
        timestamp: now,
        source_ip: failed ? "203.0.113.77" : "192.0.2." + (20 + Math.floor(Math.random() * 40)),
        username: failed ? "simulated-admin" : "analyst-" + (1 + Math.floor(Math.random() * 5)),
        event_type: failed ? "login_failure" : "login_success",
        label: failed ? "suspicious" : "normal",
      };
      setEvents(current => [...current.slice(-498), event]);
    }, 2200);
    return () => window.clearInterval(timer);
  }, [liveMode]);

  function simulateBruteForce() {
    const now = Date.now();
    const batch: AuthEvent[] = Array.from({ length: 8 }, (_, i) => ({
      event_id: "sim-attack-" + now + "-" + (i + 1),
      timestamp: new Date(now + i * 1800).toISOString(),
      source_ip: "203.0.113.77",
      username: "simulated-admin",
      event_type: "login_failure",
      label: "suspicious",
    }));
    setEvents(current => [...current.slice(-492), ...batch]);
    setSimulationCount(value => value + 1);
    setNotice("Attack simulation injected 8 synthetic failed logins from documentation-only IP 203.0.113.77. No external system was contacted.");
  }

  function simulateNormalTraffic() {
    const now = Date.now();
    const batch: AuthEvent[] = Array.from({ length: 6 }, (_, i) => ({
      event_id: "sim-normal-" + now + "-" + (i + 1),
      timestamp: new Date(now + i * 900).toISOString(),
      source_ip: "192.0.2." + (30 + i),
      username: "test-user-" + (i + 1),
      event_type: "login_success",
      label: "normal",
    }));
    setEvents(current => [...current.slice(-494), ...batch]);
    setNotice("Added 6 synthetic successful logins to the lab dataset.");
  }

  function printIncidentReport() {
    window.print();
  }

  function exportJson() {
    const blob = new Blob([JSON.stringify({ generated_at: new Date().toISOString(), config: { threshold, window_seconds: windowSeconds }, metrics, alerts, events }, null, 2)], { type: "application/json" });
    download(blob, "sentinelx-analysis.json");
  }
  function exportCsv() {
    const rows = [["alert_id","rule_id","severity","username","source_ip","event_count","first_seen","last_seen","evidence_event_ids"], ...alerts.map(a => [a.alert_id,a.rule_id,a.severity,a.username,a.source_ip,String(a.event_count),a.first_seen,a.last_seen,a.evidence_event_ids.join(";")])];
    download(new Blob([rows.map(r => r.map(v => `"${v.replace(/"/g, '""')}"`).join(",")).join("\n")], { type: "text/csv;charset=utf-8" }), "sentinelx-alerts.csv");
  }
  function download(blob: Blob, name: string) {
    const url = URL.createObjectURL(blob); const a = document.createElement("a");
    a.href = url; a.download = name; a.click(); URL.revokeObjectURL(url);
  }
  function resetDemo() {
    setEvents(buildDemoEvents()); setThreshold(5); setWindowSeconds(300); setSeverity("all"); setSearch("");
    setApiState("demo"); setApiSnapshot(null); setNotice("Synthetic lab dataset reset to baseline.");
  }

  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><div className="brand-mark"><Shield size={21}/></div><div><strong>sentinel<span>x</span></strong><small>THREAT INTELLIGENCE LAB</small></div></div>
      <div className="workspace"><span className="workspace-dot"/><div><b>Research workspace</b><small>Authentication telemetry</small></div><ChevronDown size={15}/></div>
      <div className="nav-label">WORKSPACE</div>
      <button className="nav-item active" onClick={() => setTab("incidents")}><Activity size={17}/> Overview <span className="nav-count">{alerts.length}</span></button>
      <button className="nav-item" onClick={() => setTab("incidents")}><ShieldAlert size={17}/> Incidents</button>
      <button className="nav-item" onClick={() => setTab("events")}><FileSearch size={17}/> Event explorer</button>
      <button className="nav-item" onClick={() => setTab("research")}><Gauge size={17}/> Research & metrics</button>
      <div className="nav-label">SYSTEM</div>
      <button className="nav-item" onClick={() => document.getElementById("api-config")?.scrollIntoView({ behavior: "smooth" })}><Settings2 size={17}/> API connection</button>
      <div className="sidebar-bottom">
        <div className="safe-card"><LockKeyhole size={16}/><div><b>Safe lab mode</b><p>Synthetic events only. No live targets.</p></div></div>
        <a className="github-link" href="https://github.com/uchihavamfyre-maker/SentinelX" target="_blank" rel="noreferrer"><Github size={16}/> View source <ExternalLink size={13}/></a>
        <div className="version">SENTINELX BUILD 0.1.0 <span>●</span></div>
      </div>
    </aside>

    <main className="main-content">
      <header className="topbar"><div className="breadcrumbs">Workspace <span>/</span> <b>{tab === "incidents" ? "Security overview" : tab === "events" ? "Event explorer" : "Research & metrics"}</b></div><div className="top-actions"><span className={`connection ${apiState}`}><i/>{apiState === "connected" ? "API connected" : apiState === "error" ? "API offline" : "Demo mode"}</span><button className="icon-button" title="Reset demo data" onClick={resetDemo}><RefreshCw size={16}/></button><div className="avatar">SX</div></div></header>
      <div className="page">
        <div className="page-heading"><div><div className="eyebrow"><span/> DEFENSIVE SECURITY ANALYTICS</div><h1>{tab === "incidents" ? "Security overview" : tab === "events" ? "Event explorer" : "Research & metrics"}</h1><p>Monitor authentication patterns, investigate alerts, and evaluate detection performance.</p></div><div className="heading-actions"><button className="button secondary" onClick={exportCsv}><Download size={15}/> Export CSV</button><button className="button primary" onClick={exportJson}><Download size={15}/> Export JSON</button></div></div>
        <div className="notice"><div className="notice-icon"><ShieldCheck size={16}/></div><span>{notice}</span><button onClick={() => setNotice("Safety scope: local synthetic events only. API connection is opt-in.")} title="Safety details"><CircleHelp size={15}/></button></div>

        <section className="metrics-grid">
          <Metric label="Events analyzed" value={events.length.toLocaleString()} sub="Synthetic authentication events" icon={<Activity/>} tone="blue" trend="Dataset" />
          <Metric label="Detection alerts" value={alerts.length.toLocaleString()} sub="Current rule configuration" icon={<ShieldAlert/>} tone="purple" trend={alerts.length ? "Review" : "Clear"} />
          <Metric label="Precision" value={pct(metrics.precision)} sub={`${metrics.true_positive} TP · ${metrics.false_positive} FP`} icon={<TargetIcon/>} tone="green" trend="Event-level" />
          <Metric label="Recall" value={pct(metrics.recall)} sub={`${metrics.true_positive} TP · ${metrics.false_negative} FN`} icon={<Gauge/>} tone="amber" trend="Event-level" />
        </section>

        <section className="chart-grid">
          <div className="panel timeline-panel"><div className="panel-heading"><div><h2>Authentication activity</h2><p>Successful vs. failed login events</p></div><span className="panel-tag"><span className="live-dot"/> REPLAY DATA</span></div>
            <div className="chart-legend"><span><i className="legend-blue"/> Successful</span><span><i className="legend-violet"/> Failed</span></div>
            <div className="chart-area"><ResponsiveContainer width="100%" height="100%"><AreaChart data={timeline} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}><defs><linearGradient id="successFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#38bdf8" stopOpacity={0.24}/><stop offset="95%" stopColor="#38bdf8" stopOpacity={0}/></linearGradient><linearGradient id="failedFill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#a78bfa" stopOpacity={0.24}/><stop offset="95%" stopColor="#a78bfa" stopOpacity={0}/></linearGradient></defs><CartesianGrid stroke="#20283a" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="time" tick={{ fill: "#7e8ba5", fontSize: 10 }} axisLine={false} tickLine={false}/><YAxis tick={{ fill: "#7e8ba5", fontSize: 10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={{ background: "#111827", border: "1px solid #293449", borderRadius: 10, fontSize: 12 }} /><Area type="monotone" dataKey="successful" name="Successful" stroke="#38bdf8" strokeWidth={2} fill="url(#successFill)"/><Area type="monotone" dataKey="failed" name="Failed" stroke="#a78bfa" strokeWidth={2} fill="url(#failedFill)"/></AreaChart></ResponsiveContainer></div>
          </div>
          <div className="panel severity-panel"><div className="panel-heading"><div><h2>Alert severity</h2><p>Distribution across detected alerts</p></div><AlertOctagon size={18} className="muted-icon"/></div><div className="severity-total"><strong>{alerts.length}</strong><span>Total alerts</span></div><div className="severity-bars">{severityRows.map(row => <div className="severity-row" key={row.name}><div><span className="severity-dot" style={{ background: row.color }}/><span>{row.name}</span><b>{row.value}</b></div><div className="bar-track"><div style={{ width: `${alerts.length ? row.value / alerts.length * 100 : 0}%`, background: row.color }}/></div></div>)}</div><div className="severity-foot"><ShieldCheck size={14}/> Severity reflects evidence volume, not confirmed compromise.</div></div>
        </section>

        <section className="panel config-panel"><div className="panel-heading"><div><h2><SlidersHorizontal size={17}/> Detection configuration</h2><p>Adjust the baseline rule and observe how the output changes.</p></div><span className="rule-badge">AUTH-001</span></div><div className="config-controls"><label className="range-control"><span>Failure threshold <b>{threshold} events</b></span><input type="range" min="2" max="10" value={threshold} onChange={e => setThreshold(Number(e.target.value))}/><small>Minimum failed logins required to trigger an alert</small></label><label className="select-control"><span>Correlation window</span><select value={windowSeconds} onChange={e => setWindowSeconds(Number(e.target.value))}><option value={60}>1 minute</option><option value={180}>3 minutes</option><option value={300}>5 minutes</option><option value={600}>10 minutes</option><option value={900}>15 minutes</option></select><small>Events grouped by source IP + username</small></label><div className="config-result"><div className="result-icon"><Activity size={17}/></div><div><small>Current result</small><strong>{alerts.length} alerts</strong><span>Recalculated locally</span></div></div></div></section>

        <section className="panel config-panel simulation-panel">
          <div className="panel-heading"><div><h2><Activity size={17}/> Live attack simulation</h2><p>Generate controlled test telemetry and watch AUTH-001 respond.</p></div><span className={liveMode ? "status-chip" : "rule-badge"}>{liveMode ? "● STREAMING" : "LAB MODE"}</span></div>
          <div className="simulation-actions">
            <button className="button primary" onClick={simulateBruteForce}><ShieldAlert size={15}/> Simulate brute-force</button>
            <button className="button secondary" onClick={simulateNormalTraffic}><CheckCircle2 size={15}/> Normal traffic</button>
            <button className={liveMode ? "button danger" : "button secondary"} onClick={() => setLiveMode(value => !value)}><Activity size={15}/>{liveMode ? "Stop live stream" : "Start live stream"}</button>
            <button className="button secondary" onClick={printIncidentReport}><Download size={15}/> Print report</button>
          </div>
          <div className="simulation-foot"><span><i className="live-dot"/>{events.length} events in working set</span><span>{simulationCount} attack simulations run</span><span>Reserved TEST-NET IP ranges only</span></div>
        </section>

        {tab === "research" && <section className="research-grid"><div className="panel research-panel"><div className="panel-heading"><div><h2>Evaluation summary</h2><p>Event-level classification against synthetic labels</p></div></div><div className="confusion-grid"><div><small>True positive</small><strong className="green-text">{metrics.true_positive}</strong></div><div><small>False positive</small><strong className="red-text">{metrics.false_positive}</strong></div><div><small>True negative</small><strong>{metrics.true_negative}</strong></div><div><small>False negative</small><strong className="amber-text">{metrics.false_negative}</strong></div></div><div className="metric-line"><span>F1 score</span><b>{metrics.f1.toFixed(4)}</b></div><div className="metric-line"><span>False-positive rate</span><b>{pct(metrics.false_positive_rate)}</b></div><div className="metric-line"><span>Labeled events</span><b>{metrics.labeled_events}</b></div></div><div className="panel research-panel"><div className="panel-heading"><div><h2>Threshold experiment</h2><p>Same data and window; vary threshold from 2 to 10</p></div></div><div className="sweep-chart"><ResponsiveContainer width="100%" height="100%"><BarChart data={Array.from({length:9}, (_,i) => { const t=i+2; const m=evaluate(events, detect(events,t,windowSeconds)); return { threshold: String(t), precision: +(m.precision*100).toFixed(1), recall: +(m.recall*100).toFixed(1) }; })}><CartesianGrid stroke="#20283a" strokeDasharray="3 5" vertical={false}/><XAxis dataKey="threshold" tick={{ fill:"#7e8ba5",fontSize:10 }} axisLine={false} tickLine={false}/><YAxis domain={[0,100]} tick={{ fill:"#7e8ba5",fontSize:10 }} axisLine={false} tickLine={false}/><Tooltip contentStyle={{ background:"#111827",border:"1px solid #293449",borderRadius:10,fontSize:12 }}/><Bar dataKey="precision" name="Precision %" fill="#34d399" radius={[3,3,0,0]}/><Bar dataKey="recall" name="Recall %" fill="#a78bfa" radius={[3,3,0,0]}/></BarChart></ResponsiveContainer></div><p className="research-note"><CircleHelp size={14}/> Exploratory sweep on the same synthetic dataset; not a held-out benchmark.</p></div></section>}

        {tab === "incidents" && <section className="panel table-panel"><div className="panel-heading table-title"><div><h2>Detection incidents <span className="count-pill">{filteredAlerts.length}</span></h2><p>Evidence-backed alerts from AUTH-001</p></div><div className="table-tools"><div className="search-box"><Search size={15}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search alerts…"/>{search && <button onClick={() => setSearch("")}><X size={13}/></button>}</div><select className="filter-select" value={severity} onChange={e => setSeverity(e.target.value)}><option value="all">All severity</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div><div className="table-scroll"><table><thead><tr><th>INCIDENT</th><th>SEVERITY</th><th>IDENTITY / SOURCE</th><th>EVIDENCE</th><th>LAST SEEN</th><th></th></tr></thead><tbody>{filteredAlerts.map(a => <tr key={a.alert_id} onClick={() => setSelected(a)}><td><div className="incident-name"><span className={`incident-icon ${a.severity}`}><ShieldAlert size={15}/></span><div><b>{a.title}</b><small>{a.alert_id} · {a.rule_id}</small></div></div></td><td><span className={`severity-pill ${a.severity}`}>{a.severity}</span></td><td><div className="identity"><b>{a.username}</b><small>{a.source_ip}</small></div></td><td><span className="evidence-count">{a.event_count} events</span></td><td className="time-cell">{time(a.last_seen)}</td><td><button className="row-open" title="Inspect alert"><ExternalLink size={14}/></button></td></tr>)}</tbody></table>{filteredAlerts.length === 0 && <div className="empty-state"><CheckCircle2 size={24}/><b>No matching incidents</b><span>Try a different filter or lower the detection threshold.</span></div>}</div><div className="table-footer"><span>Showing {filteredAlerts.length} of {alerts.length} alerts</span><span><span className="live-dot"/> Live rule recalculation</span></div></section>}

        {tab === "events" && <section className="panel table-panel"><div className="panel-heading table-title"><div><h2>Authentication events <span className="count-pill">{eventRows.length}</span></h2><p>Search synthetic source records and ground-truth labels</p></div><div className="table-tools"><div className="search-box"><Search size={15}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search events…"/>{search && <button onClick={() => setSearch("")}><X size={13}/></button>}</div></div></div><div className="table-scroll"><table><thead><tr><th>EVENT ID</th><th>TYPE</th><th>ACCOUNT</th><th>SOURCE IP</th><th>LABEL</th><th>TIMESTAMP</th></tr></thead><tbody>{eventRows.map(e => <tr key={e.event_id}><td className="mono">{e.event_id}</td><td><span className={`event-type ${e.event_type}`}>{e.event_type === "login_failure" ? "Failed login" : "Successful login"}</span></td><td>{e.username}</td><td className="mono">{e.source_ip}</td><td><span className={`label-pill ${e.label}`}>{e.label}</span></td><td className="time-cell">{time(e.timestamp)}</td></tr>)}</tbody></table></div><div className="table-footer"><span>All addresses are from documentation-only IP ranges.</span><span>{events.length} total events</span></div></section>}

        <section className="bottom-grid"><div className="panel api-panel" id="api-config"><div className="panel-heading"><div><h2><Terminal size={17}/> Backend connection</h2><p>Connect the dashboard to a running SentinelX API.</p></div>{apiState === "connected" ? <Wifi size={18} className="green-text"/> : <WifiOff size={18} className="muted-icon"/>}</div><label className="api-input-label">API base URL</label><div className="api-input-row"><input value={apiUrl} onChange={e => setApiUrl(e.target.value)} placeholder="https://your-api-host.example.com"/><button className="button primary" disabled={busy} onClick={refreshFromApi}>{busy ? <RefreshCw className="spin" size={14}/> : <Wifi size={14}/>} {busy ? "Checking…" : "Connect"}</button></div><small className="form-help">Requires /health and /analyze endpoints. Browser access may require CORS configuration on the API.</small></div><div className="panel rule-panel"><div className="panel-heading"><div><h2><LockKeyhole size={17}/> Active detection rule</h2><p>Transparent baseline detection</p></div><span className="status-chip"><span/> ENABLED</span></div><div className="rule-detail"><div className="rule-code">AUTH-001</div><div><b>Repeated authentication failures</b><p>Group failed logins by source IP and username. Trigger when the configured threshold is reached within the correlation window.</p></div></div><div className="rule-foot"><span><Clock3 size={13}/> Rolling time window</span><span><AlertTriangle size={13}/> Human review recommended</span></div></div></section>
        <footer className="footer"><span>SentinelX <b>·</b> Defensive Threat Detection Lab</span><span>Built for reproducible security research <b>·</b> Synthetic data only</span></footer>
      </div>
    </main>
    {selected && <div className="drawer-backdrop" onClick={() => setSelected(null)}><aside className="detail-drawer" onClick={e => e.stopPropagation()}><div className="drawer-head"><div><span className="eyebrow">INCIDENT DETAILS</span><h2>{selected.title}</h2></div><button className="icon-button" onClick={() => setSelected(null)}><X size={17}/></button></div><span className={`severity-pill ${selected.severity}`}>{selected.severity}</span><div className="detail-id">{selected.alert_id}</div><p className="drawer-explanation">{selected.explanation}</p><div className="detail-block"><label>Rule</label><b>{selected.rule_id}</b></div><div className="detail-block"><label>Account</label><b>{selected.username}</b></div><div className="detail-block"><label>Source IP</label><b className="mono">{selected.source_ip}</b></div><div className="detail-block"><label>Event count</label><b>{selected.event_count}</b></div><div className="detail-block"><label>Time range</label><b>{time(selected.first_seen)} — {time(selected.last_seen)}</b></div><div className="evidence-list"><h3>Evidence event IDs</h3>{selected.evidence_event_ids.map(id => <div key={id}><FileSearch size={14}/><span>{id}</span></div>)}</div><div className="drawer-warning"><AlertTriangle size={15}/> An alert is a triage signal, not proof of compromise.</div></aside></div>}
  </div>;
}

function TargetIcon() { return <CheckCircle2/>; }
function Metric({ label, value, sub, icon, tone, trend }: { label: string; value: string; sub: string; icon: ReactNode; tone: string; trend: string }) {
  return <div className="metric-card"><div className="metric-top"><span>{label}</span><div className={`metric-icon ${tone}`}>{icon}</div></div><div className="metric-value">{value}</div><div className="metric-bottom"><span>{sub}</span><span className="metric-trend">{trend}</span></div></div>;
}
