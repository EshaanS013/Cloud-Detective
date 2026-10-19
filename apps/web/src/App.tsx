import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { User } from "oidc-client-ts";

import { authEnabled, restoreUser, userManager } from "./auth";
import { FindingExplanation } from "./FindingExplanation";

type Health = { status: string; service: string; version: string; environment: string; response_mode: "dry_run" | "enforce" };
type Summary = { total_events: number; open_findings: number; enabled_rules: number; severity_counts: Record<string, number>; response_mode: string };
type Finding = { id: string; rule_id: string; severity: string; risk_score: string; title: string; description: string; principal_arn: string | null; status: string; created_at: string };
type Event = { event_id: string; event_time: string; event_name: string; event_source: string; principal_arn: string | null; source_address: string | null };
type Rule = { id: string; name: string; category: string; base_score: number; enabled: boolean; mitre_technique: string | null };
type View = "overview" | "findings" | "events" | "rules";

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function api<T>(path: string, token?: string): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, {
    headers: token ? { Authorization: `Bearer ${token}` } : undefined,
  });
  if (!response.ok) throw new Error(`API request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function App() {
  const [view, setView] = useState<View>("overview");
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severity, setSeverity] = useState("ALL");
  const [findingStatus, setFindingStatus] = useState("ALL");
  const [user, setUser] = useState<User | null>(null);
  const [authReady, setAuthReady] = useState(!authEnabled);
  const closeExplanation = useCallback(() => setSelectedFinding(null), []);

  useEffect(() => {
    restoreUser().then(setUser).finally(() => setAuthReady(true));
  }, []);

  const token = user?.access_token;
  const canQuery = authReady && (!authEnabled || Boolean(token));
  const health = useQuery({ queryKey: ["health"], queryFn: () => api<Health>("/health") });
  const summary = useQuery({ queryKey: ["summary", token], queryFn: () => api<Summary>("/summary", token), enabled: canQuery });
  const findings = useQuery({ queryKey: ["findings", token], queryFn: () => api<Finding[]>("/findings?limit=50", token), enabled: canQuery });
  const events = useQuery({ queryKey: ["events", token], queryFn: () => api<Event[]>("/events?limit=100", token), enabled: canQuery });
  const rules = useQuery({ queryKey: ["rules", token], queryFn: () => api<Rule[]>("/rules", token), enabled: canQuery });

  const critical = useMemo(
    () => (summary.data?.severity_counts.CRITICAL ?? 0) + (summary.data?.severity_counts.HIGH ?? 0),
    [summary.data],
  );
  const filteredFindings = useMemo(() => (findings.data ?? []).filter((finding) => {
    const text = `${finding.title} ${finding.rule_id} ${finding.principal_arn ?? ""}`.toLowerCase();
    return text.includes(search.trim().toLowerCase())
      && (severity === "ALL" || finding.severity === severity)
      && (findingStatus === "ALL" || finding.status === findingStatus);
  }), [findings.data, search, severity, findingStatus]);

  if (!authReady) return <main className="loading">Securing session…</main>;
  if (authEnabled && !user) {
    return <main className="login"><div className="login__mark">CD</div><p className="eyebrow">AWS CONTROL PLANE SECURITY</p><h1>Cloud Detective</h1><p className="lede">Investigate activity across your AWS project.</p><button className="button" onClick={() => void userManager.signinRedirect()}>Sign in securely</button></main>;
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand"><span>CD</span><div><strong>Cloud Detective</strong><small>Security workspace</small></div></div>
        <p className="sidebar__label">WORKSPACE</p>
        <nav aria-label="Primary navigation">
          {(["overview", "findings", "events", "rules"] as View[]).map((item) => <button key={item} aria-pressed={view === item} className={view === item ? "active" : ""} onClick={() => setView(item)}>{item}{item === "findings" && summary.data?.open_findings ? <b>{summary.data.open_findings}</b> : null}</button>)}
        </nav>
        <div className="sidebar__foot"><span className={`dot ${health.data?.status === "ok" ? "dot--ok" : ""}`} />{health.data?.status === "ok" ? "Systems operational" : "API unavailable"}</div>
      </aside>

      <main className="content">
        <header className="topbar"><div><p className="eyebrow">SECURITY OPERATIONS / {view.toUpperCase()}</p><h1>{view}</h1><p className="page-description">{view === "overview" ? "A clear view of activity that needs attention." : view === "findings" ? "Review detections and trace every score to its evidence." : view === "events" ? "Recent normalized control plane activity." : "The rules behind your detections."}</p></div><div className="identity"><span>{user?.profile.email?.toString() ?? "Local developer"}</span>{authEnabled ? <button onClick={() => void userManager.signoutRedirect()}>Sign out</button> : null}</div></header>
        {summary.isError ? <div className="alert" role="alert">Dashboard data is unavailable. Check the API and database.</div> : null}

        {view === "overview" ? <>
          <section className="metrics" aria-label="Security summary">
            <article><span>Open findings</span><strong>{summary.data?.open_findings ?? "—"}</strong><small>Awaiting investigation</small></article>
            <article><span>High priority</span><strong className="danger">{summary.data ? critical : "—"}</strong><small>Critical and high</small></article>
            <article><span>Events processed</span><strong>{summary.data?.total_events.toLocaleString() ?? "—"}</strong><small>Control plane activity</small></article>
            <article><span>Active rules</span><strong>{summary.data?.enabled_rules ?? "—"}</strong><small>Detection catalogue</small></article>
          </section>
          <section className="panel"><div className="panel__header"><div><p className="label">LATEST SIGNALS</p><h2>Recent findings</h2></div><button onClick={() => setView("findings")}>View all →</button></div>{findings.isPending ? <div className="state-message" role="status">Loading findings…</div> : findings.isError ? <div className="state-message state-message--error" role="alert">Findings could not be loaded. Please refresh.</div> : <FindingsTable rows={findings.data?.slice(0, 6) ?? []} onInspect={setSelectedFinding} />}</section>
          <section className="lower-grid"><article className="panel"><p className="label">RESPONSE SAFETY</p><h2>{summary.data?.response_mode === "enforce" ? "Enforcement enabled" : "Dry run active"}</h2><p>Actions require Responder membership and the <code>CloudDetectiveSandbox=true</code> resource tag.</p></article><article className="panel"><p className="label">INGESTION</p><h2>{health.data?.status === "ok" ? "Pipeline ready" : "Waiting for API"}</h2><p>CloudTrail activity is normalized, deduplicated, and evaluated against the rule catalogue.</p></article></section>
        </> : null}

        {view === "findings" ? <section className="panel"><div className="panel__header"><div><p className="label">INVESTIGATIONS</p><h2>All findings <span className="heading-count">{findings.data?.length ?? 0}</span></h2></div></div><div className="filters"><label className="search-field"><span className="sr-only">Search findings</span><span aria-hidden="true">⌕</span><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Search findings or principals" /></label><label><span className="sr-only">Filter by severity</span><select value={severity} onChange={(event) => setSeverity(event.target.value)}><option value="ALL">All severities</option><option value="CRITICAL">Critical</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="NORMAL">Normal</option></select></label><label><span className="sr-only">Filter by status</span><select value={findingStatus} onChange={(event) => setFindingStatus(event.target.value)}><option value="ALL">All statuses</option><option value="OPEN">Open</option><option value="INVESTIGATING">Investigating</option><option value="RESOLVED">Resolved</option><option value="FALSE_POSITIVE">False positive</option></select></label></div>{findings.isPending ? <div className="state-message" role="status">Loading findings…</div> : findings.isError ? <div className="state-message state-message--error" role="alert">Findings could not be loaded. Please refresh.</div> : <FindingsTable rows={filteredFindings} onInspect={setSelectedFinding} emptyMessage="No findings match these filters." />}</section> : null}
        {view === "events" ? <section className="panel"><div className="panel__header"><div><p className="label">NORMALIZED AUDIT LOG</p><h2>Recent events</h2></div></div>{events.isPending ? <div className="state-message" role="status">Loading events…</div> : events.isError ? <div className="state-message state-message--error" role="alert">Events could not be loaded. Please refresh.</div> : !events.data?.length ? <div className="empty">No events yet.</div> : <div className="table-wrap"><table><thead><tr><th>Time</th><th>Event</th><th>Service</th><th>Principal</th><th>Origin</th></tr></thead><tbody>{events.data.map((event) => <tr key={event.event_id}><td>{formatTime(event.event_time)}</td><td><strong>{event.event_name}</strong></td><td>{event.event_source}</td><td className="truncate">{event.principal_arn ?? "Unknown"}</td><td>{event.source_address ?? "—"}</td></tr>)}</tbody></table></div>}</section> : null}
        {view === "rules" ? <section className="panel"><div className="panel__header"><div><p className="label">DETECTION AS CODE</p><h2>Rule catalogue</h2></div></div>{rules.isPending ? <div className="state-message" role="status">Loading rules…</div> : rules.isError ? <div className="state-message state-message--error" role="alert">Rules could not be loaded. Please refresh.</div> : <div className="rule-grid">{(rules.data ?? []).map((rule) => <article key={rule.id}><div><span className={`dot ${rule.enabled ? "dot--ok" : ""}`} /><strong>{rule.name}</strong></div><p>{rule.category} · score {rule.base_score}</p><small>{rule.mitre_technique ?? rule.id}</small></article>)}</div>}</section> : null}
      </main>
      {selectedFinding ? <FindingExplanation id={selectedFinding} token={token} apiBase={apiBase} onClose={closeExplanation} /> : null}
    </div>
  );
}

function FindingsTable({ rows, onInspect, emptyMessage = "No findings yet. The environment is quiet." }: { rows: Finding[]; onInspect: (id: string) => void; emptyMessage?: string }) {
  if (!rows.length) return <div className="empty">{emptyMessage}</div>;
  return <div className="table-wrap"><table><thead><tr><th>Finding</th><th>Severity</th><th>Risk</th><th>Status</th><th>Detected</th><th><span className="sr-only">Details</span></th></tr></thead><tbody>{rows.map((finding) => <tr key={finding.id}><td><strong>{finding.title}</strong><small>{finding.principal_arn ?? finding.rule_id}</small></td><td><span className={`pill pill--${finding.severity.toLowerCase()}`}>{finding.severity}</span></td><td><span className="risk-score">{finding.risk_score}</span><span className="score-denominator"> / 100</span></td><td>{finding.status.replaceAll("_", " ")}</td><td>{formatTime(finding.created_at)}</td><td><button className="inspect-button" aria-label={`Explain ${finding.title}`} onClick={() => onInspect(finding.id)}>Explain →</button></td></tr>)}</tbody></table></div>;
}
