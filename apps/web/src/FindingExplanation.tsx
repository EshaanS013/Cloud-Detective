import { useQuery } from "@tanstack/react-query";
import { useEffect, useRef } from "react";

type Finding = { title: string; severity: string; risk_score: string; status: string; description: string; principal_arn: string | null; source_ip: string | null; affected_resources: string[] };
type Evidence = { event_id: string; event_time: string; event_name: string; event_source: string; aws_region: string; source_address: string | null; mfa_authenticated: boolean | null; error_code: string | null; simulated: boolean };
type Explanation = { finding: Finding; rule_name: string; rule_type: string; rule_description: string; category: string; mitre_technique: string | null; score_factors: Record<string, number>; window_start: string; window_end: string; event_count: number; evidence: Evidence[]; evidence_truncated: boolean };

const factorLabels: Record<string, string> = {
  base: "Rule base score", principal: "Principal", resource: "Resource",
  time: "Time of day", origin: "Origin", mfa: "MFA",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function FindingExplanation({ id, token, apiBase, onClose }: { id: string; token?: string; apiBase: string; onClose: () => void }) {
  const drawerRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const explanation = useQuery({
    queryKey: ["finding-explanation", id, token],
    queryFn: async () => {
      const response = await fetch(`${apiBase}/findings/${id}/explanation`, {
        headers: token ? { Authorization: `Bearer ${token}` } : undefined,
      });
      if (!response.ok) throw new Error(`API request failed: ${response.status}`);
      return response.json() as Promise<Explanation>;
    },
  });
  useEffect(() => {
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    closeRef.current?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
      if (event.key !== "Tab") return;
      const focusable = Array.from(drawerRef.current?.querySelectorAll<HTMLElement>("button, a[href], input, select, textarea, [tabindex]:not([tabindex='-1'])") ?? []);
      if (!focusable.length) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => { window.removeEventListener("keydown", onKeyDown); previousFocus?.focus(); };
  }, [onClose]);

  const data = explanation.data;
  return <div className="drawer-backdrop" onClick={onClose}>
    <aside ref={drawerRef} className="detail-drawer" role="dialog" aria-modal="true" aria-label="Finding explanation" onClick={(event) => event.stopPropagation()}>
      <div className="drawer__header"><div><p className="label">FINDING EXPLANATION</p><h2>{data?.finding.title ?? "Finding details"}</h2></div><button ref={closeRef} className="close-button" aria-label="Close explanation" onClick={onClose}>×</button></div>
      {explanation.isPending ? <div className="state-message" role="status">Loading explanation…</div> : null}
      {explanation.isError ? <div className="state-message state-message--error" role="alert">The explanation could not be loaded. Please try again.</div> : null}
      {data ? <div className="drawer__body">
        <div className="detail-summary"><span className={`pill pill--${data.finding.severity.toLowerCase()}`}>{data.finding.severity}</span><strong>{data.finding.risk_score}<small> / 100 risk score</small></strong><span className="status-tag">{data.finding.status.replaceAll("_", " ")}</span></div>
        {data.evidence.some((event) => event.simulated) ? <div className="simulation-banner">Synthetic test event · No real AWS security change occurred.</div> : null}
        <section className="detail-section"><p className="label">WHY THIS WAS FLAGGED</p><h3>{data.rule_name}</h3><p>{data.rule_description || data.finding.description}</p><div className="metadata-grid"><div><span>Rule type</span><strong>{data.rule_type}</strong></div><div><span>Category</span><strong>{data.category}</strong></div><div><span>Technique</span><strong>{data.mitre_technique ?? "Not mapped"}</strong></div><div><span>Evidence window</span><strong>{formatTime(data.window_start)} – {formatTime(data.window_end)}</strong></div></div></section>
        <section className="detail-section"><p className="label">HOW RISK WAS SCORED</p><p>The base score is multiplied by the factors below and capped at 100. This is a risk estimate, not a probability.</p><div className="score-formula"><span>Base {data.score_factors.base ?? "—"}</span>{Object.entries(data.score_factors).filter(([key]) => key !== "base").map(([key, value]) => <span key={key}>× {value} {factorLabels[key] ?? key}</span>)}<strong>= {data.finding.risk_score} / 100</strong></div></section>
        <section className="detail-section"><p className="label">OBSERVED CONTEXT</p><div className="metadata-grid"><div><span>Principal</span><strong className="breakable">{data.finding.principal_arn ?? "Unknown"}</strong></div><div><span>Source IP</span><strong>{data.finding.source_ip ?? "Unknown"}</strong></div></div>{data.finding.affected_resources.length ? <div className="resources"><span>Affected resources</span>{data.finding.affected_resources.map((resource) => <code key={resource}>{resource}</code>)}</div> : null}</section>
        <section className="detail-section"><p className="label">LINKED EVIDENCE · {data.event_count} EVENT{data.event_count === 1 ? "" : "S"}</p>{data.evidence.length ? <ol className="evidence-list">{data.evidence.map((event) => <li key={event.event_id}><div><strong>{event.event_name}</strong>{event.simulated ? <span className="test-tag">TEST</span> : null}</div><p>{event.event_source} · {event.aws_region} · {formatTime(event.event_time)}</p><small>Origin {event.source_address ?? "unknown"} · MFA {event.mfa_authenticated === null ? "unknown" : event.mfa_authenticated ? "yes" : "no"}{event.error_code ? ` · ${event.error_code}` : ""}</small></li>)}</ol> : <p>No linked events are available.</p>}{data.evidence_truncated ? <p className="evidence-note">Showing the first 50 linked events.</p> : null}</section>
      </div> : null}
    </aside>
  </div>;
}
