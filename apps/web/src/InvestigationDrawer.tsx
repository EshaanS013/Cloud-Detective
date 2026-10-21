import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useRef, useState } from "react";

type Finding = { rule_id: string; title: string; severity: string; risk_score: string; status: string; description: string; principal_arn: string | null; source_ip: string | null; affected_resources: string[]; assigned_to: string | null; notes: string | null; resolved_at: string | null };
type Evidence = { event_id: string; event_time: string; event_name: string; event_source: string; aws_region: string; source_address: string | null; mfa_authenticated: boolean | null; error_code: string | null; error_message: string | null; error_explanation: string | null; simulated: boolean };
type Explanation = { finding: Finding; rule_name: string; rule_type: string; rule_description: string; category: string; mitre_technique: string | null; score_factors: Record<string, number>; window_start: string; window_end: string; event_count: number; evidence: Evidence[]; evidence_truncated: boolean; trigger_summary: string; trigger_checks: string[]; observed_summary: string; investigation_guidance: string; limitations: string[] };

const factorLabels: Record<string, string> = {
  base: "Starting score", principal: "Identity", resource: "Resource",
  time: "Time of day", origin: "Source", mfa: "MFA",
};

function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}

export function FindingExplanation({ id, token, apiBase, responseMode, onClose, onUpdated }: { id: string; token?: string; apiBase: string; responseMode: string; onClose: () => void; onUpdated?: () => void }) {
  const drawerRef = useRef<HTMLElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);
  const queryClient = useQueryClient();
  const [working, setWorking] = useState(false);
  const [actionMessage, setActionMessage] = useState("");
  const [draftNote, setDraftNote] = useState("");
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
  async function saveStatus(status: "INVESTIGATING" | "RESOLVED") {
    const note = draftNote.trim();
    if (status === "RESOLVED" && !note) {
      setActionMessage("Add a resolution note explaining what you checked and why you are closing this case.");
      return;
    }
    setWorking(true);
    setActionMessage("");
    try {
      const response = await fetch(`${apiBase}/findings/${id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ status, ...(note ? { notes: note } : {}) }),
      });
      if (response.status === 403) {
        setActionMessage("Only a Responder can change investigation status. Ask the project owner for Responder access.");
        return;
      }
      if (response.status === 401) {
        setActionMessage("Your sign-in has expired. Sign in again before updating this case.");
        return;
      }
      if (!response.ok) throw new Error(`Status update failed: ${response.status}`);
      setDraftNote("");
      setActionMessage(status === "RESOLVED" ? "Case closed with your resolution note. No AWS resource was changed." : "Investigation started and assigned. Review the evidence and record what you find below.");
      await queryClient.invalidateQueries({ queryKey: ["finding-explanation", id] });
      onUpdated?.();
    } catch {
      setActionMessage("Case status could not be saved. Please try again.");
    } finally {
      setWorking(false);
    }
  }

  async function runS3Response(targetArn: string, enforce: boolean) {
    if (enforce && !window.confirm(`Restore all four S3 Block Public Access settings on ${targetArn}? This changes the live AWS bucket.`)) return;
    setWorking(true);
    setActionMessage("");
    try {
      const response = await fetch(`${apiBase}/findings/${id}/responses`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
        body: JSON.stringify({ playbook_id: "block-public-s3", target_arn: targetArn, confirmation: enforce ? "ENFORCE" : "DRY_RUN" }),
      });
      if (response.status === 403) { setActionMessage("Only a Responder can run this action. Ask the project owner for Responder access."); return; }
      if (response.status === 409) { setActionMessage("Live responses are disabled in this deployment."); return; }
      if (!response.ok) throw new Error(`Response failed: ${response.status}`);
      const result = await response.json() as { outcome: string };
      setActionMessage(enforce ? `Live S3 response ${result.outcome.toLowerCase()}. Refresh the bucket's Permissions tab in AWS to verify Block Public Access.` : "Dry-run response recorded. No AWS resource was changed.");
    } catch {
      setActionMessage("Response could not be submitted. Please try again.");
    } finally {
      setWorking(false);
    }
  }

  return <div className="drawer-backdrop" onClick={onClose}>
    <aside ref={drawerRef} className="detail-drawer" role="dialog" aria-modal="true" aria-label="Finding explanation" onClick={(event) => event.stopPropagation()}>
      <div className="drawer__header"><div><p className="label">INVESTIGATION CASE</p><h2>{data?.finding.title ?? "Finding details"}</h2></div><button ref={closeRef} className="close-button" aria-label="Close explanation" onClick={onClose}>×</button></div>
      {explanation.isPending ? <div className="state-message" role="status">Loading explanation…</div> : null}
      {explanation.isError ? <div className="state-message state-message--error" role="alert">The explanation could not be loaded. Please try again.</div> : null}
      {data ? <div className="drawer__body">
        <div className="detail-summary"><span className={`pill pill--${data.finding.severity.toLowerCase()}`}>{data.finding.severity}</span><strong>{data.finding.risk_score}<small> / 100 risk score</small></strong><span className="status-tag">{data.finding.status.replaceAll("_", " ")}</span></div>
        {data.evidence.some((event) => event.simulated) ? <div className="simulation-banner">Synthetic test event · No real AWS security change occurred.</div> : null}

        <section className="detail-section"><p className="label">WHAT HAPPENED</p><h3>{data.observed_summary}</h3><p>{data.rule_description || data.finding.description}</p><p className="explanation-caution">This is a detection, not a confirmed attack or a diagnosis of intent. Check the linked audit records below before deciding what happened.</p></section>

        <section className="detail-section"><p className="label">WHY THE RULE FIRED</p><h3>{data.trigger_summary}</h3><ul className="readable-list">{data.trigger_checks.map((check) => <li key={check}>{check}</li>)}</ul><div className="metadata-grid"><div><span>Rule category</span><strong>{data.category.replaceAll("-", " ")}</strong></div><div><span>Evidence window</span><strong>{formatTime(data.window_start)} – {formatTime(data.window_end)}</strong></div></div></section>

        <section className="detail-section"><p className="label">AWS ERRORS AND LINKED EVIDENCE · {data.event_count} EVENT{data.event_count === 1 ? "" : "S"}</p>{data.evidence.length ? <ol className="evidence-list">{data.evidence.map((event) => <li key={event.event_id}><div><strong>{event.event_name}</strong>{event.simulated ? <span className="test-tag">TEST</span> : null}</div><p>{event.event_source} · {event.aws_region} · {formatTime(event.event_time)}</p><small>Source {event.source_address ?? "unknown"} · MFA {event.mfa_authenticated === null ? "not recorded" : event.mfa_authenticated ? "used" : "not used"}</small>{event.error_code || event.error_message ? <div className="evidence-error"><strong>Recorded AWS error: {event.error_code ?? "No error code"}</strong><p>{event.error_message ?? "CloudTrail did not include an error message."}</p>{event.error_explanation ? <p><strong>What it means:</strong> {event.error_explanation}</p> : null}<small>The audit record reports this error; its underlying cause still needs investigation.</small></div> : <p className="evidence-ok">No AWS API error was recorded for this event.</p>}</li>)}</ol> : <p>No linked events are available.</p>}{data.evidence_truncated ? <p className="evidence-note">Showing the first 50 linked events.</p> : null}</section>

        <section className="detail-section"><p className="label">INVESTIGATION WORKSPACE</p><p><strong>What to check next:</strong> {data.investigation_guidance}</p><div className="metadata-grid"><div><span>Case status</span><strong>{data.finding.status.replaceAll("_", " ")}</strong></div><div><span>Assigned investigator</span><strong>{data.finding.assigned_to ?? "Not assigned yet"}</strong></div></div>{data.finding.notes ? <div className="case-note"><strong>Recorded investigation / resolution note</strong><p>{data.finding.notes}</p></div> : null}{data.finding.resolved_at ? <p className="case-closed">Closed {formatTime(data.finding.resolved_at)}. Closing a case does not change an AWS resource.</p> : null}<label className="note-field" htmlFor="case-note">Investigation or resolution note</label><textarea id="case-note" value={draftNote} onChange={(event) => setDraftNote(event.target.value)} maxLength={4000} placeholder="What did you check? What did you find? Why is this safe to close?" /><div className="investigation-actions__buttons"><button disabled={working || data.finding.status === "RESOLVED"} onClick={() => void saveStatus("INVESTIGATING")}>Start investigation / save note</button><button disabled={working || data.finding.status === "RESOLVED"} onClick={() => void saveStatus("RESOLVED")}>Resolve finding</button>{data.finding.rule_id === "s3-public-access-block-removed" && data.finding.affected_resources[0] ? <><button disabled={working} onClick={() => void runS3Response(data.finding.affected_resources[0], false)}>Preview S3 response (dry run)</button>{responseMode === "enforce" ? <button disabled={working} onClick={() => void runS3Response(data.finding.affected_resources[0], true)}>Restore S3 protection in AWS</button> : null}</> : null}</div><p className="workflow-help">Starting assigns this case to you. Resolving closes the case record only. Restoring S3 protection is a separate live action available for tagged demo buckets.</p>{actionMessage ? <p className="action-message" role="status">{actionMessage}</p> : null}</section>

        <section className="detail-section"><p className="label">RISK SCORE, NOT CERTAINTY</p><p>The starting score is multiplied by the context factors below and capped at 100. This is a triage estimate, not the probability of an attack.</p><div className="score-formula"><span>Base {data.score_factors.base ?? "—"}</span>{Object.entries(data.score_factors).filter(([key]) => key !== "base").map(([key, value]) => <span key={key}>× {value} {factorLabels[key] ?? key}</span>)}<strong>= {data.finding.risk_score} / 100</strong></div></section>
        <section className="detail-section"><p className="label">WHO AND WHAT</p><div className="metadata-grid"><div><span>Identity</span><strong className="breakable">{data.finding.principal_arn ?? "Unknown"}</strong></div><div><span>Source IP</span><strong>{data.finding.source_ip ?? "Unknown"}</strong></div></div>{data.finding.affected_resources.length ? <div className="resources"><span>Related resources</span>{data.finding.affected_resources.map((resource) => <code key={resource}>{resource}</code>)}</div> : null}</section>
        <section className="detail-section"><p className="label">WHAT THIS DOES NOT CONFIRM</p><ul className="readable-list">{data.limitations.map((limit) => <li key={limit}>{limit}</li>)}</ul></section>
      </div> : null}
    </aside>
  </div>;
}
