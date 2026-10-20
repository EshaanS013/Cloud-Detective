import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><App /></QueryClientProvider>);
}

function response(data: unknown, ok = true) {
  return Promise.resolve({ ok, status: ok ? 200 : 503, json: async () => data });
}

function stubApi(healthy = true, ruleId = "cloudtrail-tampering") {
  let caseStatus = "OPEN";
  let caseNotes: string | null = null;
  vi.stubGlobal("fetch", vi.fn((input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (init?.method === "PATCH") {
      const update = JSON.parse(String(init.body));
      caseStatus = update.status;
      if (update.notes) caseNotes = update.notes;
      return response({ status: caseStatus, notes: caseNotes, assigned_to: "local-developer" });
    }
    if (init?.method === "POST" && url.includes("/responses")) return response({ outcome: "SIMULATED" });
    if (url.includes("/health")) return response({ status: "ok", service: "cloud-detective-api", version: "0.1.0", environment: "local", response_mode: "dry_run" }, healthy);
    if (url.includes("/summary")) return response({ total_events: 42, open_findings: 2, enabled_rules: 21, severity_counts: { CRITICAL: 1 }, response_mode: "dry_run" }, healthy);
    if (url.includes("/explanation")) return response({
      finding: { rule_id: ruleId, title: "CloudTrail tampering", severity: "CRITICAL", risk_score: "92", status: caseStatus, description: "Logging changed", principal_arn: "arn:aws:iam::123:user/test", source_ip: "192.0.2.10", affected_resources: ruleId.startsWith("s3-public") ? ["arn:aws:s3:::presentation-example"] : [], assigned_to: caseStatus === "OPEN" ? null : "local-developer", notes: caseNotes, resolved_at: caseStatus === "RESOLVED" ? "2026-09-27T11:00:00Z" : null },
      rule_name: "CloudTrail tampering", rule_type: "signature", rule_description: "Detect attempts to stop logging.", category: "logging", mitre_technique: "T1562.008",
      score_factors: { base: 70, principal: 1.3, resource: 1, time: 1, origin: 1, mfa: 1 }, window_start: "2026-09-27T10:00:00Z", window_end: "2026-09-27T10:00:00Z", event_count: 1,
      evidence: [{ event_id: "event-1", event_time: "2026-09-27T10:00:00Z", event_name: "StopLogging", event_source: "cloudtrail.amazonaws.com", aws_region: "ap-southeast-2", source_address: "192.0.2.10", mfa_authenticated: false, error_code: "AccessDenied", error_message: "Not authorized to stop this trail", simulated: true }], evidence_truncated: false,
      trigger_summary: "A single AWS audit event matched these conditions.", trigger_checks: ["AWS action is StopLogging."], observed_summary: "1 linked AWS audit event recorded: StopLogging. 1 shown event reported an AWS error.", investigation_guidance: "Check whether this change was approved.", limitations: ["The audit events do not confirm intent."],
    }, healthy);
    if (url.includes("/findings")) return response([{ id: "1", rule_id: "cloudtrail-tampering", severity: "CRITICAL", risk_score: "92", title: "CloudTrail tampering", description: "Logging changed", principal_arn: "arn:aws:iam::123:user/test", status: "OPEN", created_at: "2026-09-27T10:00:00Z" }], healthy);
    if (url.includes("/events")) return response([], healthy);
    if (url.includes("/rules")) return response([{ id: "cloudtrail-tampering", name: "CloudTrail tampering", category: "defence-evasion", rule_type: "signature", base_score: 85, enabled: true, mitre_technique: "T1562.008", description: "Logging was stopped.", trigger_summary: "A single event matched.", trigger_checks: ["AWS action is StopLogging."], investigation_guidance: "Check whether the change was approved." }], healthy);
    return response({}, false);
  }));
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("App", () => {
  it("renders live security metrics and findings", async () => {
    stubApi();
    renderApp();
    expect(screen.getByRole("heading", { name: "overview" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("42")).toBeInTheDocument());
    expect(screen.getByText("CloudTrail tampering")).toBeInTheDocument();
    expect(screen.getByText("Dry run active")).toBeInTheDocument();
  });

  it("navigates between operational views", () => {
    stubApi();
    renderApp();
    fireEvent.click(screen.getByRole("button", { name: "events" }));
    expect(screen.getByRole("heading", { name: "events" })).toBeInTheDocument();
    expect(screen.getByText("Recent events")).toBeInTheDocument();
  });

  it("shows a visible degraded state when data is unavailable", async () => {
    stubApi(false);
    renderApp();
    await waitFor(() => expect(screen.getByText(/Dashboard data is unavailable/)).toBeInTheDocument());
  });

  it("filters findings and shows an accurate empty state", async () => {
    stubApi();
    renderApp();
    fireEvent.click(screen.getByRole("button", { name: /findings/i }));
    await waitFor(() => expect(screen.getByText("CloudTrail tampering")).toBeInTheDocument());
    fireEvent.change(screen.getByPlaceholderText("Search findings or principals"), { target: { value: "no match" } });
    expect(screen.getByText("No findings match these filters.")).toBeInTheDocument();
    fireEvent.change(screen.getByPlaceholderText("Search findings or principals"), { target: { value: "" } });
    fireEvent.change(screen.getByLabelText("Filter by severity"), { target: { value: "HIGH" } });
    expect(screen.getByText("No findings match these filters.")).toBeInTheDocument();
  });

  it("explains a finding using its rule, score and linked evidence", async () => {
    stubApi();
    renderApp();
    await waitFor(() => expect(screen.getByRole("button", { name: "Explain CloudTrail tampering" })).toBeInTheDocument());
    const explainButton = screen.getByRole("button", { name: "Explain CloudTrail tampering" });
    explainButton.focus();
    fireEvent.click(explainButton);
    expect(screen.getByRole("button", { name: "Close explanation" })).toHaveFocus();
    await waitFor(() => expect(screen.getByText("Detect attempts to stop logging.")).toBeInTheDocument());
    expect(screen.getByText(/Synthetic test event/)).toBeInTheDocument();
    expect(screen.getByText("StopLogging")).toBeInTheDocument();
    expect(screen.getByText(/triage estimate, not the probability/)).toBeInTheDocument();
    expect(screen.getByText("Recorded AWS error: AccessDenied")).toBeInTheDocument();
    expect(screen.getByText("Not authorized to stop this trail")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close explanation" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(explainButton).toHaveFocus();
  });

  it("records investigation status without changing an AWS resource", async () => {
    stubApi();
    renderApp();
    fireEvent.click(await screen.findByRole("button", { name: "Explain CloudTrail tampering" }));
    fireEvent.click(await screen.findByRole("button", { name: "Start investigation / save note" }));
    await waitFor(() => expect(screen.getByText(/Investigation started and assigned/)).toBeInTheDocument());
    await waitFor(() => expect(screen.getByText("local-developer")).toBeInTheDocument());
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/findings/1"),
      expect.objectContaining({ method: "PATCH" }),
    );
  });

  it("requires a written reason to resolve a finding and shows the saved result", async () => {
    stubApi();
    renderApp();
    fireEvent.click(await screen.findByRole("button", { name: "Explain CloudTrail tampering" }));
    fireEvent.click(await screen.findByRole("button", { name: "Resolve finding" }));
    expect(screen.getByText(/Add a resolution note/)).toBeInTheDocument();
    expect(fetch).not.toHaveBeenCalledWith(expect.stringContaining("/findings/1"), expect.objectContaining({ method: "PATCH" }));
    fireEvent.change(screen.getByLabelText("Investigation or resolution note"), { target: { value: "Confirmed this was an approved exercise." } });
    fireEvent.click(screen.getByRole("button", { name: "Resolve finding" }));
    await waitFor(() => expect(screen.getByText("Confirmed this was an approved exercise.")).toBeInTheDocument());
    expect(screen.getByText(/Case closed with your resolution note/)).toBeInTheDocument();
  });

  it("explains a rule in plain language", async () => {
    stubApi();
    renderApp();
    fireEvent.click(screen.getByRole("button", { name: "rules" }));
    await waitFor(() => expect(screen.getByText("Logging was stopped.")).toBeInTheDocument());
    fireEvent.click(screen.getByText("How this rule works"));
    expect(screen.getByText("AWS action is StopLogging.")).toBeInTheDocument();
    expect(screen.getByText(/match creates a finding/)).toBeInTheDocument();
  });

  it("offers only a dry-run response for an S3 finding", async () => {
    stubApi(true, "s3-public-policy");
    renderApp();
    fireEvent.click(await screen.findByRole("button", { name: "Explain CloudTrail tampering" }));
    fireEvent.click(await screen.findByRole("button", { name: "Preview S3 response (dry run)" }));
    await waitFor(() => expect(screen.getByText("Dry-run response recorded. No AWS resource was changed.")).toBeInTheDocument());
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining("/responses"),
      expect.objectContaining({ method: "POST", body: expect.stringContaining('"confirmation":"DRY_RUN"') }),
    );
  });
});
