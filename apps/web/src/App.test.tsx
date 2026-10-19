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

function stubApi(healthy = true) {
  vi.stubGlobal("fetch", vi.fn((input: string | URL | Request) => {
    const url = String(input);
    if (url.includes("/health")) return response({ status: "ok", service: "cloud-detective-api", version: "0.1.0", environment: "local", response_mode: "dry_run" }, healthy);
    if (url.includes("/summary")) return response({ total_events: 42, open_findings: 2, enabled_rules: 21, severity_counts: { CRITICAL: 1 }, response_mode: "dry_run" }, healthy);
    if (url.includes("/explanation")) return response({
      finding: { title: "CloudTrail tampering", severity: "CRITICAL", risk_score: "92", status: "OPEN", description: "Logging changed", principal_arn: "arn:aws:iam::123:user/test", source_ip: "192.0.2.10", affected_resources: [] },
      rule_name: "CloudTrail tampering", rule_type: "signature", rule_description: "Detect attempts to stop logging.", category: "logging", mitre_technique: "T1562.008",
      score_factors: { base: 70, principal: 1.3, resource: 1, time: 1, origin: 1, mfa: 1 }, window_start: "2026-09-27T10:00:00Z", window_end: "2026-09-27T10:00:00Z", event_count: 1,
      evidence: [{ event_id: "event-1", event_time: "2026-09-27T10:00:00Z", event_name: "StopLogging", event_source: "cloudtrail.amazonaws.com", aws_region: "ap-southeast-2", source_address: "192.0.2.10", mfa_authenticated: false, error_code: null, simulated: true }], evidence_truncated: false,
    }, healthy);
    if (url.includes("/findings")) return response([{ id: "1", rule_id: "cloudtrail-tampering", severity: "CRITICAL", risk_score: "92", title: "CloudTrail tampering", description: "Logging changed", principal_arn: "arn:aws:iam::123:user/test", status: "OPEN", created_at: "2026-09-27T10:00:00Z" }], healthy);
    if (url.includes("/events")) return response([], healthy);
    if (url.includes("/rules")) return response([], healthy);
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
    expect(screen.getByText(/risk estimate, not a probability/)).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Close explanation" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(explainButton).toHaveFocus();
  });
});
