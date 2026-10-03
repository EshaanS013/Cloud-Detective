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
});
