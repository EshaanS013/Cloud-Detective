import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";

function renderApp() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <App />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe("App", () => {
  it("shows API health and safe response mode", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({
          status: "ok",
          service: "cloud-detective-api",
          version: "0.1.0",
          environment: "local",
          response_mode: "dry_run",
        }),
      }),
    );

    renderApp();

    expect(screen.getByRole("heading", { name: "Cloud Detective" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Online")).toBeInTheDocument());
    expect(screen.getByText("Dry run")).toBeInTheDocument();
  });

  it("shows an actionable offline state", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: false }));
    renderApp();
    await waitFor(() => expect(screen.getByText("Unavailable")).toBeInTheDocument());
    expect(screen.getByText(/Start the API/)).toBeInTheDocument();
  });
});
