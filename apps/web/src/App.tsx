import { useQuery } from "@tanstack/react-query";

type Health = {
  status: string;
  service: string;
  version: string;
  environment: string;
  response_mode: "dry_run" | "enforce";
};

const apiBase = import.meta.env.VITE_API_BASE_URL ?? "http://localhost:8000/api/v1";

async function fetchHealth(): Promise<Health> {
  const response = await fetch(`${apiBase}/health`);
  if (!response.ok) {
    throw new Error("API health check failed");
  }
  return response.json() as Promise<Health>;
}

export function App() {
  const health = useQuery({
    queryKey: ["health"],
    queryFn: fetchHealth,
  });

  return (
    <main className="shell">
      <header className="masthead">
        <div>
          <p className="eyebrow">AWS CONTROL-PLANE SECURITY</p>
          <h1>Cloud Detective</h1>
          <p className="lede">Explainable detection. Scoped response. Complete audit trail.</p>
        </div>
        <span className="phase">Foundation · Day 1</span>
      </header>

      <section className="grid" aria-label="System status">
        <article className="card card--wide">
          <div className="card__heading">
            <div>
              <p className="label">API STATUS</p>
              <h2>{health.isPending ? "Checking…" : health.isError ? "Unavailable" : "Online"}</h2>
            </div>
            <span
              className={`status ${health.data?.status === "ok" ? "status--ok" : "status--pending"}`}
              aria-label={health.data?.status === "ok" ? "API online" : "API pending"}
            />
          </div>
          {health.data ? (
            <dl className="facts">
              <div><dt>Service</dt><dd>{health.data.service}</dd></div>
              <div><dt>Version</dt><dd>{health.data.version}</dd></div>
              <div><dt>Environment</dt><dd>{health.data.environment}</dd></div>
              <div><dt>Response</dt><dd>{health.data.response_mode.replace("_", " ")}</dd></div>
            </dl>
          ) : null}
          {health.isError ? <p className="error">Start the API on port 8000 to connect.</p> : null}
        </article>

        <article className="card">
          <p className="label">PIPELINE</p>
          <h2>Not connected</h2>
          <p>CloudTrail ingestion is scheduled for Day 4.</p>
        </article>

        <article className="card">
          <p className="label">RESPONSE MODE</p>
          <h2>Dry run</h2>
          <p>Enforcement stays disabled until sandbox safety tests pass.</p>
        </article>
      </section>
    </main>
  );
}
