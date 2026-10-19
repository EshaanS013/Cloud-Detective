# Cloud Detective

Cloud Detective is an AWS control-plane detection and response platform. It ingests CloudTrail events, normalizes and deduplicates them, evaluates explainable rules, scores findings, supports investigations through an authenticated dashboard, and runs tightly scoped response playbooks.

## Implemented MVP

- Single-Region AWS architecture for `ap-southeast-2`
- CloudTrail → EventBridge → collector Lambda → encrypted SQS pipeline
- Stateful ECS detector worker with duplicate-safe PostgreSQL persistence
- 21 data-driven signature, threshold, contextual, and sequence rules
- Explainable risk scoring and behavioural baselines
- FastAPI endpoints for summary, findings, events, rules, ingestion, and response approval
- Cognito authorization-code login with PKCE, mandatory TOTP MFA, and Analyst/Responder groups
- React operations dashboard with searchable findings, events, rule catalogue, and an evidence-backed explanation drawer
- Dry-run-by-default responder for EC2 stop, S3 public-access block, and access-key disable
- Two-layer remediation guardrail: IAM resource-tag conditions plus runtime verification of `CloudDetectiveSandbox=true`
- Encrypted S3, SQS, SNS, ECR, RDS, CloudTrail, KMS, CloudFront, ECS, and dead-letter queues managed by Terraform

The source specification says “18 rules,” but its catalogue enumerates 21. This implementation includes all 21 catalogue entries.

An Analyst can open a finding and inspect its detection rule, stored risk factors, principal and resource context, evidence window, and linked CloudTrail events. The explanation endpoint is `GET /api/v1/findings/{finding_id}/explanation`; it returns the first 50 linked events and an `evidence_truncated` flag when more exist. Synthetic test events are labelled in the dashboard.

## Local development

Prerequisites: Docker Desktop, Python 3.12+, Node.js 20+, and Terraform 1.10+.

```bash
copy .env.example .env
docker compose up --build
```

- Dashboard: <http://localhost:5173>
- API: <http://localhost:8000>
- API documentation: <http://localhost:8000/docs>
- PostgreSQL: `localhost:5432`

The API applies Alembic migrations on startup. Local Cognito enforcement is disabled; production ECS configuration enables it.

To run the real SQS worker locally after infrastructure exists, populate `QUEUE_URL` and start the optional profile:

```bash
docker compose --profile aws up worker
```

## Quality checks

```bash
cd apps/backend
python -m pip install -e ".[dev]"
ruff check . ../../serverless
pytest
```

```bash
cd apps/web
npm ci
npm run lint
npm test
npm run build
npm audit
```

```bash
cd infra
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
terraform plan
```

## AWS deployment sequence

All billable runtime switches default to `false`. Review the Terraform plan before any apply.

1. Copy `infra/terraform.tfvars.example` to `infra/terraform.tfvars`.
2. Apply the base plan to create networking, security, event pipeline, Cognito, ECR, and storage.
3. Upload the repository source archive to the build source key, set `deploy_builder=true` with an immutable image tag, and apply. The no-ingress EC2 builder publishes both images, records an encrypted status/log in S3, and shuts down; set `deploy_builder=false` immediately afterward to remove it.
4. Set `deploy_database=true`, `deploy_runtime=true`, `deploy_frontend=true`, and the image URIs, then apply. CloudFront provides HTTPS for both the dashboard and `/api/*`; the load balancer accepts only verified CloudFront origin traffic.
5. Build the dashboard with the Terraform Cognito outputs and `VITE_API_BASE_URL=/api/v1`, then upload `apps/web/dist` to the frontend bucket.
6. Update the Cognito callback and logout URLs to the deployed dashboard URL and apply once more.
7. Create the first Cognito team member and add them to `Responder`; all other investigators can use `Analyst`.
8. Keep `response_mode="dry_run"` until sandbox simulations pass. Enforcement also requires the target resource tag `CloudDetectiveSandbox=true`.

The new AWS experience does not allow the cross-Region EventBridge forwarder described in the original specification. This build intentionally monitors the selected Region only and uses a single-Region CloudTrail.

## Safety boundary

Never tag production resources with `CloudDetectiveSandbox=true`. Enforced response is impossible unless both the deployment response mode and the individual request are set to enforcement, the caller belongs to the Responder group, and the target passes sandbox tag checks.
