# Cloud Detective

Cloud Detective is an AWS control-plane security monitoring and automated incident-response platform. It ingests CloudTrail events, normalizes them, evaluates explainable detection rules, scores findings, and safely responds to high-confidence threats in a tagged sandbox.

## Current status

Day 1 foundation is complete on `feat/day1-foundation`:

- FastAPI backend and health endpoint
- Canonical CloudTrail event normalization
- PostgreSQL schema managed by Alembic
- React/TypeScript dashboard shell
- Docker Compose development stack
- Backend, frontend, and Terraform CI checks

## Prerequisites

- Docker Desktop with Docker Compose
- Python 3.12+
- Node.js 20+
- Terraform 1.10+ (only needed for infrastructure work)

## Local development

Copy `.env.example` to `.env`, then start the stack:

```bash
docker compose up --build
```

Services:

- Dashboard: http://localhost:5173
- API: http://localhost:8000
- API documentation: http://localhost:8000/docs
- PostgreSQL: localhost:5432

Run database migrations:

```bash
docker compose exec api alembic upgrade head
```

## Tests

Backend:

```bash
cd apps/backend
python -m pip install -e ".[dev]"
pytest
ruff check .
```

Frontend:

```bash
cd apps/web
npm ci
npm run lint
npm test
npm run build
```

Terraform:

```bash
cd infra
terraform fmt -check -recursive
terraform init -backend=false
terraform validate
```

## Safety boundary

Automated remediation will default to dry-run and will only target explicitly allowlisted or `Project=CloudDetective` sandbox resources. Never point the simulator or responder at production resources.
