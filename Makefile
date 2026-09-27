.PHONY: up down migrate backend-test frontend-test lint terraform-check

up:
	docker compose up --build

down:
	docker compose down

migrate:
	docker compose exec api alembic upgrade head

backend-test:
	cd apps/backend && pytest

frontend-test:
	cd apps/web && npm test

lint:
	cd apps/backend && ruff check .
	cd apps/web && npm run lint

terraform-check:
	cd infra && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
