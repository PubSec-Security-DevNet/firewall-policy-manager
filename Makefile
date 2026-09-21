.PHONY: up down logs migrate seed sync docker-clean reset smoke test backend-check frontend-check architecture security-check quality

COMPOSE := docker compose --project-name firewall-manager-local
DOCKER_CLEAN := ./scripts/docker-cleanup.sh

up:
	$(DOCKER_CLEAN)
	$(COMPOSE) up --build --remove-orphans -d
	$(DOCKER_CLEAN)

down:
	$(COMPOSE) down --remove-orphans
	$(DOCKER_CLEAN)

logs:
	$(COMPOSE) logs -f --tail=200

migrate:
	$(COMPOSE) run --rm migrate

seed:
	$(COMPOSE) run --rm seed

sync:
	$(COMPOSE) run --rm synchronize

docker-clean:
	$(DOCKER_CLEAN)

reset:
	@test "$(CONFIRM)" = "local" || (echo "Refusing reset. Re-run with CONFIRM=local" && exit 1)
	$(COMPOSE) down --volumes --remove-orphans --rmi local
	$(DOCKER_CLEAN) --volumes

smoke:
	./scripts/smoke.sh

test:
	$(MAKE) backend-check
	$(MAKE) frontend-check

backend-check:
	cd backend && .venv/bin/ruff format --check .
	cd backend && .venv/bin/ruff check .
	cd backend && .venv/bin/pyright
	cd backend && .venv/bin/pytest

frontend-check:
	cd frontend && npm run format:check
	cd frontend && npm run lint
	cd frontend && npm run typecheck
	cd frontend && npm test
	cd frontend && npm run build

architecture:
	cd backend && PYTHONPATH=src .venv/bin/lint-imports --config importlinter.ini

security-check:
	cd backend && .venv/bin/pip-audit
	cd frontend && npm audit --audit-level=high

quality: backend-check frontend-check architecture security-check
