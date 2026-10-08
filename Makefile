# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
.PHONY: up down logs migrate seed sync secret-check secret-rotate db-backup db-restore-test docker-clean reset smoke operational-smoke sbom test backend-check frontend-check architecture security-check license-check quality docs-build docs-preview docs-screenshots

COMPOSE := docker compose --project-name firewall-manager-local
DOCKER_CLEAN := ./scripts/docker-cleanup.sh

docs-build:
	cd docs-site && npm ci && npm run build

docs-preview:
	@test -x docs-site/node_modules/.bin/vitepress || (echo "Docs dependencies are missing; installing them first..." && cd docs-site && npm ci)
	cd docs-site && npm run preview

docs-screenshots:
	cd frontend && npm run docs:screenshots

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

secret-check:
	$(COMPOSE) run --rm backend python -m firewall_manager.secret_store_ops check

secret-rotate:
	@test -n "$(OLD_APP_SECRET_KEY)" -a -n "$(NEW_APP_SECRET_KEY)" -a -n "$(NEW_SECRET_STORE_KEY_VERSION)" || (echo "Set OLD_APP_SECRET_KEY, NEW_APP_SECRET_KEY, and NEW_SECRET_STORE_KEY_VERSION" && exit 1)
	$(COMPOSE) run --rm -e OLD_APP_SECRET_KEY -e NEW_APP_SECRET_KEY -e NEW_SECRET_STORE_KEY_VERSION backend python -m firewall_manager.secret_store_ops rotate

db-backup:
	./scripts/postgres-backup.sh $(FILE)

db-restore-test:
	@test -n "$(FILE)" || (echo "Set FILE=/path/to/backup.dump" && exit 1)
	./scripts/postgres-restore-test.sh "$(FILE)"

docker-clean:
	$(DOCKER_CLEAN)

reset:
	@test "$(CONFIRM)" = "local" || (echo "Refusing reset. Re-run with CONFIRM=local" && exit 1)
	$(COMPOSE) down --volumes --remove-orphans --rmi local
	$(DOCKER_CLEAN) --volumes

smoke:
	./scripts/smoke.sh

operational-smoke:
	./scripts/operational-smoke.sh

sbom:
	./scripts/generate-sbom.sh

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
	cd backend && .venv/bin/pip-audit -r requirements.lock
	cd backend && .venv/bin/pip-audit -r requirements-dev.lock
	cd frontend && npm audit --audit-level=high

license-check:
	./scripts/check-license-headers.sh

quality: license-check backend-check frontend-check architecture security-check
