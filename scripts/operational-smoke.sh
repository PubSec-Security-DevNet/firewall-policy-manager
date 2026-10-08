#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

compose=(docker compose --project-name firewall-manager-local)

"${compose[@]}" restart worker scheduler >/dev/null
"${compose[@]}" exec -T worker python -m firewall_manager.worker.health
curl --fail --silent --show-error http://localhost:8000/api/v1/health/ready >/dev/null
curl --fail --silent --show-error http://localhost:8000/api/v1/metrics >/dev/null
echo "Operational smoke passed: worker/scheduler restart, readiness, and metrics scrape."
