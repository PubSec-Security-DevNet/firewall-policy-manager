#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

if ! command -v syft >/dev/null 2>&1; then
  echo "Syft is required. Install it from https://github.com/anchore/syft, then rerun make sbom." >&2
  exit 1
fi

mkdir -p artifacts
syft dir:. \
  --source-name firewall-manager \
  --source-version "${SBOM_VERSION:-local}" \
  -o cyclonedx-json=artifacts/firewall-manager-sbom.json
echo "SBOM written to artifacts/firewall-manager-sbom.json"
