#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

repository_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repository_root"

files=(
  Makefile
  compose.yaml
  compose.production.yaml
  backend/Dockerfile
  backend/alembic/env.py
  frontend/Dockerfile
  frontend/Dockerfile.production
  frontend/nginx.production.conf
  ops/caddy/Caddyfile
  ops/postgres/container-backup
)

while IFS= read -r file; do
  files+=("$file")
done < <(find backend/src backend/tests -type f -name '*.py' | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find frontend/src -type f \( -name '*.ts' -o -name '*.tsx' -o -name '*.css' \) \
  ! -name 'schema.d.ts' ! -name 'vite-env.d.ts' | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find frontend/e2e -type f \( -name '*.mjs' -o -name '*.ts' \) | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find frontend -maxdepth 1 -type f \
  \( -name '*.config.js' -o -name '*.config.ts' \) | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find docs-site/.vitepress \
  \( -path '*/.temp' -o -path '*/temp' -o -path '*/cache' -o -path '*/dist' \) -prune \
  -o -type f \
  \( -name '*.mts' -o -name '*.ts' -o -name '*.vue' -o -name '*.css' \) -print | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find scripts -maxdepth 1 -type f -name '*.sh' | sort)

while IFS= read -r file; do
  files+=("$file")
done < <(find .github/workflows config ops -type f \( -name '*.yml' -o -name '*.yaml' \) | sort)

missing=0
for file in "${files[@]}"; do
  if [[ ! -f "$file" ]]; then
    printf 'Expected first-party source file is missing: %s\n' "$file" >&2
    missing=1
  elif ! head -n 12 "$file" | grep -Fq 'Copyright 2026 Cisco Systems, Inc.' || \
       ! head -n 12 "$file" | grep -Fq 'SPDX-License-Identifier: Apache-2.0'; then
    printf 'Missing Cisco copyright or Apache-2.0 SPDX header: %s\n' "$file" >&2
    missing=1
  fi
done

if ((missing)); then
  exit 1
fi

printf 'Verified Apache-2.0 SPDX headers in %d first-party files.\n' "${#files[@]}"
