#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose --project-name firewall-manager-local)
target=${1:-"backups/firewall-manager-$(date -u +%Y%m%dT%H%M%SZ).dump"}

if [[ "$target" == "/" || "$target" == *".."* ]]; then
  echo "Refusing an unsafe backup path: $target" >&2
  exit 1
fi
mkdir -p "$(dirname "$target")"
if [[ -e "$target" ]]; then
  echo "Refusing to overwrite existing backup: $target" >&2
  exit 1
fi

"${compose[@]}" up -d db >/dev/null
"${compose[@]}" exec -T db sh -c 'pg_dump --username="$POSTGRES_USER" --format=custom --no-owner "$POSTGRES_DB"' >"$target"
test -s "$target"
echo "PostgreSQL backup created: $target"
