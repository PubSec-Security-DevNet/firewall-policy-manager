#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose --project-name firewall-manager-local)
backup=${1:?"usage: $0 BACKUP_FILE CONFIRM=restore"}

if [[ "${CONFIRM:-}" != restore ]]; then
  echo "Refusing destructive restore. Re-run with CONFIRM=restore." >&2
  exit 1
fi
if [[ ! -f "$backup" || ! -s "$backup" ]]; then
  echo "Backup file does not exist or is empty: $backup" >&2
  exit 1
fi
echo "Stopping application services before restoring PostgreSQL..."
"${compose[@]}" stop backend worker scheduler frontend >/dev/null
"${compose[@]}" exec -T db sh -c 'pg_restore --username="$POSTGRES_USER" --clean --if-exists --no-owner --dbname="$POSTGRES_DB"' <"$backup"
echo "PostgreSQL restore completed. Run: make migrate && make up"
