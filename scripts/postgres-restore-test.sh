#!/usr/bin/env bash
set -euo pipefail

compose=(docker compose --project-name firewall-manager-local)
backup=${1:?"usage: $0 BACKUP_FILE [TEST_DATABASE]"}
database=${2:-firewall_manager_restore_test}

if [[ ! -f "$backup" || ! -s "$backup" ]]; then
  echo "Backup file does not exist or is empty: $backup" >&2
  exit 1
fi
if [[ "$database" != firewall_manager_restore_test ]]; then
  echo "Restore validation only permits the dedicated database firewall_manager_restore_test" >&2
  exit 1
fi

"${compose[@]}" up -d db >/dev/null
"${compose[@]}" exec -T -e RESTORE_DATABASE="$database" db sh -c 'dropdb --username="$POSTGRES_USER" --if-exists "$RESTORE_DATABASE"' 2>/dev/null || true
"${compose[@]}" exec -T -e RESTORE_DATABASE="$database" db sh -c 'createdb --username="$POSTGRES_USER" "$RESTORE_DATABASE"'
"${compose[@]}" exec -T -e RESTORE_DATABASE="$database" db sh -c 'pg_restore --username="$POSTGRES_USER" --no-owner --dbname="$RESTORE_DATABASE"' <"$backup"
version=$("${compose[@]}" exec -T -e RESTORE_DATABASE="$database" db sh -c 'psql --username="$POSTGRES_USER" -Atqc "select version_num from alembic_version" "$RESTORE_DATABASE"' | tr -d '\r')
users=$("${compose[@]}" exec -T -e RESTORE_DATABASE="$database" db sh -c 'psql --username="$POSTGRES_USER" -Atqc "select count(*) from users" "$RESTORE_DATABASE"' | tr -d '\r')
test -n "$version"
echo "Restore validation succeeded: database=$database alembic_version=$version users=$users"
