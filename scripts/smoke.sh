#!/bin/sh
set -eu

project="firewall-manager-local"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
base_url="${SMOKE_BASE_URL:-http://localhost:8000}"
frontend_url="${SMOKE_FRONTEND_URL:-http://localhost:5173}"
attempt=0

cleanup_on_exit() {
  status=$?
  trap - 0
  if ! "${script_dir}/docker-cleanup.sh"; then
    status=1
  fi
  exit "$status"
}

trap cleanup_on_exit 0

"${script_dir}/docker-cleanup.sh"
docker compose --project-name "$project" up --build --remove-orphans -d

until curl --fail --silent "${base_url}/api/v1/health/ready" >/dev/null \
  && curl --fail --silent "${frontend_url}/" >/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 60 ]; then
    docker compose --project-name "$project" ps
    docker compose --project-name "$project" logs --tail=200
    exit 1
  fi
  sleep 2
done

overview="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/overview")"
session="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/session")"
managers="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/firewall-managers")"
policies="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/policies")"
rules="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/rules")"
objects="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/objects")"
provider_status="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/providers/status")"
isolated_managers="$(curl --fail --silent -H 'X-Dev-User: other-viewer@example.test' "${base_url}/api/v1/firewall-managers")"
finance_policies="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/delegated/policies?active_group_id=20000000-0000-0000-0000-000000000001")"
delegated_policy_id="$(printf '%s' "$finance_policies" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')"
test -n "$delegated_policy_id"
finance_context="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/delegated/context?active_group_id=20000000-0000-0000-0000-000000000001&policy_id=${delegated_policy_id}")"
engineering_context="$(curl --fail --silent -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/delegated/context?active_group_id=20000000-0000-0000-0000-000000000002&policy_id=${delegated_policy_id}")"
delegated_denial_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/delegated/context?active_group_id=20000000-0000-0000-0000-000000000004&policy_id=${delegated_policy_id}")"
admin_denial_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'X-Dev-User: viewer@example.test' "${base_url}/api/v1/admin/authorization")"
admin_allow_status="$(curl --silent --output /dev/null --write-out '%{http_code}' -H 'X-Dev-User: admin@example.test' "${base_url}/api/v1/admin/authorization")"

printf '%s' "$overview" | grep -q 'Example Organization'
printf '%s' "$overview" | grep -q 'Local FMC Mock'
printf '%s' "$overview" | grep -q 'Local SCC Mock'
printf '%s' "$session" | grep -q 'viewer@example.test'
printf '%s' "$managers" | grep -q 'Local FMC Mock'
printf '%s' "$managers" | grep -q 'Local SCC Mock'
printf '%s' "$policies" | grep -q 'FMC Edge Policy'
printf '%s' "$policies" | grep -q 'SCC Edge Policy'
printf '%s' "$rules" | grep -q 'Allow application web'
printf '%s' "$objects" | grep -q 'shared-dns'
printf '%s' "$provider_status" | grep -q 'COMPLETED'
test "$(printf '%s' "$provider_status" | grep -o '"evidence_profile":"mock"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"access_rule_create":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"rule_ordering":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"rule_category_mutation":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"network_object_mutation":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"port_service_object_mutation":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"url_object_mutation":"SUPPORTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"application_object_mutation":"NOT_STARTED"' | wc -l | tr -d ' ')" = "2"
test "$(printf '%s' "$provider_status" | grep -o '"application_object_create":"PARTIAL"' | wc -l | tr -d ' ')" = "2"
printf '%s' "$isolated_managers" | grep -q 'Isolated FMC Mock'
if printf '%s' "$isolated_managers" | grep -q 'Local SCC Mock'; then
  echo "Cross-organization manager data leaked into the isolated scope." >&2
  exit 1
fi
printf '%s' "$finance_context" | grep -q 'FINANCE__APP-SUBNET'
printf '%s' "$finance_context" | grep -q '"owner_type":"GROUP"'
printf '%s' "$finance_context" | grep -q '"owner_group_id":"20000000-0000-0000-0000-000000000001"'
printf '%s' "$finance_context" | grep -q 'Inside-Finance'
printf '%s' "$finance_context" | grep -q '10.20.0.0/16'
if printf '%s' "$finance_context" | grep -q 'ENGINEERING__BUILD-SERVERS'; then
  echo "Engineering entitlement leaked into the Finance context." >&2
  exit 1
fi
printf '%s' "$engineering_context" | grep -q 'ENGINEERING__BUILD-SERVERS'
printf '%s' "$engineering_context" | grep -q 'Inside-Engineering'
printf '%s' "$engineering_context" | grep -q '172.16.0.0/12'
if printf '%s' "$engineering_context" | grep -q 'FINANCE__APP-SUBNET'; then
  echo "Finance entitlement leaked into the Engineering context." >&2
  exit 1
fi
test "$delegated_denial_status" = "403"
test "$admin_denial_status" = "403"
test "$admin_allow_status" = "200"
docker compose --project-name "$project" exec -T worker python -m firewall_manager.worker.health
docker compose --project-name "$project" ps --format json | grep -q 'healthy'

echo "Local stack smoke test passed."
