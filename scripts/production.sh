#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

repository_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
runtime_dir=${FM_RUNTIME_DIR:-/opt/firewall-manager/runtime}
backup_dir=${FM_BACKUP_DIR:-/opt/firewall-manager/backups}
environment_file="$runtime_dir/.env.production"
compose_file="$repository_dir/compose.production.yaml"
alpine_image="alpine:3.22@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"

usage() {
  cat <<'EOF'
Usage: scripts/production.sh COMMAND [ARGUMENTS]

Commands:
  setup                 Configure a new host, build, migrate, and start everything
  start                 Start the production stack and wait for health
  stop                  Stop containers without deleting them or their data
  restart               Stop and start the production stack
  down                  Remove containers/networks but preserve data and secret files
  status                Show service state and health
  logs [SERVICE ...]    Follow recent logs, optionally for selected services
  migrate               Apply database migrations and print the current revision
  backup                Create a timestamped containerized PostgreSQL backup
  cert-refresh          Replace the generated self-signed certificate and reload HTTPS
  cert-reload           Reload HTTPS after installing a renewed trusted PEM pair
  monitoring-start      Start Prometheus and Grafana
  monitoring-stop       Stop Prometheus and Grafana
  validate              Validate Compose and HTTPS/API readiness
  config                Edit the non-secret production environment file
  help                   Show this help

Optional environment variables for unattended setup:
  FM_PUBLIC_HOST         Required when setup has no interactive terminal
  FM_ADMIN_EMAIL         Operator contact email (may be empty)
  FM_RUNTIME_DIR         Runtime directory (default: /opt/firewall-manager/runtime)
  FM_BACKUP_DIR          Backup directory (default: /opt/firewall-manager/backups)

This helper intentionally has no command that deletes production volumes or secret files.
EOF
}

fail() {
  echo "Error: $*" >&2
  exit 1
}

as_root() {
  if [[ $(id -u) -eq 0 ]]; then
    "$@"
  else
    command -v sudo >/dev/null 2>&1 || fail "sudo is required to prepare protected files"
    sudo "$@"
  fi
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

check_prerequisites() {
  require_command docker
  require_command awk
  require_command curl
  require_command date
  require_command install
  require_command mktemp
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"
  docker info >/dev/null 2>&1 || fail "cannot access the Docker daemon"
  [[ -f "$compose_file" ]] || fail "run this helper from a complete Firewall Manager checkout"
}

require_initialized() {
  [[ -r "$environment_file" ]] || fail "run '$0 setup' first; missing $environment_file"
}

compose() {
  docker compose --env-file "$environment_file" -f "$compose_file" "$@"
}

operator_identity() {
  if [[ -n ${SUDO_USER:-} && ${SUDO_USER:-} != root ]]; then
    operator_user=$SUDO_USER
  else
    operator_user=$(id -un)
  fi
  operator_group=$(id -gn "$operator_user")
}

validate_path() {
  local value=$1 label=$2
  [[ "$value" == /* ]] || fail "$label must be an absolute path"
  [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] || fail "$label contains a newline"
}

prepare_directories() {
  validate_path "$runtime_dir" FM_RUNTIME_DIR
  validate_path "$backup_dir" FM_BACKUP_DIR
  operator_identity
  as_root install -d -m 0750 -o "$operator_user" -g "$operator_group" "$runtime_dir"
  as_root install -d -m 0750 -o root -g root "$runtime_dir/tls"
  as_root install -d -m 0750 -o root -g 10001 "$runtime_dir/secrets"
  as_root install -d -m 0770 -o root -g 10001 "$backup_dir"
}

prompt_configuration() (
  local public_host=${FM_PUBLIC_HOST:-}
  local administrator_email=${FM_ADMIN_EMAIL:-}
  if [[ -z "$public_host" && -t 0 ]]; then
    read -r -p "Public DNS hostname (for example firewall.example.com): " public_host
  fi
  [[ -n "$public_host" ]] || fail "set FM_PUBLIC_HOST or run setup interactively"
  [[ "$public_host" =~ ^([A-Za-z0-9_-]+\.)*[A-Za-z0-9_-]+$ ]] \
    || fail "FM_PUBLIC_HOST must be a hostname or IPv4 address without a scheme, port, or path"
  if [[ -z "$administrator_email" && -t 0 ]]; then
    read -r -p "Operator contact email (optional): " administrator_email
  fi
  [[ "$administrator_email" != *$'\n'* && "$administrator_email" != *$'\r'* ]] \
    || fail "FM_ADMIN_EMAIL contains a newline"

  local temporary_environment
  temporary_environment=$(mktemp)
  trap 'rm -f "${temporary_environment:-}"' EXIT
  awk \
    -v public_host="$public_host" \
    -v public_url="https://$public_host" \
    -v administrator_email="$administrator_email" \
    -v runtime_dir="$runtime_dir" \
    -v backup_dir="$backup_dir" '
      /^APP_PUBLIC_HOST=/ {print "APP_PUBLIC_HOST=" public_host; next}
      /^APP_PUBLIC_URL=/ {print "APP_PUBLIC_URL=" public_url; next}
      /^ADMINISTRATOR_EMAIL=/ {print "ADMINISTRATOR_EMAIL=" administrator_email; next}
      /^PRODUCTION_RUNTIME_DIR=/ {print "PRODUCTION_RUNTIME_DIR=" runtime_dir; next}
      /^PRODUCTION_BACKUP_DIR=/ {print "PRODUCTION_BACKUP_DIR=" backup_dir; next}
      {print}
    ' "$repository_dir/.env.production.example" >"$temporary_environment"
  as_root install -m 0600 -o "$operator_user" -g "$operator_group" \
    "$temporary_environment" "$environment_file"
)

generate_secret() (
  local name=$1 byte_count=$2 destination="$runtime_dir/secrets/$1"
  if as_root test -s "$destination"; then
    echo "Keeping existing secret: $destination"
    return
  fi
  local temporary_secret
  temporary_secret=$(mktemp)
  trap 'rm -f "${temporary_secret:-}"' EXIT
  umask 077
  docker run --rm "$alpine_image" sh -c "head -c $byte_count /dev/urandom | base64" \
    >"$temporary_secret"
  as_root install -m 0640 -o root -g 10001 "$temporary_secret" "$destination"
  echo "Generated protected secret: $destination"
)

initialize_files() {
  prepare_directories
  if [[ -e "$environment_file" ]]; then
    echo "Keeping existing configuration: $environment_file"
  else
    prompt_configuration
    echo "Created configuration: $environment_file"
  fi
  generate_secret postgres_password 48
  generate_secret redis_password 48
  generate_secret grafana_admin_password 48
  generate_secret app_secret_key 32
}

start_stack() {
  compose up -d --wait --wait-timeout 180
}

validate_stack() {
  compose config --quiet
  compose ps
  local public_url
  public_url=$(awk -F= '$1 == "APP_PUBLIC_URL" {sub(/^[^=]*=/, ""); print; exit}' "$environment_file")
  [[ -n "$public_url" ]] || fail "APP_PUBLIC_URL is missing from $environment_file"
  if ! curl --fail --silent --show-error "$public_url/api/v1/health/ready" >/dev/null 2>&1; then
    curl --fail --silent --show-error --cacert "$runtime_dir/tls/fullchain.pem" \
      "$public_url/api/v1/health/ready" >/dev/null
  fi
  echo "Production validation passed: $public_url"
}

command_name=${1:-help}
shift || true

case "$command_name" in
  setup)
    [[ $# -eq 0 ]] || fail "setup accepts no arguments"
    check_prerequisites
    initialize_files
    compose config --quiet
    compose build backend frontend
    compose up -d --wait --wait-timeout 180 db redis
    compose --profile ops run --rm migrate
    start_stack
    validate_stack
    echo "Open the configured HTTPS URL to complete the one-time OIDC setup."
    ;;
  start)
    [[ $# -eq 0 ]] || fail "start accepts no arguments"
    check_prerequisites
    require_initialized
    start_stack
    ;;
  stop)
    [[ $# -eq 0 ]] || fail "stop accepts no arguments"
    check_prerequisites
    require_initialized
    compose stop
    ;;
  restart)
    [[ $# -eq 0 ]] || fail "restart accepts no arguments"
    check_prerequisites
    require_initialized
    compose stop
    start_stack
    ;;
  down)
    [[ $# -eq 0 ]] || fail "down accepts no arguments"
    check_prerequisites
    require_initialized
    compose down --remove-orphans
    ;;
  status)
    [[ $# -eq 0 ]] || fail "status accepts no arguments"
    check_prerequisites
    require_initialized
    compose ps -a
    ;;
  logs)
    check_prerequisites
    require_initialized
    compose logs --tail=200 --follow "$@"
    ;;
  migrate)
    [[ $# -eq 0 ]] || fail "migrate accepts no arguments"
    check_prerequisites
    require_initialized
    compose stop backend worker scheduler
    compose --profile ops run --rm migrate
    compose --profile ops run --rm migrate alembic current
    echo "Migration complete. API, workers, and scheduler remain stopped; run start after review."
    ;;
  backup)
    [[ $# -eq 0 ]] || fail "backup accepts no arguments"
    check_prerequisites
    require_initialized
    backup_name="firewall-manager-$(date -u +%Y%m%dT%H%M%SZ).dump"
    compose --profile ops run --rm backup backup "/backups/$backup_name"
    compose --profile ops run --rm backup verify "/backups/$backup_name"
    echo "Verified backup: $backup_dir/$backup_name"
    ;;
  cert-refresh)
    [[ $# -eq 0 ]] || fail "cert-refresh accepts no arguments"
    check_prerequisites
    require_initialized
    compose run --rm tls-init python -m firewall_manager.tls_init --renew-self-signed
    compose restart edge
    compose up -d --wait --wait-timeout 180 edge
    validate_stack
    echo "The self-signed certificate was refreshed. Clients must trust the new certificate."
    ;;
  cert-reload)
    [[ $# -eq 0 ]] || fail "cert-reload accepts no arguments"
    check_prerequisites
    require_initialized
    compose exec edge caddy validate --config /etc/caddy/Caddyfile
    # The Caddy admin API is disabled; reload through container restart.
    compose restart edge
    compose up -d --wait --wait-timeout 180 edge
    validate_stack
    echo "The installed certificate pair was reloaded without rebuilding images."
    ;;
  monitoring-start)
    [[ $# -eq 0 ]] || fail "monitoring-start accepts no arguments"
    check_prerequisites
    require_initialized
    compose --profile monitoring up -d --wait --wait-timeout 180 prometheus grafana
    ;;
  monitoring-stop)
    [[ $# -eq 0 ]] || fail "monitoring-stop accepts no arguments"
    check_prerequisites
    require_initialized
    compose --profile monitoring stop prometheus grafana
    ;;
  validate)
    [[ $# -eq 0 ]] || fail "validate accepts no arguments"
    check_prerequisites
    require_initialized
    validate_stack
    ;;
  config)
    [[ $# -eq 0 ]] || fail "config accepts no arguments"
    require_initialized
    "${EDITOR:-vi}" "$environment_file"
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage >&2
    fail "unknown command: $command_name"
    ;;
esac
