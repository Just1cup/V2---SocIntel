#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"
INFRA_DIR="$ROOT_DIR/infra"
STOP_DOCKER=true

usage() {
  cat <<'EOF'
Usage: ./scripts/stop_app.sh [--keep-docker|--app-only] [--volumes]

Stops SOCINTEL API, worker, and web processes.

Options:
  --keep-docker, --app-only  Stop only local app processes and keep Docker services running.
  --volumes                 Also remove Docker volumes. This deletes local database data.
  -h, --help                Show this help.
EOF
}

REMOVE_VOLUMES=false

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-docker|--app-only)
      STOP_DOCKER=false
      ;;
    --volumes)
      REMOVE_VOLUMES=true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
  shift
done

stop_pid() {
  local name="$1"
  local pid_file="$2"

  if [[ ! -f "$pid_file" ]]; then
    return
  fi

  local pid
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill "$pid" >/dev/null 2>&1 || true
    echo "Stopped $name (pid $pid)"
  fi
  rm -f "$pid_file"
}

stop_pid "api" "$RUN_DIR/api.pid"
stop_pid "worker" "$RUN_DIR/worker.pid"
stop_pid "web" "$RUN_DIR/web.pid"

if [[ "$STOP_DOCKER" == "true" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found; skipped Docker services."
    exit 0
  fi

  compose_args=(compose -f "$INFRA_DIR/docker-compose.yml")
  if [[ -f "$ROOT_DIR/.env" ]]; then
    compose_args=(compose --env-file "$ROOT_DIR/.env" -f "$INFRA_DIR/docker-compose.yml")
  fi

  if [[ "$REMOVE_VOLUMES" == "true" ]]; then
    docker "${compose_args[@]}" down -v
  else
    docker "${compose_args[@]}" down
  fi
else
  echo "Docker services left running."
fi
