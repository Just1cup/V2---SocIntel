#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_DIR="$ROOT_DIR/apps/api"
WEB_DIR="$ROOT_DIR/apps/web"
INFRA_DIR="$ROOT_DIR/infra"
RUN_DIR="$ROOT_DIR/.run"
LOG_DIR="$ROOT_DIR/logs"
WEB_HOST="${SOCINTEL_WEB_HOST:-127.0.0.1}"

mkdir -p "$RUN_DIR" "$LOG_DIR"

require_file() {
  local path="$1"
  local message="$2"
  if [[ ! -e "$path" ]]; then
    echo "$message"
    exit 1
  fi
}

require_command() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Required command not found: $cmd"
    exit 1
  fi
}

is_running() {
  local pid_file="$1"
  if [[ ! -f "$pid_file" ]]; then
    return 1
  fi
  local pid
  pid="$(cat "$pid_file")"
  if kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  rm -f "$pid_file"
  return 1
}

start_process() {
  local name="$1"
  local pid_file="$2"
  local log_file="$3"
  shift 3

  if is_running "$pid_file"; then
    echo "$name is already running (pid $(cat "$pid_file"))."
    return
  fi

  "$@" >"$log_file" 2>&1 &
  local pid=$!
  echo "$pid" >"$pid_file"
  sleep 0.2
  if ! kill -0 "$pid" >/dev/null 2>&1; then
    echo "$name failed to start. Last log lines:"
    tail -n 40 "$log_file" || true
    rm -f "$pid_file"
    exit 1
  fi
  echo "Started $name (pid $pid)"
}

cleanup() {
  "$ROOT_DIR/scripts/stop_app.sh" --keep-docker >/dev/null 2>&1 || true
}

trap cleanup INT TERM

require_command docker
require_command npm
require_command bash
require_file "$API_DIR/.venv/bin/python" "Missing API virtualenv. Create it in apps/api before running this script."
require_file "$WEB_DIR/node_modules" "Missing frontend dependencies. Run npm install in apps/web before running this script."

if [[ -f "$ROOT_DIR/.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  source "$ROOT_DIR/.env"
  set +a
fi

if [[ -z "${JWT_SECRET:-}" || "${JWT_SECRET}" == "change-me" || ${#JWT_SECRET} -lt 32 ]]; then
  echo "Set JWT_SECRET to a strong random value of at least 32 characters before starting."
  exit 1
fi

if [[ -z "${POSTGRES_PASSWORD:-}" || -z "${REDIS_PASSWORD:-}" ]]; then
  echo "Set POSTGRES_PASSWORD and REDIS_PASSWORD before starting."
  exit 1
fi

echo "Starting infrastructure..."
docker compose --env-file "$ROOT_DIR/.env" -f "$INFRA_DIR/docker-compose.yml" up -d

echo "Preparing database..."
(
  cd "$API_DIR"
  source .venv/bin/activate
  alembic upgrade head
  PYTHONPATH=. python scripts/seed.py
)

echo "Starting API, worker, and web..."
start_process \
  "api" \
  "$RUN_DIR/api.pid" \
  "$LOG_DIR/api.log" \
  bash -lc "cd '$API_DIR' && source .venv/bin/activate && exec uvicorn app.main:app --reload"

start_process \
  "worker" \
  "$RUN_DIR/worker.pid" \
  "$LOG_DIR/worker.log" \
  bash -lc "cd '$API_DIR' && source .venv/bin/activate && export PYTHONPATH=. && exec celery -A app.workers.celery_app:celery_app worker --pool=solo --loglevel=info"

start_process \
  "web" \
  "$RUN_DIR/web.pid" \
  "$LOG_DIR/web.log" \
  bash -lc "cd '$WEB_DIR' && exec npm run dev -- --host '$WEB_HOST'"

echo
echo "SOCINTEL - V2 is starting."
echo "Frontend: http://$WEB_HOST:5173"
echo "API:      http://127.0.0.1:8000/health"
if [[ "${EXPOSE_API_DOCS:-false}" == "true" ]]; then
  echo "Docs:     http://127.0.0.1:8000/docs"
fi
echo
echo "Logs:"
echo "- $LOG_DIR/api.log"
echo "- $LOG_DIR/worker.log"
echo "- $LOG_DIR/web.log"
echo
echo "Press Ctrl+C to stop API, worker, and web. Docker services stay up."
echo "Run ./scripts/stop_app.sh to stop API, worker, web, and Docker services."

wait
