#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="$ROOT_DIR/.run"

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
