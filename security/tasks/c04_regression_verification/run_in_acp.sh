#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
APP_DIR="${1:-/app}"
OUTPUT_DIR="${C04_OUTPUT_DIR:-$SCRIPT_DIR/results}"
DB_URL="${DATABASE_URL:-postgresql://appuser:apppass@127.0.0.1:5432/appdb}"
PORT="${C04_PORT:-8000}"
BASE_URL="http://127.0.0.1:$PORT"
APP_PID=""

mkdir -p "$OUTPUT_DIR"
RUN_LOG="$OUTPUT_DIR/run.log"
APP_LOG="$OUTPUT_DIR/app.log"
PYTEST_LOG="$OUTPUT_DIR/pytest.log"
HTTP_REPORT="$OUTPUT_DIR/http_report.json"
: >"$RUN_LOG"
: >"$APP_LOG"
: >"$PYTEST_LOG"

log() {
    printf '[%s] %s\n' "$(date -Iseconds)" "$*" | tee -a "$RUN_LOG"
}

cleanup() {
    if [[ -n "${APP_PID:-}" ]] && kill -0 "$APP_PID" 2>/dev/null; then
        kill "$APP_PID" 2>/dev/null || true
        wait "$APP_PID" 2>/dev/null || true
    fi
}

trap cleanup EXIT INT TERM

if [[ ! -d "$APP_DIR" || ! -f "$APP_DIR/main.py" ]]; then
    log "ERROR: application directory is invalid: $APP_DIR"
    exit 2
fi

if [[ -x "$APP_DIR/.venv/bin/python" ]]; then
    PYTHON="$APP_DIR/.venv/bin/python"
else
    PYTHON="python3"
fi

if [[ -x "$APP_DIR/.venv/bin/uvicorn" ]]; then
    UVICORN="$APP_DIR/.venv/bin/uvicorn"
else
    UVICORN="uvicorn"
fi

log "Stopping stale application processes"
pkill -f '[u]vicorn main:app' >>"$RUN_LOG" 2>&1 || true
sleep 1

if [[ "${C04_RESET_DB:-0}" == "1" ]]; then
    if [[ "$(id -u)" != "0" ]]; then
        log "ERROR: C04_RESET_DB=1 requires root inside the disposable test container"
        exit 2
    fi
    log "Starting PostgreSQL and recreating the disposable test database"
    service postgresql start >>"$RUN_LOG" 2>&1 || service postgresql restart >>"$RUN_LOG" 2>&1
    su postgres -c "psql -c \"CREATE USER appuser WITH PASSWORD 'apppass';\"" >>"$RUN_LOG" 2>&1 || true
    su postgres -c "psql -c \"SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = 'appdb';\"" >>"$RUN_LOG" 2>&1 || true
    su postgres -c "dropdb --if-exists appdb" >>"$RUN_LOG" 2>&1
    su postgres -c "createdb appdb -O appuser" >>"$RUN_LOG" 2>&1
fi

log "Starting Uvicorn from the current files in $APP_DIR"
cd "$APP_DIR"
DATABASE_URL="$DB_URL" "$UVICORN" main:app \
    --host 127.0.0.1 --port "$PORT" --log-level info >"$APP_LOG" 2>&1 &
APP_PID=$!

healthy=0
for _ in $(seq 1 30); do
    if curl -fsS "$BASE_URL/healthz" >>"$RUN_LOG" 2>&1; then
        healthy=1
        break
    fi
    if ! kill -0 "$APP_PID" 2>/dev/null; then
        log "ERROR: application exited before it became healthy"
        exit 1
    fi
    sleep 1
done

if [[ "$healthy" != "1" ]]; then
    log "ERROR: application did not become healthy within 30 seconds"
    exit 1
fi

log "Running project regression tests"
set +e
DATABASE_URL="$DB_URL" "$PYTHON" -m pytest "$APP_DIR/tests" -v --tb=short \
    2>&1 | tee "$PYTEST_LOG"
pytest_status=${PIPESTATUS[0]}
set -e

log "Running independent HTTP security and regression checks"
set +e
"$PYTHON" "$SCRIPT_DIR/scripts/http_regression.py" \
    --base-url "$BASE_URL" --output "$HTTP_REPORT" | tee -a "$RUN_LOG"
http_status=${PIPESTATUS[0]}
set -e

if [[ "$pytest_status" == "0" && "$http_status" == "0" ]]; then
    log "C-04 PASSED: project tests and HTTP checks succeeded"
    exit 0
fi

log "C-04 FAILED: pytest_status=$pytest_status http_status=$http_status"
exit 1
