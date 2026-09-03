#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s /absolute/path/to/UniversalAgenticCompetitionPublic\n' "$0" >&2
    exit 2
fi

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
PUBLIC_REPO="$(CDPATH= cd -- "$1" && pwd)"
INCIDENT_DIR="$PUBLIC_REPO/local_task/incident-log-forensics/environment"
TASK_DIR="$REPO_DIR/security/tasks/c05_incident_forensics"
RESULTS_DIR="$REPO_DIR/evaluation/results/c05_public"
REPORT="$RESULTS_DIR/incident_report.txt"
TRACE="$RESULTS_DIR/evidence_trace.json"

. "$REPO_DIR/scripts/lib/python.sh"

if [ ! -d "$INCIDENT_DIR" ]; then
    printf 'Incident bundle not found: %s\n' "$INCIDENT_DIR" >&2
    exit 2
fi

mkdir -p "$RESULTS_DIR"
run_python "$TASK_DIR/analyze_incident.py" "$INCIDENT_DIR" \
    --output "$REPORT" \
    --trace "$TRACE"
run_python "$TASK_DIR/validate_report.py" "$REPORT"

printf 'C-05 public verification passed. Results: %s\n' "$RESULTS_DIR"
