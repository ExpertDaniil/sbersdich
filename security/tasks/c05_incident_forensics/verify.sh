#!/bin/sh
set -eu

TASK_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$TASK_DIR/../../.." && pwd)"

. "$REPO_DIR/scripts/lib/python.sh"
cd "$TASK_DIR"

run_python -m py_compile analyze_incident.py validate_report.py tests/test_analyze_incident.py
run_python -m unittest discover -s tests -p 'test_*.py' -v

printf '%s\n' "C-05 incident forensics verification passed"
