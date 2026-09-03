#!/bin/sh
set -eu

AGENT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$AGENT_DIR/.." && pwd)"

. "$REPO_DIR/scripts/lib/python.sh"
cd "$REPO_DIR"

run_python -m py_compile \
    agent/strategies.py \
    agent/tools/security_scan.py \
    agent/tools/sql_parameterize.py \
    agent/tests/test_audit_fix_tools.py
run_python -m unittest discover -s agent/tests -p 'test_*.py' -v

printf '%s\n' "C-06 audit/fix agent verification passed"
