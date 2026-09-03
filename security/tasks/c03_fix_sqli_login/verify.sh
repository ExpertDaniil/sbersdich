#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"

. "$REPO_DIR/scripts/lib/python.sh"
cd "$SCRIPT_DIR"

run_python -m py_compile routers/auth.py tests/test_auth_fix.py
run_python -m unittest discover -s tests -p 'test_*.py' -v

printf '%s\n' "C-03 verification passed"
