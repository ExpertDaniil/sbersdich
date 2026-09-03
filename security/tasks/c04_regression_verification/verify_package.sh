#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"

. "$REPO_DIR/scripts/lib/python.sh"
cd "$SCRIPT_DIR"

run_python -m py_compile scripts/http_regression.py tests/test_http_regression.py
run_python -m unittest discover -s tests -p 'test_*.py' -v
bash -n run_in_acp.sh

printf '%s\n' "C-04 package verification passed"
