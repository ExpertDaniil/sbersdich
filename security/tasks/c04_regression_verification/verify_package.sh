#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

python3 -m py_compile scripts/http_regression.py tests/test_http_regression.py
python3 -m unittest discover -s tests -p 'test_*.py' -v
bash -n run_in_acp.sh

printf '%s\n' "C-04 package verification passed"
