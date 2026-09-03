#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
cd "$SCRIPT_DIR"

python3 -m py_compile routers/auth.py tests/test_auth_fix.py
python3 -m unittest discover -s tests -p 'test_*.py' -v

printf '%s\n' "C-03 verification passed"
