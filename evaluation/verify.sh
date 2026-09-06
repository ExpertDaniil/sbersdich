#!/bin/sh
set -eu

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

# shellcheck source=../scripts/lib/python.sh
. "$REPO_DIR/scripts/lib/python.sh"

cd "$REPO_DIR"
run_python -m py_compile \
    evaluation/failure_analysis.py \
    evaluation/tests/test_failure_analysis.py
run_python -m unittest discover -s evaluation/tests -p 'test_*.py' -v

printf '%s\n' "C-11 failure analysis verification passed"
