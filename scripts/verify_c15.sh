#!/bin/sh
set -eu

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$REPO_DIR/scripts/lib/python.sh"
cd "$REPO_DIR"
run_python scripts/verify_c15.py
