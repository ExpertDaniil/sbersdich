#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'Usage: %s /absolute/path/to/UniversalAgenticCompetitionPublic\n' "$0" >&2
    exit 2
fi

REPO_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
. "$REPO_DIR/scripts/lib/python.sh"

run_python "$REPO_DIR/scripts/run_c06_public.py" "$1"
