#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${LOCAL_AGENT_WORKDIR:-$(pwd)}"

if [ "$#" -lt 1 ]; then
  echo "Usage: ./run_scaffold.sh [scaffold options] TASK_TEXT" >&2
  exit 2
fi

exec env \
  LOCAL_AGENT_WORKDIR="$WORKDIR" \
  PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m agent.scaffold.cli --workdir "$WORKDIR" "$@"
