#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

if [ -n "${LOCAL_AGENT_WORKDIR:-}" ]; then
  WORKDIR="$LOCAL_AGENT_WORKDIR"
elif [ -d /app ]; then
  WORKDIR=/app
else
  WORKDIR="$(pwd)"
fi

if [ "$#" -lt 1 ]; then
  echo "Usage: ./run.sh TASK_INSTRUCTION" >&2
  exit 2
fi

# Competition wrapper invokes this script from /opt/harbor/local-agent while
# task files live in /app. Prefer that task workspace explicitly. The scaffold
# remains importable from the submission root and requires no runtime install.
exec env \
  LOCAL_AGENT_WORKDIR="$WORKDIR" \
  PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m agent.scaffold.cli --workdir "$WORKDIR" -- "$@"
