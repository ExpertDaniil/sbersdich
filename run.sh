#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORKDIR="${LOCAL_AGENT_WORKDIR:-$(pwd)}"

if [ "$#" -lt 1 ]; then
  echo "Использование: ./run.sh ТЕКСТ_ЗАДАНИЯ" >&2
  exit 2
fi

# Корень архива добавляется в путь поиска Python, поэтому пакет agent можно
# запускать одинаково из каталога Harbor и при местной проверке.
exec env \
  LOCAL_AGENT_WORKDIR="$WORKDIR" \
  PYTHONPATH="$SCRIPT_DIR${PYTHONPATH:+:$PYTHONPATH}" \
  python3 -m agent.local_agent -- "$@"
