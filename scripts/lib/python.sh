#!/bin/sh

# shellcheck shell=sh

run_python() {
    if [ -n "${PYTHON_BIN:-}" ]; then
        "$PYTHON_BIN" "$@"
        return
    fi

    if command -v python3 >/dev/null 2>&1 && python3 -c 'import sys' >/dev/null 2>&1; then
        python3 "$@"
        return
    fi

    if command -v python >/dev/null 2>&1 && python -c 'import sys' >/dev/null 2>&1; then
        python "$@"
        return
    fi

    if command -v py >/dev/null 2>&1 && py -3 -c 'import sys' >/dev/null 2>&1; then
        py -3 "$@"
        return
    fi

    printf '%s\n' 'Python 3 was not found. Install Python 3.12+ or set PYTHON_BIN.' >&2
    return 127
}
