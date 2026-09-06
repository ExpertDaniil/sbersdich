#!/bin/sh
set -eu

AGENT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_DIR="$(CDPATH= cd -- "$AGENT_DIR/.." && pwd)"

. "$REPO_DIR/scripts/lib/python.sh"
cd "$REPO_DIR"

run_python -m py_compile \
    agent/strategies.py \
    agent/validators.py \
    agent/local_agent.py \
    agent/core/config.py \
    agent/core/contracts.py \
    agent/core/llm.py \
    agent/core/loop.py \
    agent/core/models.py \
    agent/core/playbooks.py \
    agent/core/tools.py \
    agent/core/workspace.py \
    agent/runtime/__init__.py \
    agent/runtime/adapters.py \
    agent/runtime/contracts.py \
    agent/runtime/files.py \
    agent/runtime/manifest.py \
    agent/runtime/packaging.py \
    agent/runtime/process.py \
    agent/runtime/registry.py \
    agent/runtime/sessions.py \
    agent/tools/forensics.py \
    agent/tools/security_scan.py \
    agent/tools/sql_parameterize.py \
    agent/tests/test_agent_loop.py \
    agent/tests/test_audit_fix_tools.py \
    agent/tests/test_forensics_tools.py \
    agent/tests/test_llm.py \
    agent/tests/test_runtime_files.py \
    agent/tests/test_runtime_integration.py \
    agent/tests/test_runtime_packaging.py \
    agent/tests/test_runtime_process.py \
    agent/tests/test_runtime_registry.py \
    agent/tests/test_runtime_sessions.py \
    agent/tests/test_validators.py \
    agent/tests/test_workspace_tools.py
run_python -m unittest discover -s agent/tests -p 'test_*.py' -v

printf '%s\n' "C-06/C-11 + B-runtime agent component verification passed"
