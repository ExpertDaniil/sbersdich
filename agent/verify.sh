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
    agent/scaffold/__init__.py \
    agent/scaffold/bootstrap.py \
    agent/scaffold/cli.py \
    agent/scaffold/contracts.py \
    agent/scaffold/diagnostics.py \
    agent/scaffold/extensions.py \
    agent/scaffold/interfaces.py \
    agent/scaffold/kernel.py \
    agent/scaffold/packaging.py \
    agent/scaffold/planner.py \
    agent/scaffold/providers.py \
    agent/scaffold/registry.py \
    agent/scaffold/sessions.py \
    agent/scaffold/state.py \
    agent/scaffold/verifier.py \
    agent/tools/ctf.py \
    agent/tools/forensics.py \
    agent/tools/security_scan.py \
    agent/tools/sql_parameterize.py \
    agent/tests/test_agent_loop.py \
    agent/tests/test_audit_fix_tools.py \
    agent/tests/test_ctf.py \
    agent/tests/test_forensics_tools.py \
    agent/tests/test_llm.py \
    agent/tests/test_scaffold_diagnostics.py \
    agent/tests/test_scaffold_kernel.py \
    agent/tests/test_scaffold_packaging.py \
    agent/tests/test_scaffold_registry.py \
    agent/tests/test_scaffold_sessions.py \
    agent/tests/test_scaffold_state.py \
    agent/tests/test_validators.py \
    agent/tests/test_workspace_tools.py \
    scripts/build_scaffold_submission.py \
    scripts/scaffold_doctor.py \
    scripts/scaffold_smoke.py
run_python -m unittest discover -s agent/tests -p 'test_*.py' -v
run_python scripts/scaffold_smoke.py

printf '%s\n' "C-06/C-13 + experimental scaffold verification passed"
