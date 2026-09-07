"""Mandatory post-edit project verification shared by both agent runtimes."""

from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import tempfile
import time
from dataclasses import replace
from pathlib import Path

from agent.validators import (
    CheckResult, CommandSpec, MAX_COMMAND_TIMEOUT_SECONDS, ValidationPolicy,
    ValidationReport, canonical_path, validate_task,
)
from .project_checks import ProjectCheckPlan


PROTECTED_CHECK_FILES = frozenset({"agents.md", "pytest.ini", "conftest.py", "tox.ini", "pytest.py"})
OUTPUT_BYTES = 4000


def _cleanup_process(process: subprocess.Popen) -> None:
    try:
        if os.name == "posix":
            # Includes descendants that inherited the private session, even if
            # the direct pytest process exited before its children.
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        if process.poll() is None:
            process.kill()


def run_project_check(spec: CommandSpec, workdir: Path, *, timeout: float) -> CheckResult:
    started = time.monotonic()
    if not spec.argv or not math.isfinite(timeout) or timeout <= 0:
        return CheckResult(spec.name, False, "project-test budget exhausted or command is empty")
    env = os.environ.copy()
    for key in ("OPENAI_API_KEY", "OPENAI_BASE_URL", "LOCAL_AGENT_MODEL", "PYTEST_ADDOPTS"):
        env.pop(key, None)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    options = {"start_new_session": True} if os.name == "posix" else {}
    try:
        # A file avoids pipe deadlocks and unbounded memory use on verbose suites.
        # Only a bounded head/tail is returned to the model; no log enters /app.
        with tempfile.TemporaryFile() as output:
            process = subprocess.Popen(
                list(spec.argv), cwd=canonical_path(workdir), env=env, shell=False,
                stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                **options,
            )
            timed_out = False
            try:
                exit_code = process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                _cleanup_process(process)
                exit_code = process.wait(timeout=1)
            finally:
                _cleanup_process(process)
            output.seek(0, os.SEEK_END)
            size = output.tell()
            output.seek(0)
            if size <= OUTPUT_BYTES:
                raw = output.read(OUTPUT_BYTES)
            else:
                raw = output.read(OUTPUT_BYTES // 2)
                output.seek(-OUTPUT_BYTES // 2, os.SEEK_END)
                raw += b"\n... [project-test output truncated] ...\n" + output.read(OUTPUT_BYTES // 2)
            detail = (
                "argv=" + json.dumps(list(spec.argv), ensure_ascii=False)
                + f"\nexit_code={exit_code}\n"
                + (f"timed out after {timeout:.3f}s\n" if timed_out else "")
                + raw.decode("utf-8", errors="replace")
            )
            passed = exit_code == 0 and not timed_out
    except (OSError, subprocess.SubprocessError) as error:
        passed = False
        detail = f"project test command failed to run: {error}"
    return CheckResult(spec.name, passed, detail, round((time.monotonic() - started) * 1000))


def _integrity_check(report: ValidationReport, plan: ProjectCheckPlan | None) -> CheckResult:
    selected_paths: set[str] = set()
    for command in plan.commands if plan else ():
        if command.argv[1:3] != ("-m", "pytest"):
            continue
        for argument in command.argv[3:]:
            if not argument.startswith("-"):
                name = Path(argument.split("::", 1)[0]).as_posix()
                if name != ".":
                    selected_paths.add(os.path.normcase(name))
    forbidden = [
        name for name in report.changes.all_paths()
        if Path(name).name.lower() in PROTECTED_CHECK_FILES
        or (Path(name).suffix.lower() == ".py" and
            (Path(name).name.lower().startswith("test_") or Path(name).name.lower().endswith("_test.py")))
        or "pytest" in tuple(part.lower() for part in Path(name).parts)
        or any(os.path.normcase(name) == target or os.path.normcase(name).startswith(target + os.path.normcase("/"))
               for target in selected_paths)
    ]
    return CheckResult(
        "project-test-integrity", not forbidden,
        "test guidance/configuration unchanged" if not forbidden
        else "forbidden changed test guidance/configuration: " + ", ".join(forbidden),
    )


def validate_fix_task(
    policy: ValidationPolicy, plan: ProjectCheckPlan | None, *,
    remaining_seconds: float | None = None,
) -> ValidationReport:
    """Validate the final workspace and run the frozen suite on every finish.

    A prior tool/arena check is never reused as proof of the current workspace.
    Missing suites are explicitly reported; this does not certify hidden tests.
    """
    if policy.mode != "fix":
        return validate_task(policy)
    started = time.monotonic()
    # Direct API callers get the same bounded default as a single project check.
    budget = 60.0 if remaining_seconds is None else float(remaining_seconds)
    if not math.isfinite(budget):
        budget = 0.0
    static_policy = replace(policy, commands=())
    before = validate_task(static_policy)
    checks = [*before.checks, _integrity_check(before, plan)]
    plan = plan or ProjectCheckPlan(error="project test contract was not captured before editing")
    if plan.error:
        checks.append(CheckResult("project-test-contract", False, plan.error))
    commands = (*plan.commands, *policy.commands)
    if all(check.passed for check in checks):
        if not commands:
            checks.append(CheckResult("project-tests", True,
                "no supported project test suite found at startup; only static/security checks are available"))
        for command in commands:
            remaining = budget - (time.monotonic() - started) - 0.1
            if remaining <= 0:
                checks.append(CheckResult(command.name, False, "project-test deadline budget exhausted"))
                break
            if not 1 <= command.timeout_seconds <= MAX_COMMAND_TIMEOUT_SECONDS:
                checks.append(CheckResult(command.name, False, "invalid project-test timeout"))
                break
            result = run_project_check(command, policy.target,
                timeout=min(float(command.timeout_seconds), remaining))
            checks.append(result)
            if not result.passed:
                break
        # Tests may write files: re-check the final tree and protected paths.
        after = validate_task(static_policy)
        checks = [*after.checks, _integrity_check(after, plan),
                  *(check for check in checks if check.name not in {item.name for item in before.checks}
                    and check.name != "project-test-integrity")]
    else:
        after = before
    if time.monotonic() - started >= budget:
        checks.append(CheckResult("project-test-deadline", False, "validation exceeded remaining task time"))
    return replace(after, passed=all(check.passed for check in checks), checks=tuple(checks))


def failed_validation_reason(report: ValidationReport) -> str:
    failed = [check for check in report.checks if not check.passed]
    if not failed:
        return "deterministic validator reported failed checks"
    # Keep the command failure visible even when planner state is truncated.
    check = next((item for item in failed if item.name.startswith("project-test")), failed[0])
    detail = check.detail
    if len(detail) > 1800:
        detail = detail[:500] + "\n...\n" + detail[-1200:]
    return f"validation failed: {check.name}: {detail}"
