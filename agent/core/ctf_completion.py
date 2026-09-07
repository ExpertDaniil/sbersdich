"""Shared CTF completion rules for the legacy loop and production scaffold."""

from __future__ import annotations

from collections.abc import Sequence

from agent.validators import ValidationReport, canonical_path

from .contracts import map_instruction_path
from .models import LoopEvent, TaskContract


def check_ctf_completion(
    contract: TaskContract,
    events: Sequence[LoopEvent],
    report: ValidationReport,
) -> tuple[bool, str]:
    """Require both a changed answer artifact and a successful write to each path.

    This verifies production of the requested artifacts, not correctness of an
    unknown flag. The task's independent verifier decides whether the answer is
    correct. Never infer a filename or accept a pre-existing file as a new result.
    """

    if not report.passed:
        return False, "deterministic validator reported failed checks"
    if not contract.artifacts:
        return False, "CTF task has no explicit answer artifact contract"

    root = canonical_path(report.target)
    expected = {
        canonical_path(rule.path).relative_to(root).as_posix()
        for rule in contract.artifacts
    }
    if not expected.issubset(report.changes.all_paths()):
        return False, "CTF answer artifact was not produced during this run"

    written: set[str] = set()
    for event in events:
        if (
            event.action is None
            or event.action.name != "write_exact_text"
            or event.tool_result is None
            or not event.tool_result.ok
        ):
            continue
        # Use the path confirmed by the tool, not an unexecuted planner claim.
        raw_path = event.tool_result.data.get("path")
        if not isinstance(raw_path, str) or not raw_path:
            continue
        try:
            path = map_instruction_path(raw_path, root)
            written.add(path.relative_to(root).as_posix())
        except (OSError, ValueError, RuntimeError):
            continue

    if not expected.issubset(written):
        return False, "CTF task has no successful answer write for every artifact"
    return True, "all deterministic checks and completion guards passed"
