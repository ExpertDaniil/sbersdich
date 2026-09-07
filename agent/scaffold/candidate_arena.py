"""Isolated multi-candidate evaluation and deterministic promotion.

The Candidate Arena turns patch generation into a transactional search problem instead of
letting the model mutate the only workspace repeatedly. Candidate patches are evaluated
in private copies of the task workspace, filtered by cheap deterministic checks, scored,
and only the winning candidate may be promoted back to the real workspace.

This is intentionally an execution/control-plane primitive. Candidate branches never
enter the trusted evidence ledger until a tool result reports what actually happened.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
import shutil
import tempfile
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from agent.core.models import AgentAction, ToolResult
from agent.core.workspace import (
    MAX_TEXT_FILE_BYTES,
    WorkspaceError,
    answer_path,
    apply_workspace_patch,
    resolve_workspace_path,
    run_workspace_command,
)
from agent.tools.security_scan import scan_project

from .contracts import CapabilityLevel, ExecutionContext, ToolSpec


MAX_CANDIDATES = 4
MAX_PATCH_CHARS = 96 * 1024
MAX_BRANCH_FILES = 4096
MAX_BRANCH_BYTES = 64 * 1024 * 1024
MAX_STATIC_FILES = 512
MAX_TEST_OUTPUT_CHARS = 4_000
CANDIDATE_ID_RE = re.compile(r"^[A-Za-z0-9_.-]{1,40}$")
IGNORED_COPY_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "expected",
        "solution",
        "solutions",
        "verifier",
    }
)


@dataclass(frozen=True)
class CandidateSpec:
    candidate_id: str
    patch: str
    rationale: str = ""


@dataclass(frozen=True)
class CandidateEvaluation:
    candidate_id: str
    eligible: bool
    score: float
    changed_paths: tuple[str, ...]
    patch_lines: int
    syntax_passed: bool
    syntax_errors: tuple[dict[str, str], ...]
    baseline_findings: int
    candidate_findings: int
    findings_delta: int
    test_profile: str
    tests_passed: bool | None
    test_summary: str
    failure_reason: str = ""

    def as_payload(self) -> dict[str, Any]:
        return {
            "candidate_id": self.candidate_id,
            "eligible": self.eligible,
            "score": round(self.score, 3),
            "changed_paths": list(self.changed_paths),
            "patch_lines": self.patch_lines,
            "syntax_passed": self.syntax_passed,
            "syntax_errors": list(self.syntax_errors),
            "baseline_findings": self.baseline_findings,
            "candidate_findings": self.candidate_findings,
            "findings_delta": self.findings_delta,
            "test_profile": self.test_profile,
            "tests_passed": self.tests_passed,
            "test_summary": self.test_summary,
            "failure_reason": self.failure_reason,
        }


@dataclass
class ArenaSession:
    arena_id: str
    temporary: tempfile.TemporaryDirectory[str]
    confidence: float
    branch_budget: int
    test_profile: str
    baseline_digests: dict[str, str]
    specs: dict[str, CandidateSpec]
    evaluations: dict[str, CandidateEvaluation]
    winner_id: str | None
    promoted: bool = False


@dataclass(frozen=True)
class BranchCopyStats:
    file_count: int
    byte_count: int


def adaptive_branch_budget(confidence: float) -> int:
    """Spend branch budget only where uncertainty justifies it."""

    if not 0.0 <= confidence <= 1.0:
        raise ValueError("confidence must be between 0 and 1")
    if confidence >= 0.80:
        return 1
    if confidence >= 0.55:
        return 2
    if confidence >= 0.30:
        return 3
    return 4


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _patch_changed_lines(patch: str) -> int:
    count = 0
    for line in patch.splitlines():
        if line.startswith(("+++", "---")):
            continue
        if line.startswith(("+", "-")):
            count += 1
    return count


def _safe_candidate_id(value: object) -> str:
    if not isinstance(value, str) or not CANDIDATE_ID_RE.fullmatch(value):
        raise ValueError("candidate id must match [A-Za-z0-9_.-]{1,40}")
    return value


def _parse_candidate_specs(value: object) -> tuple[CandidateSpec, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError("candidates must be a non-empty array")
    if len(value) > MAX_CANDIDATES:
        raise ValueError(f"at most {MAX_CANDIDATES} candidates may be submitted")
    specs: list[CandidateSpec] = []
    seen: set[str] = set()
    for raw in value:
        if not isinstance(raw, dict):
            raise ValueError("each candidate must be an object")
        unknown = sorted(set(raw) - {"id", "patch", "rationale"})
        if unknown:
            raise ValueError(f"unsupported candidate field(s): {unknown}")
        candidate_id = _safe_candidate_id(raw.get("id"))
        if candidate_id in seen:
            raise ValueError(f"duplicate candidate id: {candidate_id}")
        seen.add(candidate_id)
        patch = raw.get("patch")
        if not isinstance(patch, str) or not patch.strip():
            raise ValueError(f"candidate {candidate_id} patch must be non-empty text")
        if len(patch) > MAX_PATCH_CHARS:
            raise ValueError(
                f"candidate {candidate_id} patch exceeds {MAX_PATCH_CHARS} characters"
            )
        rationale = raw.get("rationale", "")
        if not isinstance(rationale, str):
            raise ValueError("candidate rationale must be text")
        specs.append(CandidateSpec(candidate_id, patch, rationale[:800]))
    return tuple(specs)


def _copy_workspace(source: Path, destination: Path) -> BranchCopyStats:
    """Copy a bounded task workspace without answer/verifier or cache trees."""

    file_count = 0
    byte_count = 0
    destination.mkdir(parents=True, exist_ok=False)
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(source)
        directories[:] = sorted(
            name
            for name in directories
            if name not in IGNORED_COPY_DIRS
            and not answer_path(relative_current / name)
            and not (current_path / name).is_symlink()
        )
        target_dir = destination / relative_current
        target_dir.mkdir(parents=True, exist_ok=True)
        for name in sorted(filenames):
            src = current_path / name
            relative = src.relative_to(source)
            if src.is_symlink() or answer_path(relative):
                continue
            stat = src.stat()
            file_count += 1
            byte_count += stat.st_size
            if file_count > MAX_BRANCH_FILES:
                raise ValueError(
                    f"workspace exceeds Candidate Arena file budget {MAX_BRANCH_FILES}"
                )
            if byte_count > MAX_BRANCH_BYTES:
                raise ValueError(
                    f"workspace exceeds Candidate Arena byte budget {MAX_BRANCH_BYTES}"
                )
            shutil.copy2(src, destination / relative)
    return BranchCopyStats(file_count, byte_count)


def _iter_static_files(root: Path) -> Iterable[Path]:
    count = 0
    for current, directories, filenames in os.walk(root, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name not in IGNORED_COPY_DIRS and not (Path(current) / name).is_symlink()
        )
        for name in sorted(filenames):
            path = Path(current) / name
            if path.is_symlink() or answer_path(path.relative_to(root)):
                continue
            if path.suffix.casefold() not in {".py", ".json", ".toml"}:
                continue
            yield path
            count += 1
            if count >= MAX_STATIC_FILES:
                return


def _static_validate(root: Path) -> tuple[bool, tuple[dict[str, str], ...]]:
    errors: list[dict[str, str]] = []
    for path in _iter_static_files(root):
        relative = path.relative_to(root).as_posix()
        try:
            raw = path.read_bytes()
            if len(raw) > MAX_TEXT_FILE_BYTES:
                raise ValueError("file exceeds static validation size limit")
            text = raw.decode("utf-8")
            suffix = path.suffix.casefold()
            if suffix == ".py":
                ast.parse(text, filename=relative)
            elif suffix == ".json":
                json.loads(text)
            elif suffix == ".toml":
                tomllib.loads(text)
        except (OSError, UnicodeError, SyntaxError, json.JSONDecodeError, tomllib.TOMLDecodeError, ValueError) as error:
            errors.append({"path": relative, "error": str(error)[:500]})
            if len(errors) >= 20:
                break
    return not errors, tuple(errors)


def _run_test_profile(root: Path, profile: str, timeout_seconds: int) -> tuple[bool | None, str]:
    if profile == "none":
        return None, "not requested"
    if profile != "pytest":
        raise ValueError("test_profile must be 'none' or 'pytest'")
    data = run_workspace_command(
        root,
        argv=["python3", "-m", "pytest", "tests"],
        cwd=".",
        timeout_seconds=timeout_seconds,
    )
    passed = int(data["exit_code"]) == 0 and not bool(data.get("timed_out", False))
    output = str(data.get("output", ""))
    if len(output) > MAX_TEST_OUTPUT_CHARS:
        output = output[:MAX_TEST_OUTPUT_CHARS] + "\n... output truncated ..."
    summary = (
        f"exit_code={data['exit_code']} timed_out={bool(data.get('timed_out', False))}"
        + (f"\n{output}" if output else "")
    )
    return passed, summary


def _score_candidate(
    *,
    patch_lines: int,
    syntax_passed: bool,
    baseline_findings: int,
    candidate_findings: int,
    tests_passed: bool | None,
) -> tuple[bool, float]:
    eligible = syntax_passed and tests_passed is not False
    if not eligible:
        return False, -1_000.0
    score = 100.0
    # Small patches win ties: minimize collateral change without drowning stronger proof.
    score -= min(25.0, math.log2(max(1, patch_lines) + 1.0) * 3.0)
    removed = max(0, baseline_findings - candidate_findings)
    added = max(0, candidate_findings - baseline_findings)
    score += min(60.0, removed * 20.0)
    score -= min(120.0, added * 40.0)
    if tests_passed is True:
        score += 40.0
    return True, score


class CandidateArena:
    """Own private branch state and promotion guards for one task run."""

    def __init__(self, workdir: Path | str):
        self.workdir = Path(workdir).resolve()
        self._counter = 0
        self._sessions: dict[str, ArenaSession] = {}

    def evaluate(
        self,
        *,
        candidates: object,
        confidence: object = 0.5,
        test_profile: object = "none",
        timeout_seconds: object = 60,
    ) -> dict[str, Any]:
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("confidence must be numeric")
        confidence_value = float(confidence)
        budget = adaptive_branch_budget(confidence_value)
        specs = _parse_candidate_specs(candidates)
        if not isinstance(test_profile, str):
            raise ValueError("test_profile must be text")
        profile = test_profile.casefold()
        if profile not in {"none", "pytest"}:
            raise ValueError("test_profile must be 'none' or 'pytest'")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int):
            raise ValueError("timeout_seconds must be an integer")
        if not 1 <= timeout_seconds <= 120:
            raise ValueError("timeout_seconds must be between 1 and 120")

        evaluated_specs = specs[:budget]
        ignored = specs[budget:]
        self._counter += 1
        arena_id = f"A{self._counter:02d}"
        temporary = tempfile.TemporaryDirectory(prefix="agent-candidate-arena-")
        arena_root = Path(temporary.name)
        baseline_findings = len(scan_project(self.workdir, include_tests=False))
        baseline_digests: dict[str, str] = {}
        evaluations: dict[str, CandidateEvaluation] = {}
        spec_index: dict[str, CandidateSpec] = {}
        copy_stats: BranchCopyStats | None = None

        try:
            for spec in evaluated_specs:
                spec_index[spec.candidate_id] = spec
                branch_root = arena_root / spec.candidate_id
                copy_stats = _copy_workspace(self.workdir, branch_root)
                changed_paths: tuple[str, ...] = ()
                failure_reason = ""
                syntax_passed = False
                syntax_errors: tuple[dict[str, str], ...] = ()
                candidate_findings = baseline_findings
                tests_passed: bool | None = None
                test_summary = "not run"
                try:
                    patch_result = apply_workspace_patch(branch_root, patch=spec.patch)
                    changed_paths = tuple(str(path) for path in patch_result["changed_paths"])
                    for relative in changed_paths:
                        if relative not in baseline_digests:
                            original = resolve_workspace_path(self.workdir, relative)
                            if not original.is_file() or original.is_symlink():
                                raise ValueError(f"promotion source is not a regular file: {relative}")
                            baseline_digests[relative] = _digest(original)
                    syntax_passed, syntax_errors = _static_validate(branch_root)
                    if syntax_passed:
                        candidate_findings = len(scan_project(branch_root, include_tests=False))
                        tests_passed, test_summary = _run_test_profile(
                            branch_root,
                            profile,
                            timeout_seconds,
                        )
                    else:
                        failure_reason = "static validation failed"
                except (OSError, UnicodeError, ValueError, RuntimeError, WorkspaceError) as error:
                    failure_reason = str(error)
                    syntax_passed = False
                    if not syntax_errors:
                        syntax_errors = ({"path": "", "error": str(error)[:500]},)

                patch_lines = _patch_changed_lines(spec.patch)
                eligible, score = _score_candidate(
                    patch_lines=patch_lines,
                    syntax_passed=syntax_passed,
                    baseline_findings=baseline_findings,
                    candidate_findings=candidate_findings,
                    tests_passed=tests_passed,
                )
                if not eligible and not failure_reason:
                    failure_reason = (
                        "tests failed" if tests_passed is False else "candidate is ineligible"
                    )
                evaluations[spec.candidate_id] = CandidateEvaluation(
                    candidate_id=spec.candidate_id,
                    eligible=eligible,
                    score=score,
                    changed_paths=changed_paths,
                    patch_lines=patch_lines,
                    syntax_passed=syntax_passed,
                    syntax_errors=syntax_errors,
                    baseline_findings=baseline_findings,
                    candidate_findings=candidate_findings,
                    findings_delta=candidate_findings - baseline_findings,
                    test_profile=profile,
                    tests_passed=tests_passed,
                    test_summary=test_summary,
                    failure_reason=failure_reason,
                )

            eligible = [item for item in evaluations.values() if item.eligible]
            eligible.sort(
                key=lambda item: (-item.score, item.patch_lines, item.candidate_id)
            )
            winner_id = eligible[0].candidate_id if eligible else None
            session = ArenaSession(
                arena_id=arena_id,
                temporary=temporary,
                confidence=confidence_value,
                branch_budget=budget,
                test_profile=profile,
                baseline_digests=baseline_digests,
                specs=spec_index,
                evaluations=evaluations,
                winner_id=winner_id,
            )
            self._sessions[arena_id] = session
        except Exception:
            temporary.cleanup()
            raise

        return {
            "arena_id": arena_id,
            "confidence": confidence_value,
            "branch_budget": budget,
            "submitted_count": len(specs),
            "evaluated_count": len(evaluated_specs),
            "ignored_candidate_ids": [spec.candidate_id for spec in ignored],
            "copy_files": copy_stats.file_count if copy_stats else 0,
            "copy_bytes": copy_stats.byte_count if copy_stats else 0,
            "baseline_findings": baseline_findings,
            "test_profile": profile,
            "candidates": [
                evaluations[spec.candidate_id].as_payload() for spec in evaluated_specs
            ],
            "winner_id": winner_id,
            "promotion_ready": winner_id is not None,
        }

    def promote(self, *, arena_id: object, candidate_id: object | None = None) -> dict[str, Any]:
        if not isinstance(arena_id, str) or arena_id not in self._sessions:
            raise ValueError("unknown arena_id")
        session = self._sessions[arena_id]
        if session.promoted:
            raise ValueError("arena winner was already promoted")
        if session.winner_id is None:
            raise ValueError("arena has no eligible winner")
        requested = session.winner_id if candidate_id is None else _safe_candidate_id(candidate_id)
        if requested != session.winner_id:
            raise ValueError(
                f"only deterministic winner {session.winner_id!r} may be promoted"
            )
        evaluation = session.evaluations[requested]
        if not evaluation.eligible:
            raise ValueError("winner is not eligible for promotion")

        stale: list[dict[str, str]] = []
        for relative in evaluation.changed_paths:
            original = resolve_workspace_path(self.workdir, relative)
            current = _digest(original)
            expected = session.baseline_digests[relative]
            if current != expected:
                stale.append(
                    {
                        "path": relative,
                        "expected_sha256": expected,
                        "current_sha256": current,
                    }
                )
        if stale:
            return {
                "arena_id": arena_id,
                "candidate_id": requested,
                "promoted": False,
                "reason": "workspace changed after arena evaluation",
                "stale_paths": stale,
            }

        spec = session.specs[requested]
        result = apply_workspace_patch(self.workdir, patch=spec.patch)
        session.promoted = True
        return {
            "arena_id": arena_id,
            "candidate_id": requested,
            "promoted": True,
            "score": round(evaluation.score, 3),
            "changed_paths": list(result["changed_paths"]),
            "file_count": int(result["file_count"]),
            "hunk_count": int(result["hunk_count"]),
        }


class CandidateArenaProvider:
    """ToolBus adapter for isolated branch evaluation and winner-only promotion."""

    name = "candidate-arena"

    def __init__(self, workdir: Path | str):
        self.arena = CandidateArena(workdir)

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        if context.decision.mode not in {"fix", "general"}:
            return ()
        modes = (context.decision.mode,)
        return (
            ToolSpec(
                "arena_evaluate",
                "Evaluate up to four unified-diff candidates in isolated workspace copies. Branch width is automatically reduced as confidence increases; returns deterministic scores and one winner.",
                {
                    "candidates": "object[]:{id,patch,rationale?}",
                    "confidence": "number=0.5",
                    "test_profile": "string=none|pytest",
                    "timeout_seconds": "integer=60",
                },
                modes,
                CapabilityLevel.EXECUTE,
                False,
                self.name,
            ),
            ToolSpec(
                "arena_promote",
                "Atomically promote only the deterministic arena winner after checking that every affected source file still matches the evaluation baseline.",
                {"arena_id": "string", "candidate_id": "string=winner"},
                modes,
                CapabilityLevel.MUTATE,
                True,
                self.name,
            ),
        )

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        try:
            if action.name == "arena_evaluate":
                allowed = {"candidates", "confidence", "test_profile", "timeout_seconds"}
                unknown = sorted(set(action.arguments) - allowed)
                if unknown:
                    raise ValueError(f"unsupported arena_evaluate argument(s): {unknown}")
                if "candidates" not in action.arguments:
                    raise ValueError("arena_evaluate requires candidates")
                data = self.arena.evaluate(
                    candidates=action.arguments["candidates"],
                    confidence=action.arguments.get("confidence", 0.5),
                    test_profile=action.arguments.get("test_profile", "none"),
                    timeout_seconds=action.arguments.get("timeout_seconds", 60),
                )
                ok = data["winner_id"] is not None
                summary = (
                    f"Candidate Arena evaluated {data['evaluated_count']} branch(es); winner={data['winner_id']}"
                    if ok
                    else f"Candidate Arena rejected all {data['evaluated_count']} branch(es)"
                )
                return ToolResult(ok, summary, data)
            if action.name == "arena_promote":
                unknown = sorted(set(action.arguments) - {"arena_id", "candidate_id"})
                if unknown:
                    raise ValueError(f"unsupported arena_promote argument(s): {unknown}")
                if "arena_id" not in action.arguments:
                    raise ValueError("arena_promote requires arena_id")
                data = self.arena.promote(
                    arena_id=action.arguments["arena_id"],
                    candidate_id=action.arguments.get("candidate_id"),
                )
                return ToolResult(
                    bool(data["promoted"]),
                    (
                        f"promoted Candidate Arena winner {data['candidate_id']}"
                        if data["promoted"]
                        else f"Candidate Arena promotion rejected: {data['reason']}"
                    ),
                    data,
                )
            return ToolResult(False, f"unknown Candidate Arena action: {action.name}")
        except (OSError, UnicodeError, ValueError, RuntimeError, WorkspaceError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")
