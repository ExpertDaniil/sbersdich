"""Safe, structured adapters around the deterministic C-06/C-07 tools."""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable

from agent.strategies import StrategyDecision
from agent.tools.forensics import (
    analyze_incident,
    ensure_output_outside_evidence,
    format_report,
    inventory_artifacts,
    inventory_digest,
    resolve_incident_directory,
)
from agent.tools.security_scan import render_report, scan_project
from agent.tools.sql_parameterize import parameterize_project
from agent.validators import (
    canonical_path,
    dependency_path,
    path_is_within,
    protected_path,
)

from .models import AgentAction, ToolResult


MAX_EXACT_TEXT_CHARS = 64_000
RESERVED_ACTIONS = frozenset({"finish", "abort"})
MODE_ACTIONS = {
    "audit": frozenset({"security_scan"}),
    "fix": frozenset({"security_scan", "sql_parameterize"}),
    "forensics": frozenset({"forensics_analyze"}),
    "general": frozenset({"write_exact_text"}),
}


class ToolPolicyError(RuntimeError):
    """Raised when a structured action exceeds the current task's authority."""


def _expect_bool(arguments: dict[str, Any], key: str, default: bool) -> bool:
    value = arguments.get(key, default)
    if not isinstance(value, bool):
        raise ToolPolicyError(f"{key} must be a boolean")
    return value


class SecurityToolRegistry:
    """Dispatch a deliberately small allowlist with workdir containment checks."""

    def __init__(self, workdir: Path | str):
        self.workdir = canonical_path(workdir)
        if not self.workdir.is_dir():
            raise ToolPolicyError(f"workdir is not a directory: {self.workdir}")
        self._handlers: dict[str, Callable[[dict[str, Any]], ToolResult]] = {
            "security_scan": self._security_scan,
            "sql_parameterize": self._sql_parameterize,
            "forensics_analyze": self._forensics_analyze,
            "write_exact_text": self._write_exact_text,
        }

    def _path(self, raw_value: object, *, default: Path | None = None) -> Path:
        if raw_value is None:
            if default is None:
                raise ToolPolicyError("required path is missing")
            candidate = default
        elif isinstance(raw_value, str) and raw_value:
            requested = Path(raw_value.replace("\\", "/"))
            candidate = requested if requested.is_absolute() else self.workdir / requested
        else:
            raise ToolPolicyError("path must be a non-empty string")
        resolved = canonical_path(candidate)
        if not path_is_within(resolved, self.workdir):
            raise ToolPolicyError(f"path is outside workdir: {candidate}")
        return resolved

    def _analysis_target(self, raw_value: object) -> Path:
        target = self._path(raw_value, default=self.workdir)
        relative = target.relative_to(self.workdir).as_posix()
        if relative != "." and protected_path(relative):
            raise ToolPolicyError(f"refusing protected analysis target: {relative}")
        return target

    def execute(self, action: AgentAction, decision: StrategyDecision) -> ToolResult:
        allowed = MODE_ACTIONS.get(decision.mode, frozenset())
        if action.name not in allowed:
            return ToolResult(
                False,
                f"action {action.name!r} is forbidden in {decision.mode!r} mode",
            )
        handler = self._handlers.get(action.name)
        if handler is None:
            return ToolResult(False, f"unknown action: {action.name}")
        if not isinstance(action.arguments, dict):
            return ToolResult(False, "action arguments must be an object")
        try:
            return handler(action.arguments)
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")

    def _security_scan(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target", "write_report", "output"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported security_scan argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        findings = scan_project(target, include_tests=False)
        write_report = _expect_bool(arguments, "write_report", False)
        output_path: Path | None = None
        if write_report:
            output_path = self._path(
                arguments.get("output"), default=self.workdir / "security_report.json"
            )
            relative = output_path.relative_to(self.workdir).as_posix()
            if protected_path(relative) or dependency_path(relative):
                raise ToolPolicyError(f"refusing report path: {relative}")
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(render_report(findings), encoding="utf-8", newline="\n")
        return ToolResult(
            True,
            f"security scan completed with {len(findings)} finding(s)",
            {
                "finding_count": len(findings),
                "report": str(output_path) if output_path else None,
            },
        )

    def _sql_parameterize(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported sql_parameterize argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        changes = parameterize_project(target, apply=True)
        return ToolResult(
            True,
            f"SQL parameterization applied {len(changes)} change(s)",
            {
                "change_count": len(changes),
                "changes": [asdict(change) for change in changes],
            },
        )

    def _forensics_analyze(self, arguments: dict[str, Any]) -> ToolResult:
        allowed_keys = {"target", "output"}
        unknown = sorted(set(arguments) - allowed_keys)
        if unknown:
            raise ToolPolicyError(f"unsupported forensics_analyze argument(s): {unknown}")
        target = self._analysis_target(arguments.get("target"))
        output = self._path(
            arguments.get("output"), default=self.workdir / "incident_report.txt"
        )
        relative = output.relative_to(self.workdir).as_posix()
        if protected_path(relative) or dependency_path(relative):
            raise ToolPolicyError(f"refusing incident report path: {relative}")

        incident_dir = resolve_incident_directory(target)
        ensure_output_outside_evidence(output, incident_dir)
        before_digest = inventory_digest(inventory_artifacts(incident_dir))
        conclusion = analyze_incident(incident_dir)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(format_report(conclusion), encoding="utf-8", newline="\n")
        after_digest = inventory_digest(inventory_artifacts(incident_dir))
        if before_digest != after_digest:
            raise ToolPolicyError("evidence changed during forensics analysis")
        return ToolResult(
            True,
            "forensics correlation completed and incident report written",
            {"report": str(output)},
        )

    def _write_exact_text(self, arguments: dict[str, Any]) -> ToolResult:
        if set(arguments) != {"path", "content"}:
            raise ToolPolicyError("write_exact_text requires only path and content")
        content = arguments["content"]
        if not isinstance(content, str):
            raise ToolPolicyError("content must be text")
        if len(content) > MAX_EXACT_TEXT_CHARS:
            raise ToolPolicyError(f"content exceeds {MAX_EXACT_TEXT_CHARS} characters")
        output = self._path(arguments["path"])
        relative = output.relative_to(self.workdir).as_posix()
        if protected_path(relative) or dependency_path(relative):
            raise ToolPolicyError(f"refusing protected output path: {relative}")
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(content, encoding="utf-8", newline="\n")
        return ToolResult(
            True,
            f"wrote exact UTF-8 content to {relative}",
            {"path": str(output), "characters": len(content)},
        )
