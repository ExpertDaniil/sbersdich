"""Adapters that expose existing tools through the scaffold provider contract."""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path
from typing import Any

from agent.core.models import AgentAction, ToolResult
from agent.core.tools import SecurityToolRegistry
from agent.core.workspace import resolve_workspace_path

from .contracts import CapabilityLevel, ExecutionContext, ToolSpec


LEGACY_CAPABILITIES = {
    "list_files": CapabilityLevel.INSPECT,
    "read_file": CapabilityLevel.INSPECT,
    "read_bytes": CapabilityLevel.INSPECT,
    "search_text": CapabilityLevel.INSPECT,
    "security_scan": CapabilityLevel.ANALYZE,
    "forensics_analyze": CapabilityLevel.ANALYZE,
    "run_command": CapabilityLevel.EXECUTE,
    "apply_patch": CapabilityLevel.MUTATE,
    "sql_parameterize": CapabilityLevel.MUTATE,
    "write_exact_text": CapabilityLevel.MUTATE,
}

MAX_WRITE_CHARS = 128_000
MAX_RESULTING_FILE_BYTES = 512 * 1024


class LegacySecurityProvider:
    name = "legacy-security"

    def __init__(self, workdir: Path):
        self._registry = SecurityToolRegistry(workdir)

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        return tuple(
            ToolSpec(
                name=tool.name,
                description=tool.description,
                parameters=tool.parameters,
                modes=(context.decision.mode,),
                capability=LEGACY_CAPABILITIES.get(tool.name, CapabilityLevel.ANALYZE),
                mutates_workspace=tool.mutates_workspace,
                provider=self.name,
            )
            for tool in self._registry.catalog(context.decision)
        )

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        return self._registry.execute(action, context.decision)


def _expect_text(arguments: dict[str, Any], key: str) -> str:
    value = arguments.get(key)
    if not isinstance(value, str):
        raise ValueError(f"{key} must be text")
    if len(value) > MAX_WRITE_CHARS:
        raise ValueError(f"{key} exceeds {MAX_WRITE_CHARS} characters")
    return value


def _atomic_replace(path: Path, content: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=".agent-write-", dir=path.parent, delete=False
        ) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


class WorkspaceFileProvider:
    """General bounded write/append primitives missing from the legacy registry."""

    name = "workspace-files"

    def __init__(self, workdir: Path):
        self.workdir = workdir

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        modes = ("general", "fix")
        return (
            ToolSpec(
                "write_file",
                "Atomically replace one bounded UTF-8 workspace file.",
                {"path": "string", "content": "string"},
                modes,
                CapabilityLevel.MUTATE,
                True,
                self.name,
            ),
            ToolSpec(
                "append_file",
                "Atomically append bounded UTF-8 text to one workspace file.",
                {"path": "string", "content": "string"},
                modes,
                CapabilityLevel.MUTATE,
                True,
                self.name,
            ),
        )

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        try:
            if set(action.arguments) != {"path", "content"}:
                raise ValueError(f"{action.name} requires only path and content")
            content = _expect_text(action.arguments, "content")
            target = resolve_workspace_path(
                self.workdir,
                action.arguments["path"],
                must_exist=False,
                for_write=True,
            )
            if action.name == "write_file":
                rendered = content.encode("utf-8")
            elif action.name == "append_file":
                existing = b""
                if target.exists():
                    if not target.is_file() or target.is_symlink():
                        raise ValueError("append target must be a regular file")
                    existing = target.read_bytes()
                    try:
                        existing.decode("utf-8")
                    except UnicodeDecodeError as error:
                        raise ValueError("append target is not UTF-8") from error
                rendered = existing + content.encode("utf-8")
            else:
                return ToolResult(False, f"unknown workspace file action: {action.name}")
            if len(rendered) > MAX_RESULTING_FILE_BYTES:
                raise ValueError(
                    f"resulting file exceeds {MAX_RESULTING_FILE_BYTES} bytes"
                )
            _atomic_replace(target, rendered)
            relative = target.relative_to(self.workdir).as_posix()
            return ToolResult(
                True,
                f"{action.name} wrote {len(rendered)} byte(s) to {relative}",
                {"path": relative, "bytes": len(rendered)},
            )
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")
