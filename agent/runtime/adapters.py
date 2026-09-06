"""Adapters that turn participant-2 primitives into plug-in tools."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from agent.core.models import ToolDefinition, ToolResult

from .contracts import CapabilityLevel, RuntimeLimits, RuntimeToolSpec
from .files import append_workspace_text, write_workspace_text
from .registry import CompositeToolRegistry, RuntimeToolRegistry


WRITE_FILE = ToolDefinition(
    "write_file",
    "Atomically replace/create one bounded UTF-8 workspace file.",
    {"path": "string", "content": "string"},
    True,
)
APPEND_FILE = ToolDefinition(
    "append_file",
    "Append bounded UTF-8 text to one workspace file.",
    {"path": "string", "content": "string"},
    True,
)


def build_workspace_extensions(
    workdir: Path | str,
    *,
    limits: RuntimeLimits | None = None,
) -> RuntimeToolRegistry:
    """Build safe file-mutation extensions without touching core tool code."""

    root = Path(workdir)
    runtime = RuntimeToolRegistry(limits=limits)

    def write_handler(arguments: dict[str, Any]) -> ToolResult:
        if set(arguments) != {"path", "content"}:
            raise ValueError("write_file requires only path and content")
        data = write_workspace_text(
            root,
            path=arguments["path"],
            content=arguments["content"],
            limits=runtime.limits,
        )
        return ToolResult(True, f"wrote {data['path']}", data)

    def append_handler(arguments: dict[str, Any]) -> ToolResult:
        if set(arguments) != {"path", "content"}:
            raise ValueError("append_file requires only path and content")
        data = append_workspace_text(
            root,
            path=arguments["path"],
            content=arguments["content"],
            limits=runtime.limits,
        )
        return ToolResult(True, f"appended {data['path']}", data)

    runtime.register(
        RuntimeToolSpec(
            WRITE_FILE,
            frozenset({"general"}),
            CapabilityLevel.MUTATE,
            source="participant2.files",
            tags=frozenset({"filesystem", "write"}),
        ),
        write_handler,
    )
    runtime.register(
        RuntimeToolSpec(
            APPEND_FILE,
            frozenset({"general"}),
            CapabilityLevel.MUTATE,
            source="participant2.files",
            tags=frozenset({"filesystem", "append"}),
        ),
        append_handler,
    )
    runtime.freeze()
    return runtime


def build_composite_runtime(
    workdir: Path | str,
    legacy_provider: object,
    *,
    limits: RuntimeLimits | None = None,
) -> CompositeToolRegistry:
    """Compose current core tools with optional participant-2 extensions."""

    extensions = build_workspace_extensions(workdir, limits=limits)
    return CompositeToolRegistry(legacy_provider, extensions)  # type: ignore[arg-type]
