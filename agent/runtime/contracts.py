"""Shared contracts for the participant-2 runtime/tooling layer.

The runtime layer deliberately reuses the core AgentAction/ToolDefinition/ToolResult
contracts instead of inventing a parallel protocol.  New tools declare where they
are allowed, how expensive/risky they are, and which handler implements them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, FrozenSet

from agent.core.models import ToolDefinition, ToolResult


class CapabilityLevel(IntEnum):
    """Escalation level used by the runtime and future planners.

    Lower levels are cheaper/safer observation; higher levels mutate state or keep
    interactive processes alive.  This is metadata only: authorization still comes
    from the mode allowlist and concrete handler policy.
    """

    INSPECT = 0
    ANALYZE = 1
    EXECUTE = 2
    INTERACTIVE = 3
    MUTATE = 4


RuntimeHandler = Callable[[dict[str, Any]], ToolResult]


@dataclass(frozen=True)
class RuntimeToolSpec:
    """One plug-in tool exposed through the common core contracts."""

    definition: ToolDefinition
    modes: FrozenSet[str]
    capability: CapabilityLevel
    source: str = "runtime"
    tags: FrozenSet[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.definition.name.strip():
            raise ValueError("tool name must not be empty")
        if not self.modes:
            raise ValueError(f"tool {self.definition.name!r} must allow at least one mode")
        if any(not mode.strip() for mode in self.modes):
            raise ValueError("tool modes must be non-empty strings")

    def as_payload(self) -> dict[str, object]:
        return {
            "definition": self.definition.as_payload(),
            "modes": sorted(self.modes),
            "capability": int(self.capability),
            "capability_name": self.capability.name.lower(),
            "source": self.source,
            "tags": sorted(self.tags),
        }


@dataclass(frozen=True)
class RuntimeLimits:
    """Hard limits shared by optional runtime extensions."""

    max_registered_tools: int = 64
    max_active_sessions: int = 1
    max_session_input_chars: int = 8_192
    max_session_output_bytes: int = 16_384
    max_session_seconds: int = 120
    max_file_write_chars: int = 64_000
    max_written_file_bytes: int = 512 * 1024

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if isinstance(value, int) and value <= 0:
                raise ValueError(f"{name} must be positive")
