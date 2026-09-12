"""Data contracts shared by the agent loop, drivers and tool registry."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Protocol

from agent.strategies import StrategyDecision
from agent.validators import ArtifactRule, ValidationReport
from .project_checks import ProjectCheckPlan


TERMINAL_STATUSES = frozenset({"succeeded", "failed"})


@dataclass(frozen=True)
class AgentAction:
    """One structured action selected by a deterministic or LLM driver."""

    name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    rationale: str = ""

    def fingerprint(self) -> str:
        try:
            arguments = json.dumps(
                self.arguments,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
        except (TypeError, ValueError) as error:
            raise ValueError(f"action arguments must be JSON-serializable: {error}") from error
        return f"{self.name}:{arguments}"

    def as_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arguments": self.arguments,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ToolResult:
    ok: bool
    summary: str
    data: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ToolDefinition:
    """Compact tool schema exposed to action drivers and the future LLM."""

    name: str
    description: str
    parameters: dict[str, str]
    mutates_workspace: bool = False

    def as_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ValidationFeedback:
    passed: bool
    reason: str
    report: ValidationReport

    def as_payload(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "reason": self.reason,
            "report": self.report.as_payload(),
        }


@dataclass(frozen=True)
class LoopEvent:
    sequence: int
    phase: str
    action: AgentAction | None = None
    tool_result: ToolResult | None = None
    validation: ValidationFeedback | None = None

    def as_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "sequence": self.sequence,
            "phase": self.phase,
        }
        if self.action is not None:
            payload["action"] = self.action.as_payload()
        if self.tool_result is not None:
            payload["tool_result"] = self.tool_result.as_payload()
        if self.validation is not None:
            payload["validation"] = self.validation.as_payload()
        return payload


@dataclass(frozen=True)
class TaskContract:
    artifacts: tuple[ArtifactRule, ...] = ()
    exact_writes: tuple[tuple[Path, str], ...] = ()
    project_checks: ProjectCheckPlan | None = None
    # High-confidence properties explicitly requested by a fix instruction.
    # They drive deterministic post-edit guards, never task-specific answers.
    security_requirements: tuple[str, ...] = ()


@dataclass(frozen=True)
class DriverContext:
    instruction: str
    workdir: Path
    decision: StrategyDecision
    task_playbook: str
    validation_playbook: str
    contract: TaskContract
    available_tools: tuple[ToolDefinition, ...]
    events: tuple[LoopEvent, ...]
    last_validation: ValidationFeedback | None
    # Остаток общего времени позволяет сетевому драйверу завершить запрос до
    # того, как ядру понадобится резерв на сохранение и проверку результата.
    remaining_seconds: float | None = None


class ActionDriver(Protocol):
    """Decision-provider interface implemented by C-09 and future LLM adapters."""

    def next_action(self, context: DriverContext) -> AgentAction:
        """Return exactly one structured action."""
        ...


@dataclass(frozen=True)
class LoopLimits:
    max_steps: int = 12
    max_validations: int = 3
    max_repeated_action: int = 2
    deadline_seconds: float = 300.0

    def __post_init__(self) -> None:
        if self.max_steps < 1:
            raise ValueError("max_steps must be positive")
        if self.max_validations < 1:
            raise ValueError("max_validations must be positive")
        if self.max_repeated_action < 1:
            raise ValueError("max_repeated_action must be positive")
        if self.deadline_seconds <= 0:
            raise ValueError("deadline_seconds must be positive")


@dataclass(frozen=True)
class AgentRunResult:
    status: str
    reason: str
    decision: StrategyDecision | None
    steps_used: int
    validations_used: int
    events: tuple[LoopEvent, ...]
    final_validation: ValidationFeedback | None

    @property
    def succeeded(self) -> bool:
        return self.status == "succeeded"

    def as_payload(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "decision": asdict(self.decision) if self.decision else None,
            "steps_used": self.steps_used,
            "validations_used": self.validations_used,
            "events": [event.as_payload() for event in self.events],
            "final_validation": (
                self.final_validation.as_payload() if self.final_validation else None
            ),
        }
