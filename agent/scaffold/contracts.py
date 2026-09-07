"""Shared contracts for the experimental extensible agent scaffold."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any

from agent.core.models import AgentAction, LoopEvent, TaskContract, ValidationFeedback
from agent.strategies import StrategyDecision


class CapabilityLevel(IntEnum):
    """Escalation ladder: prefer the cheapest capability that can answer a question."""

    INSPECT = 0
    ANALYZE = 1
    EXECUTE = 2
    INTERACTIVE = 3
    MUTATE = 4


class PlanStrategy(str, Enum):
    CONTINUE = "continue"
    BRANCH = "branch"
    BACKTRACK = "backtrack"
    VERIFY = "verify"
    ESCALATE = "escalate"
    DETERMINISTIC = "deterministic"


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, str]
    modes: tuple[str, ...]
    capability: CapabilityLevel
    mutates_workspace: bool = False
    provider: str = ""

    def as_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["capability"] = int(self.capability)
        return payload


@dataclass(frozen=True)
class PlanDecision:
    action: AgentAction
    strategy: PlanStrategy = PlanStrategy.CONTINUE
    hypothesis: str = ""
    confidence: float = 0.5
    expected_evidence: str = ""

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")


@dataclass(frozen=True)
class ExecutionContext:
    workdir: Path
    decision: StrategyDecision
    max_capability: CapabilityLevel


@dataclass(frozen=True)
class PlanningContext:
    instruction: str
    workdir: Path
    decision: StrategyDecision
    task_playbook: str
    validation_playbook: str
    contract: TaskContract
    tools: tuple[ToolSpec, ...]
    state_snapshot: dict[str, Any]
    events: tuple[LoopEvent, ...]
    last_validation: ValidationFeedback | None
    remaining_seconds: float
    extension_guidance: str = ""


@dataclass(frozen=True)
class VerificationContext:
    workdir: Path
    decision: StrategyDecision
    contract: TaskContract
    baseline: Any
    events: tuple[LoopEvent, ...]
    remaining_seconds: float | None = None


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    reason: str
    feedback: ValidationFeedback | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def as_payload(self) -> dict[str, Any]:
        payload = {
            "passed": self.passed,
            "reason": self.reason,
            "details": self.details,
        }
        if self.feedback is not None:
            payload["feedback"] = self.feedback.as_payload()
        return payload


@dataclass(frozen=True)
class KernelLimits:
    max_steps: int = 20
    max_validations: int = 4
    max_repeated_action: int = 2
    deadline_seconds: float = 300.0
    max_capability: CapabilityLevel = CapabilityLevel.MUTATE

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
class ScaffoldRunResult:
    status: str
    reason: str
    decision: StrategyDecision | None
    steps_used: int
    validations_used: int
    events: tuple[LoopEvent, ...]
    final_validation: VerificationResult | None
    state: dict[str, Any]

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
            "state": self.state,
        }
