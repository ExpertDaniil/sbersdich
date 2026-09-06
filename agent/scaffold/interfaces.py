"""Protocols used by the scaffold composition root."""

from __future__ import annotations

from typing import Protocol

from agent.core.models import AgentAction, ToolResult

from .contracts import (
    ExecutionContext,
    PlanDecision,
    PlanningContext,
    ToolSpec,
    VerificationContext,
    VerificationResult,
)


class ToolProvider(Protocol):
    name: str

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        ...

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        ...


class Planner(Protocol):
    def next_plan(self, context: PlanningContext) -> PlanDecision:
        ...


class Verifier(Protocol):
    def verify(self, context: VerificationContext) -> VerificationResult:
        ...
