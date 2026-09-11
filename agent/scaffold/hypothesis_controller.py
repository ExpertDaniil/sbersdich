"""Runtime enforcement for evidence-backed hypothesis search.

The planner may propose hypotheses and strategies, but the runtime owns the control
rules.  This module prevents textual "backtracking" that still executes the same
branch, forces capability escalation after stagnant observations, and requires
branches to declare falsifiable evidence before they consume tool budget.
"""

from __future__ import annotations

from dataclasses import dataclass

from .contracts import CapabilityLevel, PlanDecision, PlanStrategy, ToolSpec


@dataclass(frozen=True)
class ControlDecision:
    allowed: bool
    reason: str = ""
    required_strategy: PlanStrategy | None = None
    minimum_capability: CapabilityLevel | None = None


class RuntimeHypothesisController:
    """Deterministic control plane around model-proposed search decisions."""

    def evaluate(
        self,
        plan: PlanDecision,
        *,
        state_snapshot: dict[str, object],
        tools: tuple[ToolSpec, ...],
    ) -> ControlDecision:
        tool_by_name = {tool.name: tool for tool in tools}
        current = state_snapshot.get("current_hypothesis_id")
        recovery = bool(state_snapshot.get("recovery_required"))
        proposed_statement = " ".join(plan.hypothesis.casefold().split())
        for node in state_snapshot.get("hypotheses", []):
            if isinstance(node, dict) and str(node.get("id", "")).casefold() == proposed_statement:
                proposed_statement = " ".join(str(node.get("statement", "")).casefold().split())
                break

        # A branch without a falsifiable observation target is merely extra prose.
        if plan.strategy is PlanStrategy.BRANCH:
            if not plan.hypothesis.strip():
                return ControlDecision(False, "branch requires a concrete hypothesis")
            if not plan.expected_evidence.strip():
                return ControlDecision(False, "branch requires expected_evidence")

        if not recovery:
            return ControlDecision(True)

        minimum = self._minimum_capability(state_snapshot)
        if plan.strategy not in {
            PlanStrategy.BACKTRACK,
            PlanStrategy.ESCALATE,
            PlanStrategy.VERIFY,
        }:
            return ControlDecision(
                False,
                "stagnation requires backtrack, escalation, or verification",
                required_strategy=PlanStrategy.BACKTRACK,
                minimum_capability=minimum,
            )

        if plan.strategy is PlanStrategy.BACKTRACK:
            if not plan.hypothesis.strip():
                return ControlDecision(False, "backtrack requires a replacement hypothesis")
            current_statement = self._current_statement(state_snapshot, current)
            if current_statement and proposed_statement == current_statement:
                return ControlDecision(
                    False,
                    "backtrack must leave the current hypothesis",
                    required_strategy=PlanStrategy.BACKTRACK,
                )
            if not plan.expected_evidence.strip():
                return ControlDecision(False, "backtrack requires new expected_evidence")
            return ControlDecision(True)

        if plan.strategy is PlanStrategy.ESCALATE:
            spec = tool_by_name.get(plan.action.name)
            if spec is None:
                return ControlDecision(False, "escalation selected a non-tool action")
            if spec.capability < minimum:
                return ControlDecision(
                    False,
                    f"escalation requires capability >= {int(minimum)}",
                    required_strategy=PlanStrategy.ESCALATE,
                    minimum_capability=minimum,
                )
            return ControlDecision(True)

        # VERIFY is allowed under stagnation because a successful verifier result is
        # authoritative new evidence; a failed verification will challenge the branch.
        return ControlDecision(True)

    @staticmethod
    def _current_statement(snapshot: dict[str, object], current: object) -> str:
        if not isinstance(current, str):
            return ""
        hypotheses = snapshot.get("hypotheses")
        if not isinstance(hypotheses, list):
            return ""
        for raw in hypotheses:
            if isinstance(raw, dict) and raw.get("id") == current:
                statement = raw.get("statement")
                if isinstance(statement, str):
                    return " ".join(statement.casefold().split())
        return ""

    @staticmethod
    def _minimum_capability(snapshot: dict[str, object]) -> CapabilityLevel:
        raw = snapshot.get("recommended_capability_level", 0)
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 0
        value = max(int(CapabilityLevel.INSPECT), min(int(CapabilityLevel.MUTATE), value))
        return CapabilityLevel(value)
