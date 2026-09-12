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
        if plan.strategy is PlanStrategy.CONTINUE and self._changes_probe(
            plan, state_snapshot
        ):
            # Recovery is about forcing observable progress, not forcing the
            # model to abandon a hypothesis that may already be correct.  A
            # different tool family or a new collection member is a legitimate
            # next probe even when the prior observation was duplicated.
            return ControlDecision(True)
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
    def _changes_probe(
        plan: PlanDecision, snapshot: dict[str, object]
    ) -> bool:
        recent = snapshot.get("recent_events")
        if not isinstance(recent, list) or not recent:
            return False
        latest = recent[-1]
        if not isinstance(latest, dict):
            return False
        previous = latest.get("action")
        if not isinstance(previous, dict):
            return False
        previous_name = previous.get("name")
        if isinstance(previous_name, str) and previous_name != plan.action.name:
            return True
        previous_arguments = previous.get("arguments")
        if not isinstance(previous_arguments, dict):
            return False
        current_arguments = plan.action.arguments
        # Only evidence-target selectors count. Cosmetic argument changes do
        # not bypass stagnation control.
        selectors = ("path", "paths", "offset", "query", "target")
        return any(
            key in current_arguments
            and current_arguments.get(key) != previous_arguments.get(key)
            for key in selectors
        )

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
