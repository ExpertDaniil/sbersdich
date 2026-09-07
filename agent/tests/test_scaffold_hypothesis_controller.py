from __future__ import annotations

import unittest

from agent.core.models import AgentAction, ToolResult
from agent.scaffold.contracts import (
    CapabilityLevel,
    PlanDecision,
    PlanStrategy,
    ToolSpec,
)
from agent.scaffold.hypothesis_controller import RuntimeHypothesisController
from agent.scaffold.state import AgentState


TOOLS = (
    ToolSpec("read", "", {}, ("general",), CapabilityLevel.INSPECT),
    ToolSpec("analyze", "", {}, ("general",), CapabilityLevel.ANALYZE),
    ToolSpec("run", "", {}, ("general",), CapabilityLevel.EXECUTE),
)


class RuntimeHypothesisControllerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.controller = RuntimeHypothesisController()

    def _stagnant_snapshot(self):
        state = AgentState("debug", "general")
        action = AgentAction("read", {"path": "app.py"})
        plan = PlanDecision(action, hypothesis="bug is in parser")
        state.register_plan(plan, step=1)
        same = ToolResult(True, "same observation", {"line": 10})
        state.record_tool_event(1, action, same)
        state.record_tool_event(2, action, same)
        state.record_tool_event(3, action, same)
        return state.snapshot(TOOLS)

    def test_branch_requires_falsifiable_expected_evidence(self):
        decision = self.controller.evaluate(
            PlanDecision(
                AgentAction("read", {"path": "app.py"}),
                PlanStrategy.BRANCH,
                "parser may truncate input",
                0.5,
                "",
            ),
            state_snapshot=AgentState("x", "general").snapshot(TOOLS),
            tools=TOOLS,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("expected_evidence", decision.reason)

    def test_stagnation_rejects_plain_continue(self):
        decision = self.controller.evaluate(
            PlanDecision(
                AgentAction("read", {"path": "app.py"}),
                PlanStrategy.CONTINUE,
                "bug is in parser",
            ),
            state_snapshot=self._stagnant_snapshot(),
            tools=TOOLS,
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.required_strategy, PlanStrategy.BACKTRACK)

    def test_backtrack_must_change_hypothesis(self):
        decision = self.controller.evaluate(
            PlanDecision(
                AgentAction("read", {"path": "other.py"}),
                PlanStrategy.BACKTRACK,
                "bug is in parser",
                0.4,
                "different file contradicts parser hypothesis",
            ),
            state_snapshot=self._stagnant_snapshot(),
            tools=TOOLS,
        )
        self.assertFalse(decision.allowed)
        self.assertIn("leave the current hypothesis", decision.reason)

    def test_backtrack_to_new_hypothesis_is_allowed(self):
        decision = self.controller.evaluate(
            PlanDecision(
                AgentAction("read", {"path": "transport.py"}),
                PlanStrategy.BACKTRACK,
                "bug is in transport framing",
                0.4,
                "framing code explains the malformed length",
            ),
            state_snapshot=self._stagnant_snapshot(),
            tools=TOOLS,
        )
        self.assertTrue(decision.allowed)

    def test_escalation_must_reach_recommended_capability(self):
        snapshot = self._stagnant_snapshot()
        self.assertEqual(snapshot["recommended_capability_level"], 1)
        weak = self.controller.evaluate(
            PlanDecision(AgentAction("read", {}), PlanStrategy.ESCALATE),
            state_snapshot=snapshot,
            tools=TOOLS,
        )
        strong = self.controller.evaluate(
            PlanDecision(AgentAction("analyze", {}), PlanStrategy.ESCALATE),
            state_snapshot=snapshot,
            tools=TOOLS,
        )
        self.assertFalse(weak.allowed)
        self.assertTrue(strong.allowed)


if __name__ == "__main__":
    unittest.main()
