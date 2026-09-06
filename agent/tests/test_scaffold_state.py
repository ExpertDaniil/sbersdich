from __future__ import annotations

import unittest

from agent.core.models import AgentAction, ToolResult
from agent.scaffold.contracts import PlanDecision, PlanStrategy
from agent.scaffold.state import AgentState


class ScaffoldStateTests(unittest.TestCase):
    def test_model_hypothesis_is_not_trusted_evidence(self):
        state = AgentState("inspect project", "audit")
        plan = PlanDecision(
            AgentAction("search_text", {"query": "eval"}),
            PlanStrategy.BRANCH,
            "user input may reach eval",
            0.6,
            "a source-to-sink call path",
        )
        state.register_plan(plan, step=1)
        snapshot = state.snapshot(())
        self.assertEqual(len(snapshot["hypotheses"]), 1)
        self.assertEqual(snapshot["evidence"], [])

    def test_only_tool_results_enter_evidence_ledger(self):
        state = AgentState("inspect project", "audit")
        plan = PlanDecision(
            AgentAction("search_text", {"query": "eval"}),
            hypothesis="eval may be reachable",
        )
        state.register_plan(plan, step=1)
        state.record_tool_event(
            1,
            plan.action,
            ToolResult(True, "found one match", {"path": "app.py", "line": 8}),
        )
        snapshot = state.snapshot(())
        self.assertEqual(len(snapshot["evidence"]), 1)
        self.assertEqual(snapshot["evidence"][0]["source"], "tool")
        self.assertEqual(snapshot["evidence"][0]["hypothesis_id"], "H01")

    def test_repeated_observation_requests_recovery(self):
        state = AgentState("inspect project", "audit")
        action = AgentAction("search_text", {"query": "eval"})
        plan = PlanDecision(action, hypothesis="eval may be reachable")
        state.register_plan(plan, step=1)
        result = ToolResult(True, "same", {"match_count": 0})
        state.record_tool_event(1, action, result)
        state.record_tool_event(2, action, result)
        self.assertFalse(state.recovery_required)
        state.record_tool_event(3, action, result)
        self.assertTrue(state.recovery_required)

    def test_failed_probe_challenges_linked_hypothesis(self):
        state = AgentState("inspect project", "general")
        action = AgentAction("run_command", {"argv": ["pytest"]})
        state.register_plan(PlanDecision(action, hypothesis="tests reproduce the bug"), step=1)
        state.record_tool_event(1, action, ToolResult(False, "test failed to start"))
        snapshot = state.snapshot(())
        self.assertEqual(snapshot["hypotheses"][0]["status"], "challenged")


if __name__ == "__main__":
    unittest.main()
