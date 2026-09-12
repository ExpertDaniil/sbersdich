from __future__ import annotations

import json
import unittest

from agent.core.models import AgentAction, ToolResult
from agent.scaffold.contracts import PlanDecision, PlanStrategy, ScaffoldRunResult
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
        self.assertEqual(
            snapshot["hypotheses"][0]["hypothesis_status"], "challenged"
        )
        self.assertNotIn("status", snapshot["hypotheses"][0])

    def test_inventory_tracks_files_that_have_not_been_opened(self):
        state = AgentState("correlate all evidence", "forensics")
        state.record_tool_event(
            1,
            AgentAction("list_files", {"path": "evidence"}),
            ToolResult(
                True,
                "listed evidence",
                {"entries": [{"path": "evidence/auth.jsonl"},
                              {"path": "evidence/app.jsonl"}]},
            ),
        )
        state.record_tool_event(
            2,
            AgentAction("read_file", {"path": "evidence/auth.jsonl"}),
            ToolResult(True, "read auth", {"path": "evidence/auth.jsonl"}),
        )

        snapshot = state.snapshot(())

        self.assertEqual(
            snapshot["inventory_not_opened_by_tools"], ["evidence/app.jsonl"]
        )

    def test_historical_checked_edit_does_not_repeat_source_in_prompt_state(self):
        state = AgentState("fix the source", "fix")
        replacement = "x = 1\n" * 500
        action = AgentAction("checked_edit", {
            "path": "app.py",
            "start_line": 1,
            "end_line": 1,
            "replacement": replacement,
            "expected_sha256": "a" * 64,
        })
        state.record_tool_event(
            1,
            action,
            ToolResult(True, "edited", {"path": "app.py", "written": True}),
        )

        arguments = state.snapshot(())["recent_events"][0]["action"]["arguments"]

        self.assertNotIn(replacement, arguments.values())
        self.assertIn(str(len(replacement)), arguments["replacement"])

    def test_run_status_is_the_last_serialized_status_field(self):
        result = ScaffoldRunResult(
            status="failed",
            reason="not complete",
            decision=None,
            steps_used=1,
            validations_used=0,
            events=(),
            final_validation=None,
            state={"legacy_nested": {"status": "challenged"}},
        )

        payload = result.as_payload()
        encoded = json.dumps(payload)

        self.assertEqual(list(payload)[-1], "status")
        self.assertGreater(encoded.rfind('"status": "failed"'),
                           encoded.rfind('"status": "challenged"'))


if __name__ == "__main__":
    unittest.main()
