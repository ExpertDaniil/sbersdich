from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction, LoopEvent, TaskContract, ToolResult
from agent.core.project_checks import discover_project_checks
from agent.scaffold.contracts import PlanningContext
from agent.scaffold.planner import DeterministicFastPath
from agent.strategies import classify_instruction


AUTH_BUG_INSTRUCTION = (
    "There is an authorization bug in this project. Find the root cause, "
    "make the smallest safe fix, and prove the fix using the existing tests."
)


class TestGovnoOneIntegrationTests(unittest.TestCase):
    def test_authorization_bug_instruction_routes_to_fix(self) -> None:
        decision = classify_instruction(AUTH_BUG_INSTRUCTION)
        self.assertEqual(decision.mode, "fix")
        self.assertTrue(decision.should_modify_project)
        self.assertEqual(decision.confidence, "high")

    def test_do_not_fix_instruction_stays_non_mutating(self) -> None:
        decision = classify_instruction(
            "Audit the authorization bug, but do not fix or change the project."
        )
        self.assertEqual(decision.mode, "audit")
        self.assertFalse(decision.should_modify_project)

    def test_root_level_pytest_suite_is_frozen_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "access.py").write_text(
                'def can_delete(user):\n    return user.get("role") != "guest"\n',
                encoding="utf-8",
            )
            (root / "test_access.py").write_text(
                "from access import can_delete\n\n"
                "def test_admin_can_delete():\n"
                '    assert can_delete({"role": "admin"})\n',
                encoding="utf-8",
            )
            plan = discover_project_checks(AUTH_BUG_INSTRUCTION, root)

        self.assertFalse(plan.error)
        self.assertEqual(len(plan.commands), 1)
        self.assertEqual(plan.sources, ("Python root-test discovery",))
        self.assertEqual(plan.commands[0].argv[-1], ".")

    def test_clean_sql_scan_yields_unrelated_fix_to_model(self) -> None:
        decision = classify_instruction(AUTH_BUG_INSTRUCTION)
        scan_event = LoopEvent(
            1,
            "acting",
            action=AgentAction(
                "security_scan",
                {"write_report": False},
                "probe narrow SQL fast path",
            ),
            tool_result=ToolResult(
                True,
                "security scan completed with 0 finding(s)",
                {"finding_count": 0, "report": None},
            ),
        )
        context = PlanningContext(
            instruction=AUTH_BUG_INSTRUCTION,
            workdir=Path("/tmp/auth-bug"),
            decision=decision,
            task_playbook="",
            validation_playbook="",
            contract=TaskContract(),
            tools=(),
            state_snapshot={},
            events=(scan_event,),
            last_validation=None,
            remaining_seconds=30.0,
        )

        self.assertIsNone(DeterministicFastPath().try_plan(context))

    def test_positive_sql_scan_keeps_supported_fast_path(self) -> None:
        decision = classify_instruction(
            "Find and fix the SQL injection vulnerability, then run the tests."
        )
        scan_event = LoopEvent(
            1,
            "acting",
            action=AgentAction("security_scan", {"write_report": False}, "scan"),
            tool_result=ToolResult(
                True,
                "security scan completed with 1 finding(s)",
                {"finding_count": 1, "report": None},
            ),
        )
        context = PlanningContext(
            instruction="Find and fix the SQL injection vulnerability, then run the tests.",
            workdir=Path("/tmp/sql-bug"),
            decision=decision,
            task_playbook="",
            validation_playbook="",
            contract=TaskContract(),
            tools=(),
            state_snapshot={},
            events=(scan_event,),
            last_validation=None,
            remaining_seconds=30.0,
        )

        plan = DeterministicFastPath().try_plan(context)
        self.assertIsNotNone(plan)
        assert plan is not None
        self.assertEqual(plan.action.name, "sql_parameterize")


if __name__ == "__main__":
    unittest.main()
