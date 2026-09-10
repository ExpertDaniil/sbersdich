from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.project_checks import discover_project_checks
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


if __name__ == "__main__":
    unittest.main()
