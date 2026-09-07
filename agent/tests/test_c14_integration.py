"""Regression tests for CTF completion through the actual production composition."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.bootstrap import build_default_application
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext, KernelLimits, PlanDecision
from agent.strategies import classify_instruction


class ActionPlans:
    def __init__(self, actions, before_first_action=None):
        self.actions = iter(actions)
        self.before_first_action = before_first_action

    def next_plan(self, context):
        if self.before_first_action is not None:
            hook, self.before_first_action = self.before_first_action, None
            hook()
        return PlanDecision(next(self.actions, AgentAction("abort", rationale="test plan exhausted")))


def run_scaffold(root, instruction, actions, before_first_action=None):
    app = build_default_application(workdir=root, limits=KernelLimits(max_validations=1))
    app.kernel.planner = ActionPlans(actions, before_first_action)
    return app.run(instruction)


class C14ProductionIntegrationTests(unittest.TestCase):
    def test_production_catalog_exposes_ctf_without_project_mutation_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = build_default_application(workdir=root)
            decision = classify_instruction("CTF: write the flag to `/app/flag.txt`.")
            context = ExecutionContext(root, decision, CapabilityLevel.MUTATE)
            names = {tool.name for tool in app.kernel.tool_bus.catalog(context)}
            self.assertTrue({"ctf_transform", "read_file", "read_bytes", "write_exact_text"} <= names)
            self.assertFalse({"apply_patch", "run_command", "run_check", "checked_edit", "arena_evaluate", "arena_promote"} & names)

    def test_missing_answer_contract_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_scaffold(Path(tmp), "CTF challenge: recover the flag.", [
                AgentAction("ctf_transform", {"value": "41", "steps": [{"operation": "hex"}]}),
                AgentAction("finish"),
            ])
            self.assertFalse(result.succeeded)
            self.assertIn("no explicit answer artifact", result.reason)

    def test_existing_answer_read_is_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "flag.txt").write_text("FLAG{old}", encoding="utf-8")
            result = run_scaffold(root, "CTF: write the flag to `/app/flag.txt`.", [
                AgentAction("read_file", {"path": "/app/flag.txt"}), AgentAction("finish"),
            ])
            self.assertFalse(result.succeeded)
            self.assertIn("was not produced during this run", result.reason)

    def test_valid_answer_does_not_require_compilable_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "fragment.py"
            evidence.write_bytes(b"def truncated(\r\n")
            result = run_scaffold(root, "CTF: write the flag to `/app/flag.txt`.", [
                AgentAction("ctf_transform", {"value": "464c41477b6e65777d", "steps": [{"operation": "hex"}]}),
                AgentAction("write_exact_text", {"path": "/app/flag.txt", "content": "FLAG{new}"}),
                AgentAction("finish"),
            ])
            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual(evidence.read_bytes(), b"def truncated(\r\n")
            self.assertEqual((root / "flag.txt").read_bytes(), b"FLAG{new}")
            checks = result.final_validation.feedback.report.checks
            self.assertNotIn("python-syntax", {check.name for check in checks})

    def test_general_mode_keeps_python_syntax_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "fragment.py").write_text("def broken(\n", encoding="utf-8")
            result = run_scaffold(root, "Create a file at `/app/answer.txt` whose content is exactly `ok`.", [
                AgentAction("write_exact_text", {"path": "/app/answer.txt", "content": "ok"}),
                AgentAction("finish"),
            ])
            self.assertFalse(result.succeeded)
            checks = result.final_validation.feedback.report.checks
            self.assertTrue(any(c.name == "python-syntax" and not c.passed for c in checks))

    def test_modification_of_challenge_evidence_prevents_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "clue.txt").write_text("original", encoding="utf-8")
            result = run_scaffold(root, "CTF: write the flag to `/app/flag.txt`.", [
                AgentAction("write_exact_text", {"path": "/app/flag.txt", "content": "FLAG{new}"}),
                AgentAction("write_exact_text", {"path": "/app/clue.txt", "content": "changed"}),
                AgentAction("finish"),
            ])
            self.assertFalse(result.succeeded)
            self.assertIn("validation failed", result.reason)

    def test_every_answer_needs_its_own_successful_write_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "CTF: write the flag to `/app/a.txt`. Save the answer to `/app/b.txt`."
            result = run_scaffold(root, instruction, [
                AgentAction("write_exact_text", {"path": "/app/a.txt", "content": "FLAG{a}"}),
                AgentAction("finish"),
            ], before_first_action=lambda: (root / "b.txt").write_text("FLAG{unattributed}", encoding="utf-8"))
            self.assertFalse(result.succeeded)
            self.assertIn("successful answer write for every artifact", result.reason)

    def test_multiple_outputs_and_unicode_native_paths_work(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "рабочая папка"
            root.mkdir()
            answer = root / "ответ.txt"
            result = run_scaffold(root,
                "CTF: write the flag to `/app/ответ.txt`. Save the answer to `/app/nested/b.txt`.", [
                    AgentAction("write_exact_text", {"path": str(answer), "content": "FLAG{a}"}),
                    AgentAction("write_exact_text", {"path": "/app/nested/b.txt", "content": "FLAG{b}"}),
                    AgentAction("finish"),
                ])
            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual(answer.read_bytes(), b"FLAG{a}")

    def test_outside_path_cannot_create_an_answer(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "workspace"
            root.mkdir()
            outside = Path(tmp) / "outside.txt"
            result = run_scaffold(root, "CTF: write the flag to `/app/flag.txt`.", [
                AgentAction("write_exact_text", {"path": str(outside), "content": "FLAG{bad}"}),
                AgentAction("finish"),
            ])
            self.assertFalse(result.succeeded)
            self.assertFalse(outside.exists())
            self.assertFalse(result.events[0].tool_result.ok)


if __name__ == "__main__":
    unittest.main()
