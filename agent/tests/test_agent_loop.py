from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from agent.core.contracts import (  # noqa: E402
    ContractError,
    build_task_contract,
    exact_file_requests,
)
from agent.core.loop import (  # noqa: E402
    AgentLoop,
    DeterministicDriver,
    ScriptedDriver,
)
from agent.core.models import AgentAction, LoopLimits  # noqa: E402
from agent.core.playbooks import PlaybookError, load_playbook  # noqa: E402
from agent.strategies import classify_instruction  # noqa: E402
from agent.validators import CommandSpec  # noqa: E402
from agent.tests.test_forensics_tools import build_fixture  # noqa: E402


VULNERABLE_LOGIN = '''
async def login(conn, req):
    query = (
        f"SELECT id FROM users "
        f"WHERE username = '{req.username}' AND password = '{req.password}'"
    )
    return await conn.fetchrow(query)
'''.lstrip()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


class ContractAndPlaybookTests(unittest.TestCase):
    def test_exact_file_contract_maps_app_to_actual_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            instruction = (
                "Create a file at `/app/output.txt` whose entire content is "
                "exactly the single word `Ready`."
            )
            requests = exact_file_requests(instruction, root)
            self.assertEqual(requests, ((root / "output.txt", "Ready"),))
            contract = build_task_contract(
                classify_instruction(instruction), instruction, root
            )
            self.assertEqual(contract.artifacts[0].kind, "exact-text")
            self.assertEqual(contract.artifacts[0].expected_text, "Ready")

    def test_exact_file_contract_rejects_external_absolute_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            with self.assertRaises(ContractError):
                exact_file_requests(
                    "Create a file at `/etc/passwd` whose content is exactly `x`.",
                    root,
                )

    def test_playbook_loader_is_bounded_to_agent_directory(self):
        self.assertIn("# Audit playbook", load_playbook("agent/playbooks/audit.md"))
        with self.assertRaises(PlaybookError):
            load_playbook("README.md")
        with self.assertRaises(PlaybookError):
            load_playbook("../../etc/passwd")


class DeterministicAgentLoopTests(unittest.TestCase):
    def test_general_exact_file_task_succeeds_only_after_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = AgentLoop(workdir=root).run(
                "Create a file at `/app/hello.txt` whose entire content is "
                "exactly the single word `Hello`."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual((root / "hello.txt").read_text(encoding="utf-8"), "Hello")
            self.assertEqual(result.validations_used, 1)
            self.assertTrue(result.final_validation.passed)  # type: ignore[union-attr]

    def test_audit_creates_report_without_changing_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "routers" / "auth.py"
            write_text(source, VULNERABLE_LOGIN)
            before = source.read_bytes()
            result = AgentLoop(workdir=root).run(
                "Audit /app for vulnerabilities. Do not modify source code. "
                "Write a machine-readable security_report.json."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual(source.read_bytes(), before)
            payload = json.loads((root / "security_report.json").read_text())
            self.assertEqual(len(payload["findings"]), 1)
            changes = result.final_validation.report.changes  # type: ignore[union-attr]
            self.assertEqual(changes.added, ("security_report.json",))

    def test_fix_scans_parameterizes_and_rescans_before_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "routers" / "auth.py"
            write_text(source, VULNERABLE_LOGIN)
            result = AgentLoop(workdir=root).run(
                "Fix the SQL injection vulnerability in the application code."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            updated = source.read_text(encoding="utf-8")
            self.assertIn("username = $1 AND password = $2", updated)
            self.assertIn("fetchrow(query, req.username, req.password)", updated)
            names = [event.action.name for event in result.events if event.action]
            self.assertEqual(
                names,
                ["security_scan", "sql_parameterize", "security_scan", "finish"],
            )

    def test_fix_does_not_claim_success_when_no_supported_change_exists(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "safe.py", "value = 1\n")
            result = AgentLoop(
                workdir=root,
                limits=LoopLimits(max_validations=1),
            ).run("Fix the security vulnerability in the application code.")
            self.assertFalse(result.succeeded)
            self.assertIn("no project change", result.reason)

    def test_forensics_writes_correlated_report_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            incident = build_fixture(
                root,
                attacker_ip="203.0.113.77",
                user="alice",
                exfil_bytes=424242,
                timestamp="2030-02-02T03:04:05.000Z",
                request_id="req-main",
            )
            evidence_before = {
                path.relative_to(incident): path.read_bytes()
                for path in incident.rglob("*")
                if path.is_file()
            }
            result = AgentLoop(workdir=root).run(
                "Analyze the incident logs and write incident_report.txt."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual(
                (root / "incident_report.txt").read_text(encoding="utf-8"),
                "attacker_ip=203.0.113.77\n"
                "compromised_user=alice\n"
                "exfil_bytes=424242\n"
                "first_malicious_event_utc=2030-02-02T03:04:05.000Z\n",
            )
            evidence_after = {
                path.relative_to(incident): path.read_bytes()
                for path in incident.rglob("*")
                if path.is_file()
            }
            self.assertEqual(evidence_after, evidence_before)

    def test_unknown_general_task_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = AgentLoop(workdir=Path(tmp)).run("Explain this unknown task.")
            self.assertFalse(result.succeeded)
            self.assertIn("future LLM driver", result.reason)


class RetryBudgetAndPolicyTests(unittest.TestCase):
    def test_failed_validation_is_returned_to_driver_for_retry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver = ScriptedDriver(
                [
                    AgentAction("finish"),
                    AgentAction(
                        "write_exact_text",
                        {"path": str(root / "answer.txt"), "content": "ok"},
                    ),
                    AgentAction("finish"),
                ]
            )
            result = AgentLoop(workdir=root, driver=driver).run(
                "Create a file at `/app/answer.txt` whose content is exactly `ok`."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual(result.validations_used, 2)
            validations = [event.validation for event in result.events if event.validation]
            self.assertEqual([item.passed for item in validations], [False, True])

    def test_failing_project_command_prevents_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            driver = ScriptedDriver(
                [
                    AgentAction(
                        "write_exact_text",
                        {"path": str(root / "answer.txt"), "content": "ok"},
                    ),
                    AgentAction("finish"),
                ]
            )
            command = CommandSpec(
                "project-tests",
                (sys.executable, "-c", "raise SystemExit(7)"),
                10,
            )
            result = AgentLoop(
                workdir=root,
                driver=driver,
                validation_commands=(command,),
                limits=LoopLimits(max_validations=1),
            ).run(
                "Create a file at `/app/answer.txt` whose content is exactly `ok`."
            )
            self.assertFalse(result.succeeded)
            self.assertIn("validation failed", result.reason)
            checks = result.final_validation.report.checks  # type: ignore[union-attr]
            self.assertFalse(next(check for check in checks if check.name == "project-tests").passed)

    def test_mode_policy_rejects_a_fix_tool_during_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "auth.py", VULNERABLE_LOGIN)
            result = AgentLoop(
                workdir=root,
                driver=ScriptedDriver(
                    [
                        AgentAction("sql_parameterize"),
                        AgentAction("abort", rationale="stop after policy check"),
                    ]
                ),
            ).run("Do not modify code; create security_report.json.")
            self.assertFalse(result.succeeded)
            tool_result = result.events[0].tool_result
            self.assertFalse(tool_result.ok)  # type: ignore[union-attr]
            self.assertIn("forbidden", tool_result.summary)  # type: ignore[union-attr]
            self.assertEqual((root / "auth.py").read_text(), VULNERABLE_LOGIN)

    def test_fix_tool_refuses_direct_protected_test_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            test_source = root / "tests" / "test_auth.py"
            write_text(test_source, VULNERABLE_LOGIN)
            result = AgentLoop(
                workdir=root,
                driver=ScriptedDriver(
                    [
                        AgentAction(
                            "sql_parameterize", {"target": str(test_source)}
                        ),
                        AgentAction("abort", rationale="expected refusal"),
                    ]
                ),
            ).run("Fix the SQL injection vulnerability.")
            self.assertFalse(result.succeeded)
            self.assertIn(
                "protected analysis target",
                result.events[0].tool_result.summary,  # type: ignore[union-attr]
            )
            self.assertEqual(test_source.read_text(), VULNERABLE_LOGIN)

    def test_write_tool_rejects_path_outside_workdir(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as out:
            root = Path(tmp)
            external = Path(out) / "answer.txt"
            result = AgentLoop(
                workdir=root,
                driver=ScriptedDriver(
                    [
                        AgentAction(
                            "write_exact_text",
                            {"path": str(external), "content": "ok"},
                        ),
                        AgentAction("abort", rationale="expected refusal"),
                    ]
                ),
            ).run(
                "Create a file at `/app/answer.txt` whose content is exactly `ok`."
            )
            self.assertFalse(result.succeeded)
            self.assertFalse(external.exists())
            self.assertIn("outside workdir", result.events[0].tool_result.summary)  # type: ignore[union-attr]

    def test_repeated_action_budget_stops_a_loop(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            action = AgentAction(
                "write_exact_text",
                {"path": str(root / "answer.txt"), "content": "ok"},
            )
            result = AgentLoop(
                workdir=root,
                driver=ScriptedDriver([action, action, action]),
                limits=LoopLimits(max_repeated_action=2),
            ).run(
                "Create a file at `/app/answer.txt` whose content is exactly `ok`."
            )
            self.assertFalse(result.succeeded)
            self.assertIn("repeated-action budget", result.reason)
            self.assertEqual(result.steps_used, 2)

    def test_deadline_budget_is_checked_before_first_action(self):
        values = iter((0.0, 10.0))
        with tempfile.TemporaryDirectory() as tmp:
            result = AgentLoop(
                workdir=Path(tmp),
                driver=DeterministicDriver(),
                limits=LoopLimits(deadline_seconds=5),
                clock=lambda: next(values),
            ).run("Explain this unknown task.")
            self.assertFalse(result.succeeded)
            self.assertIn("deadline budget", result.reason)
            self.assertEqual(result.steps_used, 0)

    def test_invalid_non_json_action_arguments_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = AgentLoop(
                workdir=Path(tmp),
                driver=ScriptedDriver(
                    [AgentAction("write_exact_text", {"path": Path("answer.txt")})]
                ),
            ).run(
                "Create a file at `/app/answer.txt` whose content is exactly `ok`."
            )
            self.assertFalse(result.succeeded)
            self.assertIn("JSON-serializable", result.reason)

    def test_finish_action_rejects_unused_arguments(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = AgentLoop(
                workdir=Path(tmp),
                driver=ScriptedDriver([AgentAction("finish", {"passed": True})]),
            ).run("Explain this unknown task.")
            self.assertFalse(result.succeeded)
            self.assertIn("must not have arguments", result.reason)


class AgentLoopCliTests(unittest.TestCase):
    def test_cli_returns_zero_and_prints_machine_readable_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "agent.core.loop",
                    "Create a file at `/app/result.txt` whose content is exactly `done`.",
                    "--workdir",
                    tmp,
                ],
                cwd=REPO_ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
            self.assertEqual(process.stderr, "")
            payload = json.loads(process.stdout)
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(Path(tmp, "result.txt").read_text(), "done")


if __name__ == "__main__":
    unittest.main()
