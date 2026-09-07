"""C15 unit checks plus real pytest integration when pytest is installed locally."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from agent.core.contracts import build_task_contract
from agent.core.fix_validation import run_project_check, validate_fix_task
from agent.core.loop import AgentLoop
from agent.core.models import AgentAction, LoopLimits
from agent.core.project_checks import ProjectCheckPlan, discover_project_checks, project_python
from agent.scaffold.bootstrap import build_default_application
from agent.scaffold.contracts import KernelLimits, PlanDecision, PlanStrategy
from agent.scaffold.packaging import build_submission
from agent.strategies import classify_instruction
from agent.validators import CommandSpec, ValidationPolicy, capture_snapshot


HAS_PYTEST = importlib.util.find_spec("pytest") is not None
FIX_INSTRUCTION = "Fix the SQL injection vulnerability in the application code."
VULNERABLE = '''async def login(conn, req):
    query = f"SELECT id FROM users WHERE username = '{req.username}' AND password = '{req.password}'"
    return await conn.fetchrow(query)
'''
SAFE = '''async def login(conn, req):
    query = "SELECT id FROM users WHERE username = $1 AND password = $2"
    return await conn.fetchrow(query, req.username, req.password)
'''
PROJECT_TESTS = '''import asyncio
import sqlite3
from types import SimpleNamespace
from auth import login

class Connection:
    async def fetchrow(self, query, *args):
        db = sqlite3.connect(":memory:")
        try:
            db.execute("CREATE TABLE users (id INTEGER, username TEXT, password TEXT)")
            db.execute("INSERT INTO users VALUES (?, ?, ?)", (7, "alice", "secret"))
            return db.execute(query.replace("$1", "?").replace("$2", "?"), args).fetchone()
        finally:
            db.close()

def invoke(username, password):
    return asyncio.run(login(Connection(), SimpleNamespace(username=username, password=password)))

def test_valid_login():
    assert invoke("alice", "secret") == (7,)

def test_invalid_password():
    assert invoke("alice", "incorrect") is None

def test_injection_is_not_authenticated():
    assert invoke("' OR 1=1 -- ", "incorrect") is None
'''


def write_project(root: Path, *, regression: bool = False) -> None:
    (root / "tests").mkdir(parents=True)
    (root / "auth.py").write_bytes(VULNERABLE.encode("utf-8"))
    (root / "AGENTS.md").write_bytes(b"# Required Verification\r\nAfter code changes run `pytest tests/`.\r\n")
    tests = PROJECT_TESTS
    if regression:
        tests += "\ndef test_other_regression():\n    assert False, 'existing behavior broke'\n"
    (root / "tests" / "test_login.py").write_bytes(tests.encode("utf-8"))


class ProjectCheckDiscoveryTests(unittest.TestCase):
    def test_agents_command_is_captured_before_editing_with_crlf_and_unicode_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "проект с пробелами"
            write_project(root)
            contract = build_task_contract(classify_instruction(FIX_INSTRUCTION), FIX_INSTRUCTION, root)
            (root / "AGENTS.md").write_bytes(b"No checks now.\n")
            self.assertEqual(contract.project_checks.commands[0].argv[1:], ("-m", "pytest", "tests"))
            self.assertEqual(contract.project_checks.sources, ("AGENTS.md",))

    def test_equivalent_inline_and_fenced_commands_are_deduplicated(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = discover_project_checks("Run `pytest tests/`.\n```sh\npython3 -m pytest tests/\n```", Path(tmp))
            self.assertEqual(len(plan.commands), 1)
            self.assertFalse(plan.error)

    def test_virtual_app_and_quoted_test_path_are_mapped(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = discover_project_checks('Run `python -m pytest -q "/app/tests/unit cases"`.', Path(tmp))
            self.assertFalse(plan.error)
            self.assertEqual(plan.commands[0].argv[1:], ("-m", "pytest", "-q", "tests/unit cases"))

    def test_existing_python_suite_is_discovered_without_agents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "tests").mkdir()
            (root / "tests" / "test_example.py").write_bytes(b"def test_ok(): pass\n")
            self.assertEqual(len(discover_project_checks(FIX_INSTRUCTION, root).commands), 1)

    def test_missing_explicit_test_directory_does_not_remove_requirement(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = discover_project_checks("Run `pytest tests/`.", Path(tmp))
            self.assertEqual(len(plan.commands), 1)

    def test_shell_operators_collection_only_and_external_paths_fail_closed(self):
        commands = ("pytest tests/ || true", "pytest tests/; echo ok", "pytest --collect-only tests/",
                    "pytest ../tests", "pytest /tests", "pytest --ignore=tests tests/", "pytest /app/../tests")
        with tempfile.TemporaryDirectory() as tmp:
            for command in commands:
                with self.subTest(command=command):
                    self.assertTrue(discover_project_checks(f"Run `{command}`.", Path(tmp)).error)

    def test_local_venv_python_path_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / (".venv/Scripts/python.exe" if os.name == "nt" else ".venv/bin/python")
            target.parent.mkdir(parents=True)
            target.write_bytes(b"fixture executable path, not executed")
            self.assertEqual(project_python(root), str(target))

    def test_other_modes_do_not_acquire_fix_test_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root)
            for instruction in ("Audit code without modifying it. Write security_report.json.",
                                "Create a file at `/app/result.txt` whose content is exactly `ok`.",
                                "Solve this CTF and write the flag to `/app/flag.txt`."):
                with self.subTest(instruction=instruction):
                    contract = build_task_contract(classify_instruction(instruction), instruction, root)
                    self.assertIsNone(contract.project_checks)


class ProjectCheckProcessTests(unittest.TestCase):
    def run_python(self, code, *, timeout=5):
        with tempfile.TemporaryDirectory() as tmp:
            return run_project_check(CommandSpec("project-tests-1", (sys.executable, "-c", code)),
                                     Path(tmp), timeout=timeout)

    def test_success_has_captured_utf8_output(self):
        result = self.run_python("print('проверка выполнена')")
        self.assertTrue(result.passed, result.detail)
        self.assertIn("проверка выполнена", result.detail)
        self.assertIn("exit_code=0", result.detail)

    def test_nonzero_status_including_no_tests_is_failure(self):
        for status in (1, 2, 4, 5):
            with self.subTest(status=status):
                result = self.run_python(f"raise SystemExit({status})")
                self.assertFalse(result.passed)
                self.assertIn(f"exit_code={status}", result.detail)

    def test_timeout_is_bounded_and_fails(self):
        started = time.monotonic()
        result = self.run_python("import time; time.sleep(20)", timeout=0.2)
        self.assertFalse(result.passed)
        self.assertIn("timed out", result.detail)
        self.assertLess(time.monotonic() - started, 3)

    def test_missing_executable_is_a_reported_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_project_check(CommandSpec("project-tests-1", (str(Path(tmp) / "missing-python"),)),
                                       Path(tmp), timeout=1)
            self.assertFalse(result.passed)
            self.assertIn("failed to run", result.detail)

    def test_missing_pytest_module_does_not_trigger_installation_or_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_project_check(CommandSpec("project-tests-1",
                (sys.executable, "-I", "-S", "-m", "pytest", "tests")), Path(tmp), timeout=5)
            self.assertFalse(result.passed)
            self.assertIn("No module named pytest", result.detail)

    @unittest.skipUnless(os.name == "posix", "ACP process-group cleanup requires POSIX")
    def test_timeout_stops_descendants_in_the_acp_process_group(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            child = "import time; from pathlib import Path; time.sleep(0.8); Path('late.txt').write_text('orphan')"
            parent = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', " + repr(child) + "]); time.sleep(20)"
            result = run_project_check(CommandSpec("project-tests-1", (sys.executable, "-c", parent)), root, timeout=0.2)
            self.assertFalse(result.passed)
            time.sleep(0.9)
            self.assertFalse((root / "late.txt").exists())

    def test_verbose_and_invalid_utf8_output_is_bounded(self):
        result = self.run_python("import os; os.write(1, b'X' * 200000 + b'\\xffEND')")
        self.assertTrue(result.passed, result.detail)
        self.assertIn("truncated", result.detail)
        self.assertIn("END", result.detail)
        self.assertLess(len(result.detail), 5000)

    def test_model_credentials_and_external_pytest_options_are_not_inherited(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-secret", "PYTEST_ADDOPTS": "--collect-only"}):
            result = self.run_python("import os; assert 'OPENAI_API_KEY' not in os.environ; assert 'PYTEST_ADDOPTS' not in os.environ")
            self.assertTrue(result.passed, result.detail)


class FixValidationGateTests(unittest.TestCase):
    def test_explicit_custom_suite_and_root_test_files_are_protected(self):
        for name, instruction in (("verify_auth.py", "Run `pytest verify_auth.py`."),
                                  ("checks/custom.py", "Run `pytest checks/`."),
                                  ("test_root.py", "Run `pytest .`.")):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(b"def test_original(): assert False\n")
                plan = discover_project_checks(instruction, root)
                baseline = capture_snapshot(root)
                target.write_bytes(b"def test_original(): pass\n")
                with patch("agent.core.fix_validation.run_project_check") as runner:
                    report = validate_fix_task(ValidationPolicy("fix", root, baseline), plan)
                self.assertFalse(report.passed)
                runner.assert_not_called()

    def test_changed_test_configuration_is_rejected_before_any_command(self):
        for name in ("AGENTS.md", "conftest.py", "pytest.ini", "pytest.py", "tests/test_login.py"):
            with self.subTest(path=name), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_project(root)
                plan = discover_project_checks(FIX_INSTRUCTION, root)
                baseline = capture_snapshot(root)
                (root / name).write_bytes(b"# attempt to bypass tests\n")
                with patch("agent.core.fix_validation.run_project_check") as runner:
                    report = validate_fix_task(ValidationPolicy("fix", root, baseline), plan)
                self.assertFalse(report.passed)
                runner.assert_not_called()

    def test_tests_cannot_change_protected_files_during_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auth.py").write_bytes(b"VALUE = 0\n")
            baseline = capture_snapshot(root)
            (root / "auth.py").write_bytes(b"VALUE = 1\n")
            command = CommandSpec("project-tests-1", (sys.executable, "-c",
                "from pathlib import Path; Path('conftest.py').write_text('# changed')"))
            report = validate_fix_task(ValidationPolicy("fix", root, baseline), ProjectCheckPlan((command,)))
            self.assertFalse(report.passed)
            self.assertTrue(next(c for c in report.checks if c.name == "project-tests-1").passed)
            self.assertFalse(next(c for c in report.checks if c.name == "project-test-integrity").passed)

    def test_exhausted_remaining_budget_does_not_start_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root)
            policy = ValidationPolicy("fix", root, capture_snapshot(root))
            with patch("agent.core.fix_validation.run_project_check") as runner:
                report = validate_fix_task(policy, discover_project_checks(FIX_INSTRUCTION, root), remaining_seconds=0)
            self.assertFalse(report.passed)
            runner.assert_not_called()

    def test_project_check_timeout_uses_remaining_task_time(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "auth.py").write_bytes(b"VALUE = 1\n")
            command = CommandSpec("project-tests-1", (sys.executable, "-c", "import time; time.sleep(20)"))
            started = time.monotonic()
            report = validate_fix_task(ValidationPolicy("fix", root, capture_snapshot(root)),
                                      ProjectCheckPlan((command,)), remaining_seconds=0.4)
            self.assertFalse(report.passed)
            self.assertLess(time.monotonic() - started, 3)


@unittest.skipUnless(HAS_PYTEST, "real pytest integration requires locally installed pytest; no dependencies are installed by the agent")
class RealPytestIntegrationTests(unittest.TestCase):
    def test_vulnerable_fixture_fails_before_fix(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root)
            command = discover_project_checks(FIX_INSTRUCTION, root).commands[0]
            result = run_project_check(command, root, timeout=10)
            self.assertFalse(result.passed, result.detail)
            self.assertIn("test_injection_is_not_authenticated", result.detail)

    def test_both_agent_runtimes_execute_real_project_tests_after_fix(self):
        for runtime in ("core", "scaffold"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "проект с пробелами"
                write_project(root)
                before = (root / "tests" / "test_login.py").read_bytes()
                if runtime == "core":
                    result = AgentLoop(workdir=root, limits=LoopLimits(max_validations=1)).run(FIX_INSTRUCTION)
                    feedback = result.final_validation
                else:
                    app = build_default_application(workdir=root, limits=KernelLimits(max_validations=1))
                    result = app.run(FIX_INSTRUCTION)
                    feedback = result.final_validation.feedback
                    self.assertEqual(app.model_usage.requests, 0)
                self.assertTrue(result.succeeded, result.as_payload())
                check = next(c for c in feedback.report.checks if c.name == "project-tests-1")
                self.assertTrue(check.passed, check.detail)
                self.assertIn("3 passed", check.detail)
                self.assertEqual((root / "tests" / "test_login.py").read_bytes(), before)

    def test_clean_security_scan_cannot_hide_project_regression_in_either_runtime(self):
        for runtime in ("core", "scaffold"):
            with self.subTest(runtime=runtime), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                write_project(root, regression=True)
                runner = (AgentLoop(workdir=root, limits=LoopLimits(max_validations=1)) if runtime == "core"
                          else build_default_application(workdir=root, limits=KernelLimits(max_validations=1)))
                result = runner.run(FIX_INSTRUCTION)
                self.assertFalse(result.succeeded)
                self.assertIn("project-tests-1", result.reason)
                scans = [e for e in result.events if e.action and e.action.name == "security_scan"]
                self.assertEqual(scans[-1].tool_result.data["finding_count"], 0)

    def test_failed_project_check_reaches_planner_and_is_repeated_after_repair(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_project(root)
            broken = SAFE.replace("return await conn.fetchrow(query, req.username, req.password)", "return None")
            actions = [AgentAction("write_file", {"path": "auth.py", "content": broken}),
                       AgentAction("security_scan", {"write_report": False}), AgentAction("finish"),
                       AgentAction("write_file", {"path": "auth.py", "content": SAFE}),
                       AgentAction("security_scan", {"write_report": False}), AgentAction("finish")]
            feedbacks = []

            class Planner:
                def next_plan(self, context):
                    if context.last_validation:
                        feedbacks.append(context.last_validation)
                    action = actions.pop(0) if actions else AgentAction("abort")
                    return PlanDecision(action, strategy=PlanStrategy.VERIFY if action.name == "finish" else PlanStrategy.CONTINUE)

            app = build_default_application(workdir=root)
            app.kernel.planner = Planner()
            result = app.run(FIX_INSTRUCTION)
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual(result.validations_used, 2)
            self.assertTrue(any(not item.passed and "project-tests-1" in item.reason for item in feedbacks))

    def test_missing_and_empty_pytest_suites_are_not_success(self):
        for empty in (False, True):
            with self.subTest(empty=empty), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "auth.py").write_bytes(b"VALUE = 1\n")
                if empty:
                    (root / "tests").mkdir()
                plan = discover_project_checks("Run `pytest tests/`.", root)
                report = validate_fix_task(ValidationPolicy("fix", root, capture_snapshot(root)), plan)
                self.assertFalse(report.passed)
                self.assertIn("exit_code=5" if empty else "exit_code=4",
                              next(c for c in report.checks if c.name == "project-tests-1").detail)

    def test_extracted_submission_cli_runs_real_pytest_and_preserves_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            outer = Path(tmp)
            root = outer / "проект с пробелами"
            write_project(root)
            install = outer / "installed agent"
            build = build_submission(Path(__file__).resolve().parents[2], outer / "submission.zip")
            with zipfile.ZipFile(build.output) as archive:
                self.assertIn("agent/core/fix_validation.py", archive.namelist())
                self.assertIn("agent/core/project_checks.py", archive.namelist())
                self.assertNotIn("agent/tests/test_c15_project_checks.py", archive.namelist())
                archive.extractall(install)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("LOCAL_AGENT_", "OPENAI_"))}
            env.update({"PYTHONPATH": str(install), "PYTHONUTF8": "1"})
            process = subprocess.run([sys.executable, "-m", "agent.scaffold.cli", "--workdir", str(root),
                                      "--max-validations", "1", "--", FIX_INSTRUCTION],
                cwd=install, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", timeout=20)
            self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
            payload = json.loads(process.stdout)
            self.assertEqual(payload["status"], "succeeded", payload)
            self.assertEqual(payload["metrics"]["model_usage"]["requests"], 0)
            checks = payload["final_validation"]["feedback"]["report"]["checks"]
            self.assertIn("3 passed", next(c for c in checks if c["name"] == "project-tests-1")["detail"])


if __name__ == "__main__":
    unittest.main()
