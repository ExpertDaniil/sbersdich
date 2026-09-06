from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from agent.core.loop import AgentLoop, ScriptedDriver  # noqa: E402
from agent.core.models import AgentAction  # noqa: E402
from agent.core.tools import SecurityToolRegistry  # noqa: E402
from agent.core.workspace import (  # noqa: E402
    MAX_COMMAND_OUTPUT_BYTES,
    WorkspaceError,
    answer_path,
    apply_workspace_patch,
    list_workspace_files,
    parse_unified_patch,
    read_workspace_bytes,
    read_workspace_text,
    resolve_workspace_path,
    run_workspace_command,
    search_workspace_text,
)
from agent.strategies import classify_instruction  # noqa: E402


def write_text(path: Path, text: str, newline: str = "\n") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline=newline) as handle:
        handle.write(text)


class WorkspaceReadTests(unittest.TestCase):
    def test_list_is_sorted_bounded_and_hides_answers_and_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "z.py", "z = 1\n")
            write_text(root / "src" / "a.py", "a = 1\n")
            write_text(root / "tests" / "test_a.py", "def test_a(): pass\n")
            write_text(root / "solution" / "solve.py", "ANSWER = 42\n")
            write_text(root / "expected_result.txt", "secret\n")
            write_text(root / ".git" / "config", "secret\n")
            write_text(root / "__pycache__" / "z.pyc", "cache\n")
            complete = list_workspace_files(root, max_entries=10)
            self.assertEqual(
                [entry["path"] for entry in complete["entries"]],
                ["z.py", "src/a.py", "tests/test_a.py"],
            )
            self.assertFalse(complete["truncated"])
            bounded = list_workspace_files(root, max_entries=2)
            self.assertEqual(len(bounded["entries"]), 2)
            self.assertTrue(bounded["truncated"])

    def test_text_read_supports_line_windows_and_character_cap(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "app.py", "one\ntwo\n" + "x" * 13_000 + "\nfour\n")
            result = read_workspace_text(root, path="app.py", start_line=2, max_lines=2)
            self.assertEqual(result["start_line"], 2)
            self.assertEqual(result["end_line"], 3)
            self.assertTrue(result["content"].startswith("two\n"))
            self.assertLessEqual(len(result["content"]), 12_000)
            self.assertTrue(result["truncated"])

    def test_binary_file_requires_bounded_byte_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "sample.bin").write_bytes(b"A\x00B\xffC")
            with self.assertRaisesRegex(WorkspaceError, "appears binary"):
                read_workspace_text(root, path="sample.bin")
            result = read_workspace_bytes(root, path="sample.bin", offset=1, length=3)
            self.assertEqual(result["hex"], "00 42 ff")
            self.assertEqual(result["ascii"], ".B.")

    def test_read_rejects_external_and_answer_paths(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            root = Path(tmp)
            external = Path(other) / "outside.txt"
            write_text(external, "outside\n")
            write_text(root / "verifier" / "result.txt", "answer\n")
            with self.assertRaisesRegex(WorkspaceError, "outside workdir"):
                read_workspace_text(root, path=str(external))
            with self.assertRaisesRegex(WorkspaceError, "answer/verifier"):
                read_workspace_text(root, path="verifier/result.txt")

    def test_literal_search_honors_case_glob_and_answer_exclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "src" / "one.py", "Token = request.value\n")
            write_text(root / "src" / "two.txt", "token in text\n")
            write_text(root / "solution" / "answer.py", "TOKEN = secret\n")
            result = search_workspace_text(root, query="token", glob="*.py")
            self.assertEqual(result["match_count"], 1)
            self.assertEqual(result["matches"][0]["path"], "src/one.py")
            sensitive = search_workspace_text(
                root, query="token", glob="*.py", case_sensitive=True
            )
            self.assertEqual(sensitive["match_count"], 0)

    def test_search_stops_at_match_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "many.txt", "\n".join("needle" for _ in range(150)))
            result = search_workspace_text(root, query="needle")
            self.assertEqual(result["match_count"], 100)
            self.assertTrue(result["truncated"])

    def test_search_counts_oversized_files_toward_scan_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            oversized = b"x" * (512 * 1024 + 1)
            for index in range(4):
                (root / f"{index:03}.txt").write_bytes(oversized)
            with patch("agent.core.workspace.MAX_SEARCH_FILES", 3):
                result = search_workspace_text(root, query="needle")
            self.assertEqual(result["files_scanned"], 3)
            self.assertTrue(result["truncated"])

    def test_answer_path_classifier_does_not_hide_normal_tests(self):
        self.assertTrue(answer_path("solution/solve.py"))
        self.assertTrue(answer_path("tests/expected_result.txt"))
        self.assertFalse(answer_path("tests/test_expected_behavior.py"))


class UnifiedPatchTests(unittest.TestCase):
    PATCH = """--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 value = 1
-print(value)
+print(value + 1)
"""

    def test_patch_changes_existing_file_and_preserves_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app.py"
            write_text(target, "value = 1\nprint(value)\n")
            target.chmod(0o744)
            result = apply_workspace_patch(root, patch=self.PATCH)
            self.assertEqual(result["changed_paths"], ["app.py"])
            self.assertEqual(target.read_text(), "value = 1\nprint(value + 1)\n")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o744)

    def test_git_style_metadata_is_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "app.py", "value = 1\nprint(value)\n")
            patch = "diff --git a/app.py b/app.py\nindex 111..222 100644\n" + self.PATCH
            parsed = parse_unified_patch(patch)
            self.assertEqual(parsed[0].path, "app.py")
            apply_workspace_patch(root, patch=patch)
            self.assertIn("value + 1", (root / "app.py").read_text())

    def test_patch_preserves_crlf_line_endings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "app.py"
            target.write_bytes(b"value = 1\r\nprint(value)\r\n")
            apply_workspace_patch(root, patch=self.PATCH)
            self.assertEqual(target.read_bytes(), b"value = 1\r\nprint(value + 1)\r\n")

    def test_all_files_are_validated_before_any_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            one = root / "one.py"
            two = root / "two.py"
            write_text(one, "one = 1\n")
            write_text(two, "two = 2\n")
            patch = """--- a/one.py
+++ b/one.py
@@ -1 +1 @@
-one = 1
+one = 10
--- a/two.py
+++ b/two.py
@@ -1 +1 @@
-wrong context
+two = 20
"""
            with self.assertRaisesRegex(WorkspaceError, "context mismatch"):
                apply_workspace_patch(root, patch=patch)
            self.assertEqual(one.read_text(), "one = 1\n")
            self.assertEqual(two.read_text(), "two = 2\n")

    def test_patch_rejects_protected_dependency_and_answer_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ("tests/test_app.py", "pyproject.toml", "solution/solve.py"):
                write_text(root / name, "value = 1\n")
                patch = f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-value = 1\n+value = 2\n"
                with self.assertRaises(WorkspaceError, msg=name):
                    apply_workspace_patch(root, patch=patch)

    def test_patch_rejects_context_mismatch_without_modifying_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "app.py", "actual = 1\n")
            with self.assertRaisesRegex(WorkspaceError, "context mismatch"):
                apply_workspace_patch(root, patch=self.PATCH)
            self.assertEqual((root / "app.py").read_text(), "actual = 1\n")

    def test_patch_rejects_file_creation_rename_and_duplicate_sections(self):
        creation = "--- /dev/null\n+++ b/new.py\n@@ -0,0 +1 @@\n+value = 1\n"
        rename = "--- a/old.py\n+++ b/new.py\n@@ -1 +1 @@\n-old\n+new\n"
        with self.assertRaises(WorkspaceError):
            parse_unified_patch(creation)
        with self.assertRaises(WorkspaceError):
            parse_unified_patch(rename)
        with self.assertRaisesRegex(WorkspaceError, "only once"):
            parse_unified_patch(self.PATCH + self.PATCH)

    def test_patch_rejects_symlink_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            real = root / "real.py"
            link = root / "app.py"
            write_text(real, "value = 1\nprint(value)\n")
            try:
                link.symlink_to(real)
            except OSError:
                self.skipTest("symlink creation is unavailable")
            with self.assertRaisesRegex(WorkspaceError, "symlink"):
                apply_workspace_patch(root, patch=self.PATCH)
            self.assertEqual(real.read_text(), "value = 1\nprint(value)\n")

    @unittest.skipUnless(os.name == "nt", "Windows 8.3 path regression")
    def test_write_accepts_windows_short_path_alias_of_workdir(self):
        import ctypes

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            buffer = ctypes.create_unicode_buffer(32_768)
            length = ctypes.windll.kernel32.GetShortPathNameW(  # type: ignore[attr-defined]
                str(root), buffer, len(buffer)
            )
            if length == 0 or length >= len(buffer) or buffer.value == str(root):
                self.skipTest("8.3 alias is unavailable for the temporary directory")
            requested = str(Path(buffer.value) / "new_file.txt")
            resolved = resolve_workspace_path(
                root, requested, must_exist=False, for_write=True
            )
            self.assertEqual(resolved, (root / "new_file.txt").resolve())

    def test_malformed_hunk_counts_are_rejected(self):
        patch = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n-old\n+new\n"
        with self.assertRaisesRegex(WorkspaceError, "ended before"):
            parse_unified_patch(patch)


class ProcessToolTests(unittest.TestCase):
    def test_allowlisted_python_check_returns_bounded_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "valid.py", "value = 1\n")
            result = run_workspace_command(
                root,
                argv=[sys.executable, "-m", "py_compile", "valid.py"],
                timeout_seconds=10,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertFalse(result["timed_out"])
            self.assertEqual(result["profile"], "python-module:py_compile")

    def test_virtual_app_argument_is_translated_to_real_workdir(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "valid.py", "value = 1\n")
            result = run_workspace_command(
                root,
                argv=[sys.executable, "-m", "py_compile", "/app/valid.py"],
                timeout_seconds=10,
            )
            self.assertEqual(result["exit_code"], 0, result["output"])
            self.assertEqual(Path(result["argv"][-1]), root.resolve() / "valid.py")

    def test_nonzero_exit_is_observed_without_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "invalid.py", "def broken(:\n")
            result = run_workspace_command(
                root,
                argv=[sys.executable, "-m", "py_compile", "invalid.py"],
                timeout_seconds=10,
            )
            self.assertNotEqual(result["exit_code"], 0)
            self.assertIn("SyntaxError", result["output"])

    def test_timeout_terminates_allowed_test_process(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "test_sleep.py",
                "import time\nimport unittest\n\n"
                "class Slow(unittest.TestCase):\n"
                "    def test_wait(self):\n"
                "        time.sleep(10)\n",
            )
            result = run_workspace_command(
                root,
                argv=[sys.executable, "-m", "unittest", "test_sleep"],
                timeout_seconds=1,
            )
            self.assertTrue(result["timed_out"])
            self.assertNotEqual(result["exit_code"], 0)

    def test_output_is_drained_but_observation_is_capped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "test_output.py",
                "import unittest\n\n"
                "class Loud(unittest.TestCase):\n"
                "    def test_loud(self):\n"
                "        print('x' * 50000)\n",
            )
            result = run_workspace_command(
                root,
                argv=[sys.executable, "-m", "unittest", "test_output"],
                timeout_seconds=10,
            )
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["output_truncated"])
            self.assertLessEqual(len(result["output"].encode()), MAX_COMMAND_OUTPUT_BYTES)

    def test_local_model_credentials_are_removed_from_child_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(
                root / "test_environment.py",
                "import os\nimport unittest\n\n"
                "class Environment(unittest.TestCase):\n"
                "    def test_no_model_secret(self):\n"
                "        self.assertIsNone(os.getenv('OPENAI_API_KEY'))\n"
                "        self.assertIsNone(os.getenv('LOCAL_AGENT_MODEL'))\n"
                "        self.assertIsNone(os.getenv('GIT_EXTERNAL_DIFF'))\n"
                "        self.assertIsNone(os.getenv('PYTEST_ADDOPTS'))\n",
            )
            old_key = os.environ.get("OPENAI_API_KEY")
            old_model = os.environ.get("LOCAL_AGENT_MODEL")
            old_git_diff = os.environ.get("GIT_EXTERNAL_DIFF")
            old_pytest_options = os.environ.get("PYTEST_ADDOPTS")
            os.environ["OPENAI_API_KEY"] = "must-not-leak"
            os.environ["LOCAL_AGENT_MODEL"] = "local-secret-model"
            os.environ["GIT_EXTERNAL_DIFF"] = "must-not-run"
            os.environ["PYTEST_ADDOPTS"] = "--must-not-leak"
            try:
                result = run_workspace_command(
                    root,
                    argv=[sys.executable, "-m", "unittest", "test_environment"],
                    timeout_seconds=10,
                )
            finally:
                if old_key is None:
                    os.environ.pop("OPENAI_API_KEY", None)
                else:
                    os.environ["OPENAI_API_KEY"] = old_key
                if old_model is None:
                    os.environ.pop("LOCAL_AGENT_MODEL", None)
                else:
                    os.environ["LOCAL_AGENT_MODEL"] = old_model
                if old_git_diff is None:
                    os.environ.pop("GIT_EXTERNAL_DIFF", None)
                else:
                    os.environ["GIT_EXTERNAL_DIFF"] = old_git_diff
                if old_pytest_options is None:
                    os.environ.pop("PYTEST_ADDOPTS", None)
                else:
                    os.environ["PYTEST_ADDOPTS"] = old_pytest_options
            self.assertEqual(result["exit_code"], 0, result["output"])
            self.assertNotIn("must-not-leak", result["output"])

    def test_git_diff_disables_external_diff_and_textconv(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            subprocess.run(
                ["git", "init", "--quiet"], cwd=root, check=True, capture_output=True
            )
            result = run_workspace_command(root, argv=["git", "diff"])
            self.assertEqual(result["exit_code"], 0, result["output"])
            self.assertEqual(result["profile"], "git:diff")
            self.assertIn("--no-ext-diff", result["argv"])
            self.assertIn("--no-textconv", result["argv"])

    def test_shell_eval_destructive_git_and_unsafe_paths_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            invalid_commands = (
                ["bash", "-c", "echo unsafe"],
                [sys.executable, "-c", "print('unsafe')"],
                ["git", "reset", "--hard"],
                [sys.executable, "-m", "pytest", "../outside"],
                [sys.executable, "-m", "pytest", "--basetemp=tests"],
                [sys.executable, "-m", "pytest", "--pyargs", "app"],
                [sys.executable, "-m", "unittest", "application"],
                [sys.executable, "-m", "pytest", "solution/expected.py"],
            )
            for argv in invalid_commands:
                with self.assertRaises(WorkspaceError, msg=argv):
                    run_workspace_command(root, argv=argv)

    def test_command_cwd_must_exist_inside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            with self.assertRaisesRegex(WorkspaceError, "outside workdir"):
                run_workspace_command(
                    Path(tmp),
                    argv=[sys.executable, "-m", "unittest"],
                    cwd=other,
                )


class RegistryAndLoopIntegrationTests(unittest.TestCase):
    def test_catalog_grants_writes_only_to_fix_and_general(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = SecurityToolRegistry(Path(tmp))
            audit = {
                tool.name
                for tool in registry.catalog(
                    classify_instruction("Do not modify code; write security_report.json")
                )
            }
            fix = {
                tool.name
                for tool in registry.catalog(classify_instruction("Fix the vulnerability"))
            }
            for name in ("list_files", "read_file", "read_bytes", "search_text"):
                self.assertIn(name, audit)
            self.assertNotIn("apply_patch", audit)
            self.assertNotIn("run_command", audit)
            self.assertIn("apply_patch", fix)
            self.assertIn("run_command", fix)

    def test_audit_registry_rejects_patch_without_touching_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "app.py", "value = 1\nprint(value)\n")
            registry = SecurityToolRegistry(root)
            result = registry.execute(
                AgentAction("apply_patch", {"patch": UnifiedPatchTests.PATCH}),
                classify_instruction("Do not modify code; write security_report.json"),
            )
            self.assertFalse(result.ok)
            self.assertIn("forbidden", result.summary)
            self.assertEqual((root / "app.py").read_text(), "value = 1\nprint(value)\n")

    def test_fix_loop_can_read_patch_rescan_and_validate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            vulnerable = (
                "async def login(conn, username):\n"
                "    return await conn.fetchrow(\n"
                "        f\"SELECT * FROM users WHERE name = '{username}'\"\n"
                "    )\n"
            )
            write_text(root / "auth.py", vulnerable)
            patch = """--- a/auth.py
+++ b/auth.py
@@ -1,4 +1,4 @@
 async def login(conn, username):
     return await conn.fetchrow(
-        f"SELECT * FROM users WHERE name = '{username}'"
+        "SELECT * FROM users WHERE name = $1", username
     )
"""
            driver = ScriptedDriver(
                [
                    AgentAction("read_file", {"path": "auth.py"}),
                    AgentAction("apply_patch", {"patch": patch}),
                    AgentAction("security_scan", {"write_report": False}),
                    AgentAction("finish"),
                ]
            )
            result = AgentLoop(workdir=root, driver=driver).run(
                "Fix the SQL injection vulnerability in the application code."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertIn("name = $1", (root / "auth.py").read_text())
            self.assertEqual(
                [event.action.name for event in result.events if event.action],
                ["read_file", "apply_patch", "security_scan", "finish"],
            )

    def test_driver_context_receives_only_mode_available_tool_schemas(self):
        class CapturingDriver:
            context = None

            def next_action(self, context):
                self.context = context
                return AgentAction("abort", rationale="catalog captured")

        with tempfile.TemporaryDirectory() as tmp:
            driver = CapturingDriver()
            AgentLoop(workdir=Path(tmp), driver=driver).run(
                "Analyze incident logs and write incident_report.txt"
            )
            names = {tool.name for tool in driver.context.available_tools}
            self.assertIn("forensics_analyze", names)
            self.assertIn("search_text", names)
            self.assertNotIn("apply_patch", names)
            self.assertNotIn("run_command", names)

    def test_registry_read_error_is_structured_not_an_exception(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = SecurityToolRegistry(Path(tmp))
            result = registry.execute(
                AgentAction("read_file", {"path": "missing.py"}),
                classify_instruction("Fix the vulnerability"),
            )
            self.assertFalse(result.ok)
            self.assertIn("does not exist", result.summary)


if __name__ == "__main__":
    unittest.main()
