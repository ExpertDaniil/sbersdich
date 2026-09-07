from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.aci import CyberACIProvider
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext
from agent.scaffold.registry import ToolBus
from agent.strategies import classify_instruction


AUTH_SOURCE = '''\nasync def login(conn, username: str, password: str):\n    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"\n    return await conn.fetchrow(query)\n'''.lstrip()


class CyberACITests(unittest.TestCase):
    def _context(
        self,
        root: Path,
        instruction: str,
        capability: CapabilityLevel = CapabilityLevel.MUTATE,
    ) -> ExecutionContext:
        return ExecutionContext(
            workdir=root,
            decision=classify_instruction(instruction),
            max_capability=capability,
        )

    def test_mode_bundles_and_capability_gating_are_small(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            provider = CyberACIProvider(root)
            bus = ToolBus((provider,))

            fix = self._context(root, "Fix the security vulnerability in the project code")
            self.assertEqual(
                {tool.name for tool in bus.catalog(fix)},
                {"search_surface", "view_window", "checked_edit", "run_check"},
            )

            audit = self._context(
                root,
                "Perform a security audit and do not modify application code",
            )
            self.assertEqual(
                {tool.name for tool in bus.catalog(audit)},
                {"search_surface", "view_window"},
            )

            inspect_only = self._context(
                root,
                "Fix the security vulnerability in the project code",
                CapabilityLevel.INSPECT,
            )
            self.assertEqual(
                {tool.name for tool in bus.catalog(inspect_only)},
                {"view_window"},
            )

    def test_search_surface_ranks_security_code_and_caps_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app").mkdir()
            (root / "app" / "auth.py").write_text(AUTH_SOURCE, encoding="utf-8")
            (root / "README.md").write_text(
                "login username login username login username\n",
                encoding="utf-8",
            )
            (root / "app" / "profile.py").write_text(
                "def username_label(username):\n    return username\n",
                encoding="utf-8",
            )
            provider = CyberACIProvider(root)
            context = self._context(root, "Fix SQL injection in login code")
            result = provider.execute(
                AgentAction(
                    "search_surface",
                    {
                        "query": "find SQL injection around login username handling",
                        "max_results": 1,
                    },
                ),
                context,
            )
            self.assertTrue(result.ok, result.summary)
            self.assertEqual(result.data["result_count"], 1)
            self.assertEqual(result.data["results"][0]["path"], "app/auth.py")
            self.assertGreater(result.data["known_hidden_count"], 0)
            self.assertIn("username", [term.casefold() for term in result.data["query_terms"]])

    def test_view_window_is_numbered_bounded_and_returns_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "long.py"
            target.write_text(
                "".join(f"line_{index:03d} = {index}\n" for index in range(1, 181)),
                encoding="utf-8",
            )
            provider = CyberACIProvider(root)
            context = self._context(root, "Fix the code")
            result = provider.execute(
                AgentAction(
                    "view_window",
                    {"path": "long.py", "start_line": 40, "max_lines": 100},
                ),
                context,
            )
            self.assertTrue(result.ok, result.summary)
            self.assertEqual(result.data["start_line"], 40)
            self.assertEqual(result.data["end_line"], 139)
            self.assertEqual(len(result.data["sha256"]), 64)
            self.assertIn(" 40 | line_040 = 40", result.data["content"])
            self.assertIn("line(s) omitted before", result.data["content"])
            self.assertIn("line(s) omitted after", result.data["content"])

    def test_checked_edit_rejects_invalid_python_without_writing_then_reopens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "calc.py"
            original = "def add(a, b):\n    return a + b\n"
            target.write_text(original, encoding="utf-8")
            provider = CyberACIProvider(root)
            context = self._context(root, "Fix the code")
            view = provider.execute(
                AgentAction("view_window", {"path": "calc.py"}),
                context,
            )
            digest = view.data["sha256"]

            rejected = provider.execute(
                AgentAction(
                    "checked_edit",
                    {
                        "path": "calc.py",
                        "start_line": 2,
                        "end_line": 2,
                        "replacement": "    return (",
                        "expected_sha256": digest,
                    },
                ),
                context,
            )
            self.assertFalse(rejected.ok)
            self.assertFalse(rejected.data["written"])
            self.assertEqual(target.read_text(encoding="utf-8"), original)

            applied = provider.execute(
                AgentAction(
                    "checked_edit",
                    {
                        "path": "calc.py",
                        "start_line": 2,
                        "end_line": 2,
                        "replacement": "    return a - b\n",
                        "expected_sha256": digest,
                    },
                ),
                context,
            )
            self.assertTrue(applied.ok, applied.summary)
            self.assertTrue(applied.data["written"])
            self.assertNotEqual(applied.data["old_sha256"], applied.data["new_sha256"])
            self.assertIn("return a - b", target.read_text(encoding="utf-8"))
            self.assertEqual(
                applied.data["new_sha256"],
                applied.data["reopened"]["sha256"],
            )
            self.assertTrue(any(check["name"] == "python-ast" for check in applied.data["checks"]))

    def test_checked_edit_rejects_stale_view(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "value.py"
            target.write_text("VALUE = 1\n", encoding="utf-8")
            provider = CyberACIProvider(root)
            context = self._context(root, "Fix the code")
            view = provider.execute(
                AgentAction("view_window", {"path": "value.py"}),
                context,
            )
            target.write_text("VALUE = 2\n", encoding="utf-8")
            result = provider.execute(
                AgentAction(
                    "checked_edit",
                    {
                        "path": "value.py",
                        "start_line": 1,
                        "end_line": 1,
                        "replacement": "VALUE = 3\n",
                        "expected_sha256": view.data["sha256"],
                    },
                ),
                context,
            )
            self.assertFalse(result.ok)
            self.assertFalse(result.data["written"])
            self.assertEqual(target.read_text(encoding="utf-8"), "VALUE = 2\n")

    def test_run_check_python_syntax_returns_structured_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "good.py").write_text("VALUE = 1\n", encoding="utf-8")
            bad = root / "bad.py"
            bad.write_text("def broken(:\n    pass\n", encoding="utf-8")
            provider = CyberACIProvider(root)
            context = self._context(root, "Fix the code")

            failed = provider.execute(
                AgentAction("run_check", {"profile": "python-syntax"}),
                context,
            )
            self.assertFalse(failed.ok)
            self.assertEqual(failed.data["profile"], "python-syntax")
            self.assertTrue(any(item["path"] == "bad.py" for item in failed.data["errors"]))

            bad.write_text("def fixed():\n    return True\n", encoding="utf-8")
            passed = provider.execute(
                AgentAction("run_check", {"profile": "python-syntax"}),
                context,
            )
            self.assertTrue(passed.ok, passed.summary)
            self.assertEqual(passed.data["files_checked"], 2)
            self.assertEqual(passed.data["errors"], [])

    def test_answer_paths_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "verifier").mkdir()
            (root / "verifier" / "expected.txt").write_text("secret\n", encoding="utf-8")
            provider = CyberACIProvider(root)
            context = self._context(root, "Perform a security audit")
            result = provider.execute(
                AgentAction(
                    "search_surface",
                    {"query": "secret", "path": "verifier"},
                ),
                context,
            )
            self.assertFalse(result.ok)
            self.assertIn("forbidden", result.summary)


if __name__ == "__main__":
    unittest.main()
