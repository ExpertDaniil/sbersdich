from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from agent.scaffold.context_compiler import RepositoryContextCompiler, _pytest_feedback
from agent.scaffold.security_relevance import SecurityAwareRepositoryDistiller


AUTH_BUG_INSTRUCTION = (
    "There is an authorization bug in this project. Find the root cause, "
    "make the smallest safe fix, and prove the fix using the existing tests."
)


class RepositoryContextCompilerTests(unittest.TestCase):
    def test_packet_combines_semantic_readme_contract_and_trusted_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            access = root / "access.py"
            access.write_text(
                'def can_delete(user):\n    return user.get("role") != "guest"\n',
                encoding="utf-8",
            )
            (root / "test_access.py").write_text(
                "from access import can_delete\n\n"
                "def test_admin_can_delete():\n"
                '    assert can_delete({"role": "admin"})\n\n'
                "def test_viewer_cannot_delete():\n"
                '    assert not can_delete({"role": "viewer"})\n',
                encoding="utf-8",
            )
            distiller = SecurityAwareRepositoryDistiller(root)
            compiler = RepositoryContextCompiler(root, distiller=distiller)

            packet = compiler.task_guide(AUTH_BUG_INSTRUCTION)
            expected_sha = hashlib.sha256(access.read_bytes()).hexdigest()

            self.assertIn("# REPO_GUIDE.md (virtual; model-only)", packet)
            self.assertIn("authz__can_delete__impl.py", packet)
            self.assertIn("CONTRACT=can_delete(role=admin)=>true", packet)
            self.assertIn("# TRUSTED_SOURCE_WINDOWS", packet)
            self.assertIn(f"SHA256={expected_sha}", packet)
            self.assertIn('2 |     return user.get("role") != "guest"', packet)
            self.assertLessEqual(len(packet), 10_000)

    def test_packet_refreshes_sha_after_source_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            access = root / "access.py"
            access.write_text("def allowed():\n    return False\n", encoding="utf-8")
            distiller = SecurityAwareRepositoryDistiller(root)
            compiler = RepositoryContextCompiler(root, distiller=distiller)

            before = compiler.task_guide("Fix the access permission bug")
            access.write_text("def allowed():\n    return True\n", encoding="utf-8")
            after = compiler.task_guide("Fix the access permission bug")

            self.assertNotEqual(before, after)
            self.assertIn(hashlib.sha256(access.read_bytes()).hexdigest(), after)

    def test_pytest_feedback_extracts_nodes_counts_and_error_types(self):
        raw = (
            "test_access.py .F.\n"
            "E   AssertionError: assert not True\n"
            "FAILED test_access.py::test_viewer_cannot_delete - AssertionError\n"
            "1 failed, 2 passed in 0.01s\n"
        )

        feedback = _pytest_feedback(raw, passed=False)

        self.assertEqual(feedback["status"], "failed")
        self.assertEqual(
            feedback["failed_tests"],
            ["test_access.py::test_viewer_cannot_delete"],
        )
        self.assertIn("AssertionError", feedback["error_types_found"])
        self.assertEqual(feedback["counts"]["failed"], 1)
        self.assertEqual(feedback["counts"]["passed"], 2)

    def test_small_forensics_packet_includes_every_evidence_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "evidence"
            evidence.mkdir()
            for name in ("app.jsonl", "auth.jsonl", "storage.jsonl"):
                (evidence / name).write_text(
                    '{"ts":"2026-01-01T00:00:00Z","source":"' + name + '"}\n',
                    encoding="utf-8",
                )
            (evidence / "proxy.log").write_text(
                "2026-01-01T00:00:01Z request=req-1\n", encoding="utf-8"
            )
            (evidence / "collector_note.txt").write_text(
                "auth clock was 90 seconds fast", encoding="utf-8"
            )
            compiler = RepositoryContextCompiler(
                root, distiller=SecurityAwareRepositoryDistiller(root)
            )

            packet = compiler.task_guide(
                "Investigate all evidence and write `/app/reports/timeline.json`."
            )

            for name in ("app.jsonl", "auth.jsonl", "storage.jsonl",
                         "proxy.log", "collector_note.txt"):
                self.assertIn("source_path=evidence/" + name, packet)


if __name__ == "__main__":
    unittest.main()
