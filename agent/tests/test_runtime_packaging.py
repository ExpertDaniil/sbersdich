from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from agent.runtime.manifest import collect_runtime_manifest
from agent.runtime.packaging import PackagingError, build_submission


class RuntimePackagingTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "agent" / "runtime").mkdir(parents=True)
        (root / "agent" / "tests").mkdir(parents=True)
        (root / "run.sh").write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
        (root / "agent" / "__init__.py").write_text("", encoding="utf-8")
        (root / "agent" / "runtime" / "tool.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "agent" / "tests" / "test_x.py").write_text("SECRET = 'answer'\n", encoding="utf-8")
        (root / "agent" / ".env").write_text("OPENAI_API_KEY=secret\n", encoding="utf-8")

    def test_submission_is_deterministic_and_filters_tests_and_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            first = build_submission(root, root / "one.zip")
            second = build_submission(root, root / "two.zip")
            self.assertEqual(first.sha256, second.sha256)
            with zipfile.ZipFile(first.path) as archive:
                names = archive.namelist()
            self.assertIn("run.sh", names)
            self.assertIn("agent/runtime/tool.py", names)
            self.assertNotIn("agent/tests/test_x.py", names)
            self.assertNotIn("agent/.env", names)

    def test_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            (root / "agent" / "payload.bin").write_bytes(b"x" * 10_000)
            with self.assertRaisesRegex(PackagingError, "limit"):
                build_submission(root, root / "submission.zip", max_bytes=100)

    def test_runtime_manifest_never_contains_secret_value(self):
        import os
        from unittest.mock import patch

        with patch.dict(os.environ, {"OPENAI_API_KEY": "TOP-SECRET", "LOCAL_AGENT_MODEL": "m"}, clear=False):
            manifest = collect_runtime_manifest()
        rendered = repr(manifest)
        self.assertNotIn("TOP-SECRET", rendered)
        self.assertTrue(manifest["model_environment"]["OPENAI_API_KEY"])


if __name__ == "__main__":
    unittest.main()
