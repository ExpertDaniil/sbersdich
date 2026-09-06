from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path

from agent.scaffold.packaging import build_submission


class ScaffoldPackagingTests(unittest.TestCase):
    def test_builder_is_deterministic_and_filters_tests_and_secrets(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "agent" / "scaffold").mkdir(parents=True)
            (root / "agent" / "tests").mkdir(parents=True)
            production_launcher = "#!/bin/sh\necho production\n"
            (root / "run.sh").write_text(production_launcher, encoding="utf-8")
            # A developer launcher may coexist, but must not become the uploaded run.sh.
            (root / "run_scaffold.sh").write_text(
                "#!/bin/sh\necho development\n", encoding="utf-8"
            )
            (root / "agent" / "__init__.py").write_text("", encoding="utf-8")
            (root / "agent" / "scaffold" / "x.py").write_text("X = 1\n", encoding="utf-8")
            (root / "agent" / "tests" / "test_x.py").write_text("secret test\n", encoding="utf-8")
            (root / "agent" / ".env").write_text("API_KEY=secret\n", encoding="utf-8")
            one = build_submission(root, root / "one.zip")
            two = build_submission(root, root / "two.zip")
            self.assertEqual(one.sha256, two.sha256)
            with zipfile.ZipFile(one.output) as archive:
                names = set(archive.namelist())
                uploaded_launcher = archive.read("run.sh").decode("utf-8")
            self.assertIn("run.sh", names)
            self.assertEqual(uploaded_launcher, production_launcher)
            self.assertIn("agent/scaffold/x.py", names)
            self.assertNotIn("agent/tests/test_x.py", names)
            self.assertNotIn("agent/.env", names)
            self.assertNotIn("agent.py", names)


if __name__ == "__main__":
    unittest.main()
