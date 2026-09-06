from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from agent.scaffold.diagnostics import runtime_manifest


class ScaffoldDiagnosticsTests(unittest.TestCase):
    def test_manifest_reports_presence_without_secret_value(self):
        old = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "super-secret-value"
        try:
            with tempfile.TemporaryDirectory() as tmp:
                manifest = runtime_manifest(Path(tmp))
            rendered = repr(manifest)
            self.assertTrue(manifest["model_environment_present"]["OPENAI_API_KEY"])
            self.assertNotIn("super-secret-value", rendered)
        finally:
            if old is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = old


if __name__ == "__main__":
    unittest.main()
