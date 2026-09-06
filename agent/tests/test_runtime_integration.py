from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.core.tools import SecurityToolRegistry
from agent.runtime.adapters import build_composite_runtime
from agent.strategies import StrategyDecision


def decision(mode: str) -> StrategyDecision:
    return StrategyDecision(mode, mode in {"fix", "general"}, (), "", "test", "test")


class RuntimeIntegrationTests(unittest.TestCase):
    def test_composite_preserves_c10_tools_and_adds_participant2_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            legacy = SecurityToolRegistry(root)
            runtime = build_composite_runtime(root, legacy)
            names = [tool.name for tool in runtime.catalog(decision("general"))]
            self.assertIn("list_files", names)
            self.assertIn("read_file", names)
            self.assertIn("apply_patch", names)
            self.assertIn("run_command", names)
            self.assertIn("write_file", names)
            self.assertIn("append_file", names)

            write = runtime.execute(
                AgentAction("write_file", {"path": "notes.txt", "content": "one\n"}),
                decision("general"),
            )
            self.assertTrue(write.ok, write.summary)
            append = runtime.execute(
                AgentAction("append_file", {"path": "notes.txt", "content": "two\n"}),
                decision("general"),
            )
            self.assertTrue(append.ok, append.summary)
            self.assertEqual((root / "notes.txt").read_text(), "one\ntwo\n")

    def test_extension_does_not_expand_fix_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runtime = build_composite_runtime(root, SecurityToolRegistry(root))
            names = [tool.name for tool in runtime.catalog(decision("fix"))]
            self.assertNotIn("write_file", names)
            self.assertNotIn("append_file", names)


if __name__ == "__main__":
    unittest.main()
