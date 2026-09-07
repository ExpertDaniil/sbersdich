from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.contracts import (
    CapabilityLevel,
    ExecutionContext,
)
from agent.scaffold.providers import WorkspaceFileProvider
from agent.strategies import classify_instruction
from agent.validators import canonical_path


class ScaffoldWorkspacePathCompatibilityTests(unittest.TestCase):
    def test_write_provider_uses_one_canonical_workspace_identity(self):
        """A lexical alias must not make an in-workspace write look external."""

        with tempfile.TemporaryDirectory() as temporary:
            real_root = Path(temporary) / "long workspace name"
            real_root.mkdir()
            alias_root = Path(temporary) / "WORKSP~1"
            try:
                alias_root.symlink_to(real_root, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"directory aliases are unavailable: {error}")

            decision = classify_instruction(
                "Create a file at `/app/result.txt` whose content is exactly `done`."
            )
            provider = WorkspaceFileProvider(alias_root)
            context = ExecutionContext(
                workdir=canonical_path(alias_root),
                decision=decision,
                max_capability=CapabilityLevel.MUTATE,
            )

            result = provider.execute(
                AgentAction(
                    "write_file",
                    {"path": "/app/result.txt", "content": "done"},
                ),
                context,
            )

            self.assertTrue(result.ok, result.summary)
            self.assertEqual(result.data["path"], "result.txt")
            self.assertEqual(
                (real_root / "result.txt").read_text(encoding="utf-8"),
                "done",
            )


if __name__ == "__main__":
    unittest.main()
