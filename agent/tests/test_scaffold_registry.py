from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction, ToolResult
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext, ToolSpec
from agent.scaffold.registry import ToolBus, ToolRegistryError
from agent.strategies import classify_instruction


class FakeProvider:
    def __init__(self, name: str, tool_name: str, capability: CapabilityLevel):
        self.name = name
        self.tool_name = tool_name
        self.capability = capability

    def catalog(self, context: ExecutionContext):
        return (
            ToolSpec(
                self.tool_name,
                "fake tool",
                {},
                (context.decision.mode,),
                self.capability,
                False,
                self.name,
            ),
        )

    def execute(self, action: AgentAction, context: ExecutionContext):
        return ToolResult(True, "ok", {"provider": self.name})


class ScaffoldRegistryTests(unittest.TestCase):
    def _context(self, root: Path, max_capability: CapabilityLevel):
        return ExecutionContext(
            root,
            classify_instruction("inspect these incident logs for forensics"),
            max_capability,
        )

    def test_capability_budget_hides_more_powerful_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bus = ToolBus(
                (
                    FakeProvider("inspect", "peek", CapabilityLevel.INSPECT),
                    FakeProvider("mutate", "rewrite", CapabilityLevel.MUTATE),
                )
            )
            names = {tool.name for tool in bus.catalog(self._context(root, CapabilityLevel.ANALYZE))}
            self.assertEqual(names, {"peek"})

    def test_duplicate_tool_names_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bus = ToolBus(
                (
                    FakeProvider("one", "same", CapabilityLevel.INSPECT),
                    FakeProvider("two", "same", CapabilityLevel.INSPECT),
                )
            )
            with self.assertRaisesRegex(ToolRegistryError, "duplicate tool"):
                bus.catalog(self._context(root, CapabilityLevel.MUTATE))

    def test_execute_routes_to_owning_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            context = self._context(root, CapabilityLevel.MUTATE)
            bus = ToolBus((FakeProvider("owner", "peek", CapabilityLevel.INSPECT),))
            result = bus.execute(AgentAction("peek"), context)
            self.assertTrue(result.ok)
            self.assertEqual(result.data["provider"], "owner")


if __name__ == "__main__":
    unittest.main()
