from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction, ToolDefinition, ToolResult
from agent.runtime.adapters import build_workspace_extensions
from agent.runtime.contracts import CapabilityLevel, RuntimeToolSpec
from agent.runtime.registry import CompositeToolRegistry, RuntimeToolError, RuntimeToolRegistry
from agent.strategies import StrategyDecision


def decision(mode: str) -> StrategyDecision:
    return StrategyDecision(mode, mode in {"fix", "general"}, (), "", "test", "test")


class RuntimeRegistryTests(unittest.TestCase):
    def test_registration_is_mode_gated_and_returns_core_tool_result(self):
        registry = RuntimeToolRegistry()
        definition = ToolDefinition("echo_runtime", "echo", {"value": "string"})
        registry.register(
            RuntimeToolSpec(definition, frozenset({"general"}), CapabilityLevel.INSPECT),
            lambda args: ToolResult(True, "ok", {"value": args["value"]}),
        )
        self.assertEqual([tool.name for tool in registry.catalog(decision("general"))], ["echo_runtime"])
        self.assertEqual(registry.catalog(decision("audit")), ())
        result = registry.execute(AgentAction("echo_runtime", {"value": "x"}), decision("general"))
        self.assertTrue(result.ok)
        self.assertEqual(result.data["value"], "x")
        forbidden = registry.execute(AgentAction("echo_runtime", {"value": "x"}), decision("audit"))
        self.assertFalse(forbidden.ok)

    def test_duplicate_and_frozen_registration_fail_closed(self):
        registry = RuntimeToolRegistry()
        spec = RuntimeToolSpec(
            ToolDefinition("one", "one", {}),
            frozenset({"general"}),
            CapabilityLevel.INSPECT,
        )
        registry.register(spec, lambda _: ToolResult(True, "ok"))
        with self.assertRaisesRegex(RuntimeToolError, "duplicate"):
            registry.register(spec, lambda _: ToolResult(True, "ok"))
        registry.freeze()
        with self.assertRaisesRegex(RuntimeToolError, "frozen"):
            registry.register(
                RuntimeToolSpec(
                    ToolDefinition("two", "two", {}),
                    frozenset({"general"}),
                    CapabilityLevel.INSPECT,
                ),
                lambda _: ToolResult(True, "ok"),
            )

    def test_composite_routes_without_shadowing(self):
        first = RuntimeToolRegistry()
        second = RuntimeToolRegistry()
        first.register(
            RuntimeToolSpec(
                ToolDefinition("one", "one", {}),
                frozenset({"general"}),
                CapabilityLevel.INSPECT,
            ),
            lambda _: ToolResult(True, "first"),
        )
        second.register(
            RuntimeToolSpec(
                ToolDefinition("two", "two", {}),
                frozenset({"general"}),
                CapabilityLevel.INSPECT,
            ),
            lambda _: ToolResult(True, "second"),
        )
        composite = CompositeToolRegistry(first, second)
        self.assertEqual([tool.name for tool in composite.catalog(decision("general"))], ["one", "two"])
        self.assertEqual(composite.execute(AgentAction("two"), decision("general")).summary, "second")

    def test_workspace_extensions_expose_write_and_append_only_for_general(self):
        with tempfile.TemporaryDirectory() as tmp:
            provider = build_workspace_extensions(Path(tmp))
            names = [tool.name for tool in provider.catalog(decision("general"))]
            self.assertEqual(names, ["write_file", "append_file"])
            self.assertEqual(provider.catalog(decision("fix")), ())


if __name__ == "__main__":
    unittest.main()
