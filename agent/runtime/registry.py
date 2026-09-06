"""Composable runtime tool registry.

This module is the extension point for participant-2 tooling.  It keeps the
existing core contracts, rejects duplicate names, supports mode/capability
metadata, and can be composed with the current SecurityToolRegistry without
rewriting it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Protocol

from agent.core.models import AgentAction, ToolDefinition, ToolResult
from agent.strategies import StrategyDecision

from .contracts import RuntimeHandler, RuntimeLimits, RuntimeToolSpec


class RuntimeToolError(RuntimeError):
    """Raised for invalid registration or runtime-policy violations."""


@dataclass(frozen=True)
class _RegisteredTool:
    spec: RuntimeToolSpec
    handler: RuntimeHandler


class ToolProvider(Protocol):
    """Small protocol shared by the legacy and extension registries."""

    def catalog(self, decision: StrategyDecision) -> tuple[ToolDefinition, ...]: ...

    def execute(self, action: AgentAction, decision: StrategyDecision) -> ToolResult: ...


class RuntimeToolRegistry:
    """Bounded registry for optional tools owned by the runtime layer."""

    def __init__(self, *, limits: RuntimeLimits | None = None):
        self.limits = limits or RuntimeLimits()
        self._tools: dict[str, _RegisteredTool] = {}
        self._frozen = False

    @property
    def frozen(self) -> bool:
        return self._frozen

    def freeze(self) -> None:
        self._frozen = True

    def register(self, spec: RuntimeToolSpec, handler: RuntimeHandler) -> None:
        if self._frozen:
            raise RuntimeToolError("runtime tool registry is frozen")
        name = spec.definition.name
        if name in self._tools:
            raise RuntimeToolError(f"duplicate runtime tool: {name}")
        if len(self._tools) >= self.limits.max_registered_tools:
            raise RuntimeToolError("runtime tool registry capacity exhausted")
        if not callable(handler):
            raise RuntimeToolError(f"handler for {name!r} is not callable")
        self._tools[name] = _RegisteredTool(spec, handler)

    def install(self, items: Iterable[tuple[RuntimeToolSpec, RuntimeHandler]]) -> None:
        for spec, handler in items:
            self.register(spec, handler)

    def catalog(self, decision: StrategyDecision) -> tuple[ToolDefinition, ...]:
        return tuple(
            item.spec.definition
            for item in self._tools.values()
            if decision.mode in item.spec.modes
        )

    def execute(self, action: AgentAction, decision: StrategyDecision) -> ToolResult:
        item = self._tools.get(action.name)
        if item is None:
            return ToolResult(False, f"runtime tool is not registered: {action.name}")
        if decision.mode not in item.spec.modes:
            return ToolResult(
                False,
                f"runtime tool {action.name!r} is forbidden in {decision.mode!r} mode",
            )
        if not isinstance(action.arguments, dict):
            return ToolResult(False, "action arguments must be an object")
        try:
            result = item.handler(action.arguments)
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")
        if not isinstance(result, ToolResult):
            return ToolResult(False, f"{action.name} returned an invalid ToolResult")
        return result

    def describe(self) -> tuple[dict[str, object], ...]:
        return tuple(item.spec.as_payload() for item in self._tools.values())


class CompositeToolRegistry:
    """Merge existing tools with participant-2 extensions behind one interface.

    The current AgentLoop can keep using a `.catalog()` / `.execute()` provider.
    Feature owners can plug new providers here first and switch the loop to this
    composite when ownership of the integration point is agreed.
    """

    def __init__(self, *providers: ToolProvider):
        if not providers:
            raise ValueError("at least one tool provider is required")
        self.providers = providers

    def _routing_table(
        self, decision: StrategyDecision
    ) -> tuple[tuple[ToolDefinition, ...], dict[str, ToolProvider]]:
        definitions: list[ToolDefinition] = []
        routes: dict[str, ToolProvider] = {}
        for provider in self.providers:
            for definition in provider.catalog(decision):
                if definition.name in routes:
                    raise RuntimeToolError(
                        f"duplicate tool name across providers: {definition.name}"
                    )
                definitions.append(definition)
                routes[definition.name] = provider
        return tuple(definitions), routes

    def catalog(self, decision: StrategyDecision) -> tuple[ToolDefinition, ...]:
        definitions, _ = self._routing_table(decision)
        return definitions

    def execute(self, action: AgentAction, decision: StrategyDecision) -> ToolResult:
        _, routes = self._routing_table(decision)
        provider = routes.get(action.name)
        if provider is None:
            return ToolResult(False, f"unknown composite action: {action.name}")
        return provider.execute(action, decision)
