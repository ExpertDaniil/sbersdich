"""Composable tool registry with mode and capability gating."""

from __future__ import annotations

from agent.core.models import AgentAction, ToolResult

from .contracts import ExecutionContext, ToolSpec
from .interfaces import ToolProvider


RESERVED_ACTIONS = frozenset({"finish", "abort"})


class ToolRegistryError(RuntimeError):
    pass


class ToolBus:
    """Compose independent providers without coupling feature code to the kernel."""

    def __init__(self, providers: tuple[ToolProvider, ...]):
        self.providers = providers

    def _index(self, context: ExecutionContext) -> dict[str, tuple[ToolSpec, ToolProvider]]:
        index: dict[str, tuple[ToolSpec, ToolProvider]] = {}
        for provider in self.providers:
            for spec in provider.catalog(context):
                if spec.name in RESERVED_ACTIONS:
                    raise ToolRegistryError(f"provider cannot own reserved action {spec.name!r}")
                if spec.name in index:
                    other = index[spec.name][0].provider
                    raise ToolRegistryError(
                        f"duplicate tool {spec.name!r} from {other!r} and {provider.name!r}"
                    )
                if context.decision.mode not in spec.modes:
                    continue
                if spec.capability > context.max_capability:
                    continue
                index[spec.name] = (spec, provider)
        return index

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        index = self._index(context)
        return tuple(
            item[0]
            for _, item in sorted(
                index.items(), key=lambda pair: (int(pair[1][0].capability), pair[0])
            )
        )

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        index = self._index(context)
        selected = index.get(action.name)
        if selected is None:
            return ToolResult(False, f"tool {action.name!r} is unavailable in current policy")
        spec, provider = selected
        if spec.capability > context.max_capability:
            return ToolResult(False, f"tool {action.name!r} exceeds capability budget")
        return provider.execute(action, context)
