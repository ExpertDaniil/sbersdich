"""Composition root for the experimental scaffold."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent.core.llm import ModelUsage

from .contracts import KernelLimits, ScaffoldRunResult
from .extensions import ScaffoldExtension
from .kernel import AgentKernel
from .planner import HybridPlanner
from .providers import LegacySecurityProvider, WorkspaceFileProvider
from .registry import ToolBus
from .verifier import LegacyTaskVerifier


@dataclass
class ScaffoldApplication:
    kernel: AgentKernel
    planner: HybridPlanner

    @property
    def model_usage(self) -> ModelUsage:
        return self.planner.usage

    def run(self, instruction: str) -> ScaffoldRunResult:
        return self.kernel.run(instruction)


def build_default_application(
    *,
    workdir: Path,
    limits: KernelLimits | None = None,
    extensions: tuple[ScaffoldExtension, ...] = (),
) -> ScaffoldApplication:
    providers = [
        LegacySecurityProvider(workdir),
        WorkspaceFileProvider(workdir),
    ]
    guidance: list[str] = []
    for extension in extensions:
        providers.extend(extension.build_providers(workdir))
        if extension.planner_guidance:
            guidance.append(f"[{extension.name}] {extension.planner_guidance}")
    planner = HybridPlanner()
    kernel = AgentKernel(
        workdir=workdir,
        tool_bus=ToolBus(tuple(providers)),
        planner=planner,
        verifier=LegacyTaskVerifier(),
        limits=limits,
        extension_guidance="\n".join(guidance),
    )
    return ScaffoldApplication(kernel=kernel, planner=planner)
