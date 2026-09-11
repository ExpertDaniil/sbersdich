"""Composition root for the experimental scaffold."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent.core.llm import ModelUsage

from .candidate_arena import CandidateArenaProvider
from .context_compiler import RepositoryContextCompiler
from .contracts import KernelLimits, ScaffoldRunResult
from .extensions import ScaffoldExtension
from .kernel import AgentKernel
from .planner import HybridPlanner
from .providers import LegacySecurityProvider, WorkspaceFileProvider
from .registry import ToolBus
from .security_relevance import SecurityAwareRepositoryDistillerProvider
from .semantic_namespace import SemanticCyberACIProvider
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
    # Distiller, semantic namespace, context compiler and ACI share one cached index.
    # The task workspace itself is never renamed: only the model-facing names change.
    # Candidate Arena stays separate because it owns private transactional copies and
    # can only promote a deterministic winner.
    distiller_provider = SecurityAwareRepositoryDistillerProvider(workdir)
    semantic_context = RepositoryContextCompiler(
        workdir,
        distiller=distiller_provider.distiller,
    )
    providers = [
        distiller_provider,
        SemanticCyberACIProvider(
            workdir,
            distiller=distiller_provider.distiller,
            semantic_context=semantic_context,
        ),
        CandidateArenaProvider(workdir),
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
        repository_context=semantic_context,
    )
    return ScaffoldApplication(kernel=kernel, planner=planner)
