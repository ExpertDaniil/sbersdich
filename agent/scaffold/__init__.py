"""Experimental extensible scaffold for the autonomous cybersecurity agent."""

from .aci import CyberACIProvider
from .bootstrap import ScaffoldApplication, build_default_application
from .candidate_arena import CandidateArena, CandidateArenaProvider, adaptive_branch_budget
from .contracts import CapabilityLevel, KernelLimits, PlanDecision, PlanStrategy, ToolSpec
from .extensions import ScaffoldExtension, gdb_extension
from .kernel import AgentKernel
from .registry import ToolBus
from .state import AgentState

__all__ = [
    "AgentKernel",
    "AgentState",
    "CandidateArena",
    "CandidateArenaProvider",
    "CapabilityLevel",
    "CyberACIProvider",
    "KernelLimits",
    "PlanDecision",
    "PlanStrategy",
    "ScaffoldApplication",
    "ScaffoldExtension",
    "ToolBus",
    "ToolSpec",
    "adaptive_branch_budget",
    "build_default_application",
    "gdb_extension",
]
