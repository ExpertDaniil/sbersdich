"""Experimental extensible scaffold for the autonomous cybersecurity agent."""

from .aci import CyberACIProvider
from .bootstrap import ScaffoldApplication, build_default_application
from .contracts import CapabilityLevel, KernelLimits, PlanDecision, PlanStrategy, ToolSpec
from .extensions import ScaffoldExtension, gdb_extension
from .kernel import AgentKernel
from .registry import ToolBus
from .state import AgentState

__all__ = [
    "AgentKernel",
    "AgentState",
    "CapabilityLevel",
    "CyberACIProvider",
    "KernelLimits",
    "PlanDecision",
    "PlanStrategy",
    "ScaffoldApplication",
    "ScaffoldExtension",
    "ToolBus",
    "ToolSpec",
    "build_default_application",
    "gdb_extension",
]
