"""Small extension API and opt-in examples for feature teams."""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from agent.core.workspace import resolve_workspace_path

from .interfaces import ToolProvider
from .sessions import InteractiveSessionProvider, SessionProfile


ProviderFactory = Callable[[Path], ToolProvider]


@dataclass(frozen=True)
class ScaffoldExtension:
    name: str
    provider_factories: tuple[ProviderFactory, ...] = ()
    planner_guidance: str = ""

    def build_providers(self, workdir: Path) -> tuple[ToolProvider, ...]:
        return tuple(factory(workdir) for factory in self.provider_factories)


def _gdb_argv(options: dict, workdir: Path) -> tuple[str, ...]:
    if set(options) != {"target"}:
        raise ValueError("gdb profile requires only target")
    target = resolve_workspace_path(workdir, options["target"])
    if not target.is_file():
        raise ValueError("gdb target must be a file")
    executable = shutil.which("gdb")
    if executable is None:
        raise ValueError("gdb is not installed in this runtime")
    return (executable, "--quiet", "--nx", "--nh", str(target))


def _gdb_provider(_: Path) -> ToolProvider:
    return InteractiveSessionProvider(
        (
            SessionProfile(
                name="gdb",
                description="Persistent GDB session for task-local binary analysis.",
                argv_builder=_gdb_argv,
                modes=("general", "audit", "fix"),
            ),
        )
    )


def gdb_extension() -> ScaffoldExtension:
    """Opt-in example: the CLI never enables GDB unless explicitly requested."""

    return ScaffoldExtension(
        name="gdb",
        provider_factories=(_gdb_provider,),
        planner_guidance=(
            "GDB is available as an interactive session profile. Use session_start with "
            "profile='gdb' and options={'target': '<workspace binary>'}, then session_send "
            "for debugger commands. Prefer static inspection before escalating to GDB."
        ),
    )
