"""Runtime diagnostics that never expose credential values."""

from __future__ import annotations

import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Any


PROBED_TOOLS = ("gdb", "objdump", "readelf", "nm", "strings", "file", "curl", "nc")
MODEL_ENV = ("LOCAL_AGENT_MODEL", "OPENAI_BASE_URL", "OPENAI_API_KEY")


def runtime_manifest(workdir: Path) -> dict[str, Any]:
    return {
        "python": {
            "version": platform.python_version(),
            "implementation": platform.python_implementation(),
            "executable": sys.executable,
        },
        "platform": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
        },
        "workdir": str(workdir.resolve()),
        "model_environment_present": {
            name: bool(os.environ.get(name)) for name in MODEL_ENV
        },
        "tools": {name: shutil.which(name) for name in PROBED_TOOLS},
        "offline_contract": {
            "runtime_dependency_installation": "forbidden",
            "public_internet": "not required by scaffold",
            "model_transport": "OPENAI_BASE_URL only",
            "task_resources": "workspace and explicitly enabled task-local capabilities",
        },
    }
