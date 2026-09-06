"""Reproducible runtime inventory for B-01/B-02/B-15 diagnostics."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import sys
from pathlib import Path
from typing import Iterable


DEFAULT_TOOL_PROBES = (
    "bash",
    "git",
    "patch",
    "file",
    "strings",
    "objdump",
    "gdb",
    "curl",
)
MODEL_ENV_NAMES = ("LOCAL_AGENT_MODEL", "OPENAI_BASE_URL", "OPENAI_API_KEY")
IMAGE_DIGEST_ENV_NAMES = ("LOCAL_AGENT_IMAGE_DIGEST", "ACP_IMAGE_DIGEST")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_runtime_manifest(
    *,
    workdir: Path | str | None = None,
    tool_names: Iterable[str] = DEFAULT_TOOL_PROBES,
) -> dict[str, object]:
    root = Path.cwd() if workdir is None else Path(workdir)
    image_digest = next(
        (os.environ[name] for name in IMAGE_DIGEST_ENV_NAMES if os.environ.get(name)),
        None,
    )
    return {
        "schema_version": 1,
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
        "workdir": str(root.resolve()),
        "model_environment": {name: bool(os.environ.get(name)) for name in MODEL_ENV_NAMES},
        "container_image_digest": image_digest,
        "tools": {name: shutil.which(name) for name in tool_names},
        "offline_contract": {
            "installs_at_agent_runtime": False,
            "public_internet_required": False,
            "model_endpoint_from_environment": True,
        },
    }


def render_manifest(payload: dict[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
