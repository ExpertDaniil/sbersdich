"""Reusable process environment policy for future runtime tools."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping


SENSITIVE_ENV_RE = re.compile(
    r"(?:API[_-]?KEY|TOKEN|CREDENTIAL|PASSWORD|PRIVATE[_-]?KEY|SECRET)",
    re.IGNORECASE,
)
CONTROL_ENV_NAMES = frozenset(
    {
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "NODE_OPTIONS",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "RUSTC_WRAPPER",
    }
)
LOCAL_AGENT_CONTROL_PREFIXES = ("LOCAL_AGENT_", "OPENAI_")


def sanitized_child_environment(
    source: Mapping[str, str] | None = None,
    *,
    extra: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Return a child environment without model secrets or control injection.

    This function is intentionally reusable by one-shot commands, debuggers and
    future connection/session backends.  It never logs or returns stripped values.
    """

    original = dict(os.environ if source is None else source)
    clean: dict[str, str] = {}
    for key, value in original.items():
        upper = key.upper()
        if key in CONTROL_ENV_NAMES:
            continue
        if SENSITIVE_ENV_RE.search(key):
            continue
        if upper.startswith(LOCAL_AGENT_CONTROL_PREFIXES):
            continue
        clean[key] = value
    if extra:
        for key, value in extra.items():
            if not isinstance(key, str) or not isinstance(value, str):
                raise ValueError("extra environment must contain text keys and values")
            upper = key.upper()
            if (
                key in CONTROL_ENV_NAMES
                or SENSITIVE_ENV_RE.search(key)
                or upper.startswith(LOCAL_AGENT_CONTROL_PREFIXES)
            ):
                raise ValueError(f"refusing sensitive/control environment override: {key}")
            clean[key] = value
    return clean
