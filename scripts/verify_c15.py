#!/usr/bin/env python3
"""Run C15 checks, requiring real pytest integration instead of silently skipping it."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(root))
    if importlib.util.find_spec("pytest") is None:
        print(
            "C15 verification requires pytest in this development interpreter. "
            "Use an environment with pytest already installed (including the task runtime). "
            "The agent and this script never install dependencies automatically.",
            file=sys.stderr,
        )
        return 2
    suite = unittest.defaultTestLoader.loadTestsFromName("agent.tests.test_c15_project_checks")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
