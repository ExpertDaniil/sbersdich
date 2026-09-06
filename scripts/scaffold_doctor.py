#!/usr/bin/env python3
"""Print a secret-safe runtime manifest before deploying the scaffold."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.scaffold.diagnostics import runtime_manifest  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workdir",
        type=Path,
        default=Path(os.environ.get("LOCAL_AGENT_WORKDIR", os.getcwd())),
    )
    args = parser.parse_args()
    print(json.dumps(runtime_manifest(args.workdir), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
