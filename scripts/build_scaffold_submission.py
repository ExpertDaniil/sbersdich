#!/usr/bin/env python3
"""Build a deterministic deployable ZIP using run_scaffold.sh as submission run.sh."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.scaffold.packaging import build_submission  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/test_govno_submission.zip"),
    )
    args = parser.parse_args()
    result = build_submission(REPO_ROOT, args.output)
    print(json.dumps(result.as_payload(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
