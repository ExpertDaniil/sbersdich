#!/usr/bin/env python3
"""Build a deterministic deployable ZIP using run_scaffold.sh as submission run.sh."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from agent.scaffold.packaging import build_submission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("dist/test_govno_submission.zip"),
    )
    args = parser.parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    result = build_submission(repo_root, args.output)
    print(json.dumps(result.as_payload(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
