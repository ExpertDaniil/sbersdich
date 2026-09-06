#!/usr/bin/env python3
"""Build the deterministic <=10 MiB agent submission archive."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.runtime.packaging import PackagingError, build_submission


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument("--output", type=Path, default=Path("dist/submission.zip"))
    args = parser.parse_args()
    try:
        result = build_submission(args.repo_root, args.output)
    except PackagingError as error:
        print(f"submission build failed: {error}")
        return 2
    print(json.dumps(result.as_payload(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
