#!/usr/bin/env python3
"""No-model smoke test for the experimental scaffold."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.scaffold.bootstrap import build_default_application  # noqa: E402
from agent.scaffold.contracts import KernelLimits  # noqa: E402


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        app = build_default_application(
            workdir=root,
            limits=KernelLimits(deadline_seconds=20),
        )
        result = app.run(
            "Create a file at `/app/scaffold_smoke.txt` whose content is exactly `ok`."
        )
        content = (root / "scaffold_smoke.txt").read_text(encoding="utf-8")
        payload = {
            "passed": result.succeeded and content == "ok" and app.model_usage.requests == 0,
            "status": result.status,
            "reason": result.reason,
            "content": content,
            "model_requests": app.model_usage.requests,
            "steps": result.steps_used,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if payload["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
