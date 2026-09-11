"""Recover scaffold status/usage from full stdout JSON without changing verdicts.

External harnesses may read the legacy metrics layout or select a nested state
status. This development-only adapter reads the actual root result and emits a
corrected summary. It never changes verifier scores or rewrites input files.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


USAGE_FIELDS = ("requests", "input_tokens", "output_tokens", "total_tokens", "estimated_tokens")


def read_scaffold_result(path: Path) -> tuple[str, dict[str, int]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    status = payload["status"]
    if status not in {"succeeded", "failed"}:
        raise ValueError("stdout has no terminal root status")
    usage = payload["metrics"]["model_usage"]
    counters = {}
    for key in USAGE_FIELDS:
        value = usage[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid model usage counter: {key}")
        counters[key] = value
    return status, counters


def summarize_run(run_dir: Path) -> dict:
    summary = json.loads((run_dir / "summary.json").read_text(encoding="utf-8"))
    totals = dict.fromkeys(USAGE_FIELDS, 0)
    for task in summary["tasks"]:
        name = task["task"]
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
            raise ValueError("invalid task identifier")
        status, counters = read_scaffold_result(run_dir / "logs" / f"{name}.stdout.log")
        task["agent_status"] = status
        task.update(counters)
        for key in USAGE_FIELDS:
            totals[key] += counters[key]
    summary["model_requests"] = totals.pop("requests")
    summary.update(totals)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    args = parser.parse_args()
    try:
        result = summarize_run(args.run_dir)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"cannot recover scaffold summary: {error}\n")
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
