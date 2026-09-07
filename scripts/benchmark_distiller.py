#!/usr/bin/env python3
"""Benchmark Repository Distiller localization on the public Sber fixtures.

This is intentionally a small, deterministic benchmark rather than a model benchmark.
It answers four questions that matter before we build a richer ACI:

1. Does lexical/structural/security-aware ranking surface the file that actually contains the task bug?
2. How much repository text can be replaced by a compact top-file skeleton?
3. How much data did the offline index need to scan?
4. How expensive is the first localization pass?

The official public competition repository is supplied by the caller. The script never
uses the solution directory as distiller input; expected files are benchmark labels only.
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Sequence

# Executing ``python scripts/benchmark_distiller.py`` makes ``scripts`` sys.path[0].
# Insert the repository root explicitly so the benchmark behaves the same locally and in CI.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from agent.scaffold.security_relevance import SecurityAwareRepositoryDistiller


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    workspace: str
    instruction: str
    expected_files: tuple[str, ...]


PUBLIC_CASES = (
    BenchmarkCase(
        name="find-sqli-login",
        workspace="local_task/find-sqli-login/environment/app",
        instruction="local_task/find-sqli-login/instruction.md",
        expected_files=("routers/auth.py",),
    ),
    BenchmarkCase(
        name="fix-sqli-login",
        workspace="local_task/fix-sqli-login/environment/app",
        instruction="local_task/fix-sqli-login/instruction.md",
        expected_files=("routers/auth.py",),
    ),
    BenchmarkCase(
        name="fix-sqli-search",
        workspace="local_task/fix-sqli-search/environment/app",
        instruction="local_task/fix-sqli-search/instruction.md",
        expected_files=("routers/items.py",),
    ),
)


@dataclass(frozen=True)
class CaseResult:
    name: str
    expected_files: tuple[str, ...]
    expected_rank: int | None
    top_paths: tuple[str, ...]
    top1_hit: bool
    top3_hit: bool
    top5_hit: bool
    indexed_files: int
    indexed_bytes: int
    indexed_chars: int
    skeleton_chars: int
    context_ratio: float
    context_reduction: float
    first_rank_ms: float
    snapshot_truncated: bool


def _validate_public_root(root: Path) -> Path:
    root = root.resolve()
    if not (root / "local_task").is_dir():
        raise ValueError(f"not a public competition checkout: {root}")
    return root


def _rank_of(paths: Sequence[str], expected: Sequence[str]) -> int | None:
    expected_set = {item.replace("\\", "/") for item in expected}
    for index, path in enumerate(paths, 1):
        if path.replace("\\", "/") in expected_set:
            return index
    return None


def run_case(public_root: Path, case: BenchmarkCase) -> CaseResult:
    workdir = (public_root / case.workspace).resolve()
    instruction_path = (public_root / case.instruction).resolve()
    if not workdir.is_dir():
        raise ValueError(f"missing workspace for {case.name}: {workdir}")
    if not instruction_path.is_file():
        raise ValueError(f"missing instruction for {case.name}: {instruction_path}")

    instruction = instruction_path.read_text(encoding="utf-8")
    distiller = SecurityAwareRepositoryDistiller(workdir)

    started = time.perf_counter()
    ranking = distiller.rank_relevant_files(query=instruction, limit=20)
    first_rank_ms = (time.perf_counter() - started) * 1000.0

    paths = tuple(str(item["path"]) for item in ranking["candidates"])
    expected_rank = _rank_of(paths, case.expected_files)

    snapshot = distiller.snapshot()
    indexed_chars = sum(len(item.text or "") for item in snapshot.files)
    top_source_paths = [
        path
        for path in paths
        if snapshot.by_path.get(path) is not None and snapshot.by_path[path].symbols
    ][:3]
    if not top_source_paths:
        top_source_paths = list(paths[:3])

    skeleton_chars = 0
    if top_source_paths:
        skeleton = distiller.repo_skeleton(
            paths=top_source_paths,
            max_files=min(3, len(top_source_paths)),
        )
        skeleton_chars = len(str(skeleton["skeleton"]))

    context_ratio = skeleton_chars / indexed_chars if indexed_chars else 0.0
    context_reduction = 1.0 - context_ratio if indexed_chars else 1.0

    return CaseResult(
        name=case.name,
        expected_files=case.expected_files,
        expected_rank=expected_rank,
        top_paths=paths[:5],
        top1_hit=expected_rank is not None and expected_rank <= 1,
        top3_hit=expected_rank is not None and expected_rank <= 3,
        top5_hit=expected_rank is not None and expected_rank <= 5,
        indexed_files=int(ranking["indexed_files"]),
        indexed_bytes=int(ranking["indexed_bytes"]),
        indexed_chars=indexed_chars,
        skeleton_chars=skeleton_chars,
        context_ratio=round(context_ratio, 4),
        context_reduction=round(context_reduction, 4),
        first_rank_ms=round(first_rank_ms, 3),
        snapshot_truncated=bool(snapshot.truncated),
    )


def _rate(results: Sequence[CaseResult], attribute: str) -> float:
    return sum(bool(getattr(result, attribute)) for result in results) / max(1, len(results))


def summarize(results: Sequence[CaseResult]) -> dict[str, object]:
    top1_rate = _rate(results, "top1_hit")
    top3_rate = _rate(results, "top3_hit")
    top5_rate = _rate(results, "top5_hit")
    reductions = [result.context_reduction for result in results]
    latencies = [result.first_rank_ms for result in results]
    return {
        "cases": [asdict(result) for result in results],
        "summary": {
            "case_count": len(results),
            "top1_rate": round(top1_rate, 4),
            "top3_rate": round(top3_rate, 4),
            "top5_rate": round(top5_rate, 4),
            "average_context_reduction": round(statistics.fmean(reductions), 4) if reductions else 0.0,
            "average_first_rank_ms": round(statistics.fmean(latencies), 3) if latencies else 0.0,
            "max_first_rank_ms": round(max(latencies), 3) if latencies else 0.0,
        },
    }


def _print_human(report: dict[str, object]) -> None:
    print("Repository Distiller public-fixture benchmark")
    print("=" * 52)
    for raw in report["cases"]:
        case = dict(raw)
        rank = case["expected_rank"] if case["expected_rank"] is not None else "MISS"
        print(
            f"{case['name']:<20} expected_rank={str(rank):<4} "
            f"top5={list(case['top_paths'])}"
        )
        print(
            f"  indexed={case['indexed_files']} files/{case['indexed_bytes']} bytes, "
            f"skeleton={case['skeleton_chars']} chars, "
            f"reduction={case['context_reduction']:.1%}, "
            f"first_rank={case['first_rank_ms']:.3f} ms"
        )
    summary = dict(report["summary"])
    print("-" * 52)
    print(
        "top1={top1_rate:.1%} top3={top3_rate:.1%} top5={top5_rate:.1%} "
        "avg_context_reduction={average_context_reduction:.1%} "
        "avg_first_rank={average_first_rank_ms:.3f} ms".format(**summary)
    )


def _enforce(report: dict[str, object], args: argparse.Namespace) -> None:
    summary = dict(report["summary"])
    failures: list[str] = []
    checks = (
        ("top1_rate", args.min_top1_rate),
        ("top3_rate", args.min_top3_rate),
        ("top5_rate", args.min_top5_rate),
        ("average_context_reduction", args.min_context_reduction),
    )
    for key, minimum in checks:
        if minimum is None:
            continue
        actual = float(summary[key])
        if actual + 1e-12 < minimum:
            failures.append(f"{key}={actual:.4f} < required {minimum:.4f}")
    if args.max_first_rank_ms is not None:
        actual = float(summary["max_first_rank_ms"])
        if actual > args.max_first_rank_ms:
            failures.append(
                f"max_first_rank_ms={actual:.3f} > required {args.max_first_rank_ms:.3f}"
            )
    if failures:
        raise SystemExit("distiller benchmark failed: " + "; ".join(failures))


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--public-root", type=Path, required=True)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--min-top1-rate", type=float)
    parser.add_argument("--min-top3-rate", type=float)
    parser.add_argument("--min-top5-rate", type=float)
    parser.add_argument("--min-context-reduction", type=float)
    parser.add_argument("--max-first-rank-ms", type=float)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    public_root = _validate_public_root(args.public_root)
    results = tuple(run_case(public_root, case) for case in PUBLIC_CASES)
    report = summarize(results)
    _print_human(report)
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    if args.json_output is not None:
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    _enforce(report, args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
