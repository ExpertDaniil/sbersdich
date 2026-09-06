#!/usr/bin/env python3
"""Runnable CLI for the experimental extensible agent scaffold."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from agent.core.config import ModelConfig, ModelConfigError
from agent.core.llm import ModelRequestError, OpenAICompatibleClient

from .bootstrap import build_default_application
from .contracts import CapabilityLevel, KernelLimits
from .extensions import gdb_extension


def _default_workdir() -> Path:
    return Path(os.environ.get("LOCAL_AGENT_WORKDIR", os.getcwd())).resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instruction", nargs="*", help="task instruction")
    parser.add_argument("--workdir", type=Path, default=_default_workdir())
    parser.add_argument("--deadline-seconds", type=float, default=300.0)
    parser.add_argument("--max-steps", type=int, default=20)
    parser.add_argument("--max-validations", type=int, default=4)
    parser.add_argument("--max-repeated-action", type=int, default=2)
    parser.add_argument(
        "--max-capability",
        type=int,
        choices=range(0, 5),
        default=int(CapabilityLevel.MUTATE),
        help="0 inspect, 1 analyze, 2 execute, 3 interactive, 4 mutate",
    )
    parser.add_argument(
        "--enable-gdb",
        action="store_true",
        help="opt in to the persistent GDB session extension",
    )
    parser.add_argument("--probe", action="store_true", help="only probe local model endpoint")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        if args.probe:
            config = ModelConfig.from_env()
            client = OpenAICompatibleClient(config)
            answer = client.probe(timeout_seconds=args.deadline_seconds)
            print(
                json.dumps(
                    {
                        "status": "connected",
                        "answer": answer,
                        "configuration": config.public_summary(),
                        "model_usage": client.usage.as_payload(),
                    },
                    ensure_ascii=False,
                    indent=2,
                )
            )
            return 0

        if not args.instruction:
            parser.error("task instruction is required unless --probe is used")
        limits = KernelLimits(
            max_steps=args.max_steps,
            max_validations=args.max_validations,
            max_repeated_action=args.max_repeated_action,
            deadline_seconds=args.deadline_seconds,
            max_capability=CapabilityLevel(args.max_capability),
        )
        extensions = (gdb_extension(),) if args.enable_gdb else ()
        app = build_default_application(
            workdir=args.workdir.resolve(),
            limits=limits,
            extensions=extensions,
        )
        result = app.run(" ".join(args.instruction))
        payload = result.as_payload()
        payload["metrics"] = {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "model_usage": app.model_usage.as_payload(),
            "max_capability": args.max_capability,
            "gdb_enabled": args.enable_gdb,
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if result.succeeded else 1
    except (ModelConfigError, ModelRequestError, OSError, ValueError) as error:
        print(f"Scaffold launch failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
