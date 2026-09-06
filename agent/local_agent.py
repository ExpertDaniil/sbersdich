#!/usr/bin/env python3
"""Точка запуска командного агента в среде соревнования."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from agent.core.config import ModelConfig, ModelConfigError
from agent.core.llm import (
    LocalModelActionDriver,
    ModelRequestError,
    ModelUsage,
    OpenAICompatibleClient,
)
from agent.core.loop import AgentLoop, DeterministicDriver
from agent.core.models import AgentAction, DriverContext, LoopLimits


class LazyLocalModelDriver:
    """Читает настройки только тогда, когда действительно понадобилась модель."""

    def __init__(self):
        self._driver: LocalModelActionDriver | None = None
        self._unused_usage = ModelUsage()

    @property
    def usage(self) -> ModelUsage:
        if self._driver is None:
            return self._unused_usage
        return self._driver.usage

    def next_action(self, context: DriverContext) -> AgentAction:
        if self._driver is None:
            config = ModelConfig.from_env()
            self._driver = LocalModelActionDriver(OpenAICompatibleClient(config))
        return self._driver.next_action(context)


class HybridActionDriver:
    """Не расходует токены на известные профили и подключает модель при тупике."""

    def __init__(self, model_driver: LazyLocalModelDriver):
        self.deterministic = DeterministicDriver()
        self.model_driver = model_driver

    @property
    def usage(self):
        return self.model_driver.usage

    def next_action(self, context: DriverContext) -> AgentAction:
        # После неуспешной проверки нужна новая гипотеза, а не повтор `finish`.
        if context.last_validation and not context.last_validation.passed:
            return self.model_driver.next_action(context)

        action = self.deterministic.next_action(context)
        if action.name == "abort" and "future LLM driver" in action.rationale:
            return self.model_driver.next_action(context)
        return action


def _workdir() -> Path:
    return Path(os.environ.get("LOCAL_AGENT_WORKDIR", os.getcwd())).resolve()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instruction", nargs="+", help="текст задания")
    parser.add_argument("--probe", action="store_true", help="только проверить модель")
    parser.add_argument("--deadline-seconds", type=float, default=300.0)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
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

        driver = HybridActionDriver(LazyLocalModelDriver())
        result = AgentLoop(
            workdir=_workdir(),
            driver=driver,
            limits=LoopLimits(deadline_seconds=args.deadline_seconds),
        ).run(" ".join(args.instruction))
        payload = result.as_payload()
        payload["metrics"] = {
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "model_usage": driver.usage.as_payload(),
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if result.succeeded else 1
    except (ModelConfigError, ModelRequestError, OSError, ValueError) as error:
        # В сообщение не включаются значения переменных среды и ключ доступа.
        print(f"Запуск агента невозможен: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
