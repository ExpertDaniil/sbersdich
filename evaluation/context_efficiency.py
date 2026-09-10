#!/usr/bin/env python3
"""Воспроизводимое сравнение полного и сокращённого контекста для A-13.

По умолчанию проверка полностью локальная: настоящий клиент и построитель
запроса используются с детерминированным подменным транспортом. Флаг ``--live``
повторяет те же запросы через настроенный локальный адрес модели, но не запускает
инструменты и поэтому не изменяет проверяемый проект.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Mapping

from agent.core.config import ModelConfig, ModelConfigError
from agent.core.llm import (
    LocalModelActionDriver,
    ModelRequestError,
    OpenAICompatibleClient,
    Transport,
)
from agent.core.models import (
    AgentAction,
    DriverContext,
    LoopEvent,
    TaskContract,
    ToolDefinition,
    ToolResult,
)
from agent.core.playbooks import load_playbook, load_validation_playbook
from agent.core.tools import SecurityToolRegistry
from agent.strategies import classify_instruction


SCHEMA_VERSION = 1
BASELINE_EVENT_LIMIT = 24
COMPACT_EVENT_LIMIT = 6
MINIMUM_REDUCTION_PERCENT = 45.0
DEFAULT_OUTPUT = Path("evaluation/results/a13_context_efficiency.json")


@dataclass(frozen=True)
class Scenario:
    name: str
    instruction: str
    expected_mode: str


SCENARIOS = (
    Scenario(
        "audit",
        "Create security_report.json and do not modify project source files.",
        "audit",
    ),
    Scenario(
        "fix",
        "Fix the security vulnerability and validate the changed project.",
        "fix",
    ),
    Scenario(
        "forensics",
        "Analyze the incident logs and write incident_report.txt.",
        "forensics",
    ),
    Scenario(
        "general",
        "Inspect the workspace and choose the next safe diagnostic action.",
        "general",
    ),
)


class ContextEfficiencyError(RuntimeError):
    """Нарушен контракт воспроизводимого сравнения A-13."""


class EvaluationWindowDriver(LocalModelActionDriver):
    """Меняет окно событий только внутри измерения, не затрагивая ядро агента."""

    def __init__(self, client: OpenAICompatibleClient, *, event_limit: int):
        super().__init__(client)
        if isinstance(event_limit, bool) or not isinstance(event_limit, int):
            raise ValueError("event_limit должен быть целым числом")
        if not 1 <= event_limit <= 64:
            raise ValueError("event_limit должен находиться в диапазоне 1..64")
        self.event_limit = event_limit

    def _event_payload(self, context: DriverContext) -> list[dict[str, object]]:
        # Базовый преобразователь сам отбирает последние шесть событий. Чтобы
        # не копировать его правила, прогоняем через него каждое выбранное
        # событие отдельно и объединяем результат. Формат рабочего запроса
        # остаётся тем же, меняется только число событий в проверке.
        payload: list[dict[str, object]] = []
        for event in context.events[-self.event_limit :]:
            single_event_context = replace(context, events=(event,))
            payload.extend(LocalModelActionDriver._event_payload(single_event_context))
        return payload


class RecordingTransport:
    """Запоминает размер запроса и при необходимости передаёт его дальше."""

    def __init__(
        self,
        *,
        expected_marker: str,
        delegate: Transport | None = None,
    ):
        self.expected_marker = expected_marker
        self.delegate = delegate
        self.request_sizes: list[int] = []
        self.latest_evidence_preserved = False
        self.event_counts: list[int] = []

    def __call__(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout: float,
    ) -> Mapping[str, Any]:
        self.request_sizes.append(len(body))
        request = json.loads(body.decode("utf-8"))
        state = json.loads(request["messages"][1]["content"])
        events = state.get("recent_events", [])
        self.event_counts.append(len(events))
        self.latest_evidence_preserved = self.expected_marker in json.dumps(
            events,
            ensure_ascii=False,
        )
        if self.delegate is not None:
            return self.delegate(url, headers, body, timeout)

        # Подменный ответ зависит от наличия последнего доказательства. Это
        # сильнее, чем безусловный фиксированный ответ: потеря важного события
        # сразу меняет результат и проваливает сравнение.
        action_name = "finish" if self.latest_evidence_preserved else "abort"
        content = json.dumps(
            {
                "name": action_name,
                "arguments": {},
                "rationale": "latest evidence is available",
            },
            separators=(",", ":"),
        )
        return {
            "choices": [{"message": {"content": content}}],
            "usage": {
                "prompt_tokens": (len(body) + 3) // 4,
                "completion_tokens": (len(content.encode("utf-8")) + 3) // 4,
            },
        }


def _event_history(mode: str) -> tuple[LoopEvent, ...]:
    events: list[LoopEvent] = []
    for sequence in range(1, BASELINE_EVENT_LIMIT + 1):
        is_latest = sequence == BASELINE_EVENT_LIMIT
        marker = f"decisive-evidence::{mode}" if is_latest else f"noise::{sequence}"
        events.append(
            LoopEvent(
                sequence=sequence,
                phase="tool",
                action=AgentAction(
                    "read_file",
                    {"path": f"evidence/{mode}-{sequence:02d}.txt"},
                    "inspect one bounded source",
                ),
                tool_result=ToolResult(
                    True,
                    f"{marker}; " + ("наблюдение " * 55),
                    {
                        "source": f"evidence/{mode}-{sequence:02d}.txt",
                        "excerpt": marker + ":" + ("данные-" * 120),
                    },
                ),
            )
        )
    return tuple(events)


def _driver_context(
    root: Path,
    scenario: Scenario,
    *,
    remaining_seconds: float = 30.0,
) -> DriverContext:
    root.mkdir(parents=True, exist_ok=True)
    decision = classify_instruction(scenario.instruction)
    if decision.mode != scenario.expected_mode:
        raise ContextEfficiencyError(
            f"{scenario.name}: ожидался режим {scenario.expected_mode}, "
            f"получен {decision.mode}"
        )
    return DriverContext(
        instruction=scenario.instruction,
        workdir=root,
        decision=decision,
        task_playbook=load_playbook(decision.playbook),
        validation_playbook=load_validation_playbook(),
        contract=TaskContract(),
        available_tools=SecurityToolRegistry(root).catalog(decision),
        events=_event_history(decision.mode),
        last_validation=None,
        remaining_seconds=remaining_seconds,
    )


def _run_variant(
    context: DriverContext,
    *,
    event_limit: int,
    config: ModelConfig,
    live: bool,
) -> tuple[AgentAction, RecordingTransport, dict[str, int]]:
    marker = f"decisive-evidence::{context.decision.mode}"
    client = OpenAICompatibleClient(config)
    transport = RecordingTransport(
        expected_marker=marker,
        delegate=client.transport if live else None,
    )
    client.transport = transport
    driver = EvaluationWindowDriver(
        client,
        event_limit=event_limit,
    )
    action = driver.next_action(context)
    return action, transport, client.usage.as_payload()


def _schema_default(descriptor: str) -> object:
    kind, separator, raw = descriptor.partition("=")
    if not separator:
        raise ValueError("у параметра нет значения по умолчанию")
    if kind == "integer":
        return int(raw)
    if kind == "number":
        return float(raw)
    if kind == "boolean":
        if raw not in {"true", "false"}:
            raise ValueError("некорректное логическое значение по умолчанию")
        return raw == "true"
    return raw


def _action_signature(
    action: AgentAction,
    available_tools: tuple[ToolDefinition, ...] = (),
) -> dict[str, object]:
    """Вернуть фактическое действие с учётом необязательных параметров."""

    arguments = dict(action.arguments)
    definition = next(
        (tool for tool in available_tools if tool.name == action.name),
        None,
    )
    if definition is not None:
        for name, descriptor in definition.parameters.items():
            if name not in arguments and "=" in descriptor:
                arguments[name] = _schema_default(descriptor)
    return {"name": action.name, "arguments": arguments}


def _estimated_tokens(byte_count: int) -> int:
    """Отдельная грубая оценка; она не выдаётся за usage локальной модели."""

    return (byte_count + 3) // 4


def evaluate_scenario(
    root: Path,
    scenario: Scenario,
    *,
    config: ModelConfig,
    live: bool,
    before_request: Callable[[], None] | None = None,
) -> dict[str, object]:
    context = _driver_context(
        root,
        scenario,
        remaining_seconds=config.request_timeout_seconds if live else 30.0,
    )
    if before_request is not None:
        before_request()
    baseline_action, baseline, baseline_usage = _run_variant(
        context,
        event_limit=BASELINE_EVENT_LIMIT,
        config=config,
        live=live,
    )
    if before_request is not None:
        before_request()
    compact_action, compact, compact_usage = _run_variant(
        context,
        event_limit=COMPACT_EVENT_LIMIT,
        config=config,
        live=live,
    )
    if not baseline.request_sizes or not compact.request_sizes:
        raise ContextEfficiencyError("клиент не зарегистрировал запрос к модели")

    baseline_bytes = baseline.request_sizes[0]
    compact_bytes = compact.request_sizes[0]
    saved_bytes = baseline_bytes - compact_bytes
    reduction = round(saved_bytes * 100.0 / baseline_bytes, 2)
    baseline_effective = _action_signature(
        baseline_action,
        context.available_tools,
    )
    compact_effective = _action_signature(
        compact_action,
        context.available_tools,
    )
    actions_match = baseline_effective == compact_effective
    evidence_preserved = (
        baseline.latest_evidence_preserved and compact.latest_evidence_preserved
    )
    passed = (
        actions_match
        and evidence_preserved
        and compact_bytes < baseline_bytes
        and reduction >= MINIMUM_REDUCTION_PERCENT
    )
    result: dict[str, object] = {
        "name": scenario.name,
        "mode": context.decision.mode,
        "passed": passed,
        "actions_match": actions_match,
        "latest_evidence_preserved": evidence_preserved,
        "baseline_action": _action_signature(baseline_action),
        "compact_action": _action_signature(compact_action),
        "baseline_effective_action": baseline_effective,
        "compact_effective_action": compact_effective,
        "baseline_event_count": baseline.event_counts[0],
        "compact_event_count": compact.event_counts[0],
        "baseline_prompt_bytes": baseline_bytes,
        "compact_prompt_bytes": compact_bytes,
        "saved_prompt_bytes": saved_bytes,
        "baseline_estimated_input_tokens": _estimated_tokens(baseline_bytes),
        "compact_estimated_input_tokens": _estimated_tokens(compact_bytes),
        "saved_estimated_input_tokens": (
            _estimated_tokens(baseline_bytes) - _estimated_tokens(compact_bytes)
        ),
        "reduction_percent": reduction,
    }
    if live:
        baseline_tokens = int(baseline_usage["input_tokens"])
        compact_tokens = int(compact_usage["input_tokens"])
        result["baseline_input_tokens"] = baseline_tokens
        result["compact_input_tokens"] = compact_tokens
        result["saved_input_tokens"] = baseline_tokens - compact_tokens
        result["input_token_reduction_percent"] = (
            round((baseline_tokens - compact_tokens) * 100.0 / baseline_tokens, 2)
            if baseline_tokens
            else None
        )
    return result


def _offline_config() -> ModelConfig:
    return ModelConfig.from_env(
        {
            "LOCAL_AGENT_MODEL": "a13-offline-oracle",
            "OPENAI_BASE_URL": "http://model.invalid/v1",
            "OPENAI_API_KEY": "not-sent",
            "LOCAL_AGENT_RETRY_COUNT": "0",
        }
    )


def run_context_efficiency_suite(
    *,
    live: bool = False,
    config: ModelConfig | None = None,
    scenarios: tuple[Scenario, ...] = SCENARIOS,
    prior_results: Mapping[str, Mapping[str, object]] | None = None,
    cooldown_seconds: float = 0.0,
    sleeper: Callable[[float], None] = time.sleep,
    progress: Callable[[str], None] | None = None,
) -> dict[str, object]:
    if cooldown_seconds < 0 or cooldown_seconds > 120:
        raise ValueError("cooldown_seconds должен находиться в диапазоне 0..120")
    selected_config = config or (ModelConfig.from_env() if live else _offline_config())
    results: list[dict[str, object]] = []
    saved_results = prior_results or {}
    request_started = False

    def before_request() -> None:
        nonlocal request_started
        if live and request_started and cooldown_seconds:
            if progress is not None:
                progress(f"A-13: пауза {cooldown_seconds:g} с перед следующим запросом")
            sleeper(cooldown_seconds)
        request_started = True

    with tempfile.TemporaryDirectory(prefix="sbersdich-a13-") as temporary:
        root = Path(temporary).resolve()
        for scenario in scenarios:
            saved = saved_results.get(scenario.name)
            if saved is not None and saved.get("passed") is True:
                result = dict(saved)
                result["reused_from_prior_report"] = True
                results.append(result)
                if progress is not None:
                    progress(f"A-13: {scenario.name} уже пройден, повтор не нужен")
                continue
            if progress is not None:
                progress(f"A-13: выполняется сценарий {scenario.name}")
            try:
                result = evaluate_scenario(
                    root / scenario.name,
                    scenario,
                    config=selected_config,
                    live=live,
                    before_request=before_request if live else None,
                )
            except ModelRequestError as error:
                status_code = getattr(error, "status_code", None)
                result = {
                    "name": scenario.name,
                    "mode": scenario.expected_mode,
                    "passed": False,
                    "failure_kind": (
                        "temporary_service_error"
                        if status_code in {408, 409, 425, 429, 500, 502, 503, 504}
                        else "model_request_error"
                    ),
                    "http_status": status_code,
                    "error": f"{type(error).__name__}: {error}",
                }
            except (ContextEfficiencyError, OSError, ValueError) as error:
                result = {
                    "name": scenario.name,
                    "mode": scenario.expected_mode,
                    "passed": False,
                    "error": f"{type(error).__name__}: {error}",
                }
            results.append(result)
            if progress is not None:
                state = "пройден" if result.get("passed") else "не пройден"
                progress(f"A-13: {scenario.name} — {state}")

    measured = [item for item in results if "baseline_prompt_bytes" in item]
    baseline_total = sum(int(item["baseline_prompt_bytes"]) for item in measured)
    compact_total = sum(int(item["compact_prompt_bytes"]) for item in measured)
    saved_total = baseline_total - compact_total
    aggregate_reduction = (
        round(saved_total * 100.0 / baseline_total, 2) if baseline_total else 0.0
    )
    token_measured = [
        item
        for item in results
        if "baseline_input_tokens" in item and "compact_input_tokens" in item
    ]
    baseline_input_tokens = sum(
        int(item["baseline_input_tokens"]) for item in token_measured
    )
    compact_input_tokens = sum(
        int(item["compact_input_tokens"]) for item in token_measured
    )
    saved_input_tokens = baseline_input_tokens - compact_input_tokens
    passed_count = sum(bool(item.get("passed")) for item in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": "a13-context-efficiency",
        "measurement_mode": "live-local-model" if live else "offline-deterministic",
        "baseline_event_limit": BASELINE_EVENT_LIMIT,
        "compact_event_limit": COMPACT_EVENT_LIMIT,
        "minimum_reduction_percent": MINIMUM_REDUCTION_PERCENT,
        "request_timeout_seconds": selected_config.request_timeout_seconds,
        "cooldown_seconds": cooldown_seconds if live else 0.0,
        "reused_scenario_count": sum(
            bool(item.get("reused_from_prior_report")) for item in results
        ),
        "passed": bool(results) and passed_count == len(results),
        "scenario_count": len(results),
        "passed_count": passed_count,
        "failed_count": len(results) - passed_count,
        "baseline_prompt_bytes": baseline_total,
        "compact_prompt_bytes": compact_total,
        "saved_prompt_bytes": saved_total,
        "baseline_estimated_input_tokens": _estimated_tokens(baseline_total),
        "compact_estimated_input_tokens": _estimated_tokens(compact_total),
        "saved_estimated_input_tokens": (
            _estimated_tokens(baseline_total) - _estimated_tokens(compact_total)
        ),
        "reported_token_scenario_count": len(token_measured),
        "reported_input_tokens_complete": live and len(token_measured) == len(results),
        "baseline_reported_input_tokens": baseline_input_tokens,
        "compact_reported_input_tokens": compact_input_tokens,
        "saved_reported_input_tokens": saved_input_tokens,
        "reported_input_token_reduction_percent": (
            round(saved_input_tokens * 100.0 / baseline_input_tokens, 2)
            if baseline_input_tokens
            else None
        ),
        "reduction_percent": aggregate_reduction,
        "scenarios": results,
    }


def write_report(path: Path, report: Mapping[str, object]) -> None:
    if path.exists() and path.is_symlink():
        raise OSError("путь отчёта не должен быть символической ссылкой")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def load_successful_results(path: Path) -> dict[str, Mapping[str, object]]:
    """Прочитать только успешные сценарии совместимого отчёта настоящей модели."""

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"не удалось прочитать предыдущий отчёт: {error}") from error
    if not isinstance(payload, dict) or payload.get("suite") != "a13-context-efficiency":
        raise ValueError("предыдущий файл не является отчётом A-13")
    if payload.get("measurement_mode") != "live-local-model":
        raise ValueError("для возобновления нужен отчёт настоящей модели")
    scenarios = payload.get("scenarios")
    if not isinstance(scenarios, list):
        raise ValueError("в предыдущем отчёте отсутствует список сценариев")

    successful: dict[str, Mapping[str, object]] = {}
    for item in scenarios:
        if not isinstance(item, dict) or item.get("passed") is not True:
            continue
        name = item.get("name")
        if isinstance(name, str):
            successful[name] = item
    return successful


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--live",
        action="store_true",
        help="выполнить сравнение через LOCAL_AGENT_MODEL и OPENAI_BASE_URL",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="сохранить успешные сценарии из существующего выходного отчёта",
    )
    parser.add_argument(
        "--cooldown-seconds",
        type=float,
        default=15.0,
        help="пауза между запросами настоящей модели; по умолчанию 15 секунд",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.resume and not args.live:
            raise ValueError("--resume применяется только вместе с --live")
        prior_results = load_successful_results(args.output) if args.resume else None
        report = run_context_efficiency_suite(
            live=args.live,
            prior_results=prior_results,
            cooldown_seconds=args.cooldown_seconds if args.live else 0.0,
            progress=(
                (lambda message: print(message, file=sys.stderr, flush=True))
                if args.live
                else None
            ),
        )
        write_report(args.output, report)
    except (ModelConfigError, OSError, ValueError) as error:
        print(f"A-13: невозможно выполнить сравнение: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
