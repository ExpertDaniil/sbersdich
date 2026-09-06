#!/usr/bin/env python3
"""Build a deterministic C-11 failure journal from agent run artifacts.

The analyzer intentionally uses only the Python standard library.  It accepts
JSON traces, JSONL events and plain text logs, then assigns every detected run
failure to one of the C-11 buckets.  Every journal entry contains bounded,
redacted evidence from the input, a concrete reason and the next owner.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import tempfile
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
CATEGORIES = (
    "launch",
    "format",
    "hypothesis",
    "execution",
    "timeout",
    "budget",
    "regression",
)
ALL_CATEGORIES = CATEGORIES + ("unknown",)

SUPPORTED_SUFFIXES = frozenset({".json", ".jsonl", ".ndjson", ".log", ".txt"})
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_INPUT_FILES = 256
MAX_RECORDS = 10_000
MAX_SIGNALS = 2_048
MAX_EVIDENCE = 3
MAX_EXCERPT_CHARS = 500

SUCCESS_STATUSES = frozenset({"ok", "pass", "passed", "success", "succeeded"})
FAILURE_STATUSES = frozenset(
    {"abort", "aborted", "cancelled", "error", "failed", "failure", "timeout"}
)
META_KEYS = frozenset(
    {
        "expected_or_solution_read",
        "meta",
        "metadata",
        "public_repository_unchanged",
        "schema_version",
    }
)
RUN_KEYS = frozenset(
    {
        "category",
        "error",
        "events",
        "exception",
        "exit_code",
        "failure",
        "final_validation",
        "isError",
        "log",
        "ok",
        "passed",
        "reason",
        "returncode",
        "reward",
        "status",
        "stderr",
        "success",
        "timed_out",
        "timeout",
        "traceback",
    }
)
RELEVANT_FIELDS = frozenset(
    {
        "category",
        "detail",
        "error",
        "exception",
        "exit_code",
        "failure",
        "isError",
        "log",
        "message",
        "phase",
        "rationale",
        "reason",
        "returncode",
        "reward",
        "status",
        "stderr",
        "stdout",
        "summary",
        "timed_out",
        "timeout",
        "traceback",
    }
)
SECRET_FIELD_NAMES = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "secret",
        "token",
    }
)
SECRET_FIELD_SUFFIXES = (
    "_api_key",
    "_authorization",
    "_cookie",
    "_password",
    "_secret",
    "_token",
)


class AnalysisError(ValueError):
    """Raised for invalid or unsafe analyzer input."""


@dataclass(frozen=True)
class SourceRecord:
    task_id: str
    payload: Mapping[str, Any]
    source: str
    json_path: str


@dataclass(frozen=True)
class Signal:
    json_path: str
    key: str
    text: str
    order: int


@dataclass(frozen=True)
class Evidence:
    source: str
    json_path: str
    excerpt: str

    def as_payload(self) -> dict[str, str]:
        return {
            "source": self.source,
            "json_path": self.json_path,
            "excerpt": self.excerpt,
        }


@dataclass(frozen=True)
class PatternRule:
    category: str
    expression: re.Pattern[str]
    weight: int


@dataclass(frozen=True)
class Match:
    category: str
    score: int
    signal: Signal
    expression: re.Pattern[str] | None


CATEGORY_DETAILS: dict[str, dict[str, Any]] = {
    "launch": {
        "reason": (
            "Среда, entrypoint или обязательная конфигурация не позволили "
            "начать выполнение задачи."
        ),
        "owner": {"block": "B", "component": "runtime-and-entrypoint"},
        "next_action": (
            "Проверить run.sh, рабочий каталог, права, переменные окружения "
            "и доступность локального endpoint."
        ),
    },
    "format": {
        "reason": (
            "Результат не соответствует обязательному формату, пути или "
            "контракту артефакта."
        ),
        "owner": {"block": "C", "component": "validation-and-output-contract"},
        "next_action": (
            "Сверить инструкцию и validator, затем исправить имя, путь, "
            "схему или точное содержимое артефакта."
        ),
    },
    "hypothesis": {
        "reason": (
            "Агент выбрал неподтверждённую интерпретацию задачи, находку "
            "или способ исправления."
        ),
        "owner": {"block": "C", "component": "security-strategies"},
        "next_action": (
            "Повторно собрать факты, проверить альтернативные гипотезы и "
            "требовать подтверждение находки до изменения файлов."
        ),
    },
    "execution": {
        "reason": (
            "Выбранное действие или инструмент завершились ошибкой во время "
            "выполнения."
        ),
        "owner": {"block": "A", "component": "agent-core-and-tools"},
        "next_action": (
            "Воспроизвести упавшее действие с теми же аргументами и исправить "
            "обработку ошибки или контракт инструмента."
        ),
    },
    "timeout": {
        "reason": (
            "Выполнение превысило доступное время или deadline отдельной "
            "операции."
        ),
        "owner": {"block": "A", "component": "orchestration-and-deadlines"},
        "next_action": (
            "Найти самый долгий этап, ограничить объём чтения или команд и "
            "зарезервировать время на финальную проверку."
        ),
    },
    "budget": {
        "reason": (
            "Исчерпан лимит шагов, валидаций, повторов, контекста или "
            "LLM-токенов."
        ),
        "owner": {"block": "A", "component": "agent-loop-and-budgets"},
        "next_action": (
            "Устранить повторяющиеся действия, сократить контекст и "
            "перераспределить бюджет между поиском, исправлением и проверкой."
        ),
    },
    "regression": {
        "reason": (
            "Тесты, syntax-check или security-проверка обнаружили регрессию "
            "после действий агента."
        ),
        "owner": {"block": "C", "component": "security-regression-verification"},
        "next_action": (
            "Открыть первый упавший check, локализовать изменение и повторить "
            "полный набор тестов после минимального исправления."
        ),
    },
    "unknown": {
        "reason": (
            "В журнале есть факт провала, но данных недостаточно для надёжной "
            "автоматической классификации."
        ),
        "owner": {"block": "TEAM", "component": "manual-triage"},
        "next_action": (
            "Назначить ручной triage и добавить в лог status, reason, phase, "
            "tool result и final validation."
        ),
    },
}


_RULE_SPECS: dict[str, tuple[tuple[str, int], ...]] = {
    "launch": (
        (r"\b(?:entrypoint|startup|failed to start|cannot start|could not start)\b", 150),
        (r"\b(?:run\.sh|exec format error|command not found|not recognized as .*command)\b", 145),
        (r"\b(?:modulenotfounderror|importerror|no module named)\b", 140),
        (r"\b(?:no such file or directory|executable not found)\b", 135),
        (
            r"\b(?:openai_base_url|local_agent_model|missing configuration|"
            r"configuration (?:error|failed))\b",
            125,
        ),
        (r"\b(?:connection refused|failed to connect|permission denied during startup)\b", 115),
        (
            r"(?:не удалось|невозможно)\s+запуст|точк[аи]\s+входа|"
            r"команда не найдена",
            145,
        ),
    ),
    "format": (
        (r"\b(?:artifact is missing|missing artifact|required artifact)\b", 150),
        (r"\b(?:required|expected|output) file.*(?:missing|not found)\b", 145),
        (r"\b(?:exact[-_ ]text|wrong (?:file )?path|path escapes workdir|outside workdir)\b", 140),
        (r"\b(?:invalid json|jsondecodeerror|malformed json|schema validation)\b", 135),
        (r"\b(?:output contract|artifact contract|unexpected format|required format)\b", 125),
        (r"\b(?:checker rejected|invalid artifact|output file is missing)\b", 120),
        (
            r"артефакт.*(?:отсутств|не найден)|неверн(?:ый|ого) формат|"
            r"неверн(?:ый|ого) путь",
            145,
        ),
    ),
    "hypothesis": (
        (
            r"\b(?:wrong|incorrect|unsupported) "
            r"(?:hypothesis|finding|vulnerability|answer|root cause)\b",
            150,
        ),
        (r"\b(?:vulnerability|finding) (?:was )?not found\b", 145),
        (r"\b(?:no supported change|unsupported task|no high-confidence)\b", 135),
        (r"\b(?:misclassified|false positive|false negative)\b", 125),
        (
            r"уязвимост.*не найден|неверн.*(?:гипотез|уязвимост|ответ)|"
            r"ложн.*срабатыв",
            145,
        ),
    ),
    "execution": (
        (r"\btool[-_ ]failed\b|\btool .* failed\b", 145),
        (r"\b(?:apply_patch|write_exact_text|run_process|subprocess) failed\b", 140),
        (r"\b(?:action driver|model request|http request) failed\b", 135),
        (r"\b(?:unhandled exception|runtimeerror|oserror)\b", 120),
        (r"\b(?:action failed|failed action|cannot execute)\b", 115),
        (
            r"инструмент.*(?:ошиб|не выполн)|действи.*(?:ошиб|не выполн)|"
            r"исключени",
            125,
        ),
    ),
    "timeout": (
        (r"\b(?:timed out|timeout|deadline exceeded|time limit exceeded)\b", 165),
        (r"\bdeadline (?:budget )?(?:is )?exhausted\b", 165),
        (r"\b(?:exit code|returncode)\s*[:=]?\s*124\b", 160),
        (
            r"(?:таймаут|превышен.*(?:врем|deadline)|"
            r"ист[её]к.*(?:срок|врем))",
            165,
        ),
    ),
    "budget": (
        (r"\b(?:scripted )?action queue is exhausted\b", 165),
        (r"\b(?:repeated-action|max(?:imum)? steps?|max_steps|step limit)\b", 155),
        (r"\b(?:max_validations|validation budget|validation limit)\b", 150),
        (
            r"\b(?:token[_ -]?budget|token limit|context length|"
            r"context[_ -]?window|too many tokens)\b",
            145,
        ),
        (
            r"\b(?:step|validation(?:-attempt)?|token|context|action) "
            r"budget (?:is )?exhausted\b",
            150,
        ),
        (r"\b(?:budget exhausted|budget exceeded|out of budget)\b", 140),
        (
            r"исчерпан.*бюджет|лимит.*(?:шаг|валидац|токен|контекст)|"
            r"слишком много токен",
            150,
        ),
    ),
    "regression": (
        (r"\b(?:pytest|unittest|test suite|project tests?) (?:failed|failure)\b", 155),
        (r"\bfailed\s*\((?:failures?|errors?)\s*=\s*\d+", 155),
        (r"\b(?:project[-_ ]tests?|python[-_ ]syntax).*passed.*false\b", 150),
        (r"\b(?:assertionerror|syntaxerror|compile error|regression)\b", 145),
        (r"\b(?:security check|project command|syntax check) (?:failed|failure)\b", 140),
        (r"\b(?:tests? failed|failed tests?|failed checks?)\b", 115),
        (r"(?:тест|провер).*не прош|регресси|ошибка синтаксиса", 145),
    ),
}

PATTERN_RULES = tuple(
    PatternRule(category, re.compile(expression, re.IGNORECASE), weight)
    for category, specs in _RULE_SPECS.items()
    for expression, weight in specs
)

CATEGORY_TIE_ORDER = {
    category: index
    for index, category in enumerate(
        ("timeout", "budget", "launch", "format", "hypothesis", "regression", "execution")
    )
}

_FAILURE_TEXT = re.compile(
    r"\b(?:failed|failure|fatal|error|exception|traceback|timed out|timeout|denied|aborted)\b",
    re.IGNORECASE,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(openai_api_key|api[_-]?key|access[_-]?token|password|secret|token)"
    r"\s*([:=])\s*([^\s,;\]\[{}]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+\-/=]+")
_OPENAI_STYLE_KEY = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")


def _is_secret_field(key: str) -> bool:
    normalized = key.casefold().replace("-", "_")
    return (
        normalized in SECRET_FIELD_NAMES
        or normalized.startswith(("authorization_", "cookie_"))
        or normalized.endswith(SECRET_FIELD_SUFFIXES)
    )


def redact_text(text: str) -> str:
    """Remove common credentials before any value reaches the journal."""

    text = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", text)
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _OPENAI_STYLE_KEY.sub("[REDACTED]", text)


def _safe_scalar(key: str, value: Any) -> str:
    if _is_secret_field(key):
        return "[REDACTED]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return redact_text(str(value))


def _display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        rendered = resolved.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        rendered = resolved.as_posix()
    return redact_text(rendered)


def _path_identity(path: Path) -> str:
    return os.path.normcase(str(path.resolve()))


def discover_input_files(inputs: Sequence[Path], output_path: Path | None = None) -> list[Path]:
    """Resolve supported inputs without following file symlinks."""

    if not inputs:
        raise AnalysisError("at least one input file or directory is required")
    excluded = _path_identity(output_path) if output_path is not None else None
    found: dict[str, Path] = {}

    for raw in inputs:
        path = raw.expanduser()
        if not path.exists():
            raise AnalysisError(f"input does not exist: {raw}")
        if path.is_symlink():
            raise AnalysisError(f"refusing symlink input: {raw}")
        if path.is_file():
            if path.suffix.casefold() not in SUPPORTED_SUFFIXES:
                raise AnalysisError(f"unsupported input type: {raw}")
            candidates: Iterator[Path] = iter((path,))
        elif path.is_dir():
            candidates = (
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file()
                and not candidate.is_symlink()
                and candidate.suffix.casefold() in SUPPORTED_SUFFIXES
            )
        else:
            raise AnalysisError(f"input is neither a regular file nor directory: {raw}")

        for candidate in candidates:
            identity = _path_identity(candidate)
            if identity != excluded:
                found.setdefault(identity, candidate.resolve())
                if len(found) > MAX_INPUT_FILES:
                    raise AnalysisError(f"too many input files: maximum is {MAX_INPUT_FILES}")

    if not found:
        raise AnalysisError("no supported input files were found")
    return sorted(found.values(), key=lambda item: _display_path(item).casefold())


def _read_text(path: Path) -> str:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise AnalysisError(
            f"input is too large: {_display_path(path)} ({size} bytes; maximum {MAX_FILE_BYTES})"
        )
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        raise AnalysisError(f"input is not UTF-8: {_display_path(path)}") from error
    except OSError as error:
        raise AnalysisError(f"cannot read {_display_path(path)}: {error}") from error


def _looks_like_record(value: Mapping[str, Any]) -> bool:
    return bool(RUN_KEYS.intersection(value))


def _clean_task_id(value: Any, fallback: str) -> str:
    rendered = redact_text(str(value if value not in (None, "") else fallback)).strip()
    rendered = " ".join(rendered.split())
    return rendered[:200] or fallback[:200]


def _task_id(payload: Mapping[str, Any], inherited: str, fallback: str) -> str:
    for key in ("task_id", "task", "name", "id"):
        value = payload.get(key)
        if isinstance(value, (str, int)) and str(value).strip():
            return _clean_task_id(value, fallback)
    return _clean_task_id(inherited, fallback)


def _records_from_value(
    value: Any,
    *,
    source: str,
    json_path: str,
    inherited_task: str,
    fallback_task: str,
) -> Iterator[SourceRecord]:
    if isinstance(value, Mapping):
        if _looks_like_record(value):
            yield SourceRecord(
                task_id=_task_id(value, inherited_task, fallback_task),
                payload=value,
                source=source,
                json_path=json_path,
            )
            return
        for key, child in value.items():
            if str(key) in META_KEYS:
                continue
            child_path = f"{json_path}.{key}"
            child_task = inherited_task
            if isinstance(child, Mapping) and _looks_like_record(child):
                child_task = str(key)
            yield from _records_from_value(
                child,
                source=source,
                json_path=child_path,
                inherited_task=child_task,
                fallback_task=fallback_task,
            )
        return
    if isinstance(value, list):
        for index, child in enumerate(value):
            yield from _records_from_value(
                child,
                source=source,
                json_path=f"{json_path}[{index}]",
                inherited_task=inherited_task,
                fallback_task=fallback_task,
            )


def _log_has_failure(text: str) -> bool:
    normalized = re.sub(
        r"(?i)\b(?:failed|failures?|errors?)\s*[:=]?\s*0\b|\b0\s+(?:failed|failures?|errors?)\b",
        "",
        text,
    )
    return _FAILURE_TEXT.search(normalized) is not None


def load_records(path: Path) -> list[SourceRecord]:
    """Parse one supported source into run-level records."""

    text = _read_text(path)
    source = _display_path(path)
    fallback = path.stem
    suffix = path.suffix.casefold()

    if suffix == ".json":
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise AnalysisError(
                f"invalid JSON in {source} at line {error.lineno}, column {error.colno}"
            ) from error
        except RecursionError as error:
            raise AnalysisError(f"JSON is nested too deeply in {source}") from error
        try:
            records = []
            for record in _records_from_value(
                payload,
                source=source,
                json_path="$",
                inherited_task=fallback,
                fallback_task=fallback,
            ):
                records.append(record)
                if len(records) > MAX_RECORDS:
                    raise AnalysisError(
                        f"too many records in {source}: maximum is {MAX_RECORDS}"
                    )
        except RecursionError as error:
            raise AnalysisError(f"JSON is nested too deeply in {source}") from error
    elif suffix in {".jsonl", ".ndjson"}:
        records = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError as error:
                raise AnalysisError(
                    f"invalid JSONL in {source} at line {line_number}, column {error.colno}"
                ) from error
            except RecursionError as error:
                raise AnalysisError(
                    f"JSONL is nested too deeply in {source} at line {line_number}"
                ) from error
            try:
                line_records = _records_from_value(
                    payload,
                    source=source,
                    json_path=f"$line[{line_number}]",
                    inherited_task=f"{fallback}:{line_number}",
                    fallback_task=fallback,
                )
                for record in line_records:
                    records.append(record)
                    if len(records) > MAX_RECORDS:
                        raise AnalysisError(
                            f"too many records in {source}: maximum is {MAX_RECORDS}"
                        )
            except RecursionError as error:
                raise AnalysisError(f"JSONL is nested too deeply in {source}") from error
    else:
        records = []
        if _log_has_failure(text):
            records.append(
                SourceRecord(
                    task_id=fallback,
                    payload={"status": "failed", "log": text},
                    source=source,
                    json_path="$",
                )
            )

    return records


def _normalized_status(payload: Mapping[str, Any]) -> str:
    value = payload.get("status")
    return str(value).strip().casefold() if value is not None else ""


def _is_zero_reward(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) and value <= 0


def _is_nonzero_code(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value != 0


def _explicit_success(payload: Mapping[str, Any]) -> bool:
    if _is_zero_reward(payload.get("reward")):
        return False
    status = _normalized_status(payload)
    if status in FAILURE_STATUSES:
        return False
    if status in SUCCESS_STATUSES:
        return True
    for key in ("passed", "success", "ok"):
        if payload.get(key) is True:
            return True
    return False


def _mapping_is_failure(value: Mapping[str, Any]) -> bool:
    if str(value.get("category", "")).casefold() in ALL_CATEGORIES:
        return True
    if _normalized_status(value) in FAILURE_STATUSES:
        return True
    if value.get("passed") is False or value.get("success") is False or value.get("ok") is False:
        return True
    if value.get("isError") is True or value.get("timed_out") is True:
        return True
    if _is_zero_reward(value.get("reward")):
        return True
    if _is_nonzero_code(value.get("exit_code")) or _is_nonzero_code(value.get("returncode")):
        return True
    phase = str(value.get("phase", "")).casefold()
    return any(token in phase for token in ("fail", "error", "timeout", "abort"))


def _compact_context(value: Mapping[str, Any]) -> str:
    compact: dict[str, Any] = {}
    for key, child in value.items():
        rendered_key = str(key)
        if isinstance(child, (str, int, float, bool)) or child is None:
            compact[rendered_key] = _safe_scalar(rendered_key, child)
    if not compact:
        return "failure=true"
    return json.dumps(compact, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def collect_signals(payload: Mapping[str, Any], base_path: str) -> list[Signal]:
    """Collect only failure-relevant, already-redacted scalar evidence."""

    signals: list[Signal] = []

    def append(path: str, key: str, text: str) -> None:
        if len(signals) >= MAX_SIGNALS:
            return
        signals.append(Signal(path, key, redact_text(text), len(signals)))

    def walk(value: Any, path: str) -> None:
        if len(signals) >= MAX_SIGNALS:
            return
        if isinstance(value, Mapping):
            failure_context = _mapping_is_failure(value)
            if failure_context:
                append(path, "failure_context", _compact_context(value))
            for raw_key, child in value.items():
                key = str(raw_key)
                child_path = f"{path}.{key}"
                if isinstance(child, Mapping) or isinstance(child, list):
                    walk(child, child_path)
                    continue
                should_capture = key in RELEVANT_FIELDS or failure_context
                if key in {"passed", "success", "ok"} and child is False:
                    should_capture = True
                if should_capture:
                    append(child_path, key, _safe_scalar(key, child))
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{path}[{index}]")

    walk(payload, base_path)
    return signals


def _record_is_failure(record: SourceRecord, signals: Sequence[Signal]) -> bool:
    if _explicit_success(record.payload):
        return False
    if _mapping_is_failure(record.payload):
        return True
    return any(_FAILURE_TEXT.search(signal.text) for signal in signals)


def _bounded_excerpt(text: str, expression: re.Pattern[str] | None = None) -> str:
    cleaned = " ".join(redact_text(text).split())
    if len(cleaned) <= MAX_EXCERPT_CHARS:
        return cleaned
    center = 0
    if expression is not None:
        match = expression.search(cleaned)
        if match is not None:
            center = (match.start() + match.end()) // 2
    half = MAX_EXCERPT_CHARS // 2
    start = max(0, min(center - half, len(cleaned) - MAX_EXCERPT_CHARS))
    end = start + MAX_EXCERPT_CHARS
    prefix = "…" if start else ""
    suffix = "…" if end < len(cleaned) else ""
    return f"{prefix}{cleaned[start:end]}{suffix}"


def _candidate_score(rule: PatternRule, signal: Signal) -> int:
    score = rule.weight
    if signal.key in {"reason", "error", "exception", "summary", "detail", "phase"}:
        score += 5
    if ".final_validation" in signal.json_path and rule.category in {"format", "regression"}:
        score += 8
    return score


def _classify(record: SourceRecord, signals: Sequence[Signal]) -> tuple[str, str, list[Evidence]]:
    matches: list[Match] = []
    explicit_category = str(record.payload.get("category", "")).strip().casefold()
    if explicit_category in ALL_CATEGORIES:
        category_signal = next((item for item in signals if item.key == "category"), None)
        if category_signal is None:
            category_signal = Signal(record.json_path, "category", explicit_category, -1)
        matches.append(Match(explicit_category, 250, category_signal, None))

    for signal in signals:
        haystack = f"{signal.json_path} {signal.key} {signal.text}"
        if signal.key == "timed_out" and signal.text == "true":
            matches.append(Match("timeout", 190, signal, None))
        if signal.key in {"exit_code", "returncode"} and signal.text == "124":
            matches.append(Match("timeout", 185, signal, None))
        elif signal.key in {"exit_code", "returncode"}:
            try:
                nonzero_exit = int(signal.text) != 0
            except ValueError:
                nonzero_exit = False
            if nonzero_exit:
                matches.append(Match("execution", 100, signal, None))
        if signal.key == "phase" and "tool-failed" in signal.text.casefold():
            matches.append(Match("execution", 175, signal, None))
        for rule in PATTERN_RULES:
            if rule.expression.search(haystack):
                matches.append(
                    Match(rule.category, _candidate_score(rule, signal), signal, rule.expression)
                )

    if matches:
        best_score_by_category: dict[str, int] = {}
        for match in matches:
            best_score_by_category[match.category] = max(
                match.score, best_score_by_category.get(match.category, 0)
            )
        category = min(
            best_score_by_category,
            key=lambda item: (-best_score_by_category[item], CATEGORY_TIE_ORDER.get(item, 99)),
        )
        category_score = best_score_by_category[category]
        if category == "unknown":
            confidence = "low"
        else:
            confidence = "high" if category_score >= 130 else "medium"
        category_matches = sorted(
            (item for item in matches if item.category == category),
            key=lambda item: (-item.score, item.signal.order),
        )
    else:
        category = "unknown"
        confidence = "low"
        category_matches = []

    evidence: list[Evidence] = []
    seen: set[tuple[str, str]] = set()
    candidates: list[tuple[Signal, re.Pattern[str] | None]] = [
        (item.signal, item.expression) for item in category_matches
    ]
    candidates.extend((signal, None) for signal in signals)
    for signal, expression in candidates:
        excerpt = _bounded_excerpt(signal.text, expression)
        if not excerpt:
            continue
        identity = (signal.json_path, excerpt)
        if identity in seen:
            continue
        seen.add(identity)
        evidence.append(Evidence(record.source, signal.json_path, excerpt))
        if len(evidence) >= MAX_EVIDENCE:
            break
    if not evidence:
        evidence.append(Evidence(record.source, record.json_path, "failure record detected"))
    return category, confidence, evidence


def _failure_payload(record: SourceRecord) -> dict[str, Any] | None:
    signals = collect_signals(record.payload, record.json_path)
    if not _record_is_failure(record, signals):
        return None
    category, confidence, evidence = _classify(record, signals)
    details = CATEGORY_DETAILS[category]
    return {
        "task_id": record.task_id,
        "category": category,
        "confidence": confidence,
        "reason": details["reason"],
        "cause": evidence[0].excerpt,
        "owner": details["owner"],
        "next_action": details["next_action"],
        "evidence": [item.as_payload() for item in evidence],
    }


def analyze_paths(inputs: Sequence[Path], output_path: Path | None = None) -> dict[str, Any]:
    """Analyze inputs and return a deterministic, JSON-serializable report."""

    files = discover_input_files(inputs, output_path)
    failures: list[dict[str, Any]] = []
    analyzed_records = 0
    successful_records = 0
    neutral_records = 0

    for path in files:
        records = load_records(path)
        for record in records:
            analyzed_records += 1
            if analyzed_records > MAX_RECORDS:
                raise AnalysisError(f"too many records: maximum is {MAX_RECORDS}")
            if _explicit_success(record.payload):
                successful_records += 1
                continue
            try:
                failure = _failure_payload(record)
            except RecursionError as error:
                raise AnalysisError(
                    f"record is nested too deeply: {record.source} {record.json_path}"
                ) from error
            if failure is None:
                neutral_records += 1
            else:
                failures.append(failure)

    failures.sort(
        key=lambda item: (
            item["evidence"][0]["source"].casefold(),
            item["evidence"][0]["json_path"],
            item["task_id"].casefold(),
        )
    )
    counts = Counter(item["category"] for item in failures)
    return {
        "schema_version": SCHEMA_VERSION,
        "input_files": [_display_path(path) for path in files],
        "input_file_count": len(files),
        "analyzed_record_count": analyzed_records,
        "successful_record_count": successful_records,
        "neutral_record_count": neutral_records,
        "failure_count": len(failures),
        "classified_failure_count": len(failures) - counts["unknown"],
        "unknown_failure_count": counts["unknown"],
        "category_counts": {category: counts[category] for category in ALL_CATEGORIES},
        "failures": failures,
    }


def write_report(path: Path, payload: Mapping[str, Any]) -> None:
    """Atomically write one UTF-8 JSON report."""

    expanded = path.expanduser()
    if expanded.is_symlink():
        raise AnalysisError(f"refusing symlink output: {path}")
    target = expanded.resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.replace(temporary_name, target)
    except OSError as error:
        raise AnalysisError(f"cannot write {target}: {error}") from error
    finally:
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink(missing_ok=True)
            except OSError:
                pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="JSON, JSONL, log or directory with run artifacts",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evaluation/results/failure_journal.json"),
        help="journal path (default: evaluation/results/failure_journal.json)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="return exit code 1 when at least one failure remains unknown",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        report = analyze_paths(args.inputs, args.output)
        write_report(args.output, report)
    except AnalysisError as error:
        print(f"C-11 analysis error: {error}", file=sys.stderr)
        return 2

    print(
        "C-11 failure journal: "
        f"{report['failure_count']} failure(s), "
        f"{report['unknown_failure_count']} unknown; "
        f"output={args.output.resolve()}"
    )
    if args.strict and report["unknown_failure_count"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
