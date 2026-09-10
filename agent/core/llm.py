"""Ограниченный клиент локальной модели и преобразователь ответа в действие."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import ModelConfig
from .models import AgentAction, DriverContext
from .tools import RESERVED_ACTIONS


MAX_RESPONSE_BYTES = 256_000
MAX_INSTRUCTION_CHARS = 32_000
MAX_PLAYBOOK_CHARS = 8_000
MAX_EVENT_CHARS = 2_000
MAX_CONTEXT_EVENTS = 6
RETRYABLE_HTTP_CODES = frozenset({408, 409, 425, 429, 500, 502, 503, 504})


class ModelRequestError(RuntimeError):
    """Локальная модель не ответила корректно в пределах ограничений."""


@dataclass
class ModelUsage:
    """Метрики обращений; отдельно считаются реальные и оценочные токены."""

    requests: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    estimated_tokens: int = 0

    def as_payload(self) -> dict[str, int]:
        return {
            "requests": self.requests,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.input_tokens + self.output_tokens,
            "estimated_tokens": self.estimated_tokens,
        }


Transport = Callable[[str, Mapping[str, str], bytes, float], Mapping[str, Any]]


def _bounded_text(value: object, limit: int) -> str:
    text = str(value)
    if len(text) <= limit:
        return text
    return text[:limit] + "…"


def _default_transport(
    url: str, headers: Mapping[str, str], body: bytes, timeout: float
) -> Mapping[str, Any]:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - адрес проверен
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        # Тело ответа намеренно не включается: некоторые серверы отражают поля
        # запроса, а в заголовке запроса находится ключ доступа.
        wrapped = ModelRequestError(f"локальная модель вернула HTTP {error.code}")
        setattr(wrapped, "status_code", error.code)
        raise wrapped from error
    except (TimeoutError, URLError, OSError) as error:
        raise ModelRequestError("локальная модель недоступна или не ответила вовремя") from error

    if len(raw) > MAX_RESPONSE_BYTES:
        raise ModelRequestError("ответ локальной модели превышает допустимый размер")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ModelRequestError("локальная модель вернула некорректный JSON") from error
    if not isinstance(payload, dict):
        raise ModelRequestError("локальная модель вернула JSON неверного типа")
    return payload


class OpenAICompatibleClient:
    """Минимальный клиент `/chat/completions` без установки зависимостей."""

    def __init__(
        self,
        config: ModelConfig,
        *,
        transport: Transport = _default_transport,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = config
        self.transport = transport
        self.sleeper = sleeper
        self.clock = clock
        self.usage = ModelUsage()

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        max_tokens: int = 512,
        timeout_seconds: float | None = None,
    ) -> str:
        if max_tokens < 1:
            raise ValueError("max_tokens должно быть положительным")
        overall_timeout = min(
            self.config.request_timeout_seconds,
            timeout_seconds if timeout_seconds is not None else float("inf"),
        )
        if overall_timeout <= 0:
            raise ModelRequestError("не осталось времени на запрос к модели")
        deadline = self.clock() + overall_timeout

        body = json.dumps(
            {
                "model": self.config.model,
                "messages": list(messages),
                "temperature": 0,
                "max_tokens": max_tokens,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {self.config.api_key}",
            "Content-Type": "application/json",
        }

        last_error: ModelRequestError | None = None
        for attempt in range(self.config.retry_count + 1):
            attempt_timeout = deadline - self.clock()
            if attempt_timeout <= 0:
                last_error = ModelRequestError("истёк срок запроса к локальной модели")
                break
            self.usage.requests += 1
            try:
                payload = self.transport(
                    self.config.chat_completions_url,
                    headers,
                    body,
                    attempt_timeout,
                )
                return self._consume_payload(payload, body)
            except ModelRequestError as error:
                last_error = error
                code = getattr(error, "status_code", None)
                retryable = code is None or code in RETRYABLE_HTTP_CODES
                if not retryable or attempt >= self.config.retry_count:
                    break
                # Короткая ограниченная задержка не может породить бесконечный цикл.
                delay = min(0.25 * (2**attempt), 1.0)
                if self.clock() + delay >= deadline:
                    break
                self.sleeper(delay)
        raise last_error or ModelRequestError("неизвестная ошибка локальной модели")

    def _consume_payload(self, payload: Mapping[str, Any], request_body: bytes) -> str:
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise ModelRequestError("в ответе модели отсутствует choices[0].message.content") from error
        if not isinstance(content, str) or not content.strip():
            raise ModelRequestError("модель вернула пустой текст")

        usage = payload.get("usage")
        if isinstance(usage, dict):
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
            if isinstance(prompt_tokens, int) and prompt_tokens >= 0:
                self.usage.input_tokens += prompt_tokens
            if isinstance(completion_tokens, int) and completion_tokens >= 0:
                self.usage.output_tokens += completion_tokens
        else:
            # Это только грубая оценка для диагностики. Она не смешивается с
            # фактическими значениями usage, полученными от сервера.
            self.usage.estimated_tokens += (len(request_body) + len(content) + 3) // 4
        return content

    def probe(self, *, timeout_seconds: float | None = None) -> str:
        """Один дешёвый запрос для проверки модели и адреса."""

        return self.complete(
            (
                {"role": "system", "content": "Reply with only OK."},
                {"role": "user", "content": "Connection check"},
            ),
            # Четырёх токенов недостаточно для моделей со скрытым
            # рассуждением: они могут исчерпать весь предел до появления
            # видимого `content`. 128 остаётся дешёвой проверкой, но позволяет
            # таким моделям вернуть короткий итоговый ответ.
            max_tokens=128,
            timeout_seconds=timeout_seconds,
        )


def _extract_json_object(text: str) -> Mapping[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            stripped = "\n".join(lines[1:-1])
            if stripped.lstrip().lower().startswith("json\n"):
                stripped = stripped.lstrip()[5:]
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError as error:
        raise ModelRequestError("модель не вернула требуемый объект JSON") from error
    if not isinstance(payload, dict):
        raise ModelRequestError("действие модели должно быть объектом JSON")
    return payload


class LocalModelActionDriver:
    """Показывает модели краткий контекст и принимает ровно одно действие."""

    def __init__(self, client: OpenAICompatibleClient):
        self.client = client

    @property
    def usage(self) -> ModelUsage:
        return self.client.usage

    @staticmethod
    def _event_payload(context: DriverContext) -> list[dict[str, object]]:
        compact: list[dict[str, object]] = []
        for event in context.events[-MAX_CONTEXT_EVENTS:]:
            item: dict[str, object] = {"step": event.sequence, "phase": event.phase}
            if event.action:
                item["action"] = event.action.as_payload()
            if event.tool_result:
                item["result"] = {
                    "ok": event.tool_result.ok,
                    "summary": _bounded_text(event.tool_result.summary, MAX_EVENT_CHARS),
                    "data": _bounded_text(
                        json.dumps(event.tool_result.data, ensure_ascii=False),
                        MAX_EVENT_CHARS,
                    ),
                }
            if event.validation:
                item["validation"] = {
                    "passed": event.validation.passed,
                    "reason": _bounded_text(event.validation.reason, MAX_EVENT_CHARS),
                }
            compact.append(item)
        return compact

    def next_action(self, context: DriverContext) -> AgentAction:
        # The registry is the single policy source.  Besides names, the model
        # receives the bounded argument schemas introduced by C-10, so it can
        # call generic workspace tools without inventing their parameters.
        available_tools = [tool.as_payload() for tool in context.available_tools]
        allowed = sorted(
            {tool.name for tool in context.available_tools} | RESERVED_ACTIONS
        )
        state = {
            "instruction": _bounded_text(context.instruction, MAX_INSTRUCTION_CHARS),
            "mode": context.decision.mode,
            "allowed_actions": allowed,
            "available_tools": available_tools,
            "artifacts": [str(rule.path) for rule in context.contract.artifacts],
            "recent_events": self._event_payload(context),
            "last_validation": (
                {
                    "passed": context.last_validation.passed,
                    "reason": context.last_validation.reason,
                }
                if context.last_validation
                else None
            ),
        }
        system = (
            "You choose one action for an offline cybersecurity agent. "
            "Return only one JSON object with keys name, arguments, rationale. "
            "Use only an allowed action. Never invent results. Finish only when "
            "the requested artifact or code change is ready for validation.\n\n"
            + context.task_playbook[:MAX_PLAYBOOK_CHARS]
            + "\n\nValidation rules:\n"
            + context.validation_playbook[:MAX_PLAYBOOK_CHARS]
        )
        response = self.client.complete(
            (
                {"role": "system", "content": system},
                {
                    "role": "user",
                    "content": json.dumps(state, ensure_ascii=False, separators=(",", ":")),
                },
            ),
            # Оставляем секунду ядру на запись результата и проверку. Если
            # общего остатка нет (например, в отдельном модульном тесте),
            # действует обычное ограничение клиента.
            timeout_seconds=(
                max(0.1, context.remaining_seconds - 1.0)
                if context.remaining_seconds is not None
                else None
            ),
        )
        payload = _extract_json_object(response)
        name = payload.get("name")
        arguments = payload.get("arguments", {})
        rationale = payload.get("rationale", "")
        if not isinstance(name, str) or name not in allowed:
            raise ModelRequestError("модель выбрала недопустимое действие")
        if not isinstance(arguments, dict):
            raise ModelRequestError("arguments в действии модели должен быть объектом")
        if not isinstance(rationale, str):
            raise ModelRequestError("rationale в действии модели должен быть текстом")
        return AgentAction(name, arguments, rationale)
