"""Ограниченный клиент локальной модели и преобразователь ответа в действие."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
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
_CURL_STATUS_MARKER = b"\n__LOCAL_AGENT_HTTP_STATUS__:"


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


def _decode_payload(raw: bytes) -> Mapping[str, Any]:
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ModelRequestError("ответ локальной модели превышает допустимый размер")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ModelRequestError("локальная модель вернула некорректный JSON") from error
    if not isinstance(payload, dict):
        raise ModelRequestError("локальная модель вернула JSON неверного типа")
    return payload


def _default_transport(
    url: str, headers: Mapping[str, str], body: bytes, timeout: float
) -> Mapping[str, Any]:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - адрес проверен
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as error:
        wrapped = ModelRequestError(f"локальная модель вернула HTTP {error.code}")
        setattr(wrapped, "status_code", error.code)
        raise wrapped from error
    except (TimeoutError, URLError, OSError) as error:
        raise ModelRequestError("локальная модель недоступна или не ответила вовремя") from error
    return _decode_payload(raw)


def _curl_environment() -> dict[str, str]:
    """Pass networking/runtime variables to curl without leaking model secrets."""

    allowed = {
        "PATH",
        "HOME",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LANG",
        "LC_ALL",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
    }
    return {name: value for name, value in os.environ.items() if name in allowed}


def _curl_transport(
    url: str, headers: Mapping[str, str], body: bytes, timeout: float
) -> Mapping[str, Any]:
    """Development transport for hosts where Python TLS and VPN disagree.

    Secrets are stored in a short-lived 0600 header file instead of process
    arguments, and the request body is delivered on stdin. The default runtime
    transport remains urllib unless explicitly selected through configuration.
    """

    header_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", prefix="local-agent-headers-", delete=False
        ) as handle:
            header_path = handle.name
            for name, value in headers.items():
                if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
                    raise ModelRequestError("некорректный HTTP-заголовок модели")
                handle.write(f"{name}: {value}\n")
        try:
            os.chmod(header_path, 0o600)
        except OSError:
            pass

        curl_timeout = max(0.1, float(timeout))
        command = [
            "curl",
            "--silent",
            "--show-error",
            "--request",
            "POST",
            "--max-time",
            f"{curl_timeout:.3f}",
            "--max-filesize",
            str(MAX_RESPONSE_BYTES),
            "--header",
            f"@{header_path}",
            "--data-binary",
            "@-",
            "--write-out",
            _CURL_STATUS_MARKER.decode("ascii") + "%{http_code}",
            url,
        ]
        try:
            completed = subprocess.run(
                command,
                input=body,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=curl_timeout + 1.0,
                check=False,
                env=_curl_environment(),
            )
        except (FileNotFoundError, OSError) as error:
            raise ModelRequestError("curl transport недоступен") from error
        except subprocess.TimeoutExpired as error:
            raise ModelRequestError("локальная модель недоступна или не ответила вовремя") from error

        if completed.returncode != 0:
            if completed.returncode == 28:
                raise ModelRequestError("локальная модель недоступна или не ответила вовремя")
            raise ModelRequestError(
                f"curl transport завершился с кодом {completed.returncode}"
            )

        raw, marker, status_raw = completed.stdout.rpartition(_CURL_STATUS_MARKER)
        if not marker:
            raise ModelRequestError("curl transport не вернул HTTP-статус")
        try:
            status = int(status_raw.strip())
        except ValueError as error:
            raise ModelRequestError("curl transport вернул некорректный HTTP-статус") from error
        if status < 200 or status >= 300:
            wrapped = ModelRequestError(f"локальная модель вернула HTTP {status}")
            setattr(wrapped, "status_code", status)
            raise wrapped
        return _decode_payload(raw)
    finally:
        if header_path:
            try:
                os.unlink(header_path)
            except OSError:
                pass


class OpenAICompatibleClient:
    """Минимальный клиент `/chat/completions` без установки зависимостей."""

    def __init__(
        self,
        config: ModelConfig,
        *,
        transport: Transport | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = config
        if transport is not None:
            self.transport = transport
        elif config.transport == "curl":
            self.transport = _curl_transport
        else:
            self.transport = _default_transport
        self.sleeper = sleeper
        self.clock = clock
        self.usage = ModelUsage()

    def complete(
        self,
        messages: Sequence[Mapping[str, str]],
        *,
        max_tokens: int = 512,
        timeout_seconds: float | None = None,
        json_object: bool = False,
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

        request_payload: dict[str, Any] = {
            "model": self.config.model,
            "messages": list(messages),
            "temperature": 0,
            "max_tokens": max_tokens,
        }
        if self.config.reasoning_effort is not None:
            request_payload["reasoning"] = {"effort": self.config.reasoning_effort}
        if json_object and self.config.json_mode:
            request_payload["response_format"] = {"type": "json_object"}

        body = json.dumps(
            request_payload,
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
                retryable = getattr(error, "retryable", True) and (code is None or code in RETRYABLE_HTTP_CODES)
                if not retryable or attempt >= self.config.retry_count:
                    break
                delay = min(0.25 * (2**attempt), 1.0)
                if self.clock() + delay >= deadline:
                    break
                self.sleeper(delay)
        raise last_error or ModelRequestError("неизвестная ошибка локальной модели")

    def _record_usage(self, payload: Mapping[str, Any], request_body: bytes) -> None:
        usage = payload.get("usage")
        if isinstance(usage, dict):
            prompt_tokens = usage.get("prompt_tokens")
            completion_tokens = usage.get("completion_tokens")
            if isinstance(prompt_tokens, int) and prompt_tokens >= 0:
                self.usage.input_tokens += prompt_tokens
            if isinstance(completion_tokens, int) and completion_tokens >= 0:
                self.usage.output_tokens += completion_tokens
        else:
            self.usage.estimated_tokens += (len(request_body) + 3) // 4

    def _consume_payload(self, payload: Mapping[str, Any], request_body: bytes) -> str:
        self._record_usage(payload, request_body)
        try:
            choice = payload["choices"][0]
            if choice.get("finish_reason") == "length":
                error = ModelRequestError("model response hit its output limit; return a complete action JSON "
                                          "with a short rationale and omit optional planning text")
                error.retryable = False  # resending the identical prompt cannot repair it
                raise error
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as error:
            raise ModelRequestError("в ответе модели отсутствует choices[0].message.content") from error
        if not isinstance(content, str) or not content.strip():
            raise ModelRequestError("модель вернула пустой текст")
        if not isinstance(payload.get("usage"), dict):
            self.usage.estimated_tokens += (len(content) + 3) // 4
        return content

    def probe(self, *, timeout_seconds: float | None = None) -> str:
        """Один дешёвый запрос для проверки модели и адреса."""

        return self.complete(
            (
                {"role": "system", "content": "Reply with only OK."},
                {"role": "user", "content": "Connection check"},
            ),
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
            timeout_seconds=(
                max(0.1, context.remaining_seconds - 1.0)
                if context.remaining_seconds is not None
                else None
            ),
            json_object=True,
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
