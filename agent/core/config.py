"""Настройки локальной модели, получаемые только из переменных среды."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


class ModelConfigError(ValueError):
    """Настройки модели отсутствуют или имеют небезопасный формат."""


def _positive_float(raw: str | None, *, name: str, default: float) -> float:
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as error:
        raise ModelConfigError(f"{name} должно быть положительным числом") from error
    if value <= 0:
        raise ModelConfigError(f"{name} должно быть положительным числом")
    return value


def _non_negative_int(raw: str | None, *, name: str, default: int) -> int:
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as error:
        raise ModelConfigError(f"{name} должно быть целым неотрицательным числом") from error
    if value < 0:
        raise ModelConfigError(f"{name} должно быть целым неотрицательным числом")
    return value


def _boolean(raw: str | None, *, name: str, default: bool = False) -> bool:
    if raw is None:
        return default
    normalized = raw.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ModelConfigError(f"{name} должно быть true/false или 1/0")


@dataclass(frozen=True)
class ModelConfig:
    """Проверенные параметры совместимого с OpenAI локального адреса.

    `transport`, `reasoning_effort` и `json_mode` — опциональные development
    переключатели. По умолчанию сохраняется минимальный competition-контракт:
    обычный HTTP-клиент и стандартное тело OpenAI chat/completions.
    """

    model: str
    base_url: str
    api_key: str
    request_timeout_seconds: float = 45.0
    retry_count: int = 2
    transport: str = "urllib"
    reasoning_effort: str | None = None
    json_mode: bool = False

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "ModelConfig":
        values = os.environ if env is None else env
        model = values.get("LOCAL_AGENT_MODEL") or values.get("OPENAI_MODEL")
        base_url = values.get("OPENAI_BASE_URL")
        api_key = values.get("OPENAI_API_KEY")

        missing = [
            name
            for name, value in (
                ("LOCAL_AGENT_MODEL", model),
                ("OPENAI_BASE_URL", base_url),
                ("OPENAI_API_KEY", api_key),
            )
            if not value
        ]
        if missing:
            raise ModelConfigError(
                "Не заданы обязательные переменные среды: " + ", ".join(missing)
            )

        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ModelConfigError("OPENAI_BASE_URL должен быть полным HTTP(S)-адресом")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ModelConfigError(
                "OPENAI_BASE_URL не должен содержать учётные данные, запрос или якорь"
            )

        if not model or not base_url or not api_key:
            raise ModelConfigError("Внутренняя ошибка проверки настроек модели")

        transport = values.get("LOCAL_AGENT_HTTP_TRANSPORT", "urllib").strip().lower()
        if transport not in {"urllib", "curl"}:
            raise ModelConfigError(
                "LOCAL_AGENT_HTTP_TRANSPORT должен быть urllib или curl"
            )

        reasoning_raw = values.get("LOCAL_AGENT_REASONING_EFFORT")
        reasoning_effort = reasoning_raw.strip().lower() if reasoning_raw else None
        if reasoning_effort not in {None, "none", "low", "medium", "high"}:
            raise ModelConfigError(
                "LOCAL_AGENT_REASONING_EFFORT должен быть none, low, medium или high"
            )

        return cls(
            model=model,
            base_url=base_url.rstrip("/"),
            api_key=api_key,
            request_timeout_seconds=_positive_float(
                values.get("LOCAL_AGENT_REQUEST_TIMEOUT_SECONDS"),
                name="LOCAL_AGENT_REQUEST_TIMEOUT_SECONDS",
                default=45.0,
            ),
            retry_count=_non_negative_int(
                values.get("LOCAL_AGENT_RETRY_COUNT"),
                name="LOCAL_AGENT_RETRY_COUNT",
                default=2,
            ),
            transport=transport,
            reasoning_effort=reasoning_effort,
            json_mode=_boolean(
                values.get("LOCAL_AGENT_JSON_MODE"),
                name="LOCAL_AGENT_JSON_MODE",
                default=False,
            ),
        )

    @property
    def chat_completions_url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def public_summary(self) -> dict[str, object]:
        """Безопасная для журнала часть настроек без ключа доступа."""

        return {
            "model": self.model,
            "base_url": self.base_url,
            "request_timeout_seconds": self.request_timeout_seconds,
            "retry_count": self.retry_count,
            "transport": self.transport,
            "reasoning_effort": self.reasoning_effort,
            "json_mode": self.json_mode,
        }
