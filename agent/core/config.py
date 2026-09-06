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


@dataclass(frozen=True)
class ModelConfig:
    """Проверенные параметры совместимого с OpenAI локального адреса."""

    model: str
    base_url: str
    api_key: str
    request_timeout_seconds: float = 45.0
    retry_count: int = 2

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

        # Адрес проверяется до первого запроса. Логин и пароль в нём запрещены:
        # иначе они могли бы случайно попасть в диагностическое сообщение.
        parsed = urlsplit(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ModelConfigError("OPENAI_BASE_URL должен быть полным HTTP(S)-адресом")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ModelConfigError(
                "OPENAI_BASE_URL не должен содержать учётные данные, запрос или якорь"
            )

        # Повторная защита одновременно помогает статическому анализатору
        # понять, что ниже находятся строки, а не возможные значения None.
        if not model or not base_url or not api_key:
            raise ModelConfigError("Внутренняя ошибка проверки настроек модели")

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
        }
