from __future__ import annotations

import json
import unittest

from agent.core.config import ModelConfig, ModelConfigError
from agent.core.llm import (
    ModelRequestError,
    OpenAICompatibleClient,
    _curl_transport,
    _default_transport,
)


def env(**overrides: str) -> dict[str, str]:
    values = {
        "LOCAL_AGENT_MODEL": "test-model",
        "OPENAI_BASE_URL": "http://model.internal/v1",
        "OPENAI_API_KEY": "secret-value",
    }
    values.update(overrides)
    return values


class ModelTransportOptionTests(unittest.TestCase):
    def test_defaults_preserve_competition_request_shape(self) -> None:
        config = ModelConfig.from_env(env())
        self.assertEqual(config.transport, "urllib")
        self.assertIsNone(config.reasoning_effort)
        self.assertFalse(config.json_mode)
        self.assertIs(OpenAICompatibleClient(config).transport, _default_transport)

    def test_opt_in_qwen_settings_are_parsed(self) -> None:
        config = ModelConfig.from_env(
            env(
                LOCAL_AGENT_HTTP_TRANSPORT="curl",
                LOCAL_AGENT_REASONING_EFFORT="none",
                LOCAL_AGENT_JSON_MODE="true",
            )
        )
        self.assertEqual(config.transport, "curl")
        self.assertEqual(config.reasoning_effort, "none")
        self.assertTrue(config.json_mode)
        self.assertIs(OpenAICompatibleClient(config).transport, _curl_transport)
        summary = json.dumps(config.public_summary())
        self.assertNotIn("secret-value", summary)

    def test_invalid_optional_settings_fail_closed(self) -> None:
        with self.assertRaises(ModelConfigError):
            ModelConfig.from_env(env(LOCAL_AGENT_HTTP_TRANSPORT="shell"))
        with self.assertRaises(ModelConfigError):
            ModelConfig.from_env(env(LOCAL_AGENT_REASONING_EFFORT="infinite"))
        with self.assertRaises(ModelConfigError):
            ModelConfig.from_env(env(LOCAL_AGENT_JSON_MODE="maybe"))

    def test_reasoning_and_json_format_are_added_only_when_enabled(self) -> None:
        captured: dict[str, object] = {}

        def transport(url, headers, body, timeout):
            captured["request"] = json.loads(body)
            return {
                "choices": [{"message": {"content": '{"name":"finish"}'}}],
                "usage": {"prompt_tokens": 10, "completion_tokens": 3},
            }

        config = ModelConfig.from_env(
            env(
                LOCAL_AGENT_REASONING_EFFORT="none",
                LOCAL_AGENT_JSON_MODE="1",
            )
        )
        client = OpenAICompatibleClient(config, transport=transport)
        result = client.complete(
            ({"role": "user", "content": "pick one action"},),
            max_tokens=64,
            json_object=True,
        )
        self.assertEqual(result, '{"name":"finish"}')
        request = captured["request"]
        self.assertEqual(request["reasoning"], {"effort": "none"})
        self.assertEqual(request["response_format"], {"type": "json_object"})
        self.assertEqual(client.usage.as_payload()["total_tokens"], 13)

    def test_json_format_is_not_forced_on_probe_like_calls(self) -> None:
        captured: dict[str, object] = {}

        def transport(url, headers, body, timeout):
            captured["request"] = json.loads(body)
            return {"choices": [{"message": {"content": "OK"}}]}

        config = ModelConfig.from_env(env(LOCAL_AGENT_JSON_MODE="1"))
        OpenAICompatibleClient(config, transport=transport).complete(
            ({"role": "user", "content": "hello"},), max_tokens=8
        )
        self.assertNotIn("response_format", captured["request"])

    def test_usage_is_recorded_even_when_visible_content_is_empty(self) -> None:
        def transport(url, headers, body, timeout):
            return {
                "choices": [{"message": {"content": ""}}],
                "usage": {"prompt_tokens": 11, "completion_tokens": 97},
            }

        client = OpenAICompatibleClient(
            ModelConfig.from_env(env(LOCAL_AGENT_RETRY_COUNT="0")),
            transport=transport,
        )
        with self.assertRaisesRegex(ModelRequestError, "пустой текст"):
            client.complete(({"role": "user", "content": "hello"},))
        self.assertEqual(client.usage.input_tokens, 11)
        self.assertEqual(client.usage.output_tokens, 97)


if __name__ == "__main__":
    unittest.main()
