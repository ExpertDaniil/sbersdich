from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from agent.core.config import ModelConfig, ModelConfigError  # noqa: E402
from agent.core.contracts import build_task_contract  # noqa: E402
from agent.core.llm import (  # noqa: E402
    LocalModelActionDriver,
    ModelRequestError,
    OpenAICompatibleClient,
)
from agent.core.models import DriverContext  # noqa: E402
from agent.core.playbooks import load_playbook, load_validation_playbook  # noqa: E402
from agent.core.tools import SecurityToolRegistry  # noqa: E402
from agent.local_agent import build_parser  # noqa: E402
from agent.strategies import classify_instruction  # noqa: E402


def valid_env(**overrides: str) -> dict[str, str]:
    values = {
        "LOCAL_AGENT_MODEL": "local-test-model",
        "OPENAI_BASE_URL": "http://model.internal/v1",
        "OPENAI_API_KEY": "super-secret-test-key",
    }
    values.update(overrides)
    return values


class ModelConfigTests(unittest.TestCase):
    def test_required_values_and_public_summary_never_expose_key(self):
        config = ModelConfig.from_env(valid_env())
        self.assertEqual(
            config.chat_completions_url,
            "http://model.internal/v1/chat/completions",
        )
        summary = json.dumps(config.public_summary())
        self.assertNotIn("super-secret-test-key", summary)

    def test_missing_settings_have_clear_names_without_values(self):
        with self.assertRaises(ModelConfigError) as raised:
            ModelConfig.from_env({"OPENAI_API_KEY": "secret-that-must-not-leak"})
        message = str(raised.exception)
        self.assertIn("LOCAL_AGENT_MODEL", message)
        self.assertIn("OPENAI_BASE_URL", message)
        self.assertNotIn("secret-that-must-not-leak", message)

    def test_address_rejects_embedded_credentials(self):
        with self.assertRaises(ModelConfigError):
            ModelConfig.from_env(
                valid_env(OPENAI_BASE_URL="http://user:password@model.internal/v1")
            )


class OpenAICompatibleClientTests(unittest.TestCase):
    def test_probe_uses_expected_endpoint_and_collects_real_usage(self):
        captured: dict[str, object] = {}

        def transport(url, headers, body, timeout):
            captured.update(url=url, headers=headers, body=body, timeout=timeout)
            return {
                "choices": [{"message": {"content": "OK"}}],
                "usage": {"prompt_tokens": 7, "completion_tokens": 1},
            }

        client = OpenAICompatibleClient(
            ModelConfig.from_env(valid_env()), transport=transport
        )
        self.assertEqual(client.probe(timeout_seconds=3), "OK")
        self.assertEqual(captured["url"], "http://model.internal/v1/chat/completions")
        self.assertGreater(captured["timeout"], 0)
        self.assertLessEqual(captured["timeout"], 3)
        request = json.loads(bytes(captured["body"]).decode("utf-8"))
        self.assertEqual(request["max_tokens"], 128)
        self.assertEqual(client.usage.as_payload()["total_tokens"], 8)
        self.assertNotIn(
            "super-secret-test-key",
            bytes(captured["body"]).decode("utf-8"),
        )

    def test_temporary_failure_is_retried_with_a_strict_limit(self):
        calls = 0
        delays: list[float] = []

        def transport(url, headers, body, timeout):
            nonlocal calls
            calls += 1
            if calls < 3:
                raise ModelRequestError("временный сбой")
            return {"choices": [{"message": {"content": "OK"}}]}

        config = ModelConfig.from_env(valid_env(LOCAL_AGENT_RETRY_COUNT="2"))
        client = OpenAICompatibleClient(
            config, transport=transport, sleeper=delays.append
        )
        self.assertEqual(client.probe(), "OK")
        self.assertEqual(calls, 3)
        self.assertEqual(delays, [0.25, 0.5])
        self.assertGreater(client.usage.estimated_tokens, 0)

    def test_invalid_response_fails_without_echoing_key(self):
        def transport(url, headers, body, timeout):
            return {"unexpected": True}

        client = OpenAICompatibleClient(
            ModelConfig.from_env(valid_env()), transport=transport
        )
        with self.assertRaises(ModelRequestError) as raised:
            client.probe()
        self.assertNotIn("super-secret-test-key", str(raised.exception))


class LocalModelActionDriverTests(unittest.TestCase):
    def test_model_json_becomes_one_validated_action(self):
        recorded: dict[str, object] = {}

        def transport(url, headers, body, timeout):
            recorded["request"] = json.loads(body)
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "name": "finish",
                                    "arguments": {},
                                    "rationale": "artifact is ready",
                                }
                            )
                        }
                    }
                ]
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            instruction = "Explain an unknown task."
            decision = classify_instruction(instruction)
            context = DriverContext(
                instruction=instruction,
                workdir=root,
                decision=decision,
                task_playbook=load_playbook(decision.playbook),
                validation_playbook=load_validation_playbook(),
                contract=build_task_contract(decision, instruction, root),
                available_tools=SecurityToolRegistry(root).catalog(decision),
                events=(),
                last_validation=None,
            )
            client = OpenAICompatibleClient(
                ModelConfig.from_env(valid_env()), transport=transport
            )
            action = LocalModelActionDriver(client).next_action(context)

        self.assertEqual(action.name, "finish")
        request = recorded["request"]
        self.assertEqual(request["temperature"], 0)
        self.assertLessEqual(len(request["messages"][1]["content"]), 20_000)
        state = json.loads(request["messages"][1]["content"])
        tools = {tool["name"]: tool for tool in state["available_tools"]}
        self.assertIn("read_file", tools)
        self.assertIn("apply_patch", tools)
        self.assertEqual(tools["apply_patch"]["parameters"], {"patch": "string"})

    def test_model_cannot_select_action_outside_mode_policy(self):
        def transport(url, headers, body, timeout):
            return {
                "choices": [
                    {"message": {"content": '{"name":"sql_parameterize"}'}}
                ]
            }

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            instruction = "Explain an unknown task."
            decision = classify_instruction(instruction)
            context = DriverContext(
                instruction=instruction,
                workdir=root,
                decision=decision,
                task_playbook=load_playbook(decision.playbook),
                validation_playbook=load_validation_playbook(),
                contract=build_task_contract(decision, instruction, root),
                available_tools=SecurityToolRegistry(root).catalog(decision),
                events=(),
                last_validation=None,
            )
            client = OpenAICompatibleClient(
                ModelConfig.from_env(valid_env()), transport=transport
            )
            with self.assertRaises(ModelRequestError):
                LocalModelActionDriver(client).next_action(context)


class LocalAgentEntrypointTests(unittest.TestCase):
    def test_double_dash_keeps_option_like_instruction_as_text(self):
        args = build_parser().parse_args(["--", "--probe"])
        self.assertFalse(args.probe)
        self.assertEqual(args.instruction, ["--probe"])

    def test_known_exact_file_task_needs_no_model_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            temporary = Path(tmp).resolve()
            root = temporary / "workdir"
            root.mkdir()
            stdout_path = temporary / "agent-stdout.json"
            stderr_path = temporary / "agent-stderr.txt"
            env = os.environ.copy()
            for name in (
                "LOCAL_AGENT_MODEL",
                "OPENAI_MODEL",
                "OPENAI_BASE_URL",
                "OPENAI_API_KEY",
            ):
                env.pop(name, None)
            env["LOCAL_AGENT_WORKDIR"] = str(root)
            env["PYTHONUTF8"] = "1"
            with stdout_path.open("wb") as stdout_handle, stderr_path.open(
                "wb"
            ) as stderr_handle:
                process = subprocess.run(
                    [
                        sys.executable,
                        "-m",
                        "agent.local_agent",
                        "Create a file at `/app/hello.txt` whose entire content is "
                        "exactly the single word `Hello`.",
                    ],
                    cwd=REPO_ROOT,
                    env=env,
                    stdout=stdout_handle,
                    stderr=stderr_handle,
                    timeout=15,
                    check=False,
                )
            stdout_text = stdout_path.read_text(encoding="utf-8")
            stderr_text = stderr_path.read_text(encoding="utf-8")
            self.assertEqual(process.returncode, 0, stderr_text)
            self.assertEqual((root / "hello.txt").read_bytes(), b"Hello")
            payload = json.loads(stdout_text)
            self.assertEqual(payload["status"], "succeeded")
            self.assertEqual(payload["metrics"]["model_usage"]["requests"], 0)


if __name__ == "__main__":
    unittest.main()
