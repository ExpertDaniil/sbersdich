from __future__ import annotations

import base64
import codecs
import gzip
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from agent.core.contracts import (
    ContractError,
    build_task_contract,
    ctf_artifact_requests,
)
from agent.core.llm import LocalModelActionDriver
from agent.core.loop import AgentLoop, ScriptedDriver
from agent.core.models import AgentAction, DriverContext, LoopLimits
from agent.core.playbooks import load_playbook, load_validation_playbook
from agent.core.tools import SecurityToolRegistry
from agent.strategies import classify_instruction
from agent.tools.ctf import (
    MAX_TRANSFORM_BYTES,
    CtfTransformError,
    transform_ctf_data,
)


def xor_bytes(value: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(value))


class CtfRoutingAndContractTests(unittest.TestCase):
    def test_ctf_routes_to_dedicated_playbook_even_when_evidence_is_read_only(self) -> None:
        decision = classify_instruction(
            "CTF challenge: capture the flag without modifying challenge evidence. "
            "Write the flag to `/app/flag.txt`."
        )
        self.assertEqual(decision.mode, "ctf")
        self.assertTrue(decision.should_modify_project)
        self.assertEqual(decision.playbook, "agent/playbooks/ctf.md")
        self.assertEqual(decision.confidence, "high")

    def test_russian_ctf_instruction_is_recognized(self) -> None:
        decision = classify_instruction(
            "Декодируй флаг из локального файла и сохрани ответ в "
            "`/app/ответ.txt`."
        )
        self.assertEqual(decision.mode, "ctf")

    def test_ctf_playbook_is_present_and_bounded(self) -> None:
        playbook = load_playbook("agent/playbooks/ctf.md")
        self.assertIn("# CTF playbook", playbook)
        self.assertIn("ctf_transform", playbook)
        self.assertIn("не обращаться в интернет", playbook)

    def test_unrelated_feature_flag_does_not_override_fix_mode(self) -> None:
        decision = classify_instruction("Fix the feature flag validation vulnerability.")
        self.assertEqual(decision.mode, "fix")

        unrelated = classify_instruction("Find feature flag usage in the configuration.")
        self.assertEqual(unrelated.mode, "general")

    def test_ctf_contract_extracts_english_and_russian_output_paths(self) -> None:
        instructions = (
            "Capture the flag and write the recovered flag to `/app/flag.txt`.",
            "CTF. Answer file: `/app/result.txt`.",
            "Найди флаг и сохрани найденный флаг в файл `/app/ответ.txt`.",
            "CTF: recover the value.\nWrite your answer to `/app/multiline.txt`.",
        )
        expected = ("flag.txt", "result.txt", "ответ.txt", "multiline.txt")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for instruction, filename in zip(instructions, expected, strict=True):
                with self.subTest(instruction=instruction):
                    decision = classify_instruction(instruction)
                    contract = build_task_contract(decision, instruction, root)
                    self.assertEqual(decision.mode, "ctf")
                    self.assertEqual(len(contract.artifacts), 1)
                    self.assertEqual(contract.artifacts[0].kind, "text")
                    self.assertEqual(contract.artifacts[0].path, root / filename)

    def test_ctf_contract_never_guesses_a_missing_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            instruction = "CTF challenge: recover the hidden flag."
            contract = build_task_contract(
                classify_instruction(instruction), instruction, root
            )
            self.assertEqual(contract.artifacts, ())

    def test_ctf_contract_rejects_external_output_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ContractError):
                ctf_artifact_requests(
                    "CTF: write the flag to `/outside/flag.txt`.",
                    Path(temporary).resolve(),
                )


class CtfTransformTests(unittest.TestCase):
    def test_base64_then_rot13_chain_recovers_unicode_safe_flag(self) -> None:
        flag = "CTF{portable_layer_42}"
        rotated = codecs.encode(flag, "rot_13").encode("utf-8")
        encoded = base64.b64encode(rotated).decode("ascii")
        result = transform_ctf_data(
            encoded,
            [{"operation": "base64"}, {"operation": "rot13"}],
        )
        self.assertEqual(result["text"], flag)
        self.assertEqual(result["flag_candidates"], [flag])

    def test_hex_then_repeating_xor_recovers_binary_artifact(self) -> None:
        flag = b"SBER{bounded_xor_result}"
        key = b"local-key"
        ciphertext = xor_bytes(flag, key)
        result = transform_ctf_data(
            ciphertext.hex(" "),
            [
                {"operation": "hex"},
                {"operation": "xor", "key_text": key.decode("ascii")},
            ],
        )
        self.assertEqual(result["text"], flag.decode("ascii"))
        self.assertEqual(result["size_bytes"], len(flag))

        key_hex = transform_ctf_data(
            ciphertext.hex(),
            [
                {"operation": "hex"},
                {"operation": "xor", "key_hex": key.hex()},
            ],
        )
        self.assertEqual(key_hex["text"], flag.decode("ascii"))

    def test_base64url_then_gzip_recovers_compressed_value(self) -> None:
        flag = b"FLAG{offline_gzip_case}"
        encoded = base64.urlsafe_b64encode(gzip.compress(flag)).rstrip(b"=").decode()
        result = transform_ctf_data(
            encoded,
            [{"operation": "base64url"}, {"operation": "gzip"}],
        )
        self.assertEqual(result["text"], flag.decode())

    def test_url_then_reverse_chain_is_supported(self) -> None:
        result = transform_ctf_data(
            "%7DLRU_elpmas%7BFTC",
            [{"operation": "url"}, {"operation": "reverse"}],
        )
        self.assertEqual(result["text"], "CTF{sample_URL}")

    def test_base32_then_zlib_chain_is_supported(self) -> None:
        flag = b"FLAG{base32_zlib}"
        encoded = base64.b32encode(zlib.compress(flag)).rstrip(b"=").decode()
        result = transform_ctf_data(
            encoded,
            [{"operation": "base32"}, {"operation": "zlib"}],
        )
        self.assertEqual(result["text"], flag.decode())

    def test_invalid_requests_fail_closed(self) -> None:
        invalid = (
            ("", [{"operation": "hex"}]),
            ("%%%%", [{"operation": "url"}]),
            ("not-base64!", [{"operation": "base64"}]),
            ("QQ=", [{"operation": "base64url"}]),
            ("MY===", [{"operation": "base32"}]),
            ("00", [{"operation": "unknown"}]),
            ("00", []),
            ("00", [{"operation": "hex", "extra": True}]),
            ("00", [{"operation": "hex"}, {"operation": "xor"}]),
        )
        for value, steps in invalid:
            with self.subTest(value=value, steps=steps):
                with self.assertRaises(CtfTransformError):
                    transform_ctf_data(value, steps)

    def test_compression_bombs_are_stopped_at_output_bound(self) -> None:
        oversized = b"A" * (MAX_TRANSFORM_BYTES + 1)
        gzip_value = base64.b64encode(gzip.compress(oversized)).decode()
        zlib_value = base64.b64encode(zlib.compress(oversized)).decode()
        for value, operation in ((gzip_value, "gzip"), (zlib_value, "zlib")):
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(CtfTransformError, "exceeds"):
                    transform_ctf_data(
                        value,
                        [{"operation": "base64"}, {"operation": operation}],
                    )

    def test_zlib_trailing_data_is_rejected(self) -> None:
        encoded = base64.b64encode(zlib.compress(b"FLAG{valid}") + b"trailer").decode()
        with self.assertRaisesRegex(CtfTransformError, "trailing data"):
            transform_ctf_data(
                encoded,
                [{"operation": "base64"}, {"operation": "zlib"}],
            )


class CtfRegistryAndLoopTests(unittest.TestCase):
    def test_ctf_catalog_is_read_decode_write_only(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            decision = classify_instruction("CTF: find the flag in `/app/input.bin`.")
            names = {
                tool.name
                for tool in SecurityToolRegistry(Path(temporary)).catalog(decision)
            }
        self.assertEqual(
            names,
            {
                "list_files",
                "read_file",
                "read_bytes",
                "search_text",
                "ctf_transform",
                "write_exact_text",
            },
        )
        self.assertNotIn("apply_patch", names)
        self.assertNotIn("run_command", names)

    def test_invalid_transform_is_returned_as_structured_tool_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            decision = classify_instruction("CTF: find the flag in `/app/blob.txt`.")
            result = SecurityToolRegistry(Path(temporary)).execute(
                AgentAction(
                    "ctf_transform",
                    {
                        "value": "not-base64!",
                        "steps": [{"operation": "base64"}],
                    },
                ),
                decision,
            )
        self.assertFalse(result.ok)
        self.assertIn("ctf_transform failed", result.summary)
        self.assertEqual(result.data, {})

    def test_local_model_driver_receives_ctf_playbook_and_tool_schema(self) -> None:
        class StubClient:
            def __init__(self) -> None:
                self.messages = None

            def complete(self, messages, **_kwargs):
                self.messages = messages
                return json.dumps(
                    {
                        "name": "ctf_transform",
                        "arguments": {
                            "value": "41",
                            "steps": [{"operation": "hex"}],
                        },
                        "rationale": "decode evidence",
                    }
                )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            instruction = "CTF: write the flag to `/app/flag.txt`."
            decision = classify_instruction(instruction)
            registry = SecurityToolRegistry(root)
            client = StubClient()
            action = LocalModelActionDriver(client).next_action(  # type: ignore[arg-type]
                DriverContext(
                    instruction=instruction,
                    workdir=root,
                    decision=decision,
                    task_playbook=load_playbook(decision.playbook),
                    validation_playbook=load_validation_playbook(),
                    contract=build_task_contract(decision, instruction, root),
                    available_tools=registry.catalog(decision),
                    events=(),
                    last_validation=None,
                    remaining_seconds=10,
                )
            )
        self.assertEqual(action.name, "ctf_transform")
        self.assertIsNotNone(client.messages)
        state = json.loads(client.messages[1]["content"])  # type: ignore[index]
        self.assertEqual(state["mode"], "ctf")
        self.assertIn("ctf_transform", state["allowed_actions"])
        self.assertNotIn("apply_patch", state["allowed_actions"])

    def test_ctf_loop_validates_answer_and_preserves_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence = root / "challenge.txt"
            evidence.write_text("RkxBR3tsb29wX3ZhbGlkYXRlZH0=", encoding="utf-8")
            broken_source = root / "fragment.py"
            broken_source.write_text("def truncated(\n", encoding="utf-8")
            before = evidence.read_bytes()
            driver = ScriptedDriver(
                (
                    AgentAction(
                        "ctf_transform",
                        {
                            "value": evidence.read_text(encoding="utf-8"),
                            "steps": [{"operation": "base64"}],
                        },
                    ),
                    AgentAction(
                        "write_exact_text",
                        {"path": "/app/flag.txt", "content": "FLAG{loop_validated}"},
                    ),
                    AgentAction("finish"),
                )
            )
            result = AgentLoop(workdir=root, driver=driver).run(
                "CTF challenge: decode challenge.txt and write the flag to "
                "`/app/flag.txt`."
            )
            self.assertTrue(result.succeeded, result.as_payload())
            self.assertEqual((root / "flag.txt").read_text(), "FLAG{loop_validated}")
            self.assertEqual(evidence.read_bytes(), before)
            self.assertEqual(broken_source.read_text(), "def truncated(\n")
            self.assertNotIn(
                "python-syntax",
                {
                    check.name
                    for check in result.final_validation.report.checks  # type: ignore[union-attr]
                },
            )
            self.assertEqual(
                result.final_validation.report.changes.added,  # type: ignore[union-attr]
                ("flag.txt",),
            )

    def test_ctf_loop_rejects_changes_outside_answer_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            driver = ScriptedDriver(
                (
                    AgentAction(
                        "write_exact_text",
                        {"path": "/app/flag.txt", "content": "FLAG{candidate}"},
                    ),
                    AgentAction(
                        "write_exact_text",
                        {"path": "/app/evidence.txt", "content": "changed"},
                    ),
                    AgentAction("finish"),
                )
            )
            result = AgentLoop(
                workdir=root,
                driver=driver,
                limits=LoopLimits(max_validations=1),
            ).run("CTF: write the flag to `/app/flag.txt`.")
            self.assertFalse(result.succeeded)
            self.assertIn("validation failed", result.reason)
            self.assertFalse(result.final_validation.passed)  # type: ignore[union-attr]

    def test_ctf_loop_rejects_missing_or_preexisting_answer_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            missing = AgentLoop(
                workdir=root,
                driver=ScriptedDriver(
                    (
                        AgentAction(
                            "ctf_transform",
                            {"value": "41", "steps": [{"operation": "hex"}]},
                        ),
                        AgentAction("finish"),
                    )
                ),
                limits=LoopLimits(max_validations=1),
            ).run("CTF challenge: recover the flag.")
            self.assertFalse(missing.succeeded)
            self.assertIn("no explicit answer artifact", missing.reason)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "flag.txt").write_text("FLAG{old}", encoding="utf-8")
            stale = AgentLoop(
                workdir=root,
                driver=ScriptedDriver(
                    (
                        AgentAction(
                            "read_file",
                            {"path": "/app/flag.txt"},
                        ),
                        AgentAction("finish"),
                    )
                ),
                limits=LoopLimits(max_validations=1),
            ).run("CTF: write the flag to `/app/flag.txt`.")
            self.assertFalse(stale.succeeded)
            self.assertIn("was not produced", stale.reason)


if __name__ == "__main__":
    unittest.main()
