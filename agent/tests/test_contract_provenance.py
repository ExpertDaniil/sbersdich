"""Independent task formulations and proof that candidates cannot become evidence."""
from __future__ import annotations

import json
import struct
import tempfile
import unittest
import zlib
from pathlib import Path

from agent.core.contracts import ContractError, build_task_contract
from agent.core.models import AgentAction, LoopEvent, ToolResult, ValidationFeedback
from agent.core.tools import SecurityToolRegistry
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext, PlanningContext, VerificationContext
from agent.scaffold.context_compiler import RepositoryContextCompiler, _pytest_feedback
from agent.scaffold.planner import DeterministicFastPath, LazyLocalModelPlanner
from agent.scaffold.providers import LegacySecurityProvider
from agent.scaffold.security_relevance import SecurityAwareRepositoryDistiller
from agent.scaffold.semantic_namespace import SemanticCyberACIProvider
from agent.scaffold.verifier import LegacyTaskVerifier
from agent.strategies import classify_instruction
from agent.tools.binary_records import carve_records
from agent.tools.event_table import event_table
from agent.validators import ArtifactRule, capture_snapshot, validate_artifact


class ContractProvenanceTests(unittest.TestCase):
    def test_modes_preserve_scoped_constraints(self):
        cases = [
            ("Audit shell input. Do not change project code.", "audit"),
            ("Audit HTTP request redirects and write a security report.", "audit"),
            ("Audit unsafe deserialization without modifying code.", "audit"),
            ("Audit path handling and report findings.", "audit"),
            ("Fix the SQL injection. Do not change tests.", "fix"),
            ("Patch the command injection without changing tests.", "fix"),
            ("Repair path handling. Do not modify dependency files.", "fix"),
            ("Fix the JWT verification bug. Do not change tests or dependency files.", "fix"),
            ("Fix the ORDER BY bug. Do not change files under tests.", "fix"),
            ("Investigate evidence with clock skew. Do not modify inputs.", "forensics"),
            ("Analyze Kubernetes audit logs. Do not change any files. Produce a report.", "forensics"),
            ("Reconstruct cloud exfiltration from the evidence.", "forensics"),
            ("Recover the flag; write the recovered flag to `out/one.txt`.", "ctf"),
            ("Store only the complete flag in `/app/out/two.txt`.", "ctf"),
            ("Write the exact flag to `/app/out/three.out`.", "ctf"),
        ]
        for instruction, expected in cases:
            with self.subTest(instruction=instruction):
                self.assertEqual(classify_instruction(instruction).mode, expected)
        self.assertEqual(classify_instruction("Audit the issue, do not fix or change the project.").mode, "audit")

    def test_output_paths_are_directives_not_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases = [
                ("Audit `/app/source.json`. Write the report to `/app/reports/security_findings.json`.", "reports/security_findings.json"),
                ("Investigate `/app/evidence/raw.json`. Produce `/app/reports/timeline.json`.", "reports/timeline.json"),
                ("Forensics: save your final result in `/app/case_summary.json`.", "case_summary.json"),
                ("Forensics: write the report to `/app/reports/case.txt`.", "reports/case.txt"),
                ("Store only the complete flag in `/app/out/result.txt`.", "out/result.txt"),
                ("Write the exact flag to `/app/out/result.out`.", "out/result.out"),
            ]
            for instruction, expected in cases:
                with self.subTest(instruction=instruction):
                    contract = build_task_contract(classify_instruction(instruction), instruction, root)
                    self.assertEqual([r.path for r in contract.artifacts], [root / expected])
            instruction = "Forensics: write `/app/../../outside.json`."
            with self.assertRaises(ContractError):
                build_task_contract(classify_instruction(instruction), instruction, root)

    def test_audit_positive_scan_also_hands_off_without_writing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Audit SQL and other bugs. Write `/app/reports/audit.json`."
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            context = PlanningContext(instruction, root, decision, "", "", contract, (), {}, (), None, 20)
            first = DeterministicFastPath().try_plan(context)
            self.assertFalse(first.action.arguments["write_report"])
            event = LoopEvent(1, "acting", AgentAction("security_scan"), ToolResult(True, "one lead", {"finding_count": 1}))
            from dataclasses import replace
            self.assertIsNone(DeterministicFastPath().try_plan(replace(context, events=(event,))))
            execution = ExecutionContext(root, decision, CapabilityLevel.MUTATE, (root / "reports/audit.json",))
            denied = LegacySecurityProvider(root).execute(AgentAction("security_scan", {"write_report": True}), execution)
            self.assertFalse(denied.ok)
            self.assertFalse((root / "security_report.json").exists())

    def test_generated_output_never_becomes_schema_or_source_packet(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "source.py").write_text('def value():\n    return "original"\n')
            (root / "format.md").write_text("Read three little-endian integers after the marker.")
            output = root / "answer.json"
            distiller = SecurityAwareRepositoryDistiller(root)
            compiler = RepositoryContextCompiler(root, distiller=distiller)
            compiler.set_output_paths((output,))
            original_handle = compiler.card_for("source.py").handle
            output.write_text('{"made_up_answer":"SELF_CONFIRMATION_CANARY"}')
            packet = compiler.task_guide("Forensics: read format.md and source.py; write answer.json")
            self.assertNotIn("SELF_CONFIRMATION_CANARY", packet)
            self.assertNotIn("answer.json", packet)
            self.assertIn("little-endian", packet)
            self.assertEqual(compiler.card_for("source.py").handle, original_handle)
            provider = SemanticCyberACIProvider(root, distiller=distiller, semantic_context=compiler)
            execution = ExecutionContext(root, classify_instruction("Investigate evidence"), CapabilityLevel.MUTATE, (output,))
            result = provider.execute(AgentAction("view_window", {"path": compiler.card_for("answer.json").handle}), execution)
            self.assertTrue(result.ok, result.summary)
            self.assertEqual(result.data["source_path"], "answer.json")
            self.assertEqual(result.data["provenance"], "task_output_candidate_not_evidence")
            self.assertNotIn("schema", result.data["path"])

    def test_schema_failures_reach_planner_and_empty_required_text_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Audit code. Write `/app/report.json`."
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            baseline = capture_snapshot(root)
            (root / "report.json").write_text('{"findings":[{"description":"wrong schema"}]}')
            result = LegacyTaskVerifier().verify(VerificationContext(root, decision, contract, baseline, (), 10))
            self.assertFalse(result.passed)
            self.assertIn("recommendation", result.reason)
            (root / "required.txt").write_text(" \n\t")
            self.assertFalse(validate_artifact(ArtifactRule("text", root / "required.txt")).passed)

    def test_assertion_feedback_retains_expected_and_actual(self):
        feedback = _pytest_feedback("header\n> assert 'UP' == result\nE AssertionError: 'UP' != 'down'\nFAILED test_x.py::test_case\n1 failed\n", passed=False)
        self.assertIn("'UP' != 'down'", feedback["assertion_lines"][1])

    def test_model_sees_schema_and_actionable_validation(self):
        from unittest.mock import Mock
        from agent.validators import CheckResult, ChangeSet, ValidationReport
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Audit code. Write `/app/report.json`."
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            report = ValidationReport("audit", str(root), False,
                                      (CheckResult("artifact", False, "wrong finding fields"),),
                                      ChangeSet((), (), ()))
            feedback = ValidationFeedback(False, "wrong finding fields", report)
            context = PlanningContext(instruction, root, decision, "", "", contract, (), {}, (), feedback, 20)
            planner = LazyLocalModelPlanner()
            planner._client = Mock()
            planner._client.complete.return_value = '{"name":"abort","arguments":{},"rationale":"fixture"}'
            planner.next_plan(context)
            messages = planner._client.complete.call_args.args[0]
            payload = json.loads(messages[1]["content"])
            schema = payload["artifact_rules"][0]["schema"]
            self.assertIn("recommendation", schema["finding_fields"])
            self.assertEqual(schema["top_level_keys"], ["findings"])
            self.assertEqual(payload["last_validation"]["failed_checks"][0]["detail"], "wrong finding fields")

    def test_negative_output_directive_does_not_authorize_input_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Forensics: never write `/app/evidence/raw.json`. Write `/app/result.json`."
            contract = build_task_contract(classify_instruction(instruction), instruction, root)
            self.assertEqual([rule.path for rule in contract.artifacts], [root / "result.json"])

    def test_record_offsets_feed_transform_with_noise_and_decoys(self):
        for endian in (">", "<"):
            with self.subTest(endian=endian), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                key = b"independent-key"
                clear = b"CTF{schema_driven_carving}"
                encrypted = bytes(value ^ key[i % len(key)] for i, value in enumerate(clear))
                payload = zlib.compress(encrypted)[::-1]
                magic = b"BX9"
                raw = b"noise" + magic + struct.pack(endian + "BH", 2, 3) + b"abc" + b"padding"
                expected_offset = len(raw) + len(magic) + 3
                raw += magic + struct.pack(endian + "BH", 11, len(payload)) + payload + b"tail"
                (root / "binary.dat").write_bytes(raw)
                registry = SecurityToolRegistry(root)
                decision = classify_instruction("CTF recover the flag")
                carved = registry.execute(AgentAction("binary_records", {"path": "binary.dat", "magic_hex": magic.hex(), "header_format": endian + "BH", "length_field": 1}), decision)
                self.assertTrue(carved.ok, carved.summary)
                target = next(record for record in carved.data["records"] if record["header_values"][0] == 11)
                self.assertEqual(target["payload_offset"], expected_offset)
                transformed = registry.execute(AgentAction("ctf_transform", {"path": "binary.dat", "offset": target["payload_offset"], "length": target["payload_length"], "steps": [{"operation": "reverse_bytes"}, {"operation": "zlib"}, {"operation": "xor", "key_text": key.decode()}]}), decision)
                self.assertTrue(transformed.ok, transformed.summary)
                self.assertEqual(transformed.data["text"], clear.decode())
                self.assertEqual((root / "binary.dat").read_bytes(), raw)

    def test_record_parser_reports_truncation_and_rejects_bad_schemas(self):
        base = {"magic_hex": "4142", "header_format": ">BH", "length_field": 1}
        parsed = carve_records(b"AB\x01\x00\x20abc", **base)
        self.assertFalse(parsed["records"][0]["valid"])
        self.assertFalse(carve_records(b"AB", **base)["records"][0]["valid"])
        for change in ({"magic_hex": ""}, {"header_format": "@BH"}, {"header_format": ">99999s"}, {"length_field": True}, {"max_records": 0}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                carve_records(b"AB\x01\x00\x00", **(base | change))

    def test_byte_width_record_schema_and_invalid_schema_feedback(self):
        raw = b"xEVT1" + struct.pack(">BH", 7, 3) + b"abc"
        parsed = carve_records(
            raw,
            magic_hex=b"EVT1".hex(),
            field_sizes=[1, 2],
            byte_order="big",
            length_field=1,
        )
        self.assertEqual(parsed["layout"], [
            {"field": 0, "width_bytes": 1},
            {"field": 1, "width_bytes": 2},
        ])
        self.assertEqual(parsed["valid_count"], 1)
        self.assertEqual(parsed["records"][0]["payload_offset"], 8)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "records.bin").write_bytes(raw)
            result = SecurityToolRegistry(root).execute(
                AgentAction("binary_records", {
                    "path": "records.bin",
                    "magic_hex": b"EVT1".hex(),
                    "field_sizes": [1, 1, 2],
                    "byte_order": "big",
                    "length_field": 2,
                }),
                classify_instruction("Recover the CTF flag"),
            )
            self.assertFalse(result.ok)
            self.assertIn("correct the schema", result.summary)
            self.assertEqual(result.data["valid_count"], 0)

    def test_event_table_applies_fast_clock_only_inside_recorded_interval(self):
        raw = (
            b'{"ts":"2026-08-17T10:06:50Z","session":"s-91"}\n'
            b'{"ts":"2026-08-17T11:00:00Z","session":"later"}\n'
        )
        result = event_table(
            raw,
            time_field="ts",
            clock_offset_seconds=90,
            offset_start="2026-08-17T10:05:00Z",
            offset_end="2026-08-17T10:10:00Z",
        )
        self.assertEqual(result["rows"][0]["utc"], "2026-08-17T10:05:20Z")
        self.assertEqual(result["rows"][0]["offset_applied_seconds"], 90)
        self.assertEqual(result["rows"][1]["utc"], "2026-08-17T11:00:00Z")
        self.assertEqual(result["rows"][1]["offset_applied_seconds"], 0)


if __name__ == "__main__":
    unittest.main()
