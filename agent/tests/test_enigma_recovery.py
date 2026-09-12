"""Independent regressions for byte ACI, contracts and bounded planner recovery."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import zlib
from pathlib import Path

from agent.core.contracts import build_task_contract
from agent.core.llm import ModelRequestError
from agent.core.models import AgentAction, LoopEvent, ToolResult
from agent.core.tools import SecurityToolRegistry
from agent.scaffold.contracts import (
    CapabilityLevel, ExecutionContext, KernelLimits, PlanDecision, PlanStrategy,
    PlanningContext, VerificationContext,
)
from agent.scaffold.hypothesis_controller import RuntimeHypothesisController
from agent.scaffold.kernel import AgentKernel
from agent.scaffold.planner import DeterministicFastPath, MAX_STATE_CHARS, _encode_state
from agent.scaffold.providers import LegacySecurityProvider, WorkspaceFileProvider
from agent.scaffold.registry import ToolBus
from agent.scaffold.state import AgentState
from agent.scaffold.verifier import LegacyTaskVerifier
from agent.strategies import classify_instruction
from agent.tools.security_scan import scan_python_source
from agent.validators import ArtifactRule, capture_snapshot, validate_artifact


class SequencePlanner:
    def __init__(self, *items):
        self.items = list(items)
        self.contexts = []

    def next_plan(self, context):
        self.contexts.append(context)
        item = self.items.pop(0) if self.items else ModelRequestError("invalid response")
        if isinstance(item, Exception):
            raise item
        return PlanDecision(item)


class EnigmaRecoveryTests(unittest.TestCase):
    def kernel(self, root, planner, **limits):
        return AgentKernel(
            workdir=root, planner=planner, verifier=LegacyTaskVerifier(),
            tool_bus=ToolBus((LegacySecurityProvider(root), WorkspaceFileProvider(root))),
            limits=KernelLimits(deadline_seconds=20, **limits),
        )

    def test_exact_binary_range_decodes_without_model_copy(self):
        for prefix_size in (3, 27, 113):
            with self.subTest(prefix=prefix_size), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                clear = f"CTF{{range_{prefix_size}_complete}}".encode()
                key = b"range-key"
                encrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(clear))
                payload = zlib.compress(encrypted)[::-1]
                raw = b"X" * prefix_size + payload + b"ignored-trailer"
                (root / "records.bin").write_bytes(raw)
                result = SecurityToolRegistry(root).execute(AgentAction("ctf_transform", {
                    "path": "/app/records.bin", "offset": prefix_size, "length": len(payload),
                    "steps": [{"operation": "reverse_bytes"}, {"operation": "zlib"},
                              {"operation": "xor", "key_text": key.decode()}],
                }), classify_instruction("Recover the CTF flag"))
                self.assertTrue(result.ok, result.summary)
                self.assertEqual(result.data["text"], clear.decode())
                self.assertEqual(result.data["input_size_bytes"], len(payload))
                self.assertEqual(result.data["input_sha256"], hashlib.sha256(payload).hexdigest())
                self.assertEqual((root / "records.bin").read_bytes(), raw)

    def test_binary_range_short_mixed_input_and_protected_path_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.bin").write_bytes(b"abc")
            registry = SecurityToolRegistry(root)
            base = {"path": "data.bin", "offset": 0, "length": 3,
                    "steps": [{"operation": "reverse_bytes"}]}
            for changes in ({"length": 4}, {"offset": -1}, {"length": True},
                            {"value": "abc"}, {"path": "../outside"}, {"path": "expected/flag"}):
                with self.subTest(changes=changes):
                    result = registry.execute(AgentAction("ctf_transform", base | changes),
                                              classify_instruction("Recover the CTF flag"))
                    self.assertFalse(result.ok)

    def test_nonempty_audit_contract_does_not_accept_empty_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Audit and write security_report.json with a non-empty `findings` array."
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            (root / "security_report.json").write_text('{"findings": []}')
            self.assertFalse(validate_artifact(contract.artifacts[0]).passed)
            self.assertTrue(validate_artifact(ArtifactRule("security-report", root / "security_report.json")).passed)
            event = LoopEvent(1, "acting", AgentAction("security_scan"),
                              ToolResult(True, "clean SQL scan", {"finding_count": 0}))
            context = PlanningContext(instruction, root, decision, "", "", contract, (), {}, (event,), None, 20)
            self.assertIsNone(DeterministicFastPath().try_plan(context))

    def test_forensics_json_contract_and_output_only_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = (
                "Investigate evidence. Do not modify evidence. Write `/app/reports/case.json` "
                "with exactly these keys:\n`source`, `utc_time`.\nPreserve inputs."
            )
            decision = classify_instruction(instruction)
            self.assertEqual(decision.mode, "forensics")
            contract = build_task_contract(decision, instruction, root)
            self.assertEqual(contract.artifacts[0].required_keys, ("source", "utc_time"))
            context = ExecutionContext(root, decision, CapabilityLevel.MUTATE,
                                       tuple(rule.path for rule in contract.artifacts))
            provider = WorkspaceFileProvider(root)
            (root / "source.log").write_bytes(b"preserve")
            denied = provider.execute(AgentAction("write_file", {"path": "source.log", "content": "bad"}), context)
            self.assertFalse(denied.ok)
            self.assertEqual((root / "source.log").read_bytes(), b"preserve")
            output = provider.execute(AgentAction("write_file", {
                "path": "/app/reports/case.json", "content": '{"source":"log","utc_time":"UTC"}',
            }), context)
            self.assertTrue(output.ok, output.summary)
            self.assertTrue(validate_artifact(contract.artifacts[0]).passed)
            (root / "reports/case.json").write_text('{"source":"log","extra":0}')
            self.assertFalse(validate_artifact(contract.artifacts[0]).passed)

    def test_exact_flag_wording_extracts_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            instruction = "Recover the flag. Write the exact flag to `/app/output/result.out` with no newline."
            contract = build_task_contract(classify_instruction(instruction), instruction, Path(tmp))
            self.assertEqual(len(contract.artifacts), 1)
            self.assertEqual(contract.artifacts[0].path, Path(tmp) / "output/result.out")

    def test_malformed_plan_feedback_allows_corrected_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            planner = SequencePlanner(
                ModelRequestError("unavailable action: use write_file"),
                AgentAction("write_file", {"path": "result.txt", "content": "done"}),
                AgentAction("finish"),
            )
            result = self.kernel(root, planner).run("Create a file at `/app/result.txt` whose content is exactly `done`.")
            self.assertTrue(result.succeeded, result.reason)
            self.assertIn("unavailable", planner.contexts[1].state_snapshot["planner_feedback"])
            self.assertEqual(len(planner.contexts), 3)

    def test_planner_errors_are_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            planner = SequencePlanner()
            result = self.kernel(Path(tmp), planner).run("Inspect the project")
            self.assertFalse(result.succeeded)
            self.assertEqual(len(planner.contexts), 3)

    def test_recovery_validates_existing_output_without_fabricating_success(self):
        for content, passed in (("done", True), ("wrong", False)):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                planner = SequencePlanner(AgentAction("write_file", {"path": "result.txt", "content": content}))
                result = self.kernel(root, planner).run("Create a file at `/app/result.txt` whose content is exactly `done`.")
                self.assertEqual(result.succeeded, passed, result.reason)
                self.assertEqual(result.validations_used, 1)
                self.assertEqual((root / "result.txt").read_text(), content)

    def test_recovery_rejects_undeclared_workspace_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            planner = SequencePlanner(AgentAction("write_exact_text", {"path": "wrong.out", "content": "CTF{x}"}))
            result = self.kernel(root, planner).run("Recover the CTF flag and write the flag to `/app/result.out`.")
            self.assertFalse(result.succeeded)
            self.assertFalse(result.final_validation.passed)

    def test_step_exhaustion_checks_written_result_without_extra_action(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            planner = SequencePlanner(AgentAction("write_file", {"path": "result.txt", "content": "done"}))
            result = self.kernel(root, planner, max_steps=1).run(
                "Create a file at `/app/result.txt` whose content is exactly `done`."
            )
            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual(result.steps_used, 1)
            self.assertEqual(len(planner.contexts), 1)
            self.assertLess(planner.contexts[0].remaining_seconds, 19)

    def test_hypothesis_ids_select_existing_nodes_and_cannot_fake_backtracking(self):
        state = AgentState("goal", "general")
        action = AgentAction("read_file", {"path": "input"})
        state.register_plan(PlanDecision(action, hypothesis="first explanation"), step=1)
        state.register_plan(PlanDecision(action, hypothesis="H01"), step=2)
        self.assertEqual(len(state.snapshot(())["hypotheses"]), 1)
        for step in range(1, 4):
            state.record_tool_event(step, action, ToolResult(True, "same"))
        plan = PlanDecision(action, PlanStrategy.BACKTRACK, "H01", 0.5, "new clue")
        control = RuntimeHypothesisController().evaluate(plan, state_snapshot=state.snapshot(()), tools=())
        self.assertFalse(control.allowed)

    def test_latest_file_evidence_survives_fifo_and_ids_remain_unique(self):
        state = AgentState("goal", "general")
        action = AgentAction("read_file", {"path": "collector.txt"})
        state.record_tool_event(1, action, ToolResult(True, "clock note", {"path": "collector.txt", "content": "offset"}))
        for sequence in range(2, 65):
            state.record_tool_event(sequence, AgentAction("search_text"), ToolResult(True, str(sequence)))
        snapshot = state.snapshot(())
        self.assertEqual(len({item["id"] for item in snapshot["evidence"]}), len(snapshot["evidence"]))
        self.assertIn("clock note", snapshot["latest_by_path"][0]["summary"])

    def test_prompt_compaction_preserves_json_contract_and_feedback(self):
        snapshot = AgentState("goal", "ctf").snapshot(())
        snapshot["evidence"] = [{"id": str(i), "data_preview": "x" * 1400} for i in range(32)]
        snapshot["planner_feedback"] = "use key_text, never key"
        state = {"instruction": "recover", "task_state": snapshot,
                 "available_tools": [{"name": "ctf_transform", "parameters": {"steps": "key_text/key_hex"}}],
                 "artifacts": ["result.out"], "repository_guide": "source" * 1000}
        encoded = _encode_state(state)
        result = json.loads(encoded)
        self.assertLessEqual(len(encoded), MAX_STATE_CHARS)
        self.assertEqual(result["task_state"]["planner_feedback"], snapshot["planner_feedback"])
        self.assertEqual(result["artifacts"], state["artifacts"])
        self.assertEqual(result["available_tools"], state["available_tools"])
        self.assertEqual(len(snapshot["evidence"]), 32)


class SqlAllowlistTests(unittest.TestCase):
    SAFE = '''async def query(conn, field, direction):
    fields = {"title", "priority"}
    if field not in fields:
        raise ValueError("unsupported field")
    if direction.lower() in ("asc", "desc"):
        order = direction.lower()
    else:
        order = "desc"
    sql = f"SELECT id FROM records ORDER BY {field} {order.upper()}"
    return await conn.fetch(sql)
'''

    def test_both_allowlisted_identifiers_are_not_reported_as_tainted(self):
        self.assertEqual(scan_python_source(self.SAFE, "query.py"), [])

    def test_incomplete_guards_reassignment_and_mutable_allowlists_still_report(self):
        variants = (
            self.SAFE.replace('raise ValueError("unsupported field")', 'pass'),
            self.SAFE.replace('order = "desc"', 'order = direction'),
            self.SAFE.replace('    sql =', '    field = direction\n    sql ='),
            self.SAFE.replace('    if field', '    fields.add(field)\n    if field'),
            self.SAFE.replace('    if field', '    unused = mutate(fields)\n    if field'),
            self.SAFE.replace('"title", "priority"', '"title; DELETE FROM records", "priority"'),
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(scan_python_source(source, "query.py"))

    def test_terminating_case_insensitive_guards_secure_original_tokens(self):
        source = '''async def list_events(conn, order_by, direction):
    if order_by not in ("created_at", "severity", "actor"):
        raise ValueError("unsupported field")
    if direction.lower() not in ("asc", "desc"):
        raise ValueError("unsupported direction")
    query = f"SELECT id FROM events ORDER BY {order_by} {direction}"
    return await conn.fetch(query)
'''
        self.assertEqual(scan_python_source(source, "repository.py"), [])

    def test_case_guard_does_not_hide_unsafe_choices_or_nonterminating_branch(self):
        safe = '''async def list_events(conn, direction):
    if direction.lower() not in ("asc", "desc"):
        raise ValueError("unsupported")
    query = f"SELECT id FROM events ORDER BY id {direction}"
    return await conn.fetch(query)
'''
        variants = (
            safe.replace('"asc", "desc"', '"asc; drop table events", "desc"'),
            safe.replace('raise ValueError("unsupported")', 'log(direction)'),
        )
        for source in variants:
            with self.subTest(source=source):
                self.assertTrue(scan_python_source(source, "repository.py"))

    def test_silent_fallback_is_not_used_as_input_contract_proof(self):
        source = '''async def list_events(conn, order_by, direction):
    if order_by not in ("created_at", "severity", "actor"):
        order_by = "created_at"
    if direction.lower() not in ("asc", "desc"):
        direction = "desc"
    query = f"SELECT id FROM events ORDER BY {order_by} {direction}"
    return await conn.fetch(query)
'''
        findings = scan_python_source(source, "repository.py")
        self.assertTrue(findings)
        self.assertIn("order_by", findings[0].evidence)

    def test_raise_guard_is_supported(self):
        source = self.SAFE.replace('field = "title"', 'raise ValueError("invalid field")')
        self.assertEqual(scan_python_source(source, "query.py"), [])

    def test_verifier_scans_current_source_instead_of_pre_edit_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "query.py"
            path.write_text("async def query(conn, field):\n    return await conn.fetch('SELECT 1')\n")
            instruction = "Fix the security issue"
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            baseline = capture_snapshot(root)
            event = LoopEvent(1, "acting", AgentAction("security_scan"), ToolResult(True, "clean", {"finding_count": 0}))
            path.write_text('async def query(conn, field):\n    return await conn.fetch(f"SELECT {field}")\n')
            context = VerificationContext(root, decision, contract, baseline, (event,), 10)
            failed = LegacyTaskVerifier().verify(context)
            self.assertFalse(failed.passed)
            self.assertIn("post-fix", failed.reason)
            path.write_text(self.SAFE)
            passed = LegacyTaskVerifier().verify(context)
            self.assertTrue(passed.passed, passed.reason)


if __name__ == "__main__":
    unittest.main()
