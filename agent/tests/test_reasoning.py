from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from agent.core.config import ModelConfig
from agent.core.llm import LocalModelActionDriver, ModelRequestError, OpenAICompatibleClient
from agent.core.models import (
    AgentAction,
    DriverContext,
    LoopEvent,
    TaskContract,
    ToolDefinition,
    ToolResult,
)
from agent.core.reasoning import EvidenceGatedReasoning
from agent.strategies import classify_instruction


TOOLS = (
    ToolDefinition("read_file", "read", {"path": "string"}),
    ToolDefinition("search_text", "search", {"query": "string"}),
    ToolDefinition("security_scan", "scan", {}),
    ToolDefinition("run_command", "run", {}),
    ToolDefinition("apply_patch", "patch", {"patch": "string"}, True),
)


class EvidenceGatedReasoningTests(unittest.TestCase):
    def test_model_hypothesis_is_not_trusted_evidence(self):
        reasoning = EvidenceGatedReasoning("find bug", "fix")
        action = AgentAction("read_file", {"path": "app.py"})
        reasoning.propose(
            action_fingerprint=action.fingerprint(),
            action_name=action.name,
            hypothesis="SQL is concatenated",
            confidence=0.7,
            expected_evidence="unsafe query",
            step=1,
        )

        snapshot = reasoning.snapshot(TOOLS)
        self.assertEqual(len(snapshot["hypotheses"]), 1)
        self.assertEqual(snapshot["evidence"], [])

    def test_tool_observation_becomes_evidence_linked_to_hypothesis(self):
        reasoning = EvidenceGatedReasoning("find bug", "fix")
        action = AgentAction("read_file", {"path": "app.py"})
        reasoning.propose(
            action_fingerprint=action.fingerprint(),
            action_name=action.name,
            hypothesis="SQL is concatenated",
            confidence=0.7,
            step=1,
        )
        reasoning.sync(
            (
                LoopEvent(
                    1,
                    "acting",
                    action=action,
                    tool_result=ToolResult(
                        True,
                        "read app.py",
                        {"content": 'query = f"SELECT ..."'},
                    ),
                ),
            )
        )

        snapshot = reasoning.snapshot(TOOLS)
        self.assertEqual(len(snapshot["evidence"]), 1)
        self.assertEqual(snapshot["evidence"][0]["source"], "tool")
        self.assertEqual(snapshot["evidence"][0]["hypothesis_id"], "H01")
        self.assertEqual(snapshot["hypotheses"][0]["evidence_ids"], ["E01"])

    def test_duplicate_observations_trigger_recovery_and_escalation(self):
        reasoning = EvidenceGatedReasoning("find bug", "fix")
        repeated_result = ToolResult(True, "same result", {"value": 1})

        for step, arguments in enumerate(
            (
                {"path": "app.py"},
                {"path": "app.py", "start_line": 1},
                {"path": "app.py", "start_line": 2},
            ),
            1,
        ):
            action = AgentAction("read_file", arguments)
            reasoning.propose(
                action_fingerprint=action.fingerprint(),
                action_name=action.name,
                hypothesis="bug is in app.py",
                confidence=0.6,
                step=step,
            )
            reasoning.sync(
                (
                    LoopEvent(
                        step,
                        "acting",
                        action=action,
                        tool_result=repeated_result,
                    ),
                )
            )

        snapshot = reasoning.snapshot(TOOLS)
        self.assertTrue(snapshot["recovery_required"])
        self.assertEqual(snapshot["stagnant_steps"], 2)
        self.assertEqual(snapshot["recommended_capability_level"], 1)

    def test_backtrack_deprioritizes_previous_branch(self):
        reasoning = EvidenceGatedReasoning("find bug", "fix")
        first = AgentAction("read_file", {"path": "a.py"})
        reasoning.propose(
            action_fingerprint=first.fingerprint(),
            action_name=first.name,
            hypothesis="first branch",
            confidence=0.8,
            step=1,
        )
        second = AgentAction("search_text", {"query": "token"})
        reasoning.propose(
            action_fingerprint=second.fingerprint(),
            action_name=second.name,
            hypothesis="alternative branch",
            confidence=0.5,
            strategy="backtrack",
            step=2,
        )

        snapshot = reasoning.snapshot(TOOLS)
        by_id = {item["id"]: item for item in snapshot["hypotheses"]}
        self.assertEqual(by_id["H01"]["status"], "deprioritized")
        self.assertEqual(snapshot["current_hypothesis_id"], "H02")
        self.assertNotIn("H01", snapshot["backtrack_candidates"])


class ReasoningDriverIntegrationTests(unittest.TestCase):
    @staticmethod
    def _context(events: tuple[LoopEvent, ...] = ()) -> DriverContext:
        instruction = "Investigate an unknown vulnerability"
        return DriverContext(
            instruction=instruction,
            workdir=Path("."),
            decision=classify_instruction(instruction),
            task_playbook="",
            validation_playbook="",
            contract=TaskContract(),
            available_tools=TOOLS,
            events=events,
            last_validation=None,
        )

    def test_driver_sends_pipeline_state_and_accepts_reasoning(self):
        captured: list[dict[str, object]] = []

        def transport(url, headers, body, timeout):
            captured.append(json.loads(body))
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "name": "read_file",
                                    "arguments": {"path": "app.py"},
                                    "rationale": "inspect",
                                    "reasoning": {
                                        "hypothesis": "bug is in app.py",
                                        "confidence": 0.65,
                                        "expected_evidence": "unsafe data flow",
                                        "strategy": "branch",
                                    },
                                }
                            )
                        }
                    }
                ]
            }

        driver = LocalModelActionDriver(
            OpenAICompatibleClient(
                ModelConfig("local", "http://model.internal/v1", "secret"),
                transport=transport,
            )
        )
        action = driver.next_action(self._context())

        self.assertEqual(action.name, "read_file")
        state = json.loads(captured[0]["messages"][1]["content"])
        reasoning_state = state["reasoning_state"]
        self.assertEqual(
            reasoning_state["specialist"], "general_security_investigator"
        )
        self.assertEqual(reasoning_state["evidence"], [])
        self.assertIn("capability_ladder", reasoning_state)

    def test_real_tool_result_appears_as_evidence_on_next_turn(self):
        captured: list[dict[str, object]] = []
        calls = 0

        def transport(url, headers, body, timeout):
            nonlocal calls
            captured.append(json.loads(body))
            calls += 1
            if calls == 1:
                response = {
                    "name": "read_file",
                    "arguments": {"path": "app.py"},
                    "rationale": "inspect",
                    "reasoning": {
                        "hypothesis": "unsafe query",
                        "confidence": 0.7,
                    },
                }
            else:
                response = {
                    "name": "search_text",
                    "arguments": {"query": "execute"},
                    "rationale": "follow trusted evidence",
                }
            return {"choices": [{"message": {"content": json.dumps(response)}}]}

        driver = LocalModelActionDriver(
            OpenAICompatibleClient(
                ModelConfig("local", "http://model.internal/v1", "secret"),
                transport=transport,
            )
        )
        first = driver.next_action(self._context())
        event = LoopEvent(
            1,
            "acting",
            action=first,
            tool_result=ToolResult(True, "read app.py", {"content": "unsafe"}),
        )
        driver.next_action(self._context((event,)))

        state = json.loads(captured[1]["messages"][1]["content"])
        evidence = state["reasoning_state"]["evidence"]
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["hypothesis_id"], "H01")
        self.assertEqual(evidence[0]["source"], "tool")

    def test_invalid_reasoning_strategy_fails_closed(self):
        def transport(url, headers, body, timeout):
            return {
                "choices": [
                    {
                        "message": {
                            "content": json.dumps(
                                {
                                    "name": "read_file",
                                    "arguments": {"path": "x"},
                                    "reasoning": {"strategy": "teleport"},
                                }
                            )
                        }
                    }
                ]
            }

        driver = LocalModelActionDriver(
            OpenAICompatibleClient(
                ModelConfig("local", "http://model.internal/v1", "secret"),
                transport=transport,
            )
        )
        with self.assertRaises(ModelRequestError):
            driver.next_action(self._context())


if __name__ == "__main__":
    unittest.main()
