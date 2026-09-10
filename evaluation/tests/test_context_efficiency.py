from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction, ToolDefinition
from evaluation.context_efficiency import (
    BASELINE_EVENT_LIMIT,
    COMPACT_EVENT_LIMIT,
    MINIMUM_REDUCTION_PERCENT,
    SCENARIOS,
    _action_signature,
    load_successful_results,
    run_context_efficiency_suite,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class ContextEfficiencySuiteTests(unittest.TestCase):
    def test_optional_tool_defaults_are_semantically_equal(self) -> None:
        tools = (
            ToolDefinition(
                "list_files",
                "list files",
                {
                    "path": "string=.",
                    "max_depth": "integer=6",
                    "max_entries": "integer=200",
                },
            ),
        )
        implicit = _action_signature(
            AgentAction("list_files", {"path": "."}),
            tools,
        )
        explicit = _action_signature(
            AgentAction(
                "list_files",
                {"path": ".", "max_depth": 6, "max_entries": 200},
            ),
            tools,
        )
        self.assertEqual(implicit, explicit)

    def test_offline_suite_reduces_context_without_changing_actions(self) -> None:
        report = run_context_efficiency_suite()

        self.assertTrue(report["passed"], report)
        self.assertEqual(report["measurement_mode"], "offline-deterministic")
        self.assertEqual(report["scenario_count"], len(SCENARIOS))
        self.assertEqual(report["passed_count"], len(SCENARIOS))
        self.assertEqual(report["reported_token_scenario_count"], 0)
        self.assertGreaterEqual(
            report["reduction_percent"],
            MINIMUM_REDUCTION_PERCENT,
        )
        for scenario in report["scenarios"]:
            self.assertTrue(scenario["actions_match"], scenario)
            self.assertTrue(scenario["latest_evidence_preserved"], scenario)
            self.assertEqual(scenario["baseline_event_count"], BASELINE_EVENT_LIMIT)
            self.assertEqual(scenario["compact_event_count"], COMPACT_EVENT_LIMIT)
            self.assertLess(
                scenario["compact_prompt_bytes"],
                scenario["baseline_prompt_bytes"],
            )

    def test_suite_is_deterministic(self) -> None:
        self.assertEqual(
            run_context_efficiency_suite(),
            run_context_efficiency_suite(),
        )

    def test_empty_scenario_set_fails_closed(self) -> None:
        report = run_context_efficiency_suite(scenarios=())
        self.assertFalse(report["passed"])
        self.assertEqual(report["scenario_count"], 0)

    def test_successful_prior_scenario_is_reused(self) -> None:
        first = run_context_efficiency_suite(scenarios=(SCENARIOS[0],))
        saved = {"audit": first["scenarios"][0]}

        resumed = run_context_efficiency_suite(
            scenarios=(SCENARIOS[0],),
            prior_results=saved,
        )

        self.assertTrue(resumed["passed"], resumed)
        self.assertEqual(resumed["reused_scenario_count"], 1)
        self.assertTrue(resumed["scenarios"][0]["reused_from_prior_report"])

    def test_cooldown_outside_supported_range_is_rejected(self) -> None:
        for value in (-0.1, 120.1):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    run_context_efficiency_suite(cooldown_seconds=value)

    def test_resume_loader_keeps_only_successful_live_scenarios(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "a13.json"
            output.write_text(
                json.dumps(
                    {
                        "suite": "a13-context-efficiency",
                        "measurement_mode": "live-local-model",
                        "scenarios": [
                            {"name": "audit", "passed": True},
                            {"name": "fix", "passed": False},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            loaded = load_successful_results(output)

        self.assertEqual(set(loaded), {"audit"})

    def test_resume_loader_rejects_offline_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "a13.json"
            output.write_text(
                json.dumps(
                    {
                        "suite": "a13-context-efficiency",
                        "measurement_mode": "offline-deterministic",
                        "scenarios": [],
                    }
                ),
                encoding="utf-8",
            )

            with self.assertRaises(ValueError):
                load_successful_results(output)


class ContextEfficiencyCliTests(unittest.TestCase):
    def test_cli_writes_machine_readable_report(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "nested" / "a13.json"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "evaluation.context_efficiency",
                    "--output",
                    str(output),
                ],
                cwd=REPO_ROOT,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                check=False,
                timeout=30,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["suite"], "a13-context-efficiency")


if __name__ == "__main__":
    unittest.main()
