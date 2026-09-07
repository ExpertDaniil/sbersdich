from __future__ import annotations

import inspect
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from evaluation.ctf_suite import (
    PipelineCtfDriver,
    build_ctf_cases,
    main,
    run_ctf_case,
    run_ctf_suite,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class GeneratedCtfSuiteTests(unittest.TestCase):
    def test_three_independent_cases_have_no_answer_in_workspace_input(self) -> None:
        cases = build_ctf_cases()
        self.assertEqual(len(cases), 3)
        self.assertEqual(len({case.task_id for case in cases}), 3)
        self.assertEqual({case.reader for case in cases}, {"text", "bytes"})
        for case in cases:
            with self.subTest(task_id=case.task_id):
                self.assertNotIn(case.expected, case.instruction)
                self.assertNotIn(case.expected.encode(), case.input_content)
                self.assertTrue(case.output_path.endswith(".txt"))

    def test_pipeline_driver_has_no_expected_answer_parameter(self) -> None:
        parameters = inspect.signature(PipelineCtfDriver).parameters
        self.assertNotIn("expected", parameters)
        with self.assertRaisesRegex(ValueError, "unsupported CTF reader"):
            PipelineCtfDriver(
                input_path="input",
                input_size=1,
                reader="archive",
                operations=({"operation": "hex"},),
                output_path="flag.txt",
            )

    def test_complete_suite_solves_every_case_and_hides_answer_values(self) -> None:
        cases = build_ctf_cases()
        report = run_ctf_suite(cases)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["task_count"], 3)
        self.assertEqual(report["solved_count"], 3)
        self.assertEqual(report["failed_count"], 0)
        self.assertTrue(report["offline_parent_network_guard"])
        self.assertEqual(
            {task["mode"] for task in report["tasks"]},
            {"ctf"},
        )
        self.assertTrue(all(task["evidence_unchanged"] for task in report["tasks"]))
        rendered = json.dumps(report, ensure_ascii=False)
        for case in cases:
            self.assertNotIn(case.expected, rendered)

    def test_suite_is_deterministic(self) -> None:
        self.assertEqual(run_ctf_suite(), run_ctf_suite())

    def test_external_exact_verifier_rejects_plausible_wrong_answer(self) -> None:
        case = build_ctf_cases()[0]
        wrong_expected = replace(case, expected="CTF{different_but_well_formed}")
        result = run_ctf_case(wrong_expected)
        self.assertFalse(result.passed)
        self.assertEqual(result.agent_status, "succeeded")
        self.assertTrue(result.evidence_unchanged)
        self.assertIn("external exact verifier", result.reason)

    def test_one_bad_case_does_not_hide_later_case(self) -> None:
        cases = build_ctf_cases()
        malformed = replace(
            cases[0],
            operations=({"operation": "unsupported"},),
        )
        report = run_ctf_suite((malformed, cases[1]))
        self.assertFalse(report["passed"])
        self.assertEqual(report["solved_count"], 1)
        self.assertEqual(report["failed_count"], 1)
        self.assertFalse(report["tasks"][0]["passed"])
        self.assertTrue(report["tasks"][1]["passed"])

    def test_unsafe_fixture_path_is_rejected_without_external_write(self) -> None:
        case = build_ctf_cases()[0]
        unsafe = replace(case, input_path="../../outside.bin")
        with self.assertRaisesRegex(RuntimeError, "unsafe relative path"):
            run_ctf_case(unsafe)

    def test_empty_suite_fails_closed(self) -> None:
        report = run_ctf_suite(())
        self.assertFalse(report["passed"])
        self.assertEqual(report["task_count"], 0)
        self.assertEqual(report["solved_count"], 0)

    def test_suite_source_does_not_reference_public_tasks_or_answers(self) -> None:
        source = (REPO_ROOT / "evaluation" / "ctf_suite.py").read_text(
            encoding="utf-8"
        )
        forbidden = {
            "hello-file",
            "bye-file",
            "find-sqli-login",
            "fix-sqli-login",
            "fix-sqli-search",
            "incident-log-forensics",
            "local_task/",
            "/solution",
            "/expected",
        }
        for value in forbidden:
            self.assertNotIn(value, source)


class CtfSuiteCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cli_runs_real_suite_and_writes_machine_readable_report(self) -> None:
        output = self.root / "nested" / "c13.json"
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "evaluation.ctf_suite",
                "--output",
                str(output),
            ],
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
        )
        self.assertEqual(process.returncode, 0)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(report["passed"])
        self.assertEqual(report["solved_count"], 3)

    def test_main_returns_one_and_keeps_failed_report(self) -> None:
        output = self.root / "failed.json"
        report = {
            "schema_version": 1,
            "suite": "c13-generated-ctf",
            "offline_parent_network_guard": True,
            "passed": False,
            "task_count": 1,
            "solved_count": 0,
            "failed_count": 1,
            "tasks": [],
        }
        with mock.patch("evaluation.ctf_suite.run_ctf_suite", return_value=report):
            with mock.patch("sys.stderr"):
                status = main(["--output", str(output)])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), report)

    def test_main_returns_two_for_unsafe_symlink_output(self) -> None:
        target = self.root / "target.json"
        target.write_text("{}", encoding="utf-8")
        output = self.root / "report.json"
        try:
            output.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("file symlinks are unavailable")
        with mock.patch("sys.stderr"):
            status = main(["--output", str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(target.read_text(encoding="utf-8"), "{}")


if __name__ == "__main__":
    unittest.main()
