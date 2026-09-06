from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evaluation.failure_analysis import (
    ALL_CATEGORIES,
    MAX_EVIDENCE,
    MAX_EXCERPT_CHARS,
    AnalysisError,
    analyze_paths,
    discover_input_files,
    write_report,
)


REPO_ROOT = Path(__file__).resolve().parents[2]


class FailureAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_json(self, name: str, payload: object) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        return path

    def analyze_record(self, payload: object) -> dict[str, object]:
        report = analyze_paths([self.write_json("run.json", payload)])
        self.assertEqual(report["failure_count"], 1, report)
        return report["failures"][0]  # type: ignore[index,return-value]

    def test_each_required_failure_category_has_owner_reason_and_evidence(self) -> None:
        cases = {
            "launch": {
                "status": "failed",
                "reason": "entrypoint run.sh: command not found",
            },
            "format": {
                "status": "failed",
                "final_validation": {
                    "passed": False,
                    "report": {
                        "checks": [
                            {
                                "name": "artifact:exact-text:/app/result.txt",
                                "passed": False,
                                "detail": "artifact is missing: /app/result.txt",
                            }
                        ]
                    },
                },
            },
            "hypothesis": {
                "status": "failed",
                "reason": "vulnerability was not found after the audit",
            },
            "execution": {
                "status": "failed",
                "events": [
                    {
                        "phase": "tool-failed",
                        "tool_result": {
                            "ok": False,
                            "summary": "apply_patch failed: invalid hunk",
                        },
                    }
                ],
            },
            "timeout": {
                "status": "failed",
                "reason": "deadline exceeded while running the project command",
            },
            "budget": {
                "status": "failed",
                "reason": "scripted action queue is exhausted",
            },
            "regression": {
                "status": "failed",
                "final_validation": {
                    "passed": False,
                    "report": {
                        "checks": [
                            {
                                "name": "project-tests",
                                "passed": False,
                                "detail": "pytest tests failed with exit code 1",
                            }
                        ]
                    },
                },
            },
        }

        for expected, payload in cases.items():
            with self.subTest(category=expected):
                path = self.write_json(f"{expected}.json", payload)
                report = analyze_paths([path])
                failure = report["failures"][0]
                self.assertEqual(failure["category"], expected)
                self.assertIn(failure["confidence"], {"high", "medium"})
                self.assertTrue(failure["reason"])
                self.assertTrue(failure["cause"])
                self.assertTrue(failure["owner"]["block"])
                self.assertTrue(failure["owner"]["component"])
                self.assertTrue(failure["next_action"])
                self.assertGreaterEqual(len(failure["evidence"]), 1)
                self.assertLessEqual(len(failure["evidence"]), MAX_EVIDENCE)
                self.assertTrue(failure["evidence"][0]["source"].endswith(f"{expected}.json"))
                self.assertTrue(failure["evidence"][0]["json_path"].startswith("$"))

    def test_successful_run_ignores_failed_retry_events(self) -> None:
        path = self.write_json(
            "recovered.json",
            {
                "status": "succeeded",
                "reason": "final validation passed",
                "events": [
                    {
                        "phase": "tool-failed",
                        "tool_result": {"ok": False, "summary": "first attempt failed"},
                    }
                ],
            },
        )
        report = analyze_paths([path])
        self.assertEqual(report["failure_count"], 0)
        self.assertEqual(report["successful_record_count"], 1)

    def test_c09_trace_mapping_keeps_task_name_and_skips_success(self) -> None:
        path = self.write_json(
            "traces.json",
            {
                "hello-file": {"status": "succeeded", "reason": "validated"},
                "fix-sqli-login": {
                    "status": "failed",
                    "reason": "repeated-action budget was exhausted",
                },
            },
        )
        report = analyze_paths([path])
        self.assertEqual(report["analyzed_record_count"], 2)
        self.assertEqual(report["successful_record_count"], 1)
        self.assertEqual(report["failure_count"], 1)
        self.assertEqual(report["failures"][0]["task_id"], "fix-sqli-login")
        self.assertEqual(report["failures"][0]["category"], "budget")

    def test_summary_metadata_is_not_treated_as_a_run(self) -> None:
        path = self.write_json(
            "summary.json",
            {
                "hello-file": {"status": "succeeded"},
                "public_repository_unchanged": True,
                "expected_or_solution_read": False,
            },
        )
        report = analyze_paths([path])
        self.assertEqual(report["analyzed_record_count"], 1)
        self.assertEqual(report["failure_count"], 0)

    def test_zero_reward_without_details_fails_closed_as_unknown(self) -> None:
        failure = self.analyze_record({"task_id": "opaque", "reward": 0})
        self.assertEqual(failure["category"], "unknown")
        self.assertEqual(failure["confidence"], "low")
        self.assertEqual(failure["owner"]["block"], "TEAM")  # type: ignore[index]
        self.assertTrue(failure["evidence"])

    def test_existing_unknown_category_keeps_low_confidence(self) -> None:
        failure = self.analyze_record(
            {"task_id": "opaque", "category": "unknown", "reason": "reward=0"}
        )
        self.assertEqual(failure["category"], "unknown")
        self.assertEqual(failure["confidence"], "low")

    def test_actual_loop_budget_reasons_are_separated(self) -> None:
        cases = {
            "deadline budget exhausted": "timeout",
            "step budget exhausted": "budget",
            "validation-attempt budget exhausted": "budget",
            "repeated-action budget exhausted for 'search'": "budget",
        }
        for reason, expected in cases.items():
            with self.subTest(reason=reason):
                path = self.write_json(
                    f"{expected}-{len(reason)}.json",
                    {"status": "failed", "reason": reason},
                )
                report = analyze_paths([path])
                self.assertEqual(report["failures"][0]["category"], expected)

    def test_failed_project_check_without_word_failed_is_regression(self) -> None:
        failure = self.analyze_record(
            {
                "status": "failed",
                "final_validation": {
                    "passed": False,
                    "report": {
                        "checks": [
                            {
                                "name": "project-tests",
                                "passed": False,
                                "detail": "exit code 1",
                            }
                        ]
                    },
                },
            }
        )
        self.assertEqual(failure["category"], "regression")

    def test_nonzero_tool_exit_without_more_context_is_execution(self) -> None:
        failure = self.analyze_record({"status": "failed", "returncode": 2})
        self.assertEqual(failure["category"], "execution")
        self.assertEqual(failure["confidence"], "medium")

    def test_existing_failure_journal_entry_preserves_explicit_category(self) -> None:
        failure = self.analyze_record(
            {
                "schema_version": 1,
                "failures": [
                    {
                        "task_id": "old-run",
                        "category": "timeout",
                        "reason": "worker stopped",
                        "evidence": [{"source": "run.log", "excerpt": "worker stopped"}],
                    }
                ],
            }
        )
        self.assertEqual(failure["task_id"], "old-run")
        self.assertEqual(failure["category"], "timeout")
        self.assertEqual(failure["confidence"], "high")

    def test_jsonl_input_supports_multiple_runs(self) -> None:
        path = self.root / "events.jsonl"
        path.write_text(
            "\n".join(
                (
                    json.dumps({"task_id": "one", "status": "succeeded"}),
                    json.dumps(
                        {"task_id": "two", "status": "failed", "timed_out": True}
                    ),
                )
            )
            + "\n",
            encoding="utf-8",
        )
        report = analyze_paths([path])
        self.assertEqual(report["analyzed_record_count"], 2)
        self.assertEqual(report["failure_count"], 1)
        self.assertEqual(report["failures"][0]["task_id"], "two")
        self.assertEqual(report["failures"][0]["category"], "timeout")

    def test_plain_test_log_is_classified_as_regression(self) -> None:
        path = self.root / "unittest.log"
        path.write_text(
            "Ran 103 tests in 4.6s\nFAILED (failures=1)\n",
            encoding="utf-8",
        )
        report = analyze_paths([path])
        self.assertEqual(report["failure_count"], 1)
        self.assertEqual(report["failures"][0]["category"], "regression")

    def test_success_only_plain_log_produces_no_record(self) -> None:
        path = self.root / "success.log"
        path.write_text("Ran 103 tests\nOK\n0 errors, 0 failures\n", encoding="utf-8")
        report = analyze_paths([path])
        self.assertEqual(report["analyzed_record_count"], 0)
        self.assertEqual(report["failure_count"], 0)

    def test_secrets_are_redacted_from_the_complete_report(self) -> None:
        secret = "sk-super-secret-123456789"
        path = self.write_json(
            "secret.json",
            {
                "status": "failed",
                "reason": f"timeout contacting model OPENAI_API_KEY={secret}",
                "authorization": f"Bearer {secret}",
                "password": "do-not-write-this",
            },
        )
        report = analyze_paths([path])
        rendered = json.dumps(report, ensure_ascii=False)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("do-not-write-this", rendered)
        self.assertNotIn("super-secret", rendered)
        self.assertIn("[REDACTED]", rendered)

    def test_token_usage_is_not_mistaken_for_a_secret(self) -> None:
        failure = self.analyze_record(
            {
                "status": "failed",
                "reason": "token budget exhausted",
                "token_budget": 512,
                "tokens_used": 512,
            }
        )
        rendered = json.dumps(failure, ensure_ascii=False)
        self.assertEqual(failure["category"], "budget")
        self.assertIn("512", rendered)

    def test_long_evidence_is_bounded_around_the_matching_signal(self) -> None:
        path = self.write_json(
            "long.json",
            {"status": "failed", "reason": "x" * 2_000 + " timeout " + "y" * 2_000},
        )
        report = analyze_paths([path])
        evidence = report["failures"][0]["evidence"][0]["excerpt"]
        self.assertIn("timeout", evidence)
        self.assertLessEqual(len(evidence), MAX_EXCERPT_CHARS + 2)

    def test_directory_discovery_is_sorted_and_excludes_output(self) -> None:
        second = self.write_json("z/run.json", {"status": "succeeded"})
        first = self.write_json("a/run.json", {"status": "succeeded"})
        output = self.write_json(
            "failure_journal.json",
            {"status": "failed", "reason": "timeout"},
        )
        files = discover_input_files([self.root], output)
        self.assertEqual(files, [first.resolve(), second.resolve()])

    def test_repeated_analysis_is_deterministic(self) -> None:
        path = self.write_json(
            "run.json",
            {"task_id": "stable", "status": "failed", "reason": "tests failed"},
        )
        first = analyze_paths([path])
        second = analyze_paths([path])
        self.assertEqual(first, second)
        self.assertEqual(set(first["category_counts"]), set(ALL_CATEGORIES))

    def test_invalid_json_is_rejected_without_partial_result(self) -> None:
        path = self.root / "broken.json"
        path.write_text('{"status":', encoding="utf-8")
        with self.assertRaisesRegex(AnalysisError, "invalid JSON"):
            analyze_paths([path])

    def test_invalid_jsonl_reports_the_bad_line(self) -> None:
        path = self.root / "broken.jsonl"
        path.write_text('{"status":"failed"}\nnot-json\n', encoding="utf-8")
        with self.assertRaisesRegex(AnalysisError, "line 2"):
            analyze_paths([path])

    def test_deeply_nested_json_is_rejected_without_traceback(self) -> None:
        path = self.root / "deep.json"
        path.write_text("[" * 2_000 + "]" * 2_000, encoding="utf-8")
        with self.assertRaisesRegex(AnalysisError, "nested too deeply"):
            analyze_paths([path])

    def test_oversized_input_is_rejected(self) -> None:
        path = self.root / "large.log"
        path.write_text("123456789", encoding="utf-8")
        with mock.patch("evaluation.failure_analysis.MAX_FILE_BYTES", 8):
            with self.assertRaisesRegex(AnalysisError, "too large"):
                analyze_paths([path])

    def test_unsupported_explicit_input_is_rejected(self) -> None:
        path = self.root / "archive.zip"
        path.write_bytes(b"not a supported log")
        with self.assertRaisesRegex(AnalysisError, "unsupported input type"):
            analyze_paths([path])

    def test_write_report_creates_valid_utf8_json(self) -> None:
        output = self.root / "nested" / "report.json"
        write_report(output, {"message": "ошибка", "passed": False})
        self.assertEqual(
            json.loads(output.read_text(encoding="utf-8")),
            {"message": "ошибка", "passed": False},
        )

    def test_write_report_rejects_existing_symlink(self) -> None:
        target = self.root / "actual.json"
        target.write_text("{}", encoding="utf-8")
        link = self.root / "report.json"
        try:
            link.symlink_to(target)
        except (NotImplementedError, OSError):
            self.skipTest("file symlinks are unavailable")
        with self.assertRaisesRegex(AnalysisError, "symlink output"):
            write_report(link, {"failure_count": 0})


class FailureAnalysisCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(
        self, payload: str, *, strict: bool = False
    ) -> tuple[subprocess.CompletedProcess[bytes], Path]:
        source = self.root / "input.json"
        output = self.root / "journal.json"
        source.write_text(payload, encoding="utf-8")
        command = [
            sys.executable,
            "-m",
            "evaluation.failure_analysis",
            str(source),
            "--output",
            str(output),
        ]
        if strict:
            command.append("--strict")
        process = subprocess.run(
            command,
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        return process, output

    def test_cli_writes_classified_journal_and_returns_zero(self) -> None:
        process, output = self.run_cli(
            json.dumps({"status": "failed", "reason": "deadline exceeded"}),
            strict=True,
        )
        self.assertEqual(process.returncode, 0)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["failure_count"], 1)
        self.assertEqual(report["unknown_failure_count"], 0)

    def test_cli_strict_returns_one_for_unknown_failure_but_keeps_journal(self) -> None:
        process, output = self.run_cli(json.dumps({"reward": 0}), strict=True)
        self.assertEqual(process.returncode, 1)
        report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(report["unknown_failure_count"], 1)

    def test_cli_returns_two_and_does_not_write_for_invalid_input(self) -> None:
        process, output = self.run_cli("not-json")
        self.assertEqual(process.returncode, 2)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
