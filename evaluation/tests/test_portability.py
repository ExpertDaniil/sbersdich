from __future__ import annotations

import json
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from evaluation.portability import (
    PORTABILITY_CHECKS,
    CheckSpec,
    OfflineNetworkUse,
    execute_checks,
    main,
    network_disabled,
    run_portability_suite,
)


REPO_ROOT = Path(__file__).resolve().parents[2]
EXPECTED_CHECKS = {
    "artifact-output-contracts",
    "sql-source-variations",
    "partial-security-fix",
    "atomic-workspace-patch",
    "forensics-log-shards",
    "missing-inputs-fail-closed",
    "failure-journal-shards",
    "bounded-processes",
    "stdlib-runtime-dependencies",
}


class PortabilitySuiteTests(unittest.TestCase):
    def test_registered_checks_are_unique_and_complete(self) -> None:
        names = [check.name for check in PORTABILITY_CHECKS]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), EXPECTED_CHECKS)
        self.assertEqual(
            {check.area for check in PORTABILITY_CHECKS},
            {"format", "audit-fix", "workspace", "forensics", "validation", "triage", "execution", "offline"},
        )

    def test_complete_suite_passes_with_machine_readable_contract(self) -> None:
        report = run_portability_suite()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["check_count"], len(EXPECTED_CHECKS))
        self.assertEqual(report["passed_count"], len(EXPECTED_CHECKS))
        self.assertEqual(report["failed_count"], 0)
        self.assertTrue(report["offline_parent_network_guard"])
        self.assertEqual(
            {check["name"] for check in report["checks"]},
            EXPECTED_CHECKS,
        )
        self.assertTrue(all(check["passed"] for check in report["checks"]))
        json.dumps(report, ensure_ascii=False)

    def test_network_guard_blocks_socket_entrypoints(self) -> None:
        with network_disabled():
            with self.assertRaises(OfflineNetworkUse):
                socket.create_connection(("127.0.0.1", 9))
            with socket.socket() as client:
                with self.assertRaises(OfflineNetworkUse):
                    client.connect(("127.0.0.1", 9))

    def test_failed_check_is_recorded_and_does_not_stop_next_check(self) -> None:
        def fail() -> str:
            raise RuntimeError("deliberate failure")

        checks = (
            CheckSpec("first", "test", fail),
            CheckSpec("second", "test", lambda: "continued"),
        )
        report = run_portability_suite(checks)
        self.assertFalse(report["passed"])
        self.assertEqual(report["passed_count"], 1)
        self.assertEqual(report["failed_count"], 1)
        self.assertFalse(report["checks"][0]["passed"])
        self.assertIn("RuntimeError", report["checks"][0]["detail"])
        self.assertTrue(report["checks"][1]["passed"])

    def test_failure_detail_redacts_credentials(self) -> None:
        secret = "sk-portability-secret-123456"

        def leak() -> str:
            raise RuntimeError(f"OPENAI_API_KEY={secret}")

        result = execute_checks((CheckSpec("redact", "test", leak),))[0]
        self.assertFalse(result.passed)
        self.assertNotIn(secret, result.detail)
        self.assertIn("[REDACTED]", result.detail)

    def test_small_custom_suite_is_deterministic(self) -> None:
        checks = (
            CheckSpec("one", "test", lambda: "stable one"),
            CheckSpec("two", "test", lambda: "stable two"),
        )
        self.assertEqual(run_portability_suite(checks), run_portability_suite(checks))

    def test_empty_check_registry_fails_closed(self) -> None:
        report = run_portability_suite(())
        self.assertFalse(report["passed"])
        self.assertEqual(report["check_count"], 0)

    def test_suite_contains_no_public_task_names_or_answers(self) -> None:
        source = (REPO_ROOT / "evaluation" / "portability.py").read_text(encoding="utf-8")
        forbidden = {
            "hello-file",
            "bye-file",
            "find-sqli-login",
            "fix-sqli-login",
            "fix-sqli-search",
            "incident-log-forensics",
        }
        for value in forbidden:
            self.assertNotIn(value, source)
        self.assertNotIn("local_task/", source)
        self.assertNotIn("/solution", source)
        self.assertNotIn("/expected", source)


class PortabilityCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_cli_runs_real_suite_and_writes_report(self) -> None:
        output = self.root / "nested" / "c12.json"
        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "evaluation.portability",
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
        self.assertEqual(report["passed_count"], len(EXPECTED_CHECKS))

    def test_main_returns_one_and_keeps_report_when_a_check_fails(self) -> None:
        output = self.root / "failed.json"
        failed_report = {
            "schema_version": 1,
            "suite": "c12-portability-adversarial",
            "offline_parent_network_guard": True,
            "passed": False,
            "check_count": 1,
            "passed_count": 0,
            "failed_count": 1,
            "checks": [
                {"name": "broken", "area": "test", "passed": False, "detail": "evidence"}
            ],
        }
        with mock.patch(
            "evaluation.portability.run_portability_suite",
            return_value=failed_report,
        ):
            with mock.patch("sys.stderr"):
                status = main(["--output", str(output)])
        self.assertEqual(status, 1)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), failed_report)

    def test_main_returns_two_for_symlink_output(self) -> None:
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
