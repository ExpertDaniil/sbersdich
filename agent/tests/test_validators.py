from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
VALIDATORS = REPO_ROOT / "agent" / "validators.py"
sys.path.insert(0, str(REPO_ROOT))

from agent.validators import (  # noqa: E402
    ArtifactRule,
    CommandSpec,
    ValidationError,
    ValidationPolicy,
    capture_snapshot,
    compare_snapshots,
    load_snapshot,
    parse_snapshot_payload,
    run_command_check,
    snapshot_payload,
    validate_artifact,
    validate_python_syntax,
    validate_task,
)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def valid_security_report() -> dict:
    return {
        "findings": [
            {
                "title": "Dynamic SQL query",
                "severity": "high",
                "category": "CWE-89: SQL Injection",
                "location": "routers/auth.py:10",
                "evidence": "Untrusted input reaches an SQL f-string.",
                "impact": "Authentication can be bypassed.",
                "recommendation": "Use driver placeholders.",
            }
        ]
    }


def make_project(root: Path) -> None:
    write_text(root / "app.py", "def value():\n    return 1\n")
    write_text(root / "tests" / "test_app.py", "def test_value():\n    assert True\n")
    write_text(root / "pyproject.toml", "[project]\nname = 'fixture'\n")


class SnapshotTests(unittest.TestCase):
    def test_snapshot_detects_added_modified_and_deleted_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "modified.txt", "before\n")
            write_text(root / "deleted.txt", "delete me\n")
            before = capture_snapshot(root)
            write_text(root / "modified.txt", "after\n")
            (root / "deleted.txt").unlink()
            write_text(root / "added.txt", "new\n")
            changes = compare_snapshots(before, capture_snapshot(root))
            self.assertEqual(changes.added, ("added.txt",))
            self.assertEqual(changes.modified, ("modified.txt",))
            self.assertEqual(changes.deleted, ("deleted.txt",))

    def test_snapshot_ignores_runtime_caches(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "app.py", "x = 1\n")
            before = capture_snapshot(root)
            write_text(root / "__pycache__" / "app.pyc", "cache\n")
            write_text(root / ".pytest_cache" / "state", "cache\n")
            self.assertEqual(compare_snapshots(before, capture_snapshot(root)).all_paths(), ())

    def test_snapshot_payload_rejects_unsafe_paths_and_invalid_hashes(self):
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = capture_snapshot(Path(tmp))
            payload = snapshot_payload(snapshot)
            payload["files"] = {
                "../outside": {
                    "kind": "file",
                    "mode": 0o644,
                    "size_bytes": 1,
                    "sha256": "bad",
                }
            }
            with self.assertRaises(ValidationError):
                parse_snapshot_payload(payload)


class ArtifactValidationTests(unittest.TestCase):
    def test_security_report_requires_exact_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "security_report.json"
            write_text(path, json.dumps(valid_security_report()))
            self.assertTrue(validate_artifact(ArtifactRule("security-report", path)).passed)

            invalid = valid_security_report()
            invalid["findings"][0]["severity"] = "urgent"
            write_text(path, json.dumps(invalid))
            result = validate_artifact(ArtifactRule("security-report", path))
            self.assertFalse(result.passed)
            self.assertIn("severity", result.detail)

    def test_incident_report_uses_forensics_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "incident_report.txt"
            write_text(
                path,
                "attacker_ip=203.0.113.45\n"
                "compromised_user=runtime-user\n"
                "exfil_bytes=445566\n"
                "first_malicious_event_utc=2040-01-02T03:04:05.006Z\n",
            )
            self.assertTrue(validate_artifact(ArtifactRule("incident-report", path)).passed)
            write_text(path, path.read_text(encoding="utf-8") + "extra=forbidden\n")
            self.assertFalse(validate_artifact(ArtifactRule("incident-report", path)).passed)

    def test_exact_text_rejects_newline_and_symlink_free_file_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hello.txt"
            write_text(path, "Hello")
            rule = ArtifactRule("exact-text", path, "Hello")
            self.assertTrue(validate_artifact(rule).passed)
            write_text(path, "Hello\n")
            self.assertFalse(validate_artifact(rule).passed)

    def test_json_and_utf8_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "result.json"
            write_text(path, "{broken")
            self.assertFalse(validate_artifact(ArtifactRule("json", path)).passed)
            path.write_bytes(b"\xff\xfe")
            self.assertFalse(validate_artifact(ArtifactRule("text", path)).passed)


class PolicyValidationTests(unittest.TestCase):
    def test_audit_allows_only_declared_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_project(root)
            baseline = capture_snapshot(root)
            report = root / "security_report.json"
            write_text(report, json.dumps(valid_security_report()))
            result = validate_task(
                ValidationPolicy(
                    mode="audit",
                    target=root,
                    baseline=baseline,
                    artifacts=(ArtifactRule("security-report", report),),
                )
            )
            self.assertTrue(result.passed, result.as_payload())
            self.assertEqual(result.changes.added, ("security_report.json",))

    def test_audit_rejects_source_change_even_with_valid_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_project(root)
            baseline = capture_snapshot(root)
            write_text(root / "app.py", "def value():\n    return 2\n")
            report = root / "security_report.json"
            write_text(report, json.dumps(valid_security_report()))
            result = validate_task(
                ValidationPolicy(
                    mode="audit",
                    target=root,
                    baseline=baseline,
                    artifacts=(ArtifactRule("security-report", report),),
                )
            )
            self.assertFalse(result.passed)
            change_check = next(check for check in result.checks if check.name == "change-policy")
            self.assertIn("app.py", change_check.detail)

    def test_fix_allows_source_change_but_protects_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_project(root)
            baseline = capture_snapshot(root)
            write_text(root / "app.py", "def value():\n    return 2\n")
            source_result = validate_task(
                ValidationPolicy(mode="fix", target=root, baseline=baseline)
            )
            self.assertTrue(source_result.passed, source_result.as_payload())

            write_text(root / "tests" / "test_app.py", "def test_value():\n    assert False\n")
            test_result = validate_task(
                ValidationPolicy(mode="fix", target=root, baseline=baseline)
            )
            self.assertFalse(test_result.passed)
            self.assertIn(
                "tests/test_app.py",
                next(check for check in test_result.checks if check.name == "change-policy").detail,
            )

    def test_fix_rejects_dependency_change_unless_explicitly_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_project(root)
            baseline = capture_snapshot(root)
            write_text(root / "pyproject.toml", "[project]\nname='fixture'\ndependencies=['x']\n")
            rejected = validate_task(
                ValidationPolicy(mode="fix", target=root, baseline=baseline)
            )
            self.assertFalse(rejected.passed)
            allowed = validate_task(
                ValidationPolicy(
                    mode="fix",
                    target=root,
                    baseline=baseline,
                    allow_dependency_changes=True,
                )
            )
            self.assertTrue(allowed.passed, allowed.as_payload())

    def test_forensics_allows_report_but_not_evidence_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            evidence = root / "incident" / "events.log"
            write_text(evidence, "immutable evidence\n")
            baseline = capture_snapshot(root)
            report = root / "incident_report.txt"
            write_text(
                report,
                "attacker_ip=1.1.1.1\n"
                "compromised_user=forensic-user\n"
                "exfil_bytes=10101\n"
                "first_malicious_event_utc=2041-02-03T04:05:06.007Z\n",
            )
            policy = ValidationPolicy(
                mode="forensics",
                target=root,
                baseline=baseline,
                artifacts=(ArtifactRule("incident-report", report),),
                check_python_syntax=False,
            )
            self.assertTrue(validate_task(policy).passed)
            write_text(evidence, "tampered evidence\n")
            self.assertFalse(validate_task(policy).passed)

    def test_invalid_python_fails_without_importing_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "broken.py", "def broken(:\n    pass\n")
            result = validate_python_syntax(root)
            self.assertFalse(result.passed)
            self.assertIn("broken.py", result.detail)


class CommandValidationTests(unittest.TestCase):
    def test_command_pass_and_failure_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            passed = run_command_check(
                CommandSpec("pass", (sys.executable, "-c", "print('ok')"), 5), root
            )
            failed = run_command_check(
                CommandSpec("fail", (sys.executable, "-c", "raise SystemExit(7)"), 5),
                root,
            )
            self.assertTrue(passed.passed)
            self.assertIn("ok", passed.detail)
            self.assertFalse(failed.passed)
            self.assertIn("exit_code=7", failed.detail)

    def test_command_timeout_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = run_command_check(
                CommandSpec(
                    "timeout",
                    (sys.executable, "-c", "import time; time.sleep(2)"),
                    1,
                ),
                Path(tmp),
            )
            self.assertFalse(result.passed)
            self.assertIn("timed out", result.detail)


class ValidatorCliTests(unittest.TestCase):
    def test_cli_snapshot_and_exact_text_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            root = workspace / "app"
            root.mkdir()
            baseline_path = workspace / "baseline.json"
            validation_path = workspace / "validation.json"
            snapshot = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATORS),
                    "snapshot",
                    str(root),
                    "--output",
                    str(baseline_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(snapshot.returncode, 0, snapshot.stdout + snapshot.stderr)
            self.assertEqual(load_snapshot(baseline_path).files, {})
            write_text(root / "hello.txt", "Hello")
            validation = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATORS),
                    "validate",
                    str(root),
                    "--mode",
                    "general",
                    "--baseline",
                    str(baseline_path),
                    "--exact-text",
                    "hello.txt=Hello",
                    "--skip-python-syntax",
                    "--output",
                    str(validation_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)
            report = json.loads(validation_path.read_text(encoding="utf-8"))
            self.assertTrue(report["passed"])
            self.assertEqual(report["changes"]["added"], ["hello.txt"])

    def test_cli_returns_one_for_failed_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            root = workspace / "app"
            root.mkdir()
            write_text(root / "source.py", "x = 1\n")
            baseline_path = workspace / "baseline.json"
            baseline_path.write_text(
                json.dumps(snapshot_payload(capture_snapshot(root))), encoding="utf-8"
            )
            write_text(root / "source.py", "x = 2\n")
            process = subprocess.run(
                [
                    sys.executable,
                    str(VALIDATORS),
                    "validate",
                    str(root),
                    "--mode",
                    "audit",
                    "--baseline",
                    str(baseline_path),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
            self.assertFalse(json.loads(process.stdout)["passed"])


if __name__ == "__main__":
    unittest.main()
