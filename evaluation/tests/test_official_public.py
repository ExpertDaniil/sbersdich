"""Harness regression tests; mocked Docker calls here are not benchmark results."""

from __future__ import annotations

import io
import json
import stat
import sys
import tarfile
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evaluation import official_public as c16
from evaluation.failure_analysis import load_records


IMAGE = "sha256:" + "a" * 64
TASK_TOML = '''[agent]
timeout_sec = 120.0
[verifier]
timeout_sec = 120.0
[environment]
build_timeout_sec = 600.0
cpus = 1
memory_mb = 2048
'''


def fixture(root: Path, task_id="hello-file") -> Path:
    task = root / "public/local_task" / task_id
    (task / "environment").mkdir(parents=True)
    (task / "tests").mkdir()
    (task / "task.toml").write_bytes(TASK_TOML.encode())
    (task / "instruction.md").write_bytes(b"fixture instruction with 'quotes' and $shell characters")
    (task / "environment/Dockerfile").write_bytes(b"FROM secureintelligent/acp:latest\nWORKDIR /app\n")
    (task / "tests/test.sh").write_bytes(b"#!/bin/sh\n# fixture verifier\n")
    (root / "public/agent").mkdir(parents=True, exist_ok=True)
    (root / "public/agent/agent.py").write_bytes(b"# standard wrapper fixture\n")
    return task


def archive(path: Path, extra: dict[str, bytes] | None = None, launcher=b"#!/bin/sh\nexit 0\n") -> Path:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        bundle.writestr("run.sh", launcher)
        bundle.writestr("agent/__init__.py", b"")
        for name, content in (extra or {}).items():
            bundle.writestr(name, content)
    return path


class FakeDocker:
    def __init__(self, *, agent_status=0, agent_timeout=False, verifier_status=0,
                 verifier_timeout=False, reward="1\n", cleanup_status=0, setup_status=0):
        self.agent_status, self.agent_timeout = agent_status, agent_timeout
        self.verifier_status, self.verifier_timeout = verifier_status, verifier_timeout
        self.reward, self.cleanup_status, self.setup_status = reward, cleanup_status, setup_status
        self.calls = []

    def __call__(self, argv, log, *, timeout, cwd=None):
        self.calls.append((argv, timeout))
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_bytes(b"fixture command output\n")
        status, timed_out = 0, False
        if argv[1] == "run":
            status = self.setup_status
        elif "./run.sh" in argv:
            status, timed_out = self.agent_status, self.agent_timeout
        elif "/tests/test.sh" in argv:
            status, timed_out = self.verifier_status, self.verifier_timeout
        elif argv[-2:] == ["cat", "/logs/verifier/reward.txt"]:
            log.write_bytes(self.reward.encode())
        elif argv[1] == "rm":
            status = self.cleanup_status
        return c16.Outcome(status, timed_out, 0.01, str(log))


class SubmissionInspectionTests(unittest.TestCase):
    def test_valid_archive_keeps_bytes_and_records_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(Path(tmp) / "архив с пробелами.zip")
            before = path.read_bytes()
            info = c16.inspect_submission(path)
            self.assertEqual(info["sha256"], c16.file_sha(path))
            self.assertEqual(path.read_bytes(), before)

    def test_unsafe_or_nonruntime_members_are_rejected(self):
        names = ("../escape", "/absolute", "C:/drive", "agent\\escape.py", "agent.py",
                 "agent/agent.py", "agent/tests/test_x.py", "evaluation/results.json", "agent/.env", "agent/key.pem")
        with tempfile.TemporaryDirectory() as tmp:
            for name in names:
                with self.subTest(name=name):
                    path = archive(Path(tmp) / "bad.zip", {name: b"fixture"})
                    with self.assertRaises(c16.HarnessError):
                        c16.inspect_submission(path)

    def test_crlf_launcher_fails_before_container_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(Path(tmp) / "bad.zip", launcher=b"#!/bin/sh\r\nexit 0\r\n")
            with self.assertRaisesRegex(c16.HarnessError, "CRLF"):
                c16.inspect_submission(path)

    def test_duplicate_symlink_and_extraction_limits_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = archive(Path(tmp) / "bad.zip", {"agent/./__init__.py": b"duplicate"})
            with self.assertRaisesRegex(c16.HarnessError, "duplicate"):
                c16.inspect_submission(path)
            path = archive(path)
            with zipfile.ZipFile(path, "a") as bundle:
                link = zipfile.ZipInfo("agent/link")
                link.external_attr = (stat.S_IFLNK | 0o777) << 16
                bundle.writestr(link, "outside")
            with self.assertRaisesRegex(c16.HarnessError, "symlink"):
                c16.inspect_submission(path)
            path = archive(path, {"agent/blob": b"x" * 100})
            with patch.object(c16, "MAX_EXTRACTED_BYTES", 50), self.assertRaisesRegex(c16.HarnessError, "extraction"):
                c16.inspect_submission(path)

    def test_missing_launcher_and_compressed_size_limit_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(path, "w"):
                pass
            with self.assertRaisesRegex(c16.HarnessError, "run.sh"):
                c16.inspect_submission(path)
            archive(path)
            with patch.object(c16, "MAX_ARCHIVE_BYTES", 1), self.assertRaisesRegex(c16.HarnessError, "10 MB"):
                c16.inspect_submission(path)


class ProcessAndFixtureTests(unittest.TestCase):
    def test_preparation_pins_images_and_keeps_verifier_out_of_build_context(self):
        digest = "secureintelligent/acp@" + IMAGE
        def export(_public_root, destination):
            for task_id in c16.TASKS:
                fixture(destination.parent, task_id)
        def docker(argv, log, **kwargs):
            log.parent.mkdir(parents=True, exist_ok=True)
            log.write_bytes(b"prepared\n")
            if argv[1] == "image":
                log.write_bytes(("WARNING: fixture\n" + json.dumps([digest]) + "\n").encode())
            if argv[1] == "build":
                context = Path(argv[-1])
                self.assertTrue((context / "Dockerfile").read_bytes().startswith(("FROM " + digest + "\n").encode()))
                self.assertFalse((context / "tests").exists())
                Path(argv[argv.index("--iidfile") + 1]).write_bytes((IMAGE + "\n").encode())
            return c16.Outcome(0, False, 0, str(log))
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with patch.object(c16, "docker_preflight", return_value="docker"), patch.object(c16, "export_public", side_effect=export), patch.object(c16, "execute", side_effect=docker):
                report = c16.prepare(root, root / "prepared")
            self.assertEqual(report["status"], "ready", report)
            self.assertEqual(report["base_image"], digest)
            self.assertEqual(set(report["tasks"]), set(c16.TASKS))
            for task_id, task in report["tasks"].items():
                self.assertEqual(task["image_id"], IMAGE)
                original = root / "prepared/public/local_task" / task_id
                self.assertIn(b"FROM secureintelligent/acp:latest\n", (original / "environment/Dockerfile").read_bytes())
                self.assertEqual((original / "tests/test.sh").read_bytes(), b"#!/bin/sh\n# fixture verifier\n")
            self.assertEqual(report["public_tree_sha256"], c16.tree_sha(root / "prepared/public"))

    def test_subprocess_logs_utf8_without_stdout_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "журнал с пробелами.log"
            result = c16.execute([sys.executable, "-c", "import sys; sys.stdout.buffer.write('проверка'.encode('utf-8'))"], output, timeout=5)
            self.assertEqual(result.exit_code, 0)
            self.assertIn("проверка", c16.tail(output))

    def test_missing_executable_and_timeout_are_outcomes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            missing = c16.execute([str(root / "missing")], root / "missing.log", timeout=1)
            self.assertIsNone(missing.exit_code)
            timeout = c16.execute([sys.executable, "-c", "import time; time.sleep(10)"], root / "timeout.log", timeout=0.1)
            self.assertTrue(timeout.timed_out)

    def test_missing_docker_preparation_is_blocked_and_has_a_report(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(c16.shutil, "which", return_value=None):
            root = Path(tmp)
            report = c16.prepare(root, root / "prepared")
            self.assertEqual(report["status"], "blocked")
            self.assertEqual(report["tasks"], {})
            self.assertIn("Docker", report["reason"])
            self.assertTrue((root / "prepared/prepared.json").is_file())

    def test_docker_warnings_do_not_hide_linux_daemon(self):
        def docker_info(argv, log, **kwargs):
            log.write_bytes(b"linux\nWARNING: fixture warning\n")
            return c16.Outcome(0, False, 0, str(log))
        with tempfile.TemporaryDirectory() as tmp, patch.object(c16.shutil, "which", return_value="docker"), patch.object(c16, "execute", side_effect=docker_info):
            self.assertEqual(c16.docker_preflight(Path(tmp)), "docker")

    def test_export_uses_pinned_git_bytes_without_checkout_or_crlf_conversion(self):
        def git_export(argv, log, **kwargs):
            self.assertIn(c16.PUBLIC_SHA, argv)
            self.assertNotIn("checkout", argv)
            output = Path(next(arg.split("=", 1)[1] for arg in argv if arg.startswith("--output=")))
            raw = b"#!/bin/sh\noriginal bytes\n"
            with tarfile.open(output, "w") as bundle:
                member = tarfile.TarInfo("local_task/demo/tests/test.sh")
                member.size = len(raw)
                bundle.addfile(member, io.BytesIO(raw))
            log.write_bytes(b"export ok")
            return c16.Outcome(0, False, 0, str(log))
        with tempfile.TemporaryDirectory() as tmp, patch.object(c16, "execute", side_effect=git_export):
            root = Path(tmp)
            c16.export_public(root, root / "public")
            self.assertEqual((root / "public/local_task/demo/tests/test.sh").read_bytes(), b"#!/bin/sh\noriginal bytes\n")

    def test_task_limits_come_from_original_toml_and_invalid_values_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            task = fixture(Path(tmp))
            result = c16.load_task(task)
            self.assertEqual(result["agent_timeout"], 120)
            self.assertEqual(result["memory_mb"], 2048)
            (task / "task.toml").write_text(TASK_TOML.replace("cpus = 1", "cpus = true"), encoding="utf-8")
            with self.assertRaises(c16.HarnessError):
                c16.load_task(task)


class OfficialExecutionOrderTests(unittest.TestCase):
    def run_fake(self, fake):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = fixture(root)
            before = c16.tree_sha(root / "public")
            bundle = archive(root / "submission.zip")
            metadata = {**c16.load_task(task), "image_id": IMAGE}
            with patch.object(c16, "execute", side_effect=fake):
                result = c16.run_task("docker", root, bundle, "hello-file", metadata, root / "results")
            self.assertEqual(c16.tree_sha(root / "public"), before)
            return result

    def test_verifier_arrives_after_agent_and_uses_original_reward(self):
        fake = FakeDocker()
        result = self.run_fake(fake)
        self.assertTrue(result["passed"], result)
        calls = [argv for argv, _ in fake.calls]
        agent_index = next(i for i, argv in enumerate(calls) if "./run.sh" in argv)
        upload_index = next(i for i, argv in enumerate(calls) if argv[1] == "cp" and argv[-1].endswith(":/tests"))
        verifier_index = next(i for i, argv in enumerate(calls) if "/tests/test.sh" in argv)
        self.assertLess(agent_index, upload_index)
        self.assertLess(upload_index, verifier_index)
        self.assertIn(c16.REMOTE_AGENT, calls[agent_index])
        self.assertEqual(calls[agent_index][-1], "fixture instruction with 'quotes' and $shell characters")
        start = next(argv for argv in calls if argv[1] == "run")
        self.assertEqual(start[start.index("--network") + 1], "none")
        self.assertIn("--pull=never", start)
        self.assertNotIn("--mount", start)
        self.assertEqual(result["reward"], 1)

    def test_reward_zero_nonbinary_and_missing_are_not_success(self):
        for reward in ("0\n", "", "1\n0\n", "true", "1.0"):
            with self.subTest(reward=reward):
                self.assertFalse(self.run_fake(FakeDocker(reward=reward))["passed"])

    def test_agent_failure_or_timeout_never_runs_verifier(self):
        for fake in (FakeDocker(agent_status=1), FakeDocker(agent_timeout=True)):
            result = self.run_fake(fake)
            self.assertFalse(result["passed"])
            self.assertFalse(any("/tests/test.sh" in argv for argv, _ in fake.calls))
            self.assertTrue(any(argv[1] == "rm" for argv, _ in fake.calls))

    def test_verifier_exit_failure_or_timeout_cannot_be_hidden_by_reward_one(self):
        for fake in (FakeDocker(verifier_status=1), FakeDocker(verifier_timeout=True)):
            self.assertFalse(self.run_fake(fake)["passed"])

    def test_setup_failure_is_blocked_and_cleanup_is_attempted(self):
        fake = FakeDocker(setup_status=1)
        result = self.run_fake(fake)
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(any("./run.sh" in argv for argv, _ in fake.calls))
        self.assertTrue(any(argv[1] == "rm" for argv, _ in fake.calls))

    def test_cleanup_failure_does_not_report_a_fully_successful_run(self):
        result = self.run_fake(FakeDocker(cleanup_status=1))
        self.assertEqual(result["reward"], 1)
        self.assertFalse(result["passed"])


class RunManifestAndCliTests(unittest.TestCase):
    def prepare_fake(self, root):
        task = fixture(root)
        manifest = {"schema": "c16-prepared-v1", "status": "ready", "public_commit": c16.PUBLIC_SHA,
                    "public_tree_sha256": c16.tree_sha(root / "public"), "base_image": "secureintelligent/acp@" + IMAGE,
                    "tasks": {"hello-file": {**c16.load_task(task), "image_id": IMAGE}}}
        c16.write_json(root / "prepared.json", manifest)
        return task

    def test_changed_fixture_blocks_run_before_docker(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            task = self.prepare_fake(root)
            (task / "tests/test.sh").write_bytes(b"modified verifier")
            bundle = archive(root / "submission.zip")
            with patch.object(c16, "docker_preflight") as docker:
                report = c16.run_prepared(root, bundle, root / "results", ("hello-file",))
            self.assertEqual(report["status"], "blocked")
            docker.assert_not_called()

    def test_missing_docker_creates_failure_analysis_compatible_preflight_trace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.prepare_fake(root)
            bundle = archive(root / "submission.zip")
            with patch.object(c16.shutil, "which", return_value=None):
                report = c16.run_prepared(root, bundle, root / "results", ("hello-file",))
            self.assertEqual(report["status"], "blocked")
            self.assertFalse(report["all_passed"])
            records = load_records(root / "results/traces.json")
            self.assertEqual(records[0].task_id, "c16-preflight")

    def test_cli_reports_blocked_with_exit_two_without_traceback(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(c16.shutil, "which", return_value=None):
            output = io.StringIO()
            with redirect_stdout(output):
                code = c16.main(["prepare", "--public-root", tmp, "--output", str(Path(tmp) / "prepared")])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(output.getvalue())["status"], "blocked")

    def test_existing_result_directory_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "summary.json"
            marker.write_bytes(b"existing report")
            with self.assertRaises(FileExistsError):
                c16.run_prepared(root, root / "absent.zip", root)
            self.assertEqual(marker.read_bytes(), b"existing report")


if __name__ == "__main__":
    unittest.main()
