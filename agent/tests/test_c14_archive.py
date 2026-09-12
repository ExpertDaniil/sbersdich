"""Exercise the shipped package against a loopback OpenAI protocol simulator.

The simulator supplies a known strategy and derives action arguments from real
tool observations. These are integration tests, not tests of real LLM ability
and not official competition CTF scores. No simulator is shipped in the ZIP.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from agent.scaffold.packaging import build_submission
from evaluation.ctf_suite import build_ctf_cases


class ProtocolServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, case):
        super().__init__(("127.0.0.1", 0), ProtocolHandler)
        self.case = case
        self.calls = []
        self.errors = []

    def action_for(self, body):
        self.calls.append(body)
        state = json.loads(body["messages"][-1]["content"])
        if state["mode"] != "ctf" or "ctf_transform" not in state["allowed_actions"]:
            raise AssertionError("production planner did not receive the CTF contract/catalog")
        evidence = state["task_state"]["evidence"]
        if not evidence:
            if self.case.reader == "text":
                return {"name": "read_file", "arguments": {"path": self.case.input_path}}
            return {"name": "read_bytes", "arguments": {
                "path": self.case.input_path, "length": len(self.case.input_content)}}
        last = evidence[-1]
        if not last["ok"]:
            raise AssertionError("real tool failed: " + last["summary"])
        data = json.loads(last["data_preview"])
        if last["action"] in {"read_file", "read_bytes"}:
            if any(item["action"] == "write_exact_text" for item in evidence):
                return {"name": "finish", "arguments": {}}
            value = data["content"] if last["action"] == "read_file" else data["hex"]
            return {"name": "ctf_transform", "arguments": {
                "value": value, "steps": list(self.case.operations)}}
        if last["action"] == "ctf_transform":
            return {"name": "write_exact_text", "arguments": {
                "path": "/app/" + self.case.output_path, "content": data["text"]}}
        if last["action"] == "write_exact_text":
            return {"name": "read_file", "arguments": {"path": "/app/" + self.case.output_path}}
        raise AssertionError("unexpected production observation: " + last["action"])


class ProtocolHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        try:
            if self.path != "/v1/chat/completions":
                raise AssertionError("unexpected endpoint path: " + self.path)
            size = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(size))
            action = self.server.action_for(body)
        except Exception as error:
            self.server.errors.append(str(error))
            action = {"name": "abort", "arguments": {}, "rationale": str(error)}
        payload = json.dumps({
            "choices": [{"message": {"content": json.dumps(action)}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10},
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


class C14ArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.storage = tempfile.TemporaryDirectory(prefix="c14-package-")
        cls.package_root = Path(cls.storage.name)
        cls.repo_root = Path(__file__).resolve().parents[2]
        cls.archive = cls.package_root / "submission.zip"
        cls.build = build_submission(cls.repo_root, cls.archive)

    @classmethod
    def tearDownClass(cls):
        cls.storage.cleanup()

    def test_archive_contains_production_launcher_and_ctf_without_test_code(self):
        with zipfile.ZipFile(self.archive) as archive:
            names = set(archive.namelist())
            # Shell line endings are normalized for Linux, including Windows checkouts.
            expected_launcher = (self.repo_root / "run.sh").read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(archive.read("run.sh"), expected_launcher)
            self.assertNotIn(b"\r\n", archive.read("run.sh"))
            self.assertTrue(archive.getinfo("run.sh").external_attr >> 16 & 0o111)
        self.assertTrue({"agent/tools/ctf.py", "agent/core/ctf_completion.py", "agent/playbooks/ctf.md"} <= names)
        self.assertFalse(any("tests" in Path(name).parts or name.startswith("evaluation/") for name in names))
        self.assertNotIn("agent.py", names)
        self.assertLess(self.build.size_bytes, 10_000_000)

    def exercise_archive(self, case, *, shell=False):
        with tempfile.TemporaryDirectory(prefix="c14-run-") as tmp:
            outer = Path(tmp)
            install = outer / "installed agent"
            workdir = outer / "рабочая папка"
            install.mkdir()
            workdir.mkdir()
            with zipfile.ZipFile(self.archive) as archive:
                archive.extractall(install)
            # Final competition supplies a wrapper next to our package. It must
            # not replace the package selected by `python -m agent.scaffold.cli`.
            (install / "agent.py").write_text("raise RuntimeError('wrapper must not be run by -m')\n", encoding="utf-8")
            evidence = workdir / case.input_path
            evidence.parent.mkdir(parents=True)
            evidence.write_bytes(case.input_content)
            (workdir / "fragment.py").write_bytes(b"def partial(\n")
            server = ProtocolServer(case)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                env = {k: v for k, v in os.environ.items()
                       if not k.startswith(("LOCAL_AGENT_", "OPENAI_"))}
                env.update({
                    "LOCAL_AGENT_MODEL": "c14-protocol-simulator",
                    "OPENAI_BASE_URL": f"http://127.0.0.1:{server.server_port}/v1",
                    "OPENAI_API_KEY": "local-test-only",
                    "LOCAL_AGENT_WORKDIR": str(workdir),
                    "PYTHONPATH": str(install),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "PYTHONUTF8": "1",
                    "NO_PROXY": "127.0.0.1,localhost",
                    "no_proxy": "127.0.0.1,localhost",
                })
                if shell:
                    argv = [shutil.which("sh"), "./run.sh", case.instruction]
                else:
                    argv = [sys.executable, "-m", "agent.scaffold.cli", "--workdir", str(workdir),
                            "--deadline-seconds", "20", "--", case.instruction]
                process = subprocess.run(argv, cwd=install, env=env, text=True,
                    encoding="utf-8", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
            self.assertEqual(server.errors, [])
            self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
            self.assertIsInstance(process.stdout, str)
            result = json.loads(process.stdout)
            self.assertEqual(result["status"], "succeeded", result)
            self.assertEqual(result["decision"]["mode"], "ctf")
            self.assertEqual((workdir / case.output_path).read_bytes(), case.expected.encode("utf-8"))
            self.assertEqual(evidence.read_bytes(), case.input_content)
            self.assertEqual((workdir / "fragment.py").read_bytes(), b"def partial(\n")
            self.assertFalse((install / case.output_path).exists())
            # read -> transform -> write; the declared artifact is verified
            # immediately without spending calls on read-back + finish.
            self.assertEqual(len(server.calls), 3)
            self.assertEqual(result["metrics"]["model_usage"]["requests"], 3)

    def test_packaged_cli_solves_three_observation_driven_ctf_cases(self):
        for case in build_ctf_cases():
            with self.subTest(case=case.task_id):
                self.exercise_archive(case)

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "production shell entrypoint requires POSIX; packaged Python CLI is tested on every OS")
    def test_packaged_run_sh_uses_task_workdir_from_install_directory(self):
        self.exercise_archive(build_ctf_cases()[0], shell=True)


if __name__ == "__main__":
    unittest.main()
