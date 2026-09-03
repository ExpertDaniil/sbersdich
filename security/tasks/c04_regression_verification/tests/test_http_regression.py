import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CHECKER = PROJECT_ROOT / "scripts" / "http_regression.py"
RUNNER = PROJECT_ROOT / "run_in_acp.sh"


def bash_path(path):
    """Return a path that Bash can use, including Git Bash on Windows."""

    resolved = os.path.abspath(os.fspath(path))
    if os.name != "nt":
        return resolved
    drive, tail = os.path.splitdrive(resolved)
    normalized_tail = tail.replace("\\", "/")
    if drive:
        return f"/{drive[0].lower()}{normalized_tail}"
    return normalized_tail


def make_handler(vulnerable_login=False):
    class FakeApiHandler(BaseHTTPRequestHandler):
        items = {
            1: {
                "id": 1,
                "name": "Fix login timeout",
                "description": "Seed",
                "status": "open",
                "priority": "high",
                "owner_id": 1,
            }
        }
        next_id = 2

        def log_message(self, _format, *_args):
            pass

        def read_json(self):
            length = int(self.headers.get("Content-Length", "0"))
            return json.loads(self.rfile.read(length) or b"{}")

        def send_json(self, status, payload):
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            parsed = urlparse(self.path)
            if parsed.path == "/healthz":
                return self.send_json(200, {"status": "ok"})
            if parsed.path == "/search":
                query = parse_qs(parsed.query).get("q", [""])[0].lower()
                rows = [item for item in self.items.values() if query in item["name"].lower()]
                return self.send_json(200, rows)
            if parsed.path == "/items":
                wanted = parse_qs(parsed.query).get("status", [None])[0]
                rows = [item for item in self.items.values() if wanted is None or item["status"] == wanted]
                return self.send_json(200, rows)
            if parsed.path.startswith("/items/") and parsed.path.endswith("/comments"):
                return self.send_json(200, [])
            if parsed.path.startswith("/items/"):
                item_id = int(parsed.path.rsplit("/", 1)[1])
                item = self.items.get(item_id)
                return self.send_json(200, item) if item else self.send_json(404, {"detail": "Item not found"})
            if parsed.path == "/tags":
                return self.send_json(200, [{"id": 1, "name": "bug"}])
            if parsed.path == "/users":
                return self.send_json(200, [{"id": i, "username": name} for i, name in enumerate(("admin", "alice", "bob"), 1)])
            return self.send_json(404, {"detail": "Not found"})

        def do_POST(self):
            parsed = urlparse(self.path)
            payload = self.read_json()
            if parsed.path == "/login":
                valid = payload == {"username": "admin", "password": "secret123"}
                injected = vulnerable_login and "'" in payload.get("username", "")
                return self.send_json(200, {"token": "token-1"}) if valid or injected else self.send_json(401, {"detail": "Invalid credentials"})
            if parsed.path == "/items":
                item_id = self.next_id
                type(self).next_id += 1
                item = {"id": item_id, **payload}
                self.items[item_id] = item
                return self.send_json(200, item)
            if parsed.path.startswith("/items/") and parsed.path.endswith("/comments"):
                return self.send_json(200, {"id": 1, **payload})
            return self.send_json(404, {"detail": "Not found"})

        def do_PUT(self):
            item_id = int(urlparse(self.path).path.rsplit("/", 1)[1])
            payload = self.read_json()
            if item_id not in self.items:
                return self.send_json(404, {"detail": "Item not found"})
            self.items[item_id].update(payload)
            return self.send_json(200, self.items[item_id])

        def do_DELETE(self):
            item_id = int(urlparse(self.path).path.rsplit("/", 1)[1])
            if self.items.pop(item_id, None) is None:
                return self.send_json(404, {"detail": "Item not found"})
            return self.send_json(200, {"status": "ok"})

    return FakeApiHandler


class RunningServer:
    def __init__(self, handler):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}"

    def __exit__(self, _exc_type, _exc, _traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class HttpRegressionCheckerTests(unittest.TestCase):
    def run_checker(self, handler):
        with RunningServer(handler) as base_url, tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "report.json"
            process = subprocess.run(
                [
                    sys.executable,
                    str(CHECKER),
                    "--base-url",
                    base_url,
                    "--output",
                    str(output),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            return process, json.loads(output.read_text(encoding="utf-8"))

    def test_safe_service_passes_all_checks(self):
        process, report = self.run_checker(make_handler(vulnerable_login=False))
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(report["failed"], 0)
        self.assertEqual(report["passed"], report["total"])
        self.assertEqual(report["total"], 11)

    def test_vulnerable_login_is_detected(self):
        process, report = self.run_checker(make_handler(vulnerable_login=True))
        self.assertNotEqual(process.returncode, 0)
        failed = {row["name"] for row in report["checks"] if not row["passed"]}
        self.assertEqual(failed, {"sqli_comment_rejected", "sqli_or_rejected"})


def reserve_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class RuntimeRunnerTests(unittest.TestCase):
    def run_runtime(self, pytest_status):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = root / "app"
            venv_bin = app / ".venv" / "bin"
            tests = app / "tests"
            output = root / "results"
            venv_bin.mkdir(parents=True)
            tests.mkdir()
            (app / "main.py").write_text("# fake app for runner orchestration test\n")

            python_wrapper = venv_bin / "python"
            python_wrapper.write_text(
                "#!/bin/sh\n"
                "if [ \"${1:-}\" = \"-m\" ] && [ \"${2:-}\" = \"pytest\" ]; then\n"
                "  exit \"${FAKE_PYTEST_STATUS:-0}\"\n"
                "fi\n"
                "exec \"$C04_TEST_PYTHON\" \"$@\"\n",
                encoding="utf-8",
            )
            python_wrapper.chmod(0o755)

            uvicorn_wrapper = venv_bin / "uvicorn"
            uvicorn_wrapper.write_text(
                "#!/bin/sh\n"
                "exec \"$C04_TEST_PYTHON\" \"$C04_TEST_SERVER\" --serve\n",
                encoding="utf-8",
            )
            uvicorn_wrapper.chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "C04_OUTPUT_DIR": bash_path(output),
                    "C04_PORT": str(reserve_port()),
                    "C04_TEST_PYTHON": bash_path(sys.executable),
                    "C04_TEST_SERVER": bash_path(Path(__file__).resolve()),
                    "FAKE_PYTEST_STATUS": str(pytest_status),
                }
            )
            process = subprocess.run(
                ["bash", bash_path(RUNNER), bash_path(app)],
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,
                check=False,
            )
            report_path = output / "http_report.json"
            if not report_path.is_file():
                self.fail(
                    "runtime runner did not create http_report.json\n"
                    f"stdout:\n{process.stdout}\n"
                    f"stderr:\n{process.stderr}"
                )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            return process, report

    def test_runtime_runner_passes_only_when_both_suites_pass(self):
        process, report = self.run_runtime(pytest_status=0)
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        self.assertEqual(report["failed"], 0)
        self.assertIn("C-04 PASSED", process.stdout)

    def test_runtime_runner_propagates_project_test_failure(self):
        process, report = self.run_runtime(pytest_status=1)
        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        self.assertEqual(report["failed"], 0)
        self.assertIn("pytest_status=1 http_status=0", process.stdout)


if __name__ == "__main__":
    if "--serve" in sys.argv:
        server = ThreadingHTTPServer(
            ("127.0.0.1", int(os.environ["C04_PORT"])),
            make_handler(vulnerable_login=False),
        )
        server.serve_forever()
    else:
        unittest.main()
