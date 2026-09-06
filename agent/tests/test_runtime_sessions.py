from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from agent.runtime.contracts import RuntimeLimits
from agent.runtime.sessions import InteractiveSessionManager, SessionError


def python_only(argv: tuple[str, ...]) -> str:
    if Path(argv[0]).resolve() != Path(sys.executable).resolve():
        raise SessionError("only test Python is allowed")
    return "test-python-repl"


class RuntimeSessionTests(unittest.TestCase):
    def test_session_is_single_non_shell_and_interactive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "echo_server.py"
            helper.write_text(
                "import sys\n"
                "print('ready', flush=True)\n"
                "for line in sys.stdin:\n"
                "    print('echo:' + line.strip(), flush=True)\n",
                encoding="utf-8",
            )
            with InteractiveSessionManager(root, argv_policy=python_only) as manager:
                started = manager.start([sys.executable, "-u", "echo_server.py"])
                self.assertTrue(started.running)
                with self.assertRaisesRegex(SessionError, "already running"):
                    manager.start([sys.executable, "-u", "echo_server.py"])
                snapshot = manager.send("hello", settle_seconds=0.5)
                self.assertIn("echo:hello", snapshot.output)
                stopped = manager.stop()
                self.assertFalse(stopped.running)

    def test_default_policy_denies_every_interactive_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = InteractiveSessionManager(tmp)
            with self.assertRaisesRegex(SessionError, "not enabled"):
                manager.start([sys.executable, "-V"])

    def test_transcript_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            helper = root / "loud.py"
            helper.write_text("print('x' * 5000, flush=True)\ninput()\n", encoding="utf-8")
            limits = RuntimeLimits(max_session_output_bytes=512)
            with InteractiveSessionManager(root, argv_policy=python_only, limits=limits) as manager:
                manager.start([sys.executable, "-u", "loud.py"])
                snapshot = manager.snapshot()
                self.assertLessEqual(len(snapshot.output.encode()), 512)
                self.assertTrue(snapshot.output_truncated)


if __name__ == "__main__":
    unittest.main()
