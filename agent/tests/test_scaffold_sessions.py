from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from agent.scaffold.sessions import (
    InteractiveSessionError,
    InteractiveSessionManager,
    SessionProfile,
    sanitized_environment,
)


def echo_profile(options, workdir: Path):
    if options:
        raise ValueError("echo profile takes no options")
    program = (
        "import sys\n"
        "print('READY', flush=True)\n"
        "for line in sys.stdin:\n"
        "    print('ECHO:' + line.rstrip('\\n'), flush=True)\n"
    )
    return (sys.executable, "-u", "-c", program)


class ScaffoldSessionTests(unittest.TestCase):
    def test_secret_environment_is_not_inherited(self):
        import os

        old = os.environ.get("OPENAI_API_KEY")
        os.environ["OPENAI_API_KEY"] = "should-not-leak"
        try:
            self.assertNotIn("OPENAI_API_KEY", sanitized_environment())
        finally:
            if old is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = old

    def test_one_non_blocking_session_can_receive_multiple_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = InteractiveSessionManager()
            profile = SessionProfile("echo", "test echo", echo_profile)
            started = manager.start(profile, {}, Path(tmp))
            self.assertTrue(started["active"])
            first = manager.send("one")
            second = manager.send("two")
            self.assertIn("ECHO:one", first["output_tail"] + second["output_tail"])
            self.assertIn("ECHO:two", second["output_tail"])
            stopped = manager.stop()
            self.assertFalse(stopped["active"])

    def test_second_parallel_session_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = InteractiveSessionManager()
            profile = SessionProfile("echo", "test echo", echo_profile)
            manager.start(profile, {}, Path(tmp))
            try:
                with self.assertRaisesRegex(InteractiveSessionError, "only one"):
                    manager.start(profile, {}, Path(tmp))
            finally:
                manager.stop()


if __name__ == "__main__":
    unittest.main()
