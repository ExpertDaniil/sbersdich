from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.workspace import WorkspaceError
from agent.runtime.files import append_workspace_text, write_workspace_text


class RuntimeFileTests(unittest.TestCase):
    def test_write_replaces_and_append_does_not_duplicate_previous_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first = write_workspace_text(root, path="notes.txt", content="one\n")
            self.assertEqual(first["operation"], "write")
            write_workspace_text(root, path="notes.txt", content="two\n")
            append = append_workspace_text(root, path="notes.txt", content="three\n")
            self.assertEqual(append["operation"], "append")
            self.assertEqual((root / "notes.txt").read_text(), "two\nthree\n")

    def test_write_rejects_outside_and_protected_paths(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as other:
            root = Path(tmp)
            outside = Path(other) / "x.txt"
            with self.assertRaises(WorkspaceError):
                write_workspace_text(root, path=str(outside), content="x")
            with self.assertRaises(WorkspaceError):
                write_workspace_text(root, path="tests/test_agent.py", content="x")

    def test_append_rejects_non_utf8_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "data.bin").write_bytes(b"\xff\xfe")
            with self.assertRaisesRegex(WorkspaceError, "UTF-8"):
                append_workspace_text(root, path="data.bin", content="x")


if __name__ == "__main__":
    unittest.main()
