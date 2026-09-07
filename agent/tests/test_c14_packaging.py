"""Reproduce Windows shell line endings on every OS, without changing Git config."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from agent.scaffold.packaging import build_submission


class C14PackagingLineEndingTests(unittest.TestCase):
    def test_crlf_shells_are_normalized_without_changing_sources_or_other_files(self):
        with tempfile.TemporaryDirectory(prefix="c14-crlf-") as tmp:
            root = Path(tmp) / "исходники с пробелами"
            (root / "agent").mkdir(parents=True)
            sources = {
                "run.sh": b"#!/bin/sh\r\nsh ./agent/helper.sh\r\n",
                "agent/helper.sh": b"#!/bin/sh\r\nprintf 'packaged-ok\\n'\r\n",
                "agent/payload.bin": b"\x00\xff\r\n\x01\r\x02\n",
                "agent/config.py": b"VALUE = 1\r\n",
            }
            for name, content in sources.items():
                (root / name).write_bytes(content)
            result = build_submission(root, root / "submission.zip")
            with zipfile.ZipFile(result.output) as archive:
                for name, original in sources.items():
                    with self.subTest(path=name):
                        expected = original.replace(b"\r\n", b"\n") if name.endswith(".sh") else original
                        self.assertEqual(archive.read(name), expected)
                        self.assertEqual((root / name).read_bytes(), original)
                self.assertEqual((archive.getinfo("run.sh").external_attr >> 16) & 0o777, 0o755)

    def test_lf_and_crlf_shell_sources_produce_identical_archive(self):
        with tempfile.TemporaryDirectory(prefix="c14-crlf-") as tmp:
            root = Path(tmp)
            (root / "agent").mkdir()
            shells = {
                "run.sh": b"#!/bin/sh\nsh ./agent/helper.sh\n",
                "agent/helper.sh": b"#!/bin/sh\nprintf 'packaged-ok\\n'\n",
            }
            for name, content in shells.items():
                (root / name).write_bytes(content)
            lf = build_submission(root, root / "lf.zip")
            for name, content in shells.items():
                (root / name).write_bytes(content.replace(b"\n", b"\r\n"))
            crlf = build_submission(root, root / "crlf.zip")
            self.assertEqual(lf.sha256, crlf.sha256)
            self.assertEqual(lf.output.read_bytes(), crlf.output.read_bytes())

    @unittest.skipUnless(os.name == "posix" and shutil.which("sh"), "requires POSIX shell")
    def test_crlf_launcher_executes_after_packaging(self):
        with tempfile.TemporaryDirectory(prefix="c14-crlf-") as tmp:
            outer = Path(tmp)
            root = outer / "source"
            (root / "agent").mkdir(parents=True)
            (root / "run.sh").write_bytes(b"#!/bin/sh\r\nset -eu\r\nsh ./agent/helper.sh\r\n")
            (root / "agent" / "helper.sh").write_bytes(b"#!/bin/sh\r\nprintf 'packaged-ok\\n'\r\n")
            result = build_submission(root, outer / "submission.zip")
            install = outer / "установленный агент"
            with zipfile.ZipFile(result.output) as archive:
                archive.extractall(install)
            process = subprocess.run(
                [shutil.which("sh"), "./run.sh"], cwd=install,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, encoding="utf-8", timeout=10,
            )
            self.assertEqual(process.returncode, 0, process.stderr or process.stdout)
            self.assertEqual(process.stdout, "packaged-ok\n")


if __name__ == "__main__":
    unittest.main()
