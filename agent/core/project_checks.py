"""Freeze a bounded project-test contract before the agent edits any files."""

from __future__ import annotations

import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from agent.validators import CommandSpec, canonical_path, path_is_within


MAX_GUIDANCE_BYTES = 64_000
MAX_TEST_COMMANDS = 4
PYTEST_START = re.compile(r"^(?:pytest|python(?:3(?:\.\d+)?)?\s+-m\s+pytest)(?:\s|$)")
SAFE_FLAGS = frozenset({"-q", "-qq", "-v", "-vv", "-x", "--disable-warnings", "--strict-markers"})


@dataclass(frozen=True)
class ProjectCheckPlan:
    commands: tuple[CommandSpec, ...] = ()
    sources: tuple[str, ...] = ()
    error: str = ""


def project_python(root: Path) -> str:
    # Keep the venv executable path: resolving its symlink to the system binary
    # would silently discard the virtual environment and its installed pytest.
    relative = Path(".venv/Scripts/python.exe" if os.name == "nt" else ".venv/bin/python")
    candidate = root / relative
    return str(candidate) if candidate.is_file() else sys.executable


def _pytest_arguments(command: str, root: Path) -> tuple[str, ...]:
    if len(command) > 2048 or any(char in command for char in ";&|<>$\x00\r\n"):
        raise ValueError("project test command contains shell syntax or exceeds its size limit")
    parts = shlex.split(command, posix=True)
    args = parts[1:] if parts[0] == "pytest" else parts[3:]
    if len(args) > 32:
        raise ValueError("project test command has too many arguments")
    normalized: list[str] = []
    paths = 0
    for value in args:
        if value in SAFE_FLAGS or re.fullmatch(r"--maxfail=[1-9]\d?", value):
            normalized.append(value)
            continue
        if value.startswith("-"):
            raise ValueError(f"unsupported project-test option: {value}")
        path_text, separator, node = value.partition("::")
        path_text = path_text.replace("\\", "/")
        if path_text == "/app":
            path_text = "."
        elif path_text.startswith("/app/"):
            path_text = path_text[5:]
        pure = PurePosixPath(path_text)
        if pure.is_absolute() or ".." in pure.parts or ":" in path_text:
            raise ValueError(f"project test path must stay inside workdir: {value}")
        if any(part.lower() in {"solution", "solutions", "verifier", "expected", ".git"} for part in pure.parts):
            raise ValueError(f"project test path is not a project suite: {value}")
        target = canonical_path(root / path_text)
        if not path_is_within(target, root):
            raise ValueError(f"project test path escapes workdir: {value}")
        normalized.append(pure.as_posix() + (separator + node if separator else ""))
        paths += 1
    if not paths:
        normalized.append("tests" if (root / "tests").is_dir() else ".")
    return (project_python(root), "-m", "pytest", *normalized)


def _has_python_tests(root: Path, directory: Path) -> bool:
    return any(directory.glob("**/test_*.py")) or any(directory.glob("**/*_test.py"))


def discover_project_checks(instruction: str, workdir: Path) -> ProjectCheckPlan:
    """Support explicit pytest commands and ordinary Python test discovery.

    This is deliberately not a shell interpreter. Unknown pytest options block
    completion with a diagnostic instead of silently dropping a required check.
    """
    root = canonical_path(workdir)
    documents = [("instruction", instruction)]
    guidance = root / "AGENTS.md"
    try:
        if guidance.exists() or guidance.is_symlink():
            if guidance.is_symlink() or not guidance.is_file():
                raise ValueError("AGENTS.md must be a regular file")
            if guidance.stat().st_size > MAX_GUIDANCE_BYTES:
                raise ValueError("AGENTS.md exceeds the project-check guidance limit")
            documents.append(("AGENTS.md", guidance.read_text(encoding="utf-8-sig")))
        commands: list[CommandSpec] = []
        sources: list[str] = []
        seen: set[tuple[str, ...]] = set()
        for source, text in documents:
            candidates = re.findall(r"`([^`\r\n]+)`", text)
            candidates.extend(line.strip() for line in text.splitlines())
            for candidate in candidates:
                if not PYTEST_START.match(candidate):
                    continue
                argv = _pytest_arguments(candidate, root)
                if argv in seen:
                    continue
                if len(commands) >= MAX_TEST_COMMANDS:
                    raise ValueError("too many required project-test commands")
                seen.add(argv)
                sources.append(source)
                commands.append(CommandSpec(f"project-tests-{len(commands) + 1}", argv))
        if not commands and (root / "tests").is_dir() and _has_python_tests(root, root / "tests"):
            commands.append(CommandSpec("project-tests-1", _pytest_arguments("pytest tests/", root)))
            sources.append("Python tests/ discovery")
        if not commands:
            root_tests = list(root.glob("test_*.py")) + list(root.glob("*_test.py"))
            if any(path.is_file() and not path.is_symlink() for path in root_tests):
                commands.append(CommandSpec("project-tests-1", _pytest_arguments("pytest .", root)))
                sources.append("Python root-test discovery")
        return ProjectCheckPlan(tuple(commands), tuple(sources))
    except (OSError, UnicodeError, ValueError) as error:
        return ProjectCheckPlan(error=str(error))
