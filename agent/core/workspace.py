"""Bounded workspace inspection, patching and process execution primitives."""

from __future__ import annotations

import fnmatch
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

from agent.validators import (
    canonical_path,
    dependency_path,
    path_is_within,
    protected_path,
)

from .contracts import ContractError, map_instruction_path


MAX_LIST_ENTRIES = 500
MAX_LIST_DEPTH = 10
MAX_TEXT_FILE_BYTES = 512 * 1024
MAX_TEXT_CHARS = 12_000
MAX_TEXT_LINES = 400
MAX_BINARY_BYTES = 4_096
MAX_SEARCH_FILES = 512
MAX_SEARCH_BYTES = 8 * 1024 * 1024
MAX_SEARCH_MATCHES = 100
MAX_SEARCH_QUERY_CHARS = 256
MAX_PATCH_CHARS = 128 * 1024
MAX_PATCH_FILES = 16
MAX_PATCH_HUNKS = 64
MAX_PATCH_SOURCE_BYTES = 2 * 1024 * 1024
MAX_COMMAND_ARGS = 128
MAX_COMMAND_ARG_CHARS = 2_048
MAX_COMMAND_TOTAL_CHARS = 16_384
MAX_COMMAND_TIMEOUT_SECONDS = 120
MAX_COMMAND_OUTPUT_BYTES = 12_000

IGNORED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)
ANSWER_DIRECTORY_NAMES = frozenset(
    {"expected", "solution", "solutions", "verifier"}
)
ANSWER_PREFIXES = ("expected", "solution", "verifier")
SAFE_PYTHON_MODULES = frozenset(
    {"compileall", "py_compile", "pytest", "unittest"}
)
SAFE_DIRECT_COMMANDS = frozenset(
    {
        "pytest",
        "py.test",
        "cargo",
        "go",
        "gradle",
        "gradlew",
        "make",
        "mvn",
        "node",
        "npm",
    }
)
SAFE_BUILD_TASKS = frozenset({"check", "lint", "test", "tests", "verify"})
SENSITIVE_ENV_RE = re.compile(
    r"(?:API[_-]?KEY|TOKEN|CREDENTIAL|PASSWORD|PRIVATE[_-]?KEY|SECRET)",
    re.IGNORECASE,
)
CONTROL_ENV_NAMES = frozenset(
    {
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_CONFIG_COUNT",
        "NODE_OPTIONS",
        "PYTHONHOME",
        "PYTHONPATH",
        "PYTEST_ADDOPTS",
        "PYTEST_PLUGINS",
        "RUSTC_WRAPPER",
    }
)
DRIVE_PATH_RE = re.compile(r"^[A-Za-z]:[/\\]")
HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$"
)


class WorkspaceError(RuntimeError):
    """Raised when a workspace operation is invalid, unsafe or too large."""


@dataclass(frozen=True)
class PatchHunk:
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    lines: tuple[str, ...]


@dataclass(frozen=True)
class FilePatch:
    path: str
    hunks: tuple[PatchHunk, ...]


def _integer(
    value: object,
    name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise WorkspaceError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise WorkspaceError(f"{name} must be between {minimum} and {maximum}")
    return value


def _raw_parts(raw_path: str) -> tuple[str, ...]:
    normalized = raw_path.replace("\\", "/")
    if normalized.startswith("/"):
        return PurePosixPath(normalized).parts
    return PurePosixPath(normalized).parts


def answer_path(path: str | Path) -> bool:
    parts = tuple(part.lower() for part in _raw_parts(str(path)))
    if any(part in ANSWER_DIRECTORY_NAMES for part in parts):
        return True
    return bool(parts and parts[-1].startswith(ANSWER_PREFIXES))


def _lexical_candidate(workdir: Path, raw_path: str) -> Path:
    normalized = raw_path.replace("\\", "/")
    posix = PurePosixPath(normalized)
    if (
        normalized.startswith("/")
        and len(posix.parts) >= 2
        and posix.parts[1].lower() == "app"
    ):
        return workdir.joinpath(*posix.parts[2:])
    requested = Path(normalized)
    return requested if requested.is_absolute() else workdir / requested


def _contains_symlink(candidate: Path, workdir: Path) -> bool:
    root = canonical_path(workdir)
    current = candidate
    while path_is_within(current, root):
        junction_check = getattr(current, "is_junction", None)
        if current.is_symlink() or (
            junction_check is not None and junction_check()
        ):
            return True
        # On Windows the same directory can be written as a long path or as an
        # 8.3 alias (for example ``User Name`` and ``US781A~1``).  Lexical Path
        # equality would never reach the boundary in that case and used to
        # report a false symlink.  Compare canonical identities while keeping
        # the lexical path for the link/junction checks above.
        if canonical_path(current) == root:
            return False
        parent = current.parent
        if parent == current:
            break
        current = parent
    return True


def resolve_workspace_path(
    workdir: Path | str,
    raw_path: object,
    *,
    must_exist: bool = True,
    for_write: bool = False,
) -> Path:
    root = canonical_path(workdir)
    if not isinstance(raw_path, str) or not raw_path.strip() or "\x00" in raw_path:
        raise WorkspaceError("path must be non-empty text without NUL")
    if answer_path(raw_path):
        raise WorkspaceError(f"access to answer/verifier path is forbidden: {raw_path}")
    try:
        resolved = map_instruction_path(raw_path, root)
    except ContractError as error:
        raise WorkspaceError(str(error)) from error
    if not path_is_within(resolved, root):
        raise WorkspaceError(f"path is outside workdir: {raw_path}")
    relative = resolved.relative_to(root).as_posix()
    if answer_path(relative):
        raise WorkspaceError(f"access to answer/verifier path is forbidden: {relative}")
    if for_write:
        lexical = _lexical_candidate(root, raw_path)
        if _contains_symlink(lexical, root):
            raise WorkspaceError(f"refusing write through symlink: {raw_path}")
        if protected_path(relative):
            raise WorkspaceError(f"refusing protected write path: {relative}")
        if dependency_path(relative):
            raise WorkspaceError(f"refusing dependency write path: {relative}")
    if must_exist and not resolved.exists():
        raise WorkspaceError(f"path does not exist: {raw_path}")
    return resolved


def _walk_files(root: Path, target: Path, max_depth: int) -> Iterable[Path]:
    if target.is_file():
        yield target
        return
    for current, directories, filenames in os.walk(target, followlinks=False):
        current_path = Path(current)
        relative_current = current_path.relative_to(target)
        depth = 0 if relative_current == Path(".") else len(relative_current.parts)
        directories[:] = sorted(
            name
            for name in directories
            if name not in IGNORED_DIRECTORY_NAMES
            and not answer_path(current_path.relative_to(root) / name)
            and not (current_path / name).is_symlink()
            and depth < max_depth
        )
        for name in sorted(filenames):
            path = current_path / name
            relative = path.relative_to(root)
            if path.is_symlink() or answer_path(relative):
                continue
            yield path


def list_workspace_files(
    workdir: Path | str,
    *,
    path: object = ".",
    max_depth: object = 6,
    max_entries: object = 200,
) -> dict[str, Any]:
    root = canonical_path(workdir)
    depth = _integer(max_depth, "max_depth", minimum=0, maximum=MAX_LIST_DEPTH)
    limit = _integer(max_entries, "max_entries", minimum=1, maximum=MAX_LIST_ENTRIES)
    target = resolve_workspace_path(root, path)
    if not target.is_dir() and not target.is_file():
        raise WorkspaceError(f"list target is not a file or directory: {path}")
    entries: list[dict[str, Any]] = []
    truncated = False
    for candidate in _walk_files(root, target, depth):
        if len(entries) >= limit:
            truncated = True
            break
        try:
            size = candidate.stat().st_size
        except OSError as error:
            raise WorkspaceError(f"cannot stat {candidate}: {error}") from error
        entries.append(
            {
                "path": candidate.relative_to(root).as_posix(),
                "size_bytes": size,
            }
        )
    return {"entries": entries, "count": len(entries), "truncated": truncated}


def _read_regular_bytes(workdir: Path, raw_path: object) -> tuple[Path, bytes]:
    path = resolve_workspace_path(workdir, raw_path)
    if path.is_symlink() or not path.is_file():
        raise WorkspaceError(f"path is not a regular file: {raw_path}")
    try:
        size = path.stat().st_size
        if size > MAX_TEXT_FILE_BYTES:
            raise WorkspaceError(
                f"file exceeds {MAX_TEXT_FILE_BYTES} byte inspection limit: {raw_path}"
            )
        return path, path.read_bytes()
    except OSError as error:
        raise WorkspaceError(f"cannot read {raw_path}: {error}") from error


def read_workspace_text(
    workdir: Path | str,
    *,
    path: object,
    start_line: object = 1,
    max_lines: object = 200,
) -> dict[str, Any]:
    root = canonical_path(workdir)
    first = _integer(start_line, "start_line", minimum=1, maximum=10_000_000)
    line_limit = _integer(max_lines, "max_lines", minimum=1, maximum=MAX_TEXT_LINES)
    resolved, raw = _read_regular_bytes(root, path)
    if b"\x00" in raw:
        raise WorkspaceError("file appears binary; use read_bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise WorkspaceError("file is not valid UTF-8; use read_bytes") from error
    lines = text.splitlines()
    selected = lines[first - 1 : first - 1 + line_limit]
    content = "\n".join(selected)
    char_truncated = len(content) > MAX_TEXT_CHARS
    if char_truncated:
        content = content[:MAX_TEXT_CHARS]
    end_line = first + len(selected) - 1 if selected else first - 1
    return {
        "path": resolved.relative_to(root).as_posix(),
        "start_line": first,
        "end_line": end_line,
        "total_lines": len(lines),
        "content": content,
        "truncated": first - 1 + len(selected) < len(lines) or char_truncated,
    }


def read_workspace_bytes(
    workdir: Path | str,
    *,
    path: object,
    offset: object = 0,
    length: object = 256,
) -> dict[str, Any]:
    root = canonical_path(workdir)
    start = _integer(offset, "offset", minimum=0, maximum=MAX_TEXT_FILE_BYTES)
    count = _integer(length, "length", minimum=1, maximum=MAX_BINARY_BYTES)
    resolved, raw = _read_regular_bytes(root, path)
    selected = raw[start : start + count]
    return {
        "path": resolved.relative_to(root).as_posix(),
        "offset": start,
        "bytes_read": len(selected),
        "total_bytes": len(raw),
        "hex": selected.hex(" "),
        "ascii": "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in selected),
        "truncated": start + len(selected) < len(raw),
    }


def search_workspace_text(
    workdir: Path | str,
    *,
    query: object,
    path: object = ".",
    glob: object = "*",
    case_sensitive: object = False,
) -> dict[str, Any]:
    root = canonical_path(workdir)
    target = resolve_workspace_path(root, path)
    if not isinstance(query, str) or not query or len(query) > MAX_SEARCH_QUERY_CHARS:
        raise WorkspaceError(
            f"query must be 1..{MAX_SEARCH_QUERY_CHARS} characters of text"
        )
    if not isinstance(glob, str) or not glob or len(glob) > 128:
        raise WorkspaceError("glob must be 1..128 characters of text")
    if Path(glob).is_absolute() or ".." in PurePosixPath(glob.replace("\\", "/")).parts:
        raise WorkspaceError("glob must not be absolute or contain '..'")
    if not isinstance(case_sensitive, bool):
        raise WorkspaceError("case_sensitive must be a boolean")

    needle = query if case_sensitive else query.casefold()
    matches: list[dict[str, Any]] = []
    files_scanned = 0
    bytes_scanned = 0
    truncated = False
    for candidate in _walk_files(root, target, MAX_LIST_DEPTH):
        relative = candidate.relative_to(root).as_posix()
        if not fnmatch.fnmatch(relative, glob) and not fnmatch.fnmatch(candidate.name, glob):
            continue
        if files_scanned >= MAX_SEARCH_FILES:
            truncated = True
            break
        files_scanned += 1
        try:
            size = candidate.stat().st_size
            if size > MAX_TEXT_FILE_BYTES or bytes_scanned + size > MAX_SEARCH_BYTES:
                truncated = True
                continue
            raw = candidate.read_bytes()
        except OSError as error:
            raise WorkspaceError(f"cannot search {relative}: {error}") from error
        bytes_scanned += len(raw)
        if b"\x00" in raw:
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(text.splitlines(), 1):
            haystack = line if case_sensitive else line.casefold()
            if needle not in haystack:
                continue
            matches.append(
                {
                    "path": relative,
                    "line": line_number,
                    "text": line[:300],
                }
            )
            if len(matches) >= MAX_SEARCH_MATCHES:
                truncated = True
                break
        if len(matches) >= MAX_SEARCH_MATCHES:
            break
    return {
        "query": query,
        "matches": matches,
        "match_count": len(matches),
        "files_scanned": files_scanned,
        "bytes_scanned": bytes_scanned,
        "truncated": truncated,
    }


def _clean_patch_path(header: str, prefix: str) -> str:
    if not header.startswith(prefix):
        raise WorkspaceError(f"expected {prefix.strip()} patch header")
    path = header[len(prefix) :]
    if "\t" in path:
        path = path.split("\t", 1)[0]
    if path in {"/dev/null", "dev/null"}:
        raise WorkspaceError("creating or deleting files via patch is not supported")
    if path.startswith(("a/", "b/")):
        path = path[2:]
    normalized = path.replace("\\", "/")
    parts = PurePosixPath(normalized).parts
    if (
        not normalized
        or normalized.startswith("/")
        or DRIVE_PATH_RE.match(normalized)
        or ".." in parts
    ):
        raise WorkspaceError(f"unsafe patch path: {path}")
    return normalized


def parse_unified_patch(patch_text: object) -> tuple[FilePatch, ...]:
    if not isinstance(patch_text, str) or not patch_text.strip():
        raise WorkspaceError("patch must be non-empty text")
    if len(patch_text) > MAX_PATCH_CHARS or "\x00" in patch_text:
        raise WorkspaceError(f"patch exceeds {MAX_PATCH_CHARS} characters or contains NUL")
    lines = patch_text.replace("\r\n", "\n").split("\n")
    index = 0
    patches: list[FilePatch] = []
    total_hunks = 0
    while index < len(lines):
        line = lines[index]
        if not line:
            index += 1
            continue
        if line.startswith(("diff --git ", "index ")):
            index += 1
            continue
        if line.startswith(("new file mode ", "deleted file mode ", "rename ", "Binary files ")):
            raise WorkspaceError("file creation, deletion, rename and binary patch are forbidden")
        old_path = _clean_patch_path(line, "--- ")
        index += 1
        if index >= len(lines):
            raise WorkspaceError("patch is missing +++ header")
        new_path = _clean_patch_path(lines[index], "+++ ")
        if new_path != old_path:
            raise WorkspaceError("patch rename is forbidden")
        index += 1
        hunks: list[PatchHunk] = []
        while index < len(lines) and lines[index].startswith("@@ "):
            match = HUNK_RE.fullmatch(lines[index])
            if match is None:
                raise WorkspaceError(f"invalid hunk header: {lines[index]}")
            old_start = int(match.group(1))
            old_count = int(match.group(2) or "1")
            new_start = int(match.group(3))
            new_count = int(match.group(4) or "1")
            index += 1
            body: list[str] = []
            seen_old = 0
            seen_new = 0
            while seen_old < old_count or seen_new < new_count:
                if index >= len(lines):
                    raise WorkspaceError("patch hunk ended before declared line counts")
                body_line = lines[index]
                if not body_line and index == len(lines) - 1:
                    raise WorkspaceError("patch hunk ended before declared line counts")
                if not body_line or body_line[0] not in {" ", "+", "-"}:
                    raise WorkspaceError(f"invalid patch body line: {body_line!r}")
                prefix = body_line[0]
                if prefix in {" ", "-"}:
                    seen_old += 1
                if prefix in {" ", "+"}:
                    seen_new += 1
                if seen_old > old_count or seen_new > new_count:
                    raise WorkspaceError("patch hunk line counts do not match header")
                body.append(body_line)
                index += 1
            if index < len(lines) and lines[index] == r"\ No newline at end of file":
                raise WorkspaceError("no-newline patch markers are not supported")
            hunks.append(PatchHunk(old_start, old_count, new_start, new_count, tuple(body)))
            total_hunks += 1
            if total_hunks > MAX_PATCH_HUNKS:
                raise WorkspaceError(f"patch exceeds {MAX_PATCH_HUNKS} hunks")
        if not hunks:
            raise WorkspaceError(f"patch for {old_path} contains no hunks")
        patches.append(FilePatch(old_path, tuple(hunks)))
        if len(patches) > MAX_PATCH_FILES:
            raise WorkspaceError(f"patch exceeds {MAX_PATCH_FILES} files")
    if not patches:
        raise WorkspaceError("patch contains no file changes")
    paths = [patch.path for patch in patches]
    if len(paths) != len(set(paths)):
        raise WorkspaceError("a file may appear only once in a patch")
    return tuple(patches)


def _apply_hunks(source: str, patch: FilePatch) -> str:
    if "\r" in source.replace("\r\n", ""):
        raise WorkspaceError(f"unsupported bare CR line ending in {patch.path}")
    newline = "\r\n" if "\r\n" in source else "\n"
    normalized = source.replace("\r\n", "\n")
    final_newline = normalized.endswith("\n")
    source_lines = normalized.splitlines()
    output: list[str] = []
    cursor = 0
    for hunk in patch.hunks:
        old_index = hunk.old_start if hunk.old_count == 0 else hunk.old_start - 1
        if old_index < cursor or old_index > len(source_lines):
            raise WorkspaceError(f"overlapping or out-of-range hunk in {patch.path}")
        output.extend(source_lines[cursor:old_index])
        cursor = old_index
        for patch_line in hunk.lines:
            prefix, value = patch_line[0], patch_line[1:]
            if prefix in {" ", "-"}:
                if cursor >= len(source_lines) or source_lines[cursor] != value:
                    raise WorkspaceError(
                        f"patch context mismatch in {patch.path} at source line {cursor + 1}"
                    )
                if prefix == " ":
                    output.append(value)
                cursor += 1
            else:
                output.append(value)
    output.extend(source_lines[cursor:])
    rendered = newline.join(output)
    if final_newline:
        rendered += newline
    return rendered


def apply_workspace_patch(workdir: Path | str, *, patch: object) -> dict[str, Any]:
    root = canonical_path(workdir)
    file_patches = parse_unified_patch(patch)
    prepared: list[tuple[Path, bytes, int, int]] = []
    total_hunks = 0
    for file_patch in file_patches:
        path = resolve_workspace_path(root, file_patch.path, for_write=True)
        if path.is_symlink() or not path.is_file():
            raise WorkspaceError(f"patch target is not a regular file: {file_patch.path}")
        raw = path.read_bytes()
        if len(raw) > MAX_PATCH_SOURCE_BYTES:
            raise WorkspaceError(
                f"patch target exceeds {MAX_PATCH_SOURCE_BYTES} bytes: {file_patch.path}"
            )
        try:
            source = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise WorkspaceError(f"patch target is not UTF-8: {file_patch.path}") from error
        updated = _apply_hunks(source, file_patch)
        if updated == source:
            raise WorkspaceError(f"patch makes no change: {file_patch.path}")
        prepared.append(
            (path, updated.encode("utf-8"), stat.S_IMODE(path.stat().st_mode), len(file_patch.hunks))
        )
        total_hunks += len(file_patch.hunks)

    temporary_paths: list[tuple[Path, Path]] = []
    try:
        for target, content, mode, _ in prepared:
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=".agent-patch-", dir=target.parent, delete=False
            ) as handle:
                handle.write(content)
                temporary = Path(handle.name)
            os.chmod(temporary, mode)
            temporary_paths.append((target, temporary))
        for target, temporary in temporary_paths:
            os.replace(temporary, target)
    finally:
        for _, temporary in temporary_paths:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
    return {
        "changed_paths": [path.relative_to(root).as_posix() for path, _, _, _ in prepared],
        "file_count": len(prepared),
        "hunk_count": total_hunks,
    }


def _safe_command_profile(argv: tuple[str, ...]) -> str:
    executable = Path(argv[0]).name.lower()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    arguments = argv[1:]
    if executable in {"python", "python3", "py", "pypy3"}:
        if len(arguments) < 2 or arguments[0] != "-m" or arguments[1] not in SAFE_PYTHON_MODULES:
            raise WorkspaceError(
                "Python process is limited to -m pytest/unittest/compileall/py_compile"
            )
        module = arguments[1]
        if module == "unittest":
            positional = [
                argument
                for argument in arguments[2:]
                if not argument.startswith("-")
                and argument not in {"discover", "."}
                and "/" not in argument.replace("\\", "/")
            ]
            if any(
                not argument.startswith("test") and not argument.startswith("tests.")
                for argument in positional
            ):
                raise WorkspaceError("unittest is limited to test modules or discovery")
        return f"python-module:{module}"
    if executable in {"pytest", "py.test"}:
        return "pytest"
    if executable == "git":
        if not arguments or arguments[0] not in {"diff", "status"}:
            raise WorkspaceError("git process is limited to diff and status")
        forbidden_git = {"--ext-diff", "--no-index", "--output", "--textconv"}
        if any(arg.split("=", 1)[0] in forbidden_git for arg in arguments[1:]):
            raise WorkspaceError("unsafe git diff option is forbidden")
        return f"git:{arguments[0]}"
    if executable not in SAFE_DIRECT_COMMANDS:
        raise WorkspaceError(f"command is not in the safe process allowlist: {executable}")
    if executable == "node" and (not arguments or arguments[0] != "--test"):
        raise WorkspaceError("node process is limited to --test")
    if executable == "npm" and (not arguments or arguments[0] not in {"test", "run"}):
        raise WorkspaceError("npm process is limited to test or run")
    if executable == "npm" and arguments[0] == "run":
        if len(arguments) < 2 or arguments[1] not in SAFE_BUILD_TASKS:
            raise WorkspaceError("npm run is limited to check/lint/test/verify scripts")
    if executable == "cargo" and (not arguments or arguments[0] not in {"check", "test"}):
        raise WorkspaceError("cargo process is limited to check or test")
    if executable == "go" and (not arguments or arguments[0] not in {"test", "vet"}):
        raise WorkspaceError("go process is limited to test or vet")
    if executable in {"gradle", "gradlew", "make", "mvn"}:
        tasks = [argument for argument in arguments if not argument.startswith("-")]
        if not tasks or any(task not in SAFE_BUILD_TASKS for task in tasks):
            raise WorkspaceError(
                f"{executable} is limited to check/lint/test/tests/verify tasks"
            )
    return f"project-check:{executable}"


def _validate_command_arguments(argv: object, workdir: Path) -> tuple[str, ...]:
    if not isinstance(argv, list) or not argv or len(argv) > MAX_COMMAND_ARGS:
        raise WorkspaceError(f"argv must be a non-empty array of at most {MAX_COMMAND_ARGS} strings")
    if any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv):
        raise WorkspaceError("every argv item must be non-empty text without NUL")
    typed = tuple(argv)
    if any(len(arg) > MAX_COMMAND_ARG_CHARS for arg in typed):
        raise WorkspaceError(f"an argv item exceeds {MAX_COMMAND_ARG_CHARS} characters")
    if sum(len(arg) for arg in typed) > MAX_COMMAND_TOTAL_CHARS:
        raise WorkspaceError(f"argv exceeds {MAX_COMMAND_TOTAL_CHARS} total characters")
    executable_text = typed[0].replace("\\", "/")
    if ".." in PurePosixPath(executable_text).parts:
        raise WorkspaceError("command executable must not escape workdir with '..'")
    if "/" in executable_text or DRIVE_PATH_RE.match(executable_text):
        executable = canonical_path(typed[0])
        system_python = canonical_path(sys.executable)
        if executable != system_python and not path_is_within(executable, workdir):
            raise WorkspaceError("absolute command executable is outside the allowlist")
    forbidden_pytest = {"--basetemp", "--junit-xml", "--junitxml", "--pyargs"}
    normalized_arguments = list(typed)
    for argument_index, argument in enumerate(typed[1:], 1):
        option = argument.split("=", 1)[0]
        if option in forbidden_pytest:
            raise WorkspaceError(f"unsafe test-runner output option is forbidden: {option}")
        value = argument.split("=", 1)[1] if "=" in argument else argument
        normalized = value.replace("\\", "/")
        value_path = workdir / Path(normalized)
        if answer_path(value) and (
            "/" in normalized
            or normalized.lower() in ANSWER_DIRECTORY_NAMES
            or value_path.exists()
        ):
            raise WorkspaceError(f"command access to answer/verifier path is forbidden: {value}")
        if ".." in PurePosixPath(normalized).parts:
            raise WorkspaceError("command arguments must not escape workdir with '..'")
        if normalized.startswith("/") or DRIVE_PATH_RE.match(normalized):
            try:
                resolved = map_instruction_path(value, workdir)
            except ContractError as error:
                raise WorkspaceError(f"absolute command path is outside workdir: {value}") from error
            if not path_is_within(resolved, workdir):
                raise WorkspaceError(f"absolute command path is outside workdir: {value}")
            if normalized == "/app" or normalized.startswith("/app/"):
                replacement = str(resolved)
                normalized_arguments[argument_index] = (
                    f"{argument.split('=', 1)[0]}={replacement}"
                    if "=" in argument
                    else replacement
                )
    return tuple(normalized_arguments)


def _child_environment() -> dict[str, str]:
    return {
        key: value
        for key, value in os.environ.items()
        if not SENSITIVE_ENV_RE.search(key)
        and key.upper() not in CONTROL_ENV_NAMES
        and key not in {"OPENAI_API_KEY", "OPENAI_BASE_URL", "LOCAL_AGENT_MODEL"}
    }


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except (OSError, ProcessLookupError):
        process.kill()


def run_workspace_command(
    workdir: Path | str,
    *,
    argv: object,
    cwd: object = ".",
    timeout_seconds: object = 60,
) -> dict[str, Any]:
    root = canonical_path(workdir)
    command = _validate_command_arguments(argv, root)
    profile = _safe_command_profile(command)
    if profile == "git:diff":
        command = (
            command[0],
            "-c",
            "core.fsmonitor=false",
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            *command[2:],
        )
    elif profile == "git:status":
        command = (
            command[0],
            "-c",
            "core.fsmonitor=false",
            "status",
            *command[2:],
        )
    command_cwd = resolve_workspace_path(root, cwd)
    if not command_cwd.is_dir():
        raise WorkspaceError(f"command cwd is not a directory: {cwd}")
    timeout = _integer(
        timeout_seconds,
        "timeout_seconds",
        minimum=1,
        maximum=MAX_COMMAND_TIMEOUT_SECONDS,
    )

    popen_options: dict[str, Any] = {}
    if os.name == "posix":
        popen_options["start_new_session"] = True
    elif os.name == "nt":
        popen_options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            command,
            cwd=command_cwd,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_child_environment(),
            shell=False,
            **popen_options,
        )
    except OSError as error:
        raise WorkspaceError(f"command failed to start: {error}") from error

    captured = bytearray()
    total_output = 0

    def drain_output() -> None:
        nonlocal total_output
        assert process.stdout is not None
        try:
            while chunk := process.stdout.read(4096):
                total_output += len(chunk)
                remaining = MAX_COMMAND_OUTPUT_BYTES - len(captured)
                if remaining > 0:
                    captured.extend(chunk[:remaining])
        except (OSError, ValueError):
            return

    reader = threading.Thread(target=drain_output, daemon=True)
    reader.start()
    timed_out = False
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
        return_code = process.wait(timeout=5)
    finally:
        reader.join(timeout=5)
        if process.stdout is not None:
            process.stdout.close()
    duration_ms = round((time.monotonic() - started) * 1000)
    output = bytes(captured).decode("utf-8", errors="replace")
    return {
        "profile": profile,
        "argv": list(command),
        "exit_code": return_code,
        "timed_out": timed_out,
        "duration_ms": duration_ms,
        "output": output,
        "output_truncated": total_output > len(captured),
        "total_output_bytes": total_output,
    }
