"""Safe write/append primitives missing from the C-10 workspace layer."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from agent.core.workspace import WorkspaceError, resolve_workspace_path

from .contracts import RuntimeLimits


_DEFAULT_LIMITS = RuntimeLimits()


def _validate_content(content: object, limit: int) -> str:
    if not isinstance(content, str):
        raise WorkspaceError("content must be text")
    if "\x00" in content:
        raise WorkspaceError("content must not contain NUL")
    if len(content) > limit:
        raise WorkspaceError(f"content exceeds {limit} characters")
    return content


def _atomic_replace_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o644
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=".agent-write-",
            dir=path.parent,
            delete=False,
        ) as handle:
            handle.write(content)
            temporary = Path(handle.name)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass


def write_workspace_text(
    workdir: Path | str,
    *,
    path: object,
    content: object,
    limits: RuntimeLimits | None = None,
) -> dict[str, Any]:
    """Replace/create one UTF-8 file atomically inside the workspace."""

    active_limits = limits or _DEFAULT_LIMITS
    text = _validate_content(content, active_limits.max_file_write_chars)
    root = Path(workdir).resolve()
    target = resolve_workspace_path(root, path, must_exist=False, for_write=True)
    previous_size = target.stat().st_size if target.exists() else 0
    encoded = text.encode("utf-8")
    if len(encoded) > active_limits.max_written_file_bytes:
        raise WorkspaceError(
            f"written file exceeds {active_limits.max_written_file_bytes} bytes"
        )
    _atomic_replace_text(target, text)
    return {
        "path": target.relative_to(root).as_posix(),
        "operation": "write",
        "characters": len(text),
        "bytes_written": len(encoded),
        "previous_size_bytes": previous_size,
        "final_size_bytes": len(encoded),
    }


def append_workspace_text(
    workdir: Path | str,
    *,
    path: object,
    content: object,
    limits: RuntimeLimits | None = None,
) -> dict[str, Any]:
    """Append text while preserving the same containment and size guarantees."""

    active_limits = limits or _DEFAULT_LIMITS
    text = _validate_content(content, active_limits.max_file_write_chars)
    root = Path(workdir).resolve()
    target = resolve_workspace_path(root, path, must_exist=False, for_write=True)
    previous = ""
    if target.exists():
        if not target.is_file() or target.is_symlink():
            raise WorkspaceError(f"append target is not a regular file: {path}")
        raw = target.read_bytes()
        try:
            previous = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise WorkspaceError("append target is not valid UTF-8") from error
    rendered = previous + text
    encoded = rendered.encode("utf-8")
    if len(encoded) > active_limits.max_written_file_bytes:
        raise WorkspaceError(
            f"appended file exceeds {active_limits.max_written_file_bytes} bytes"
        )
    _atomic_replace_text(target, rendered)
    return {
        "path": target.relative_to(root).as_posix(),
        "operation": "append",
        "characters": len(text),
        "bytes_written": len(text.encode("utf-8")),
        "previous_size_bytes": len(previous.encode("utf-8")),
        "final_size_bytes": len(encoded),
    }
