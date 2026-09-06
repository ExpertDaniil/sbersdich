"""Deterministic submission ZIP builder for participant-2 B-16."""

from __future__ import annotations

import hashlib
import os
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable


MAX_SUBMISSION_BYTES = 10 * 1024 * 1024
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".hg",
        ".mypy_cache",
        ".pytest_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "node_modules",
        "tests",
    }
)
EXCLUDED_NAMES = frozenset(
    {
        ".env",
        ".env.local",
        "verify.sh",
        "Thumbs.db",
        ".DS_Store",
    }
)
SENSITIVE_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".kdbx")
ALLOWED_TOP_LEVEL = frozenset({"run.sh", "agent"})


class PackagingError(RuntimeError):
    """Submission would be incomplete, unsafe or outside size limits."""


@dataclass(frozen=True)
class SubmissionBuild:
    path: Path
    file_count: int
    size_bytes: int
    sha256: str
    members: tuple[str, ...]

    def as_payload(self) -> dict[str, object]:
        return {
            "path": str(self.path),
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "members": list(self.members),
        }


def _safe_member(relative: Path) -> bool:
    parts = relative.parts
    if not parts:
        return False
    if parts[0] not in ALLOWED_TOP_LEVEL:
        return False
    if any(part in EXCLUDED_PARTS for part in parts):
        return False
    if relative.name in EXCLUDED_NAMES:
        return False
    lower = relative.name.lower()
    if lower.endswith(SENSITIVE_SUFFIXES) or lower.endswith(".pyc"):
        return False
    return True


def _iter_members(repo_root: Path) -> Iterable[tuple[Path, str]]:
    run_sh = repo_root / "run.sh"
    agent_dir = repo_root / "agent"
    if not run_sh.is_file():
        raise PackagingError("run.sh is missing")
    if not agent_dir.is_dir():
        raise PackagingError("agent package is missing")

    candidates = [run_sh]
    candidates.extend(path for path in agent_dir.rglob("*") if path.is_file())
    for path in sorted(candidates, key=lambda item: item.relative_to(repo_root).as_posix()):
        if path.is_symlink():
            raise PackagingError(f"submission refuses symlink: {path}")
        relative = path.relative_to(repo_root)
        if not _safe_member(relative):
            continue
        member = relative.as_posix()
        normalized = PurePosixPath(member)
        if normalized.is_absolute() or ".." in normalized.parts:
            raise PackagingError(f"unsafe archive member: {member}")
        yield path, member


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(64 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_submission(
    repo_root: Path | str,
    output: Path | str,
    *,
    max_bytes: int = MAX_SUBMISSION_BYTES,
) -> SubmissionBuild:
    root = Path(repo_root).resolve()
    destination = Path(output).resolve()
    if not root.is_dir():
        raise PackagingError(f"repository root does not exist: {root}")
    if max_bytes <= 0:
        raise PackagingError("max_bytes must be positive")
    destination.parent.mkdir(parents=True, exist_ok=True)

    members: list[str] = []
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with zipfile.ZipFile(
            temporary,
            mode="w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        ) as archive:
            for source, member in _iter_members(root):
                data = source.read_bytes()
                info = zipfile.ZipInfo(member, FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                executable = source.name == "run.sh" or bool(source.stat().st_mode & stat.S_IXUSR)
                mode = 0o755 if executable else 0o644
                info.external_attr = (stat.S_IFREG | mode) << 16
                info.create_system = 3
                archive.writestr(info, data)
                members.append(member)
        size = temporary.stat().st_size
        if size > max_bytes:
            raise PackagingError(
                f"submission archive is {size} bytes, limit is {max_bytes} bytes"
            )
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass

    return SubmissionBuild(
        path=destination,
        file_count=len(members),
        size_bytes=destination.stat().st_size,
        sha256=_sha256(destination),
        members=tuple(members),
    )
