"""Deterministic submission ZIP builder for the experimental scaffold."""

from __future__ import annotations

import hashlib
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


MAX_SUBMISSION_BYTES = 10 * 1024 * 1024
FIXED_ZIP_TIME = (2024, 1, 1, 0, 0, 0)
EXCLUDED_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        "node_modules",
        "tests",
    }
)
SECRET_SUFFIXES = frozenset({".pem", ".key", ".p12", ".pfx"})
SECRET_NAMES = frozenset({".env", ".env.local", "credentials.json", "secrets.json"})


@dataclass(frozen=True)
class BuildResult:
    output: Path
    sha256: str
    size_bytes: int
    members: tuple[str, ...]

    def as_payload(self) -> dict[str, object]:
        return {
            "output": str(self.output),
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
            "members": list(self.members),
        }


def _allowed(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if path.name in SECRET_NAMES or path.suffix.lower() in SECRET_SUFFIXES:
        return False
    return path.is_file() and not path.is_symlink()


def _agent_files(repo_root: Path) -> Iterable[tuple[Path, str]]:
    agent_root = repo_root / "agent"
    for path in sorted(agent_root.rglob("*")):
        if _allowed(path, repo_root):
            yield path, path.relative_to(repo_root).as_posix()


def _zip_info(name: str, executable: bool) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    info.compress_type = zipfile.ZIP_DEFLATED
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.create_system = 3
    return info


def build_submission(repo_root: Path, output: Path) -> BuildResult:
    repo_root = repo_root.resolve()
    launcher = repo_root / "run_scaffold.sh"
    if not launcher.is_file():
        raise ValueError("run_scaffold.sh is missing")
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)

    entries: list[tuple[str, bytes, bool]] = [
        ("run.sh", launcher.read_bytes(), True),
    ]
    entries.extend(
        (member, path.read_bytes(), bool(path.stat().st_mode & stat.S_IXUSR))
        for path, member in _agent_files(repo_root)
    )
    names = [name for name, _, _ in entries]
    if len(names) != len(set(names)):
        raise ValueError("duplicate submission member")

    with zipfile.ZipFile(output, "w") as archive:
        for name, content, executable in entries:
            archive.writestr(_zip_info(name, executable), content)

    size = output.stat().st_size
    if size > MAX_SUBMISSION_BYTES:
        output.unlink(missing_ok=True)
        raise ValueError(f"submission exceeds {MAX_SUBMISSION_BYTES} bytes")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    return BuildResult(output, digest, size, tuple(names))
