"""Bounded loading of repository-owned task playbooks."""

from __future__ import annotations

from pathlib import Path


class PlaybookError(RuntimeError):
    """Raised when a requested playbook is missing or outside the agent tree."""


AGENT_DIR = Path(__file__).resolve().parents[1]
REPO_DIR = AGENT_DIR.parent
MAX_PLAYBOOK_CHARS = 32_000


def load_playbook(relative_path: str) -> str:
    if not relative_path:
        return ""
    requested = Path(relative_path)
    candidate = (
        requested.resolve()
        if requested.is_absolute()
        else (REPO_DIR / requested).resolve()
    )
    try:
        candidate.relative_to(AGENT_DIR)
    except ValueError as error:
        raise PlaybookError(f"playbook escapes agent directory: {relative_path}") from error
    if candidate.suffix.lower() != ".md" or not candidate.is_file():
        raise PlaybookError(f"playbook is missing or unsupported: {relative_path}")
    try:
        text = candidate.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise PlaybookError(f"cannot read playbook {relative_path}: {error}") from error
    if not text.strip():
        raise PlaybookError(f"playbook is empty: {relative_path}")
    if len(text) > MAX_PLAYBOOK_CHARS:
        raise PlaybookError(f"playbook exceeds {MAX_PLAYBOOK_CHARS} characters")
    return text


def load_validation_playbook() -> str:
    return load_playbook("agent/playbooks/validation.md")
