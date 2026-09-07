"""Derive deterministic validation contracts from task instructions."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from agent.strategies import StrategyDecision
from agent.validators import ArtifactRule, canonical_path, path_is_within

from .models import TaskContract


EXACT_FILE_PATTERNS = (
    re.compile(
        r"create\s+(?:a\s+)?file\s+at\s+[`'\"](?P<path>[^`'\"]+)[`'\"]"
        r".*?content\s+is\s+exactly\s+(?:the\s+single\s+word\s+)?"
        r"[`'\"](?P<value>[^`'\"]*)[`'\"]",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"созда(?:й|йте|ть)\s+файл\s+(?:по\s+пути\s+)?"
        r"[`'\"](?P<path>[^`'\"]+)[`'\"]"
        r".*?(?:содержим(?:ым|ое)|текстом)\s+(?:ровно\s+|точно\s+)?"
        r"[`'\"](?P<value>[^`'\"]*)[`'\"]",
        re.IGNORECASE | re.DOTALL,
    ),
)

CTF_ARTIFACT_PATTERNS = (
    re.compile(
        r"(?:write|save|store|submit|put)\s+(?:(?:the|your)\s+)?"
        r"(?:recovered\s+|decoded\s+)?(?:flag|answer|result|value)"
        r".{0,100}?(?:to|at|in|into)\s+(?:the\s+)?(?:file\s+)?"
        r"[`'\"](?P<path>[^`'\"]+)[`'\"]",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(?:flag|answer|output)\s+(?:file|path)\s*(?::|=|is)\s*"
        r"[`'\"](?P<path>[^`'\"]+)[`'\"]",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"(?:запиши|сохрани|помести|выведи)\w*\s+"
        r"(?:найденн\w*\s+|извлеч[её]нн\w*\s+|декодированн\w*\s+)?"
        r"(?:флаг|ответ|результат)\w*.{0,100}?"
        r"(?:в\s+(?:файл\s+)?|по\s+пути\s+)"
        r"[`'\"](?P<path>[^`'\"]+)[`'\"]",
        re.IGNORECASE | re.DOTALL,
    ),
)


class ContractError(RuntimeError):
    """Raised when an instruction requests an unsafe artifact path."""


def map_instruction_path(raw_path: str, workdir: Path) -> Path:
    """Map the benchmark's /app path to the actual isolated work directory."""

    normalized = raw_path.replace("\\", "/")
    posix_path = PurePosixPath(normalized)
    posix_parts = posix_path.parts
    if (
        normalized.startswith("/")
        and len(posix_parts) >= 2
        and posix_parts[1].lower() == "app"
    ):
        candidate = workdir.joinpath(*posix_parts[2:])
        resolved = canonical_path(candidate)
        if not path_is_within(resolved, workdir):
            raise ContractError(f"artifact path escapes workdir: {raw_path}")
        return resolved

    requested = Path(normalized)
    if requested.is_absolute():
        if path_is_within(requested, workdir):
            candidate = requested
        else:
            raise ContractError(f"artifact path is outside workdir: {raw_path}")
    elif normalized.startswith("/"):
        # Windows treats /path as drive-relative rather than absolute.  It is
        # still an external POSIX path unless it matched virtual /app above.
        raise ContractError(f"artifact path is outside workdir: {raw_path}")
    else:
        candidate = workdir / requested
    resolved = canonical_path(candidate)
    if not path_is_within(resolved, workdir):
        raise ContractError(f"artifact path escapes workdir: {raw_path}")
    return resolved


def exact_file_requests(instruction: str, workdir: Path) -> tuple[tuple[Path, str], ...]:
    matches: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    for pattern in EXACT_FILE_PATTERNS:
        for match in pattern.finditer(instruction):
            path = map_instruction_path(match.group("path"), workdir)
            if path in seen:
                continue
            seen.add(path)
            matches.append((path, match.group("value")))
    return tuple(matches)


def ctf_artifact_requests(instruction: str, workdir: Path) -> tuple[Path, ...]:
    """Extract CTF answer paths without guessing an implicit filename."""

    matches: list[Path] = []
    seen: set[Path] = set()
    for pattern in CTF_ARTIFACT_PATTERNS:
        for match in pattern.finditer(instruction):
            path = map_instruction_path(match.group("path"), workdir)
            if path in seen:
                continue
            seen.add(path)
            matches.append(path)
    return tuple(matches)


def build_task_contract(
    decision: StrategyDecision, instruction: str, workdir: Path
) -> TaskContract:
    root = canonical_path(workdir)
    if decision.mode == "audit":
        return TaskContract(
            artifacts=(ArtifactRule("security-report", root / "security_report.json"),)
        )
    if decision.mode == "forensics":
        return TaskContract(
            artifacts=(ArtifactRule("incident-report", root / "incident_report.txt"),)
        )
    if decision.mode == "ctf":
        return TaskContract(
            artifacts=tuple(
                ArtifactRule("text", path)
                for path in ctf_artifact_requests(instruction, root)
            )
        )
    exact_writes = exact_file_requests(instruction, root)
    return TaskContract(
        artifacts=tuple(
            ArtifactRule("exact-text", path, expected_text=value)
            for path, value in exact_writes
        ),
        exact_writes=exact_writes,
    )
