"""Derive deterministic validation contracts from task instructions."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from agent.strategies import StrategyDecision
from agent.validators import ArtifactRule, canonical_path, path_is_within

from .models import TaskContract
from .project_checks import discover_project_checks


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
        r"(?:write|save|store|submit|put)\s+(?:(?:only|the|your|complete|recovered|decoded|exact)\s+)*"
        r"(?:flag|answer|result|value)"
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


# Anchor paths to an output directive, never an arbitrary input/evidence mention.
REPORT_PATH_PATTERN = re.compile(
    r"\b(?:write|produce|save|store|create|generate|output|submit)\b"
    r"[^.\n`\"']{0,140}[`\"'](?P<path>[^`\"'\n]+\.(?:json|txt|md))[`\"']"
    r"|\b(?:report|output|deliverable)\s+(?:file|path)\s*(?::|=|is)\s*"
    r"[`\"'](?P<label_path>[^`\"'\n]+\.(?:json|txt|md))[`\"']",
    re.IGNORECASE,
)


def report_artifact_requests(instruction: str, workdir: Path) -> tuple[Path, ...]:
    return tuple(dict.fromkeys(
        map_instruction_path(match.group("path") or match.group("label_path"), workdir)
        for match in REPORT_PATH_PATTERN.finditer(instruction)
        if not re.search(r"(?:do not|don't|never|must not|avoid)\s*$",
                         instruction[max(0, match.start() - 32):match.start()], re.IGNORECASE)
    ))


def build_task_contract(
    decision: StrategyDecision, instruction: str, workdir: Path
) -> TaskContract:
    root = canonical_path(workdir)
    if decision.mode in {"audit", "forensics"}:
        paths = report_artifact_requests(instruction, root)
        if not paths:
            default = "security_report.json" if decision.mode == "audit" else "incident_report.txt"
            paths = (root / default,)
        keys_match = re.search(
            r"\bexactly\s+(?:these|the following)\s+keys\s*:\s*([^\n]*(?:\n[^\n]+)?)",
            instruction, re.IGNORECASE,
        )
        keys = tuple(re.findall(r"[`\"']([A-Za-z_][A-Za-z_0-9]*)[`\"']", keys_match[1])) if keys_match else ()
        nonempty = bool(re.search(
            r"non[- ]empty\s+[`\"']?findings|findings[`\"']?\s+(?:array\s+)?must\s+not\s+be\s+empty",
            instruction, re.IGNORECASE,
        ))
        return TaskContract(artifacts=tuple(
            ArtifactRule(
                "security-report" if decision.mode == "audit" and path.suffix.lower() == ".json"
                else "json" if path.suffix.lower() == ".json"
                else "incident-report" if path.name == "incident_report.txt" else "text",
                path, required_keys=keys, nonempty_findings=nonempty,
            ) for path in paths
        ))
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
        project_checks=(discover_project_checks(instruction, root) if decision.mode == "fix" else None),
    )
