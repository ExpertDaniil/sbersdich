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


def _quoted_identifiers(text: str) -> tuple[str, ...]:
    return tuple(dict.fromkeys(re.findall(r"[`\"']([A-Za-z_][A-Za-z_0-9]*)[`\"']", text)))


def _declared_top_level_keys(instruction: str) -> tuple[str, ...]:
    patterns = (
        r"exactly\s+one\s+top[- ]level\s+key\s+([^.]+)",
        r"exactly\s+(?:these|the following)\s+(?:top[- ]level\s+)?keys\s*:\s*([^.]+)",
        r"(?:top[- ]level|JSON object)\s+(?:must\s+)?contain\s+exactly\s+([^.]+)",
    )
    for pattern in patterns:
        match = re.search(pattern, instruction, re.IGNORECASE)
        if match:
            keys = _quoted_identifiers(match.group(1))
            if keys:
                return keys
    return ()


def _declared_item_keys(instruction: str) -> tuple[str, ...]:
    match = re.search(
        r"(?:every|each)\s+(?:array\s+)?(?:item|finding|entry|object)\s+"
        r"must\s+contain\s+exactly\s+([^.]+)",
        instruction,
        re.IGNORECASE,
    )
    return _quoted_identifiers(match.group(1)) if match else ()


def _declared_array_key(instruction: str, top_keys: tuple[str, ...]) -> str | None:
    for key in top_keys:
        if re.search(
            rf"[`\"']?{re.escape(key)}[`\"']?\s+must\s+be\s+(?:a\s+)?(?:non[- ]empty\s+)?array",
            instruction,
            re.IGNORECASE,
        ):
            return key
    if len(top_keys) == 1 and re.search(
        r"(?:every|each)\s+(?:array\s+)?(?:item|finding|entry|object)",
        instruction,
        re.IGNORECASE,
    ):
        return top_keys[0]
    return None


def _artifact_rule_for_report(
    *, decision: StrategyDecision, path: Path, instruction: str
) -> ArtifactRule:
    top_keys = _declared_top_level_keys(instruction)
    item_keys = _declared_item_keys(instruction)
    array_key = _declared_array_key(instruction, top_keys) if item_keys else None
    integer_keys: tuple[str, ...] = ()
    if "line" in item_keys and re.search(
        r"(?:a\s+)?positive\s+integer(?:\s+source)?\s+line|line\s+(?:must\s+be\s+)?(?:a\s+)?positive\s+integer",
        instruction,
        re.IGNORECASE,
    ):
        integer_keys = ("line",)
    string_keys = tuple(key for key in item_keys if key not in integer_keys)

    item_enums: list[tuple[str, tuple[str, ...]]] = []
    if "severity" in item_keys:
        severity_match = re.search(
            r"(?:use\s+)?lowercase\s+(.{0,160}?)\s+for\s+severity",
            instruction,
            re.IGNORECASE | re.DOTALL,
        )
        severity_values = _quoted_identifiers(severity_match.group(1)) if severity_match else ()
        if severity_values:
            item_enums.append(("severity", severity_values))

    item_patterns: list[tuple[str, str]] = []
    if "cwe" in item_keys and re.search(r"canonical\s+[`\"']?CWE-NNN", instruction, re.IGNORECASE):
        item_patterns.append(("cwe", r"CWE-[1-9][0-9]{1,4}"))
    if "file" in item_keys and re.search(
        r"(?:[`\"']?/app[`\"']?[- ]relative|workspace[- ]relative)\s+source\s+path",
        instruction,
        re.IGNORECASE,
    ):
        item_patterns.append(("file", r"(?!/)(?!.*(?:^|/)\.\.(?:/|$)).+"))

    nonempty = bool(re.search(
        r"non[- ]empty\s+[`\"']?findings|"
        r"findings[`\"']?\s+must\s+be\s+(?:a\s+)?non[- ]empty\s+array|"
        r"findings[`\"']?\s+(?:array\s+)?must\s+not\s+be\s+empty",
        instruction,
        re.IGNORECASE,
    ))
    kind = (
        "security-report" if decision.mode == "audit" and path.suffix.lower() == ".json"
        else "json" if path.suffix.lower() == ".json"
        else "incident-report" if path.name == "incident_report.txt" else "text"
    )
    return ArtifactRule(
        kind,
        path,
        required_keys=top_keys,
        nonempty_findings=nonempty,
        array_item_key=array_key,
        item_required_keys=item_keys,
        item_integer_keys=integer_keys,
        item_string_keys=string_keys,
        item_enums=tuple(item_enums),
        item_patterns=tuple(item_patterns),
    )


def _fix_security_requirements(instruction: str) -> tuple[str, ...]:
    """Extract only explicit, high-confidence security properties."""

    lowered = instruction.casefold()
    requirements: list[str] = []
    if any(term in lowered for term in ("path traversal", "directory traversal", "sibling-prefix", "sibling prefix")):
        requirements.append("path-containment")
    if "token" in lowered and "plaintext" in lowered and any(
        term in lowered for term in ("reset", "recovery", "store", "storage", "persist")
    ):
        requirements.append("no-plaintext-token-storage")
    if any(term in lowered for term in ("nosql", "operator injection", "mongo")) and any(
        term in lowered for term in ("structured", "object", "mapping", "dictionary", "non-string")
    ):
        requirements.append("reject-structured-credentials")
    if "webhook" in lowered and any(term in lowered for term in ("signature", "hmac")):
        requirements.append("webhook-hmac")
    if "mass assignment" in lowered or "over-posting" in lowered or "overposting" in lowered:
        requirements.append("mass-assignment")
    return tuple(requirements)


def build_task_contract(
    decision: StrategyDecision, instruction: str, workdir: Path
) -> TaskContract:
    root = canonical_path(workdir)
    if decision.mode in {"audit", "forensics"}:
        paths = report_artifact_requests(instruction, root)
        if not paths:
            default = "security_report.json" if decision.mode == "audit" else "incident_report.txt"
            paths = (root / default,)
        return TaskContract(artifacts=tuple(
            _artifact_rule_for_report(decision=decision, path=path, instruction=instruction)
            for path in paths
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
        security_requirements=(
            _fix_security_requirements(instruction) if decision.mode == "fix" else ()
        ),
    )
