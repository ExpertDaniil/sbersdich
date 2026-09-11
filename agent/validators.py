#!/usr/bin/env python3
"""Deterministic task-result validation for every supported agent mode."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

try:
    from .tools.forensics import validate_report_text as validate_incident_report_text
except ImportError:  # Direct execution from the agent directory.
    from tools.forensics import (  # type: ignore
        validate_report_text as validate_incident_report_text,
    )


VALID_MODES = frozenset({"audit", "fix", "forensics", "ctf", "general"})
ARTIFACT_KINDS = frozenset(
    {"file", "text", "exact-text", "json", "security-report", "incident-report"}
)
SECURITY_FINDING_FIELDS = frozenset(
    {"title", "severity", "category", "location", "evidence", "impact", "recommendation"}
)
SECURITY_SEVERITIES = frozenset(
    {"critical", "high", "medium", "low", "informational"}
)
IGNORED_DIRECTORIES = frozenset(
    {".git", ".hg", ".mypy_cache", ".pytest_cache", ".tox", ".venv", "__pycache__", "node_modules"}
)
IGNORED_FILES = frozenset({".coverage"})
PROTECTED_PARTS = frozenset(
    {".git", "solution", "solutions", "verifier", "expected", "test", "tests"}
)
PROTECTED_PREFIXES = ("expected", "solution", "verifier")
DEPENDENCY_FILES = frozenset(
    {
        "composer.json",
        "composer.lock",
        "cargo.lock",
        "cargo.toml",
        "gemfile",
        "gemfile.lock",
        "go.mod",
        "go.sum",
        "go.work",
        "package-lock.json",
        "package.json",
        "pipfile",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pyproject.toml",
        "requirements.txt",
        "setup.cfg",
        "setup.py",
        "uv.lock",
        "yarn.lock",
    }
)
MAX_SNAPSHOT_FILES = 4096
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
MAX_PYTHON_FILE_BYTES = 4 * 1024 * 1024
MAX_COMMAND_TIMEOUT_SECONDS = 120
MAX_COMMAND_OUTPUT_CHARS = 4000
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidationError(RuntimeError):
    """Raised when a validation request or baseline is unsafe or malformed."""


@dataclass(frozen=True)
class FileState:
    kind: str
    mode: int
    size_bytes: int
    sha256: str


@dataclass(frozen=True)
class TreeSnapshot:
    root: str
    files: dict[str, FileState]


@dataclass(frozen=True)
class ChangeSet:
    added: tuple[str, ...]
    modified: tuple[str, ...]
    deleted: tuple[str, ...]

    def all_paths(self) -> tuple[str, ...]:
        return tuple(sorted(set(self.added + self.modified + self.deleted)))


@dataclass(frozen=True)
class ArtifactRule:
    kind: str
    path: Path
    expected_text: str | None = None
    required_keys: tuple[str, ...] = ()
    nonempty_findings: bool = False


@dataclass(frozen=True)
class CommandSpec:
    name: str
    argv: tuple[str, ...]
    timeout_seconds: int = 60


@dataclass(frozen=True)
class CheckResult:
    name: str
    passed: bool
    detail: str
    duration_ms: int = 0


@dataclass(frozen=True)
class ValidationPolicy:
    mode: str
    target: Path
    baseline: TreeSnapshot
    artifacts: tuple[ArtifactRule, ...] = ()
    commands: tuple[CommandSpec, ...] = ()
    allowed_change_paths: tuple[str, ...] = ()
    check_python_syntax: bool = True
    allow_dependency_changes: bool = False


@dataclass(frozen=True)
class ValidationReport:
    mode: str
    target: str
    passed: bool
    checks: tuple[CheckResult, ...]
    changes: ChangeSet

    def as_payload(self) -> dict[str, Any]:
        return {
            "mode": self.mode,
            "target": self.target,
            "passed": self.passed,
            "checks": [asdict(check) for check in self.checks],
            "changes": asdict(self.changes),
        }


def canonical_path(path: Path | str) -> Path:
    """Canonicalize existing ancestors before appending missing path parts.

    On Windows, resolving a non-existent child in one operation may preserve a
    long path while resolving its existing parent yields an 8.3 alias (or the
    reverse).  That makes two paths to the same directory fail a containment
    check.  Resolve the nearest existing ancestor once, then append the lexical
    missing suffix so both sides use the same representation.
    """

    candidate = Path(os.path.abspath(os.fspath(path)))
    missing_parts: list[str] = []
    existing = candidate
    while not existing.exists() and not existing.is_symlink():
        parent = existing.parent
        if parent == existing:
            break
        missing_parts.append(existing.name)
        existing = parent
    resolved = existing.resolve(strict=False)
    return resolved.joinpath(*reversed(missing_parts))


def path_is_within(path: Path | str, root: Path | str) -> bool:
    candidate = canonical_path(path)
    parent = canonical_path(root)
    try:
        candidate.relative_to(parent)
        return True
    except ValueError:
        return False


def normalize_relative_path(value: str) -> str:
    normalized = value.replace("\\", "/").strip("/")
    path = Path(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValidationError(f"unsafe relative path: {value!r}")
    return path.as_posix()


def ignored_path(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    return (
        any(part in IGNORED_DIRECTORIES for part in relative.parts[:-1])
        or path.name in IGNORED_FILES
        or path.suffix in {".pyc", ".pyo"}
    )


def hash_regular_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def file_state(path: Path) -> FileState:
    if path.is_symlink():
        target = os.readlink(path)
        encoded = os.fsencode(target)
        return FileState(
            kind="symlink",
            mode=stat.S_IMODE(path.lstat().st_mode),
            size_bytes=len(encoded),
            sha256=hashlib.sha256(encoded).hexdigest(),
        )
    return FileState(
        kind="file",
        mode=stat.S_IMODE(path.stat().st_mode),
        size_bytes=path.stat().st_size,
        sha256=hash_regular_file(path),
    )


def capture_snapshot(
    target: Path | str,
    *,
    max_files: int = MAX_SNAPSHOT_FILES,
    max_bytes: int = MAX_SNAPSHOT_BYTES,
) -> TreeSnapshot:
    root = canonical_path(target)
    if not root.is_dir():
        raise ValidationError(f"snapshot target is not a directory: {root}")
    candidates = [
        path
        for path in sorted(root.rglob("*"))
        if (path.is_file() or path.is_symlink()) and not ignored_path(path, root)
    ]
    if len(candidates) > max_files:
        raise ValidationError(
            f"snapshot exceeds file limit: {len(candidates)} > {max_files}"
        )
    total_bytes = sum(path.lstat().st_size for path in candidates)
    if total_bytes > max_bytes:
        raise ValidationError(
            f"snapshot exceeds byte limit: {total_bytes} > {max_bytes}"
        )
    states = {
        path.relative_to(root).as_posix(): file_state(path) for path in candidates
    }
    return TreeSnapshot(root=str(root), files=states)


def snapshot_payload(snapshot: TreeSnapshot) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "root": snapshot.root,
        "files": {
            path: asdict(state) for path, state in sorted(snapshot.files.items())
        },
    }


def render_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def parse_snapshot_payload(payload: Any) -> TreeSnapshot:
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "root",
        "files",
    }:
        raise ValidationError("baseline must contain schema_version, root and files")
    if payload["schema_version"] != 1 or not isinstance(payload["root"], str):
        raise ValidationError("unsupported baseline schema")
    raw_files = payload["files"]
    if not isinstance(raw_files, dict):
        raise ValidationError("baseline files must be an object")
    files: dict[str, FileState] = {}
    for raw_path, raw_state in raw_files.items():
        if not isinstance(raw_path, str):
            raise ValidationError("baseline path must be a string")
        path = normalize_relative_path(raw_path)
        if not isinstance(raw_state, dict) or set(raw_state) != {
            "kind",
            "mode",
            "size_bytes",
            "sha256",
        }:
            raise ValidationError(f"invalid baseline state for {path}")
        kind = raw_state["kind"]
        mode = raw_state["mode"]
        size = raw_state["size_bytes"]
        digest = raw_state["sha256"]
        if kind not in {"file", "symlink"}:
            raise ValidationError(f"invalid file kind for {path}")
        if isinstance(mode, bool) or not isinstance(mode, int) or not 0 <= mode <= 0o7777:
            raise ValidationError(f"invalid file mode for {path}")
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise ValidationError(f"invalid size for {path}")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise ValidationError(f"invalid sha256 for {path}")
        files[path] = FileState(
            kind=kind, mode=mode, size_bytes=size, sha256=digest
        )
    return TreeSnapshot(root=payload["root"], files=files)


def load_snapshot(path: Path | str) -> TreeSnapshot:
    try:
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"cannot read baseline {path}: {error}") from error
    return parse_snapshot_payload(payload)


def compare_snapshots(before: TreeSnapshot, after: TreeSnapshot) -> ChangeSet:
    if os.path.normcase(str(canonical_path(before.root))) != os.path.normcase(
        str(canonical_path(after.root))
    ):
        raise ValidationError(
            f"snapshot roots differ: {before.root!r} != {after.root!r}"
        )
    before_paths = set(before.files)
    after_paths = set(after.files)
    return ChangeSet(
        added=tuple(sorted(after_paths - before_paths)),
        modified=tuple(
            sorted(
                path
                for path in before_paths & after_paths
                if before.files[path] != after.files[path]
            )
        ),
        deleted=tuple(sorted(before_paths - after_paths)),
    )


def protected_path(path: str) -> bool:
    parts = Path(path).parts
    name = parts[-1].lower() if parts else ""
    return (
        any(part.lower() in PROTECTED_PARTS for part in parts)
        or name.startswith(PROTECTED_PREFIXES)
    )


def dependency_path(path: str) -> bool:
    name = Path(path).name.lower()
    return name in DEPENDENCY_FILES or name.startswith("requirements-")


def artifact_relative_paths(target: Path, artifacts: Iterable[ArtifactRule]) -> set[str]:
    root = canonical_path(target)
    paths: set[str] = set()
    for artifact in artifacts:
        artifact_path = canonical_path(artifact.path)
        try:
            paths.add(artifact_path.relative_to(root).as_posix())
        except ValueError:
            continue
    return paths


def validate_change_policy(
    policy: ValidationPolicy, changes: ChangeSet
) -> CheckResult:
    started = time.monotonic()
    allowed = {
        normalize_relative_path(path) for path in policy.allowed_change_paths
    }
    allowed.update(artifact_relative_paths(policy.target, policy.artifacts))
    changed = changes.all_paths()
    violations: list[str] = []
    if policy.mode in {"audit", "forensics", "ctf"}:
        violations.extend(path for path in changed if path not in allowed)
    else:
        violations.extend(path for path in changed if protected_path(path))
        if not policy.allow_dependency_changes:
            violations.extend(path for path in changed if dependency_path(path))
    violations = sorted(set(violations))
    elapsed = round((time.monotonic() - started) * 1000)
    if violations:
        return CheckResult(
            name="change-policy",
            passed=False,
            detail=f"forbidden changed paths: {', '.join(violations)}",
            duration_ms=elapsed,
        )
    return CheckResult(
        name="change-policy",
        passed=True,
        detail=f"{len(changed)} changed path(s); policy satisfied",
        duration_ms=elapsed,
    )


def read_utf8_file(path: Path) -> str:
    if path.is_symlink():
        raise ValidationError(f"artifact must not be a symlink: {path}")
    if not path.is_file():
        raise ValidationError(f"artifact is missing: {path}")
    try:
        return path.read_bytes().decode("utf-8")
    except UnicodeError as error:
        raise ValidationError(f"artifact is not valid UTF-8: {path}") from error


def validate_security_report_payload(payload: Any) -> None:
    if not isinstance(payload, dict) or set(payload) != {"findings"}:
        raise ValidationError("security report must contain only top-level findings")
    findings = payload["findings"]
    if not isinstance(findings, list):
        raise ValidationError("security report findings must be an array")
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or set(finding) != SECURITY_FINDING_FIELDS:
            raise ValidationError(f"finding {index} has an invalid field set")
        if finding["severity"] not in SECURITY_SEVERITIES:
            raise ValidationError(f"finding {index} has an invalid severity")
        for key in SECURITY_FINDING_FIELDS:
            value = finding[key]
            if not isinstance(value, str) or not value.strip():
                raise ValidationError(f"finding {index}.{key} must be non-empty text")


def validate_artifact(rule: ArtifactRule) -> CheckResult:
    started = time.monotonic()
    name = f"artifact:{rule.kind}:{rule.path}"
    try:
        if rule.kind not in ARTIFACT_KINDS:
            raise ValidationError(f"unsupported artifact kind: {rule.kind}")
        if rule.kind == "file":
            if rule.path.is_symlink() or not rule.path.is_file():
                raise ValidationError(f"regular artifact file is missing: {rule.path}")
        else:
            text = read_utf8_file(rule.path)
            if rule.kind == "text" and not text:
                raise ValidationError("text artifact must not be empty")
            if rule.kind == "exact-text":
                if rule.expected_text is None:
                    raise ValidationError("exact-text artifact requires expected_text")
                if text != rule.expected_text:
                    raise ValidationError("artifact content does not match exactly")
            if rule.kind in {"json", "security-report"}:
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError as error:
                    raise ValidationError(f"artifact is not valid JSON: {error}") from error
                if rule.kind == "security-report":
                    validate_security_report_payload(payload)
                    if rule.nonempty_findings and not payload["findings"]:
                        raise ValidationError("instruction requires non-empty findings; inspect beyond the SQL scanner")
                if rule.required_keys and (
                    not isinstance(payload, dict) or set(payload) != set(rule.required_keys)
                ):
                    raise ValidationError("JSON artifact must contain exactly the declared keys")
            if rule.kind == "incident-report":
                validate_incident_report_text(text)
        elapsed = round((time.monotonic() - started) * 1000)
        return CheckResult(name=name, passed=True, detail="artifact is valid", duration_ms=elapsed)
    except (OSError, UnicodeError, ValueError, ValidationError) as error:
        elapsed = round((time.monotonic() - started) * 1000)
        return CheckResult(name=name, passed=False, detail=str(error), duration_ms=elapsed)


def iter_python_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*.py")):
        if path.is_symlink() or not path.is_file() or ignored_path(path, root):
            continue
        yield path


def validate_python_syntax(target: Path | str) -> CheckResult:
    started = time.monotonic()
    root = canonical_path(target)
    errors: list[str] = []
    checked = 0
    try:
        for path in iter_python_files(root):
            size = path.stat().st_size
            if size > MAX_PYTHON_FILE_BYTES:
                errors.append(f"{path.relative_to(root)} exceeds Python size limit")
                continue
            try:
                source = path.read_text(encoding="utf-8")
                ast.parse(source, filename=str(path))
                checked += 1
            except (OSError, UnicodeError, SyntaxError) as error:
                errors.append(f"{path.relative_to(root)}: {error}")
    except OSError as error:
        errors.append(str(error))
    elapsed = round((time.monotonic() - started) * 1000)
    return CheckResult(
        name="python-syntax",
        passed=not errors,
        detail=(f"parsed {checked} Python file(s)" if not errors else "; ".join(errors)),
        duration_ms=elapsed,
    )


def truncate(value: str, limit: int = MAX_COMMAND_OUTPUT_CHARS) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + f"\n... [truncated to {limit} chars]"


def run_command_check(spec: CommandSpec, cwd: Path | str) -> CheckResult:
    started = time.monotonic()
    if not spec.argv:
        return CheckResult(spec.name, False, "command argv is empty")
    if not 1 <= spec.timeout_seconds <= MAX_COMMAND_TIMEOUT_SECONDS:
        return CheckResult(
            spec.name,
            False,
            f"command timeout must be 1..{MAX_COMMAND_TIMEOUT_SECONDS} seconds",
        )
    try:
        process = subprocess.run(
            list(spec.argv),
            cwd=str(canonical_path(cwd)),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=spec.timeout_seconds,
            check=False,
        )
        passed = process.returncode == 0
        detail = truncate(
            f"exit_code={process.returncode}\n"
            f"stdout:\n{process.stdout or '<empty>'}\n"
            f"stderr:\n{process.stderr or '<empty>'}"
        )
    except subprocess.TimeoutExpired as error:
        passed = False
        detail = f"timed out after {spec.timeout_seconds}s: {error}"
    except OSError as error:
        passed = False
        detail = f"command failed to start: {error}"
    elapsed = round((time.monotonic() - started) * 1000)
    return CheckResult(spec.name, passed, detail, elapsed)


def validate_task(policy: ValidationPolicy) -> ValidationReport:
    if policy.mode not in VALID_MODES:
        raise ValidationError(f"unsupported validation mode: {policy.mode}")
    target = canonical_path(policy.target)
    if not target.is_dir():
        raise ValidationError(f"validation target is not a directory: {target}")
    if os.path.normcase(str(canonical_path(policy.baseline.root))) != os.path.normcase(
        str(target)
    ):
        raise ValidationError("baseline root does not match validation target")

    checks: list[CheckResult] = []
    for command in policy.commands:
        checks.append(run_command_check(command, target))
    if policy.check_python_syntax:
        checks.append(validate_python_syntax(target))
    for artifact in policy.artifacts:
        checks.append(validate_artifact(artifact))

    try:
        current = capture_snapshot(target)
        changes = compare_snapshots(policy.baseline, current)
        checks.append(validate_change_policy(policy, changes))
    except ValidationError as error:
        changes = ChangeSet((), (), ())
        checks.append(CheckResult("change-policy", False, str(error)))

    return ValidationReport(
        mode=policy.mode,
        target=str(target),
        passed=all(check.passed for check in checks),
        checks=tuple(checks),
        changes=changes,
    )


def parse_artifact(value: str, target: Path) -> ArtifactRule:
    if "=" not in value:
        raise ValidationError("artifact must use KIND=PATH")
    kind, raw_path = value.split("=", 1)
    if kind not in ARTIFACT_KINDS - {"exact-text"} or not raw_path:
        raise ValidationError(f"invalid artifact rule: {value!r}")
    path = Path(raw_path)
    return ArtifactRule(kind, path if path.is_absolute() else target / path)


def parse_exact_text(value: str, target: Path) -> ArtifactRule:
    if "=" not in value:
        raise ValidationError("exact text must use PATH=VALUE")
    raw_path, expected = value.split("=", 1)
    if not raw_path:
        raise ValidationError("exact text path must not be empty")
    path = Path(raw_path)
    return ArtifactRule(
        "exact-text", path if path.is_absolute() else target / path, expected
    )


def parse_command_json(value: str, index: int, timeout: int) -> CommandSpec:
    try:
        payload = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValidationError(f"invalid command JSON: {error}") from error
    if (
        not isinstance(payload, list)
        or not payload
        or any(not isinstance(item, str) or not item for item in payload)
    ):
        raise ValidationError("command JSON must be a non-empty string array")
    return CommandSpec(f"command-{index}", tuple(payload), timeout)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    snapshot = commands.add_parser("snapshot", help="capture a pre-task tree baseline")
    snapshot.add_argument("target", type=Path)
    snapshot.add_argument("--output", type=Path, required=True)

    validate = commands.add_parser("validate", help="validate the completed task")
    validate.add_argument("target", type=Path)
    validate.add_argument("--mode", choices=sorted(VALID_MODES), required=True)
    validate.add_argument("--baseline", type=Path, required=True)
    validate.add_argument("--artifact", action="append", default=[])
    validate.add_argument("--exact-text", action="append", default=[])
    validate.add_argument("--allow-path", action="append", default=[])
    validate.add_argument("--allow-dependency-changes", action="store_true")
    validate.add_argument("--skip-python-syntax", action="store_true")
    validate.add_argument("--command-json", action="append", default=[])
    validate.add_argument(
        "--command-timeout", type=int, default=60, metavar="SECONDS"
    )
    validate.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        target = canonical_path(args.target)
        if args.command == "snapshot":
            if path_is_within(args.output, target):
                raise ValidationError("baseline output must be outside target")
            snapshot = capture_snapshot(target)
            write_utf8_lf(args.output, render_json(snapshot_payload(snapshot)))
            print(f"validation baseline written: {args.output}")
            return 0

        if args.output and path_is_within(args.output, target):
            raise ValidationError("validation report output must be outside target")
        artifacts = tuple(
            [parse_artifact(value, target) for value in args.artifact]
            + [parse_exact_text(value, target) for value in args.exact_text]
        )
        commands = tuple(
            parse_command_json(value, index, args.command_timeout)
            for index, value in enumerate(args.command_json, 1)
        )
        policy = ValidationPolicy(
            mode=args.mode,
            target=target,
            baseline=load_snapshot(args.baseline),
            artifacts=artifacts,
            commands=commands,
            allowed_change_paths=tuple(args.allow_path),
            check_python_syntax=not args.skip_python_syntax,
            allow_dependency_changes=args.allow_dependency_changes,
        )
        report = validate_task(policy)
        rendered = render_json(report.as_payload())
        if args.output:
            write_utf8_lf(args.output, rendered)
        print(rendered, end="")
        return 0 if report.passed else 1
    except (OSError, UnicodeError, ValueError, ValidationError) as error:
        print(f"validation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
