"""Compact Agent-Computer Interface for repository security work.

The ACI is deliberately narrower than a shell. It gives the planner four stable
operations with bounded, structured observations:

    search_surface -> view_window -> checked_edit -> run_check

The interface is mode/capability gated by ToolBus and reuses the existing workspace
containment and command allowlist. A checked edit is optimistic-concurrency guarded
by the SHA-256 returned from view_window and is rejected before write when lightweight
syntax validation fails.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
import json
import os
import re
import stat
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Iterable

from agent.core.models import AgentAction, ToolResult
from agent.core.workspace import (
    MAX_TEXT_FILE_BYTES,
    WorkspaceError,
    read_workspace_text,
    resolve_workspace_path,
    run_workspace_command,
    search_workspace_text,
)
from agent.tools.security_scan import scan_python_source

from .contracts import CapabilityLevel, ExecutionContext, ToolSpec
from .security_relevance import SecurityAwareRepositoryDistiller


MAX_QUERY_CHARS = 512
MAX_QUERY_TERMS = 6
MAX_SEARCH_RESULTS = 25
DEFAULT_SEARCH_RESULTS = 12
MAX_VIEW_LINES = 120
DEFAULT_VIEW_LINES = 100
MAX_REPLACEMENT_CHARS = 64_000
MAX_DIFF_CHARS = 8_000
MAX_SYNTAX_FILES = 256

WORD_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.:/-]{2,}|[А-Яа-яЁё][А-Яа-яЁё0-9_.:/-]{2,}"
)
STOPWORDS = frozenset(
    {
        "about",
        "after",
        "agent",
        "analyse",
        "analyze",
        "application",
        "code",
        "find",
        "fix",
        "from",
        "into",
        "issue",
        "most",
        "project",
        "security",
        "task",
        "that",
        "the",
        "this",
        "with",
        "анализ",
        "безопасность",
        "задача",
        "код",
        "найди",
        "найти",
        "проект",
        "уязвимость",
    }
)

ACI_MODE_BUNDLES: dict[str, tuple[str, ...]] = {
    "audit": ("view_window", "search_surface"),
    "fix": ("view_window", "search_surface", "run_check", "checked_edit"),
    "forensics": ("view_window", "search_surface"),
    "ctf": ("view_window", "search_surface"),
    "general": ("view_window", "search_surface", "run_check", "checked_edit"),
}


def _integer(
    value: object,
    name: str,
    *,
    default: int | None = None,
    minimum: int,
    maximum: int,
) -> int:
    if value is None and default is not None:
        value = default
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


def _boolean(value: object, name: str, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"{name} must be a boolean")
    return value


def _bounded_text(value: object, name: str, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be non-empty text")
    if len(value) > maximum:
        raise ValueError(f"{name} exceeds {maximum} characters")
    return value


def _query_terms(query: str) -> tuple[str, ...]:
    seen: set[str] = set()
    candidates: list[tuple[int, str]] = []
    for index, match in enumerate(WORD_RE.finditer(query)):
        raw = match.group(0).strip("._:/-")
        key = raw.casefold()
        if len(raw) < 3 or key in STOPWORDS or key in seen:
            continue
        seen.add(key)
        candidates.append((index, raw))
    # Longer terms generally carry more information. Preserve source order as a
    # deterministic tiebreak so the interface is stable across runs.
    candidates.sort(key=lambda item: (-len(item[1]), item[0]))
    selected = [term for _, term in candidates[:MAX_QUERY_TERMS]]
    if not selected:
        fallback = query.strip()
        if fallback:
            selected = [fallback[:256]]
    return tuple(selected)


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _atomic_replace(path: Path, raw: bytes) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            prefix=".agent-aci-",
            dir=path.parent,
            delete=False,
        ) as handle:
            handle.write(raw)
            temporary = Path(handle.name)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _candidate_checks(path: Path, text: str) -> tuple[dict[str, Any], ...]:
    suffix = path.suffix.casefold()
    checks: list[dict[str, Any]] = [{"name": "utf8", "passed": True}]
    if "\x00" in text:
        raise ValueError("candidate contains NUL bytes")
    if suffix == ".py":
        try:
            ast.parse(text, filename=path.name)
        except SyntaxError as error:
            raise ValueError(
                f"python syntax error at line {error.lineno}: {error.msg}"
            ) from error
        checks.append({"name": "python-ast", "passed": True})
    elif suffix == ".json":
        try:
            json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"JSON syntax error at line {error.lineno}: {error.msg}"
            ) from error
        checks.append({"name": "json-parse", "passed": True})
    elif suffix == ".toml":
        try:
            tomllib.loads(text)
        except tomllib.TOMLDecodeError as error:
            raise ValueError(f"TOML syntax error: {error}") from error
        checks.append({"name": "toml-parse", "passed": True})
    return tuple(checks)


def _iter_python_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        if target.suffix.casefold() == ".py" and not target.is_symlink():
            yield target
        return
    count = 0
    for current, directories, filenames in os.walk(target, followlinks=False):
        directories[:] = sorted(
            name
            for name in directories
            if name
            not in {
                ".git",
                ".hg",
                ".mypy_cache",
                ".pytest_cache",
                ".tox",
                ".venv",
                "__pycache__",
                "node_modules",
            }
            and not (Path(current) / name).is_symlink()
        )
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = Path(current) / name
            if path.is_symlink():
                continue
            yield path
            count += 1
            if count >= MAX_SYNTAX_FILES:
                return


class CyberACIProvider:
    """SWE-agent-style compact interface over existing safe workspace primitives."""

    name = "cyber-aci"

    def __init__(
        self,
        workdir: Path | str,
        *,
        distiller: SecurityAwareRepositoryDistiller | None = None,
    ):
        self.workdir = Path(workdir).resolve()
        self.distiller = distiller or SecurityAwareRepositoryDistiller(self.workdir)

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        active = set(
            ACI_MODE_BUNDLES.get(context.decision.mode, ACI_MODE_BUNDLES["general"])
        )
        modes = (context.decision.mode,)
        specs = (
            ToolSpec(
                "view_window",
                "View at most 120 numbered lines from one UTF-8 file and return a full-file SHA-256 edit guard.",
                {"path": "string", "start_line": "integer=1", "max_lines": "integer=100"},
                modes,
                CapabilityLevel.INSPECT,
                False,
                self.name,
            ),
            ToolSpec(
                "search_surface",
                "Natural-language bounded repository search. Returns ranked path:line hits and hides low-confidence overflow.",
                {
                    "query": "string",
                    "path": "string=.",
                    "glob": "string=*",
                    "case_sensitive": "boolean=false",
                    "max_results": "integer=12",
                },
                modes,
                CapabilityLevel.ANALYZE,
                False,
                self.name,
            ),
            ToolSpec(
                "run_check",
                "Run one structured proof/check profile: python-syntax, pytest, git-diff, or git-status.",
                {
                    "profile": "string",
                    "target": "string=.",
                    "timeout_seconds": "integer=60",
                },
                modes,
                CapabilityLevel.EXECUTE,
                False,
                self.name,
            ),
            ToolSpec(
                "checked_edit",
                "Replace an inclusive line range only if the file SHA-256 still matches view_window; reject invalid Python/JSON/TOML before write.",
                {
                    "path": "string",
                    "start_line": "integer",
                    "end_line": "integer",
                    "replacement": "string",
                    "expected_sha256": "string",
                },
                modes,
                CapabilityLevel.MUTATE,
                True,
                self.name,
            ),
        )
        return tuple(spec for spec in specs if spec.name in active)

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        try:
            if action.name == "search_surface":
                return self._search_surface(action.arguments)
            if action.name == "view_window":
                return self._view_window(action.arguments)
            if action.name == "checked_edit":
                return self._checked_edit(
                    action.arguments,
                    require_security_remediation=context.decision.mode == "fix",
                )
            if action.name == "run_check":
                return self._run_check(action.arguments)
            return ToolResult(False, f"unknown Cyber ACI action: {action.name}")
        except (OSError, UnicodeError, ValueError, RuntimeError, WorkspaceError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")

    @staticmethod
    def _only(arguments: dict[str, Any], allowed: set[str], action: str) -> None:
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise ValueError(f"unsupported {action} argument(s): {unknown}")

    def _search_surface(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(
            arguments,
            {"query", "path", "glob", "case_sensitive", "max_results"},
            "search_surface",
        )
        query = _bounded_text(arguments.get("query"), "query", MAX_QUERY_CHARS)
        limit = _integer(
            arguments.get("max_results"),
            "max_results",
            default=DEFAULT_SEARCH_RESULTS,
            minimum=1,
            maximum=MAX_SEARCH_RESULTS,
        )
        case_sensitive = _boolean(arguments.get("case_sensitive"), "case_sensitive")
        path = arguments.get("path", ".")
        glob = arguments.get("glob", "*")
        terms = _query_terms(query)

        merged: dict[tuple[str, int], dict[str, Any]] = {}
        source_truncated = False
        files_scanned = 0
        bytes_scanned = 0
        for term in terms:
            data = search_workspace_text(
                self.workdir,
                query=term,
                path=path,
                glob=glob,
                case_sensitive=case_sensitive,
            )
            source_truncated = source_truncated or bool(data["truncated"])
            files_scanned += int(data["files_scanned"])
            bytes_scanned += int(data["bytes_scanned"])
            for match in data["matches"]:
                key = (str(match["path"]), int(match["line"]))
                current = merged.setdefault(
                    key,
                    {
                        "path": key[0],
                        "line": key[1],
                        "text": str(match["text"])[:240],
                        "matched_terms": [],
                    },
                )
                if term not in current["matched_terms"]:
                    current["matched_terms"].append(term)

        ranking = self.distiller.rank_relevant_files(query=query, limit=50)
        relevance: dict[str, tuple[float, tuple[str, ...]]] = {}
        for candidate in ranking["candidates"]:
            relevance[str(candidate["path"])] = (
                float(candidate["score"]),
                tuple(str(reason) for reason in candidate.get("reasons", ())),
            )

        ranked_hits: list[dict[str, Any]] = []
        for hit in merged.values():
            base_score, reasons = relevance.get(hit["path"], (0.0, ()))
            score = base_score + 6.0 * len(hit["matched_terms"])
            ranked_hits.append(
                {
                    "ref": f"{hit['path']}:{hit['line']}",
                    "kind": "line",
                    "path": hit["path"],
                    "line": hit["line"],
                    "text": hit["text"],
                    "score": round(score, 3),
                    "matched_terms": hit["matched_terms"],
                    "ranking_reasons": list(reasons[:3]),
                }
            )
        ranked_hits.sort(
            key=lambda item: (-float(item["score"]), str(item["path"]), int(item["line"]))
        )

        # If none of the high-information terms occur literally, keep the interface
        # useful by returning file-level structural/security localization instead of
        # forcing a second broad tool call.
        if not ranked_hits:
            for candidate in ranking["candidates"]:
                ranked_hits.append(
                    {
                        "ref": f"{candidate['path']}:1",
                        "kind": "file",
                        "path": candidate["path"],
                        "line": 1,
                        "text": "",
                        "score": float(candidate["score"]),
                        "matched_terms": [],
                        "ranking_reasons": list(candidate.get("reasons", ()))[:3],
                    }
                )

        selected = ranked_hits[:limit]
        hidden = max(0, len(ranked_hits) - len(selected))
        data = {
            "query": query,
            "query_terms": list(terms),
            "results": selected,
            "result_count": len(selected),
            "known_hidden_count": hidden,
            "source_truncated": source_truncated,
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
        }
        return ToolResult(
            True,
            f"search_surface returned {len(selected)} ranked location(s)"
            + (f" and hid {hidden} lower-ranked hit(s)" if hidden else ""),
            data,
        )

    def _view_payload(
        self, *, path: object, start_line: object, max_lines: object
    ) -> dict[str, Any]:
        first = _integer(
            start_line,
            "start_line",
            default=1,
            minimum=1,
            maximum=10_000_000,
        )
        line_limit = _integer(
            max_lines,
            "max_lines",
            default=DEFAULT_VIEW_LINES,
            minimum=1,
            maximum=MAX_VIEW_LINES,
        )
        data = read_workspace_text(
            self.workdir,
            path=path,
            start_line=first,
            max_lines=line_limit,
        )
        resolved = resolve_workspace_path(self.workdir, path)
        raw = resolved.read_bytes()
        content_lines = str(data["content"]).splitlines()
        end_line = int(data["end_line"])
        total_lines = int(data["total_lines"])
        width = max(1, len(str(max(total_lines, end_line, first))))
        rendered_lines = [
            f"{line_number:>{width}} | {line}"
            for line_number, line in enumerate(content_lines, first)
        ]
        rendered = "\n".join(rendered_lines)
        if first > 1:
            rendered = f"... {first - 1} line(s) omitted before ...\n" + rendered
        if end_line < total_lines:
            suffix = f"... {total_lines - end_line} line(s) omitted after ..."
            rendered = rendered + ("\n" if rendered else "") + suffix
        return {
            "path": data["path"],
            "start_line": first,
            "end_line": end_line,
            "total_lines": total_lines,
            "content": rendered,
            "sha256": _sha256(raw),
            "truncated": bool(data["truncated"]),
        }

    def _view_window(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"path", "start_line", "max_lines"}, "view_window")
        if "path" not in arguments:
            raise ValueError("view_window requires path")
        data = self._view_payload(
            path=arguments["path"],
            start_line=arguments.get("start_line"),
            max_lines=arguments.get("max_lines"),
        )
        return ToolResult(
            True,
            f"viewed lines {data['start_line']}..{data['end_line']} from {data['path']}",
            data,
        )

    def _checked_edit(
        self,
        arguments: dict[str, Any],
        *,
        require_security_remediation: bool = False,
    ) -> ToolResult:
        self._only(
            arguments,
            {"path", "start_line", "end_line", "replacement", "expected_sha256"},
            "checked_edit",
        )
        required = {"path", "start_line", "end_line", "replacement", "expected_sha256"}
        missing = sorted(required - set(arguments))
        if missing:
            raise ValueError(f"checked_edit missing required argument(s): {missing}")

        start_line = _integer(
            arguments["start_line"], "start_line", minimum=1, maximum=10_000_000
        )
        end_line = _integer(
            arguments["end_line"],
            "end_line",
            minimum=start_line,
            maximum=10_000_000,
        )
        replacement = arguments["replacement"]
        if not isinstance(replacement, str):
            raise ValueError("replacement must be text")
        if len(replacement) > MAX_REPLACEMENT_CHARS:
            raise ValueError(f"replacement exceeds {MAX_REPLACEMENT_CHARS} characters")
        expected = _bounded_text(
            arguments["expected_sha256"], "expected_sha256", 64
        ).casefold()
        if not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("expected_sha256 must be a full 64-character SHA-256")

        target = resolve_workspace_path(
            self.workdir,
            arguments["path"],
            must_exist=True,
            for_write=True,
        )
        if target.is_symlink() or not target.is_file():
            raise ValueError("checked_edit target must be a regular file")
        raw = target.read_bytes()
        if len(raw) > MAX_TEXT_FILE_BYTES:
            raise ValueError(f"file exceeds {MAX_TEXT_FILE_BYTES} byte edit limit")
        current_sha = _sha256(raw)
        if current_sha != expected:
            return ToolResult(
                False,
                "checked_edit rejected stale view: file SHA-256 changed",
                {
                    "path": target.relative_to(self.workdir).as_posix(),
                    "expected_sha256": expected,
                    "current_sha256": current_sha,
                    "written": False,
                },
            )
        if b"\x00" in raw:
            raise ValueError("checked_edit target appears binary")
        try:
            old_text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("checked_edit target is not UTF-8") from error

        lines = old_text.splitlines(keepends=True)
        if not lines:
            raise ValueError("checked_edit cannot range-edit an empty file; use write_file")
        if end_line > len(lines):
            raise ValueError(f"end_line {end_line} exceeds file length {len(lines)}")
        newline = "\r\n" if "\r\n" in old_text else "\n"
        rendered_replacement = replacement
        auto_newline = False
        if end_line < len(lines) and replacement and not replacement.endswith(("\n", "\r")):
            rendered_replacement += newline
            auto_newline = True
        new_text = (
            "".join(lines[: start_line - 1])
            + rendered_replacement
            + "".join(lines[end_line:])
        )
        new_raw = new_text.encode("utf-8")
        if len(new_raw) > MAX_TEXT_FILE_BYTES:
            raise ValueError(f"edited file exceeds {MAX_TEXT_FILE_BYTES} bytes")

        try:
            checks = _candidate_checks(target, new_text)
        except ValueError as error:
            return ToolResult(
                False,
                f"checked_edit rejected before write: {error}",
                {
                    "path": target.relative_to(self.workdir).as_posix(),
                    "sha256": current_sha,
                    "written": False,
                    "guard": "static-parse",
                },
            )

        if require_security_remediation and target.suffix.casefold() == ".py":
            relative = target.relative_to(self.workdir).as_posix()
            before_findings = scan_python_source(old_text, relative)
            edited_findings = []
            edited_functions: set[str] = set()
            for finding in before_findings:
                match = re.search(r":(\d+)\s+\(([^)]+)\)$", finding.location)
                if match and start_line <= int(match.group(1)) <= end_line:
                    edited_findings.append(finding)
                    edited_functions.add(match.group(2))
            after_findings = scan_python_source(new_text, relative)
            remaining = [
                finding
                for finding in after_findings
                if any(f"({name})" in finding.location for name in edited_functions)
            ]
            if edited_findings and remaining:
                return ToolResult(
                    False,
                    "checked_edit rejected before write: the edited function still has a dynamic SQL finding; "
                    "use terminating rejection guards and interpolate only finite canonical locals "
                    "(for a case-insensitive direction, validate direction.lower() then derive direction.upper())",
                    {
                        "path": relative,
                        "sha256": current_sha,
                        "written": False,
                        "guard": "security-remediation",
                        "before_findings_in_range": len(edited_findings),
                        "remaining_findings_in_function": len(remaining),
                        "remaining_evidence": [finding.evidence for finding in remaining[:3]],
                    },
                )
            if edited_findings:
                checks = checks + ({"name": "security-remediation", "passed": True},)

        diff = "\n".join(
            difflib.unified_diff(
                old_text.splitlines(),
                new_text.splitlines(),
                fromfile=f"a/{target.relative_to(self.workdir).as_posix()}",
                tofile=f"b/{target.relative_to(self.workdir).as_posix()}",
                lineterm="",
                n=3,
            )
        )
        diff_truncated = len(diff) > MAX_DIFF_CHARS
        if diff_truncated:
            diff = diff[:MAX_DIFF_CHARS] + "\n... diff truncated ..."

        _atomic_replace(target, new_raw)
        new_sha = _sha256(new_raw)
        reopened = self._view_payload(
            path=target.relative_to(self.workdir).as_posix(),
            start_line=max(1, start_line - 3),
            max_lines=min(30, MAX_VIEW_LINES),
        )
        return ToolResult(
            True,
            f"checked_edit updated {target.relative_to(self.workdir).as_posix()} and passed {len(checks)} static guard(s)",
            {
                "path": target.relative_to(self.workdir).as_posix(),
                "old_sha256": current_sha,
                "new_sha256": new_sha,
                "start_line": start_line,
                "end_line": end_line,
                "auto_newline": auto_newline,
                "checks": list(checks),
                "diff": diff,
                "diff_truncated": diff_truncated,
                "reopened": reopened,
                "written": True,
            },
        )

    def _run_python_syntax(self, target_value: object) -> ToolResult:
        target = resolve_workspace_path(self.workdir, target_value)
        errors: list[dict[str, Any]] = []
        files_checked = 0
        for path in _iter_python_files(target):
            files_checked += 1
            try:
                raw = path.read_bytes()
                if len(raw) > MAX_TEXT_FILE_BYTES:
                    raise ValueError("file exceeds syntax-check size limit")
                text = raw.decode("utf-8")
                ast.parse(text, filename=path.name)
            except (OSError, UnicodeError, SyntaxError, ValueError) as error:
                errors.append(
                    {
                        "path": path.relative_to(self.workdir).as_posix(),
                        "error": str(error)[:500],
                    }
                )
                if len(errors) >= 20:
                    break
        passed = not errors and files_checked > 0
        if files_checked == 0:
            errors.append({"path": str(target_value), "error": "no Python files found"})
        return ToolResult(
            passed,
            (
                f"python-syntax passed for {files_checked} file(s)"
                if passed
                else f"python-syntax found {len(errors)} error(s) across {files_checked} file(s)"
            ),
            {
                "profile": "python-syntax",
                "passed": passed,
                "files_checked": files_checked,
                "errors": errors,
            },
        )

    def _run_check(self, arguments: dict[str, Any]) -> ToolResult:
        self._only(arguments, {"profile", "target", "timeout_seconds"}, "run_check")
        profile = _bounded_text(arguments.get("profile"), "profile", 32).casefold()
        target_value = arguments.get("target", ".")
        timeout = _integer(
            arguments.get("timeout_seconds"),
            "timeout_seconds",
            default=60,
            minimum=1,
            maximum=120,
        )
        if profile == "python-syntax":
            return self._run_python_syntax(target_value)

        target = resolve_workspace_path(self.workdir, target_value)
        relative = target.relative_to(self.workdir).as_posix()
        if profile == "pytest":
            argv = ["python3", "-m", "pytest", relative]
        elif profile == "git-diff":
            argv = ["git", "diff", "--", relative]
        elif profile == "git-status":
            argv = ["git", "status", "--short"]
        else:
            raise ValueError(
                "profile must be one of python-syntax, pytest, git-diff, git-status"
            )
        data = run_workspace_command(
            self.workdir,
            argv=argv,
            cwd=".",
            timeout_seconds=timeout,
        )
        passed = int(data["exit_code"]) == 0 and not bool(data.get("timed_out", False))
        payload = {"profile": profile, "target": relative, "passed": passed, **data}
        return ToolResult(
            passed,
            f"{profile} {'passed' if passed else 'failed'} with exit code {data['exit_code']}",
            payload,
        )
