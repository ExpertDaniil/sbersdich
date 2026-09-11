"""Task-conditioned repository context compiler for the model-facing interface.

The task workspace is never renamed. The model receives three bounded levels of
context in one locally-derived packet:

L0 semantic filename/handle -> L1 compact REPO_GUIDE -> L2 trusted source window.

The module also adds typed pytest summaries to the semantic ACI. This independently
adopts the useful *idea* of structured test feedback used by other competition agents,
without importing their implementation: the planner sees failed node ids and error
classes before raw process noise.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

from agent.core.models import ToolResult

from .semantic_namespace import (
    SemanticCyberACIProvider,
    SemanticRepositoryContext,
    _is_test_path,
)


MAX_CONTEXT_PACKET_CHARS = 6_000
MAX_BASE_GUIDE_CHARS = 2_200
MAX_SOURCE_FILES = 3
MAX_SOURCE_LINES = 64
MAX_SINGLE_SOURCE_CHARS = 1_800
MAX_TYPED_FAILURES = 8
MAX_ERROR_TYPES = 6

_FAILED_RE = re.compile(r"^FAILED\s+([^\s]+)", re.MULTILINE)
_ERROR_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*(?:Error|Exception))\b")


def _query_terms(text: str) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    token: list[str] = []
    for char in text.casefold() + " ":
        if char.isalnum() or char == "_":
            token.append(char)
            continue
        if token:
            value = "".join(token).strip("_")
            token.clear()
            if len(value) >= 3 and value not in seen:
                seen.add(value)
                result.append(value)
    return tuple(result[:32])


def _window_for(item, instruction: str) -> tuple[int, int, str]:
    """Choose one deterministic bounded source window around the best symbol."""

    lines = (item.text or "").splitlines()
    if not lines:
        return 1, 0, ""
    terms = _query_terms(instruction)
    center = 1
    best = -1
    for symbol in item.symbols:
        haystack = f"{symbol.name} {symbol.qualname} {symbol.signature}".casefold()
        score = sum(1 for term in terms if term in haystack)
        if score > best:
            best = score
            center = max(1, symbol.start_line)
    if item.symbols and best <= 0:
        center = max(1, item.symbols[0].start_line)

    first = max(1, center - 10)
    last = min(len(lines), first + MAX_SOURCE_LINES - 1)
    if last - first + 1 < MAX_SOURCE_LINES and first > 1:
        first = max(1, last - MAX_SOURCE_LINES + 1)
    rendered = "\n".join(
        f"{lineno} | {lines[lineno - 1]}" for lineno in range(first, last + 1)
    )
    if len(rendered) > MAX_SINGLE_SOURCE_CHARS:
        rendered = rendered[:MAX_SINGLE_SOURCE_CHARS] + "\n... source window truncated ..."
    return first, last, rendered


def _pytest_feedback(output: str, *, passed: bool) -> dict[str, Any]:
    failed: list[str] = []
    for match in _FAILED_RE.finditer(output):
        node_id = match.group(1)
        if node_id not in failed:
            failed.append(node_id)
        if len(failed) >= MAX_TYPED_FAILURES:
            break

    errors: list[str] = []
    for match in _ERROR_RE.finditer(output):
        name = match.group(1)
        if name not in errors:
            errors.append(name)
        if len(errors) >= MAX_ERROR_TYPES:
            break

    counts = {"failed": 0, "passed": 0, "errors": 0}
    tail = output[-1200:]
    for key, pattern in (
        ("failed", r"(\d+)\s+failed"),
        ("passed", r"(\d+)\s+passed"),
        ("errors", r"(\d+)\s+errors?"),
    ):
        matches = re.findall(pattern, tail, re.IGNORECASE)
        if matches:
            counts[key] = int(matches[-1])

    return {
        "status": "passed" if passed else "failed",
        "counts": counts,
        "failed_tests": failed,
        "error_types_found": errors,
        "assertion_lines": [line[:500] for line in output.splitlines()
                            if line.startswith((">", "E "))][:12],
    }


class RepositoryContextCompiler(SemanticRepositoryContext):
    """Compile semantic names, contracts and a few trusted source windows."""

    def task_guide(self, instruction: str) -> str:
        raw_guide = super().task_guide(instruction)
        guide = raw_guide[:MAX_BASE_GUIDE_CHARS]
        if len(raw_guide) > MAX_BASE_GUIDE_CHARS:
            guide += "\n... semantic index truncated; use search_surface for lower-ranked files ..."
        snapshot = self.distiller.snapshot()
        # Format documentation can be the decisive input for data tasks. Generic
        # security ranking deliberately downranks docs, so honor explicit mentions.
        selected_paths = [item.path for item in snapshot.files
                          if item.text and not self.is_task_output(item.path)
                          and Path(item.path).suffix.casefold() in {".md", ".rst"}
                          and len(Path(item.path).stem) >= 3
                          and Path(item.path).stem.casefold() in instruction.casefold()][:1]
        try:
            ranked = self.distiller.rank_relevant_files(query=instruction, limit=10)
            for candidate in ranked.get("candidates", ()):
                path = str(candidate.get("path", ""))
                item = snapshot.by_path.get(path)
                if item is None or item.text is None or _is_test_path(path) or self.is_task_output(path) or path in selected_paths:
                    continue
                selected_paths.append(path)
                if len(selected_paths) >= MAX_SOURCE_FILES:
                    break
        except (OSError, UnicodeError, ValueError, RuntimeError):
            selected_paths = []

        if not selected_paths:
            for item in snapshot.files:
                if item.text is None or _is_test_path(item.path) or self.is_task_output(item.path) or not item.symbols:
                    continue
                selected_paths.append(item.path)
                if len(selected_paths) >= MAX_SOURCE_FILES:
                    break

        sections: list[str] = [guide]
        if selected_paths:
            sections.append(
                "\n# TRUSTED_SOURCE_WINDOWS\n"
                "Runtime file bytes, not verified conclusions or expected answers. Outputs are excluded. "
                "Full SHA256 is a valid checked_edit guard; "
                "skip view_window when the needed edit is fully visible and unambiguous."
            )
        for path in selected_paths:
            item = snapshot.by_path[path]
            card = self.card_for(path)
            if card is None or item.text is None:
                continue
            target = self.workdir / path
            try:
                raw = target.read_bytes()
            except OSError:
                continue
            if b"\x00" in raw:
                continue
            digest = hashlib.sha256(raw).hexdigest()
            first, last, rendered = _window_for(item, instruction)
            if not rendered:
                continue
            section = (
                f"\n## SOURCE {card.handle} {card.semantic_path} "
                f"source_path={path} SHA256={digest} LINES={first}-{last}/{len(item.text.splitlines())}\n"
                f"{rendered}"
            )
            projected = "".join((*sections, section))
            if len(projected) > MAX_CONTEXT_PACKET_CHARS:
                sections.append("\n... trusted source packet truncated ...")
                break
            sections.append(section)
        return "".join(sections)[:MAX_CONTEXT_PACKET_CHARS]


class CompiledSemanticCyberACIProvider(SemanticCyberACIProvider):
    """Semantic ACI plus compact typed feedback for pytest observations."""

    def _run_check(self, arguments: dict[str, Any]) -> ToolResult:
        result = super()._run_check(arguments)
        profile = str(arguments.get("profile", "")).casefold()
        if profile != "pytest" or not result.data:
            return result
        data = dict(result.data)
        output = str(data.get("output", ""))
        typed = _pytest_feedback(output, passed=result.ok)
        data["typed_feedback"] = typed
        counts = typed["counts"]
        if result.ok:
            summary = f"pytest passed: {counts['passed']} passed"
        else:
            failed = ", ".join(typed["failed_tests"][:3]) or "unknown failing node"
            errors = ", ".join(typed["error_types_found"][:3]) or "no classified exception"
            summary = f"pytest failed: {failed}; errors={errors}"
        return ToolResult(result.ok, summary, data)
