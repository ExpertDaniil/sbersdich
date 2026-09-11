"""Task-conditioned repository context compiler for the model-facing interface.

This module deliberately does not mutate or rename the task workspace.  It extends
``SemanticRepositoryContext`` with a tiny packet of trusted source windows for the
highest-ranked files.  The LLM therefore gets three levels of context in one bounded
observation:

L0 semantic filename/handle -> L1 compact REPO_GUIDE -> L2 selected source window.

Everything is derived locally from the repository index; no model call is spent on
building the packet.  Full-file SHA-256 digests make an included source window usable
as the optimistic-concurrency guard for ``checked_edit``.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from .semantic_namespace import SemanticRepositoryContext, _is_test_path


MAX_CONTEXT_PACKET_CHARS = 10_000
MAX_SOURCE_FILES = 3
MAX_SOURCE_LINES = 64
MAX_SINGLE_SOURCE_CHARS = 3_600


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


class RepositoryContextCompiler(SemanticRepositoryContext):
    """Compile semantic names, contracts and a few trusted source windows."""

    def task_guide(self, instruction: str) -> str:
        guide = super().task_guide(instruction)
        snapshot = self.distiller.snapshot()
        selected_paths: list[str] = []
        try:
            ranked = self.distiller.rank_relevant_files(query=instruction, limit=10)
            for candidate in ranked.get("candidates", ()):
                path = str(candidate.get("path", ""))
                item = snapshot.by_path.get(path)
                if item is None or item.text is None or _is_test_path(path):
                    continue
                if Path(path).suffix.casefold() in {".md", ".rst"}:
                    continue
                selected_paths.append(path)
                if len(selected_paths) >= MAX_SOURCE_FILES:
                    break
        except (OSError, UnicodeError, ValueError, RuntimeError):
            selected_paths = []

        # Structural fallback: a useful packet is preferable to another model call.
        if not selected_paths:
            for item in snapshot.files:
                if item.text is None or _is_test_path(item.path) or not item.symbols:
                    continue
                selected_paths.append(item.path)
                if len(selected_paths) >= MAX_SOURCE_FILES:
                    break

        sections: list[str] = [guide]
        if selected_paths:
            sections.append(
                "\n# TRUSTED_SOURCE_WINDOWS\n"
                "These windows are direct runtime reads, not summaries. Their full SHA256 may be "
                "used directly as checked_edit.expected_sha256; view_window is unnecessary when "
                "the required edit is fully visible and unambiguous."
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
                f"SHA256={digest} LINES={first}-{last}/{len(item.text.splitlines())}\n"
                f"{rendered}"
            )
            projected = "".join((*sections, section))
            if len(projected) > MAX_CONTEXT_PACKET_CHARS:
                sections.append("\n... trusted source packet truncated ...")
                break
            sections.append(section)
        packet = "".join(sections)
        return packet[:MAX_CONTEXT_PACKET_CHARS]
