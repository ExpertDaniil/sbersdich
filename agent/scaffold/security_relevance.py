"""Security-aware ranking signals for repository localization.

The generic RepositoryDistiller deliberately stays domain-neutral.  This module adds a
thin security policy on top of it: lexical relevance is retained, but files containing
static evidence of dangerous data flows receive additional ranking weight when the task
is security-related.

These signals are *localization hints*, not findings.  They must never be treated as
trusted vulnerability evidence by the agent; a selected file still has to be inspected
and verified through tools/environment feedback.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable

from .distiller import RepositoryDistiller, RepositoryDistillerProvider


SECURITY_INTENT_TERMS = frozenset(
    {
        "attack",
        "audit",
        "auth",
        "bounty",
        "critical",
        "cve",
        "exploit",
        "forensic",
        "injection",
        "malicious",
        "pentest",
        "security",
        "secure",
        "vulnerability",
        "vulnerable",
        "уязвим",
        "безопасн",
        "аудит",
        "взлом",
        "эксплойт",
    }
)

SQL_RE = re.compile(r"\b(select|insert|update|delete|replace|where|from|join|like)\b", re.I)
DYNAMIC_SQL_RE = re.compile(
    r"(?:f[\"'].*\b(?:select|insert|update|delete|where|like)\b|"
    r"\b(?:select|insert|update|delete)\b.*(?:\.format\s*\(|%\s*[a-z_(]))",
    re.I,
)

SOURCE_LIKE_NAMES = frozenset(
    {
        "body",
        "data",
        "email",
        "filename",
        "host",
        "input",
        "name",
        "password",
        "path",
        "payload",
        "q",
        "query",
        "redirect",
        "request",
        "req",
        "search",
        "token",
        "url",
        "user",
        "username",
        "value",
    }
)

DOC_NAMES = frozenset(
    {
        "agents.md",
        "changelog.md",
        "contributing.md",
        "license",
        "license.md",
        "readme",
        "readme.md",
        "security.md",
    }
)

TEST_PARTS = frozenset({"test", "tests", "testing", "spec", "specs", "fixtures"})
SOURCE_SUFFIXES = frozenset(
    {
        ".c",
        ".cc",
        ".cpp",
        ".cs",
        ".go",
        ".h",
        ".hpp",
        ".java",
        ".js",
        ".jsx",
        ".kt",
        ".kts",
        ".php",
        ".py",
        ".rb",
        ".rs",
        ".scala",
        ".sh",
        ".sql",
        ".ts",
        ".tsx",
    }
)


def _security_intent(query: str) -> bool:
    lowered = query.casefold()
    return any(term in lowered for term in SECURITY_INTENT_TERMS)


def _joined_string_text(node: ast.JoinedStr) -> str:
    return "".join(part.value for part in node.values if isinstance(part, ast.Constant) and isinstance(part.value, str))


def _formatted_expressions(node: ast.JoinedStr) -> tuple[str, ...]:
    expressions: list[str] = []
    for part in node.values:
        if not isinstance(part, ast.FormattedValue):
            continue
        try:
            expressions.append(ast.unparse(part.value))
        except (ValueError, TypeError):
            expressions.append("")
    return tuple(expressions)


def _expression_looks_external(expression: str) -> bool:
    tokens = {token.casefold() for token in re.findall(r"[A-Za-z_]\w*", expression)}
    return bool(tokens.intersection(SOURCE_LIKE_NAMES))


def _call_name(node: ast.Call) -> str:
    try:
        return ast.unparse(node.func).casefold()
    except (ValueError, TypeError):
        return ""


def _keyword_is_false(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is False:
            return True
    return False


def _python_security_signals(text: str) -> list[tuple[float, str]]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []

    signals: list[tuple[float, str]] = []
    for node in ast.walk(tree):
        value: ast.AST | None = None
        if isinstance(node, ast.Assign):
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            value = node.value
        if isinstance(value, ast.JoinedStr):
            literal = _joined_string_text(value)
            expressions = _formatted_expressions(value)
            if SQL_RE.search(literal) and expressions:
                signals.append((70.0, "dynamic-sql-interpolation"))
                if any(_expression_looks_external(expression) for expression in expressions):
                    signals.append((260.0, "external-input-in-sql"))

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if name in {"eval", "exec"} or name.endswith(".eval") or name.endswith(".exec"):
            signals.append((220.0, "dynamic-code-execution"))
        if name.endswith("os.system") or name == "os.system":
            signals.append((230.0, "shell-command-execution"))
        if "subprocess" in name and _keyword_is_false(node, "shell") is False:
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    signals.append((230.0, "subprocess-shell-true"))
                    break
        if name.endswith("pickle.loads") or name.endswith("pickle.load"):
            signals.append((190.0, "pickle-deserialization"))
        if name.endswith("yaml.load") and not name.endswith("safe_load"):
            signals.append((150.0, "unsafe-yaml-load"))
        if name.endswith("render_template_string"):
            signals.append((160.0, "template-string-render"))
        if _keyword_is_false(node, "verify"):
            signals.append((100.0, "verification-disabled"))
        if name.endswith((".fetch", ".fetchrow", ".execute", ".executemany")):
            if node.args:
                try:
                    first_arg = ast.unparse(node.args[0])
                except (ValueError, TypeError):
                    first_arg = ""
                if first_arg in {"query", "sql", "statement", "stmt"}:
                    signals.append((18.0, "database-query-variable"))
    return signals


def _generic_security_signals(text: str) -> list[tuple[float, str]]:
    lowered = text.casefold()
    signals: list[tuple[float, str]] = []
    if DYNAMIC_SQL_RE.search(text):
        signals.append((55.0, "dynamic-sql-text"))
    patterns = (
        (r"\beval\s*\(", 180.0, "eval-call"),
        (r"\bexec\s*\(", 180.0, "exec-call"),
        (r"\bos\.system\s*\(", 210.0, "os-system-call"),
        (r"shell\s*=\s*true", 210.0, "shell-true"),
        (r"verify\s*=\s*false", 90.0, "verification-disabled"),
        (r"pickle\.loads?\s*\(", 170.0, "pickle-deserialization"),
    )
    for pattern, weight, label in patterns:
        if re.search(pattern, lowered, re.I):
            signals.append((weight, label))
    return signals


def _path_signals(path: str) -> list[tuple[float, str]]:
    pure = Path(path)
    lowered_parts = {part.casefold() for part in pure.parts}
    basename = pure.name.casefold()
    stem = pure.stem.casefold()
    signals: list[tuple[float, str]] = []

    if pure.suffix.casefold() in SOURCE_SUFFIXES:
        signals.append((7.0, "source-file"))
    if lowered_parts.intersection(TEST_PARTS) or stem.startswith("test_") or stem.endswith("_test"):
        signals.append((-65.0, "test-path"))
    if basename in DOC_NAMES or pure.suffix.casefold() in {".md", ".rst"}:
        signals.append((-90.0, "documentation-path"))
    if basename in {"pyproject.toml", "package.json", "package-lock.json", "poetry.lock", "requirements.txt"}:
        signals.append((-45.0, "dependency-metadata"))
    if lowered_parts.intersection({"router", "routers", "route", "routes", "controller", "controllers", "api"}):
        signals.append((12.0, "request-surface-path"))
    if any(token in stem for token in ("auth", "login", "session", "permission", "admin")):
        signals.append((22.0, "auth-surface-path"))
    return signals


def _merge_signal_labels(signals: Iterable[tuple[float, str]], limit: int = 6) -> list[str]:
    ordered = sorted(signals, key=lambda item: (-abs(item[0]), item[1]))
    return [f"{label}:{weight:+.0f}" for weight, label in ordered[:limit]]


class SecurityAwareRepositoryDistiller(RepositoryDistiller):
    """Add static security priors to generic relevance ranking under security intent."""

    def rank_relevant_files(self, *, query: str, limit: int = 8) -> dict[str, object]:
        base = super().rank_relevant_files(query=query, limit=20)
        if not _security_intent(query):
            return super().rank_relevant_files(query=query, limit=limit)

        snapshot = self.snapshot()
        base_by_path = {str(item["path"]): item for item in base["candidates"]}
        ranked: list[dict[str, object]] = []

        for item in snapshot.files:
            if item.text is None:
                continue
            base_item = base_by_path.get(item.path)
            base_score = float(base_item["score"]) if base_item is not None else 0.0
            signals = _path_signals(item.path)
            if item.language == "python":
                signals.extend(_python_security_signals(item.text))
            else:
                signals.extend(_generic_security_signals(item.text))
            security_score = sum(weight for weight, _ in signals)
            total = base_score + security_score
            if total <= 0:
                continue
            reasons = list(base_item.get("reasons", [])) if base_item is not None else []
            reasons.extend(_merge_signal_labels(signals))
            ranked.append(
                {
                    "path": item.path,
                    "score": round(total, 3),
                    "base_score": round(base_score, 3),
                    "security_score": round(security_score, 3),
                    "reasons": reasons[:8],
                    "top_symbols": list(base_item.get("top_symbols", [])) if base_item is not None else [],
                }
            )

        ranked.sort(key=lambda candidate: (-float(candidate["score"]), str(candidate["path"])))
        selected = ranked[:limit]
        return {
            "query_terms": base["query_terms"],
            "security_intent": True,
            "candidates": selected,
            "indexed_files": base["indexed_files"],
            "indexed_bytes": base["indexed_bytes"],
            "truncated": len(ranked) > limit or bool(base["truncated"]),
            "snapshot": base["snapshot"],
        }


class SecurityAwareRepositoryDistillerProvider(RepositoryDistillerProvider):
    """Production provider using security-aware ranking with the same ToolBus contract."""

    name = "repository-distiller"

    def __init__(self, workdir: Path | str):
        self.distiller = SecurityAwareRepositoryDistiller(workdir)
