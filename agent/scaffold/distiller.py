"""Bounded repository distillation for low-token code localization.

This module intentionally uses only the Python standard library.  It gives the
planner compact structural views before it starts reading whole files:

    repo tree -> symbol index -> file ranking -> skeleton -> symbol inspection

The index is deterministic, bounded, workdir-contained and automatically rebuilt
when repository metadata changes.
"""

from __future__ import annotations

import ast
import hashlib
import math
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

from agent.core.models import AgentAction, ToolResult
from agent.core.workspace import IGNORED_DIRECTORY_NAMES, answer_path
from agent.validators import canonical_path

from .contracts import CapabilityLevel, ExecutionContext, ToolSpec


MAX_FILES = 1_500
MAX_FILE_BYTES = 512 * 1024
MAX_TOTAL_INDEX_BYTES = 12 * 1024 * 1024
MAX_TREE_ENTRIES = 400
MAX_TREE_DEPTH = 8
MAX_SYMBOLS = 4_000
MAX_SYMBOLS_PER_FILE = 250
MAX_SKELETON_FILES = 12
MAX_SKELETON_CHARS = 14_000
MAX_RANK_RESULTS = 20
MAX_QUERY_CHARS = 2_000
MAX_QUERY_TERMS = 32
MAX_INSPECT_LINES = 180
MAX_REFERENCES = 20
MAX_SIGNATURE_CHARS = 260
MAX_SNIPPET_CHARS = 320

GENERATED_DIRECTORIES = frozenset(
    {
        ".gradle",
        ".next",
        ".nuxt",
        ".parcel-cache",
        ".svelte-kit",
        ".terraform",
        "build",
        "coverage",
        "dist",
        "site-packages",
        "target",
        "venv",
    }
)

TEXT_EXTENSIONS = frozenset(
    {
        ".c", ".cc", ".cfg", ".conf", ".cpp", ".cs", ".css", ".go",
        ".h", ".hh", ".hpp", ".htm", ".html", ".ini", ".java", ".js",
        ".json", ".jsx", ".kt", ".kts", ".md", ".php", ".py", ".rb",
        ".rs", ".scala", ".sh", ".sql", ".toml", ".ts", ".tsx", ".txt",
        ".xml", ".yaml", ".yml",
    }
)

SOURCE_EXTENSIONS = frozenset(
    {
        ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hh", ".hpp", ".java",
        ".js", ".jsx", ".kt", ".kts", ".php", ".py", ".rb", ".rs", ".scala",
        ".sh", ".sql", ".ts", ".tsx",
    }
)

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".c": "c",
    ".h": "c",
    ".hh": "cpp",
    ".hpp": "cpp",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".sh": "shell",
    ".sql": "sql",
}

STOP_WORDS = frozenset(
    {
        "about", "after", "agent", "also", "and", "are", "create", "does",
        "file", "find", "fix", "for", "from", "have", "into", "issue", "make",
        "need", "project", "repository", "should", "task", "that", "the", "this",
        "with", "without", "you", "ваш", "где", "для", "есть", "задача", "код",
        "котор", "найди", "найти", "нужно", "проект", "репозитор", "созда", "что",
        "это",
    }
)

WORD_RE = re.compile(r"[^\W\d][\w$./:-]{1,}", re.UNICODE)
CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


@dataclass(frozen=True)
class SymbolInfo:
    path: str
    name: str
    qualname: str
    kind: str
    start_line: int
    end_line: int
    signature: str
    language: str

    def as_payload(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class IndexedFile:
    path: str
    size_bytes: int
    language: str
    text: str | None
    symbols: tuple[SymbolInfo, ...]


@dataclass(frozen=True)
class RepositorySnapshot:
    signature: str
    files: tuple[IndexedFile, ...]
    symbols: tuple[SymbolInfo, ...]
    all_paths: tuple[str, ...]
    indexed_bytes: int
    truncated: bool

    @property
    def by_path(self) -> dict[str, IndexedFile]:
        return {item.path: item for item in self.files}


def _bounded(text: str, limit: int) -> str:
    text = " ".join(text.strip().split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _language(path: Path) -> str:
    return LANGUAGE_BY_EXTENSION.get(path.suffix.lower(), "text")


def _query_terms(query: str) -> tuple[str, ...]:
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be non-empty text")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"query exceeds {MAX_QUERY_CHARS} characters")
    result: list[str] = []
    seen: set[str] = set()
    for raw in WORD_RE.findall(query):
        fragments = [raw]
        fragments.extend(CAMEL_BOUNDARY_RE.sub(" ", raw).split())
        fragments.extend(part for part in re.split(r"[_./:$-]+", raw) if part)
        for fragment in fragments:
            term = fragment.casefold().strip("._-$")
            if len(term) < 3 or term in STOP_WORDS or term in seen:
                continue
            seen.add(term)
            result.append(term)
            if len(result) >= MAX_QUERY_TERMS:
                return tuple(result)
    if not result:
        return (query.casefold().strip()[:128],)
    return tuple(result)


def _safe_signature_line(lines: Sequence[str], lineno: int) -> str:
    if not 1 <= lineno <= len(lines):
        return ""
    return _bounded(lines[lineno - 1], MAX_SIGNATURE_CHARS)


def _target_names(target: ast.AST) -> Iterable[str]:
    if isinstance(target, ast.Name):
        yield target.id
    elif isinstance(target, (ast.Tuple, ast.List)):
        for child in target.elts:
            yield from _target_names(child)


class _PythonSymbolVisitor(ast.NodeVisitor):
    def __init__(self, path: str, text: str):
        self.path = path
        self.lines = text.splitlines()
        self.stack: list[str] = []
        self.symbols: list[SymbolInfo] = []

    def _append(self, node: ast.AST, name: str, kind: str) -> None:
        if len(self.symbols) >= MAX_SYMBOLS_PER_FILE:
            return
        start = int(getattr(node, "lineno", 1))
        end = int(getattr(node, "end_lineno", start))
        qualname = ".".join((*self.stack, name)) if self.stack else name
        self.symbols.append(
            SymbolInfo(
                path=self.path,
                name=name,
                qualname=qualname,
                kind=kind,
                start_line=start,
                end_line=max(start, end),
                signature=_safe_signature_line(self.lines, start),
                language="python",
            )
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> Any:
        self._append(node, node.name, "class")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> Any:
        self._append(node, node.name, "method" if self.stack else "function")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> Any:
        self._append(node, node.name, "async_method" if self.stack else "async_function")
        self.stack.append(node.name)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Assign(self, node: ast.Assign) -> Any:
        if not self.stack:
            for target in node.targets:
                for name in _target_names(target):
                    if name.isupper():
                        self._append(node, name, "constant")
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> Any:
        if not self.stack:
            for name in _target_names(node.target):
                if name.isupper():
                    self._append(node, name, "constant")
        self.generic_visit(node)


GENERIC_PATTERNS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "javascript": (
        ("class", re.compile(r"^\s*(?:export\s+default\s+|export\s+)?class\s+([A-Za-z_$][\w$]*)")),
        ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")),
        ("function", re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(")),
    ),
    "typescript": (
        ("class", re.compile(r"^\s*(?:export\s+default\s+|export\s+)?class\s+([A-Za-z_$][\w$]*)")),
        ("interface", re.compile(r"^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)")),
        ("type", re.compile(r"^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)\s*=")),
        ("function", re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(")),
        ("function", re.compile(r"^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(")),
    ),
    "go": (
        ("function", re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(")),
        ("type", re.compile(r"^\s*type\s+([A-Za-z_]\w*)\s+(?:struct|interface)\b")),
    ),
    "rust": (
        ("function", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_]\w*)\s*[<(]")),
        ("struct", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)")),
        ("enum", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_]\w*)")),
        ("trait", re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_]\w*)")),
    ),
    "java": (
        ("type", re.compile(r"^\s*(?:(?:public|protected|private|abstract|final|static)\s+)*(?:class|interface|enum|record)\s+([A-Za-z_]\w*)")),
        ("method", re.compile(r"^\s*(?:(?:public|protected|private|static|final|synchronized|abstract|native)\s+)+[\w<>\[\], ?.@]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:throws[^{]+)?\{")),
    ),
    "kotlin": (
        ("type", re.compile(r"^\s*(?:(?:public|private|protected|internal|open|data|sealed|abstract)\s+)*(?:class|interface|object)\s+([A-Za-z_]\w*)")),
        ("function", re.compile(r"^\s*(?:(?:public|private|protected|internal|open|override|suspend)\s+)*fun\s+([A-Za-z_]\w*)\s*\(")),
    ),
    "csharp": (
        ("type", re.compile(r"^\s*(?:(?:public|private|protected|internal|static|sealed|abstract|partial)\s+)*(?:class|interface|struct|enum|record)\s+([A-Za-z_]\w*)")),
        ("method", re.compile(r"^\s*(?:(?:public|private|protected|internal|static|virtual|override|async|sealed|abstract)\s+)+[\w<>\[\], ?.]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*(?:=>|\{)")),
    ),
    "c": (
        ("type", re.compile(r"^\s*(?:typedef\s+)?(?:struct|enum|union)\s+([A-Za-z_]\w*)")),
        ("function", re.compile(r"^\s*(?!if\b|for\b|while\b|switch\b)[\w\s*]+\s+([A-Za-z_]\w*)\s*\([^;]*\)\s*\{")),
    ),
    "cpp": (
        ("type", re.compile(r"^\s*(?:template\s*<[^>]+>\s*)?(?:class|struct|enum)\s+([A-Za-z_]\w*)")),
        ("function", re.compile(r"^\s*(?!if\b|for\b|while\b|switch\b)[\w:<>,~&*\s]+\s+([A-Za-z_~]\w*)\s*\([^;]*\)\s*(?:const\s*)?\{")),
    ),
    "ruby": (
        ("class", re.compile(r"^\s*class\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)")),
        ("module", re.compile(r"^\s*module\s+([A-Za-z_]\w*(?:::[A-Za-z_]\w*)*)")),
        ("function", re.compile(r"^\s*def\s+(?:self\.)?([A-Za-z_]\w*[!?=]?)")),
    ),
    "php": (
        ("type", re.compile(r"^\s*(?:(?:final|abstract)\s+)?(?:class|interface|trait|enum)\s+([A-Za-z_]\w*)", re.I)),
        ("function", re.compile(r"^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+&?\s*([A-Za-z_]\w*)\s*\(", re.I)),
    ),
    "shell": (("function", re.compile(r"^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\s*\)\s*\{")),),
    "sql": (
        ("table", re.compile(r"^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?[\"`\[]?([\w.]+)", re.I)),
        ("function", re.compile(r"^\s*create\s+(?:or\s+replace\s+)?(?:function|procedure)\s+[\"`\[]?([\w.]+)", re.I)),
    ),
}


def _extract_symbols(path: str, text: str) -> tuple[SymbolInfo, ...]:
    language = _language(Path(path))
    if language == "python":
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError):
            return ()
        visitor = _PythonSymbolVisitor(path, text)
        visitor.visit(tree)
        return tuple(visitor.symbols[:MAX_SYMBOLS_PER_FILE])

    patterns = GENERIC_PATTERNS.get(language, ())
    if not patterns:
        return ()
    symbols: list[SymbolInfo] = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for kind, pattern in patterns:
            match = pattern.search(line)
            if match is None:
                continue
            name = match.group(1)
            symbols.append(
                SymbolInfo(
                    path=path,
                    name=name,
                    qualname=name,
                    kind=kind,
                    start_line=lineno,
                    end_line=lineno,
                    signature=_bounded(line, MAX_SIGNATURE_CHARS),
                    language=language,
                )
            )
            break
        if len(symbols) >= MAX_SYMBOLS_PER_FILE:
            break
    return tuple(symbols)


def _numbered(lines: Sequence[str], start: int) -> str:
    return "\n".join(f"{start + offset:>5}: {line}" for offset, line in enumerate(lines))


class RepositoryDistiller:
    """Build and query a bounded repository snapshot."""

    def __init__(self, workdir: Path | str):
        self.root = canonical_path(workdir)
        if not self.root.is_dir():
            raise ValueError(f"workdir is not a directory: {self.root}")
        self._snapshot: RepositorySnapshot | None = None

    def _walk(self) -> tuple[list[Path], bool]:
        files: list[Path] = []
        for current, directories, filenames in os.walk(self.root, followlinks=False):
            current_path = Path(current)
            directories[:] = sorted(
                name
                for name in directories
                if name not in IGNORED_DIRECTORY_NAMES
                and name not in GENERATED_DIRECTORIES
                and not answer_path(current_path.relative_to(self.root) / name)
                and not (current_path / name).is_symlink()
            )
            for filename in sorted(filenames):
                path = current_path / filename
                relative = path.relative_to(self.root)
                if path.is_symlink() or answer_path(relative):
                    continue
                try:
                    if not path.is_file():
                        continue
                except OSError:
                    continue
                files.append(path)
                if len(files) >= MAX_FILES:
                    return files, True
        return files, False

    @staticmethod
    def _signature(files: Sequence[Path], root: Path, truncated: bool) -> str:
        digest = hashlib.sha256(b"1" if truncated else b"0")
        for path in files:
            try:
                stat_result = path.stat()
            except OSError:
                continue
            digest.update(path.relative_to(root).as_posix().encode("utf-8", "surrogatepass"))
            digest.update(f":{stat_result.st_size}:{stat_result.st_mtime_ns}\0".encode("ascii"))
        return digest.hexdigest()[:20]

    def _build_snapshot(self, files: Sequence[Path], signature: str, truncated: bool) -> RepositorySnapshot:
        indexed: list[IndexedFile] = []
        symbols: list[SymbolInfo] = []
        indexed_bytes = 0
        all_paths: list[str] = []
        for path in files:
            relative = path.relative_to(self.root).as_posix()
            all_paths.append(relative)
            try:
                size = path.stat().st_size
            except OSError:
                continue
            extension = path.suffix.lower()
            text: str | None = None
            file_symbols: tuple[SymbolInfo, ...] = ()
            if extension in TEXT_EXTENSIONS and size <= MAX_FILE_BYTES and indexed_bytes + size <= MAX_TOTAL_INDEX_BYTES:
                try:
                    raw = path.read_bytes()
                    if b"\x00" not in raw:
                        text = raw.decode("utf-8")
                except (OSError, UnicodeDecodeError):
                    text = None
                if text is not None:
                    indexed_bytes += size
                    if extension in SOURCE_EXTENSIONS and len(symbols) < MAX_SYMBOLS:
                        file_symbols = _extract_symbols(relative, text)[: MAX_SYMBOLS - len(symbols)]
                        symbols.extend(file_symbols)
            indexed.append(IndexedFile(relative, size, _language(path), text, file_symbols))
        return RepositorySnapshot(
            signature=signature,
            files=tuple(indexed),
            symbols=tuple(symbols),
            all_paths=tuple(all_paths),
            indexed_bytes=indexed_bytes,
            truncated=truncated,
        )

    def snapshot(self) -> RepositorySnapshot:
        files, truncated = self._walk()
        signature = self._signature(files, self.root, truncated)
        if self._snapshot is None or self._snapshot.signature != signature:
            self._snapshot = self._build_snapshot(files, signature, truncated)
        return self._snapshot

    def repo_tree(self, *, max_depth: int = 5, max_entries: int = 250) -> dict[str, object]:
        if isinstance(max_depth, bool) or not isinstance(max_depth, int) or not 1 <= max_depth <= MAX_TREE_DEPTH:
            raise ValueError(f"max_depth must be between 1 and {MAX_TREE_DEPTH}")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or not 1 <= max_entries <= MAX_TREE_ENTRIES:
            raise ValueError(f"max_entries must be between 1 and {MAX_TREE_ENTRIES}")
        snapshot = self.snapshot()
        selected = [path for path in snapshot.all_paths if len(Path(path).parts) <= max_depth][:max_entries]
        previous: tuple[str, ...] = ()
        lines: list[str] = ["."]
        for raw in selected:
            parts = Path(raw).parts
            common = 0
            while common < len(previous) and common < len(parts) - 1 and previous[common] == parts[common]:
                common += 1
            for index in range(common, len(parts) - 1):
                lines.append("  " * (index + 1) + parts[index] + "/")
            lines.append("  " * len(parts) + parts[-1])
            previous = parts[:-1]
        return {
            "tree": "\n".join(lines),
            "file_count": len(snapshot.all_paths),
            "shown_files": len(selected),
            "truncated": snapshot.truncated or len(selected) < len(snapshot.all_paths),
            "snapshot": snapshot.signature,
        }

    def symbol_index(self, *, query: str = "", path: str = ".", limit: int = 100) -> dict[str, object]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError("limit must be between 1 and 200")
        snapshot = self.snapshot()
        prefix = "" if path in {"", "."} else path.strip("/\\").replace("\\", "/") + "/"
        symbols = [s for s in snapshot.symbols if not prefix or s.path == prefix[:-1] or s.path.startswith(prefix)]
        if query:
            terms = _query_terms(query)
            def score(symbol: SymbolInfo) -> float:
                value = 0.0
                for term in terms:
                    name = symbol.name.casefold()
                    qual = symbol.qualname.casefold()
                    if term == name or term == qual:
                        value += 8
                    elif term in name or term in qual:
                        value += 4
                    if term in symbol.path.casefold():
                        value += 2
                return value
            symbols = [s for s in symbols if score(s) > 0]
            symbols.sort(key=lambda s: (-score(s), s.path, s.start_line))
        else:
            symbols.sort(key=lambda s: (s.path, s.start_line, s.qualname))
        selected = symbols[:limit]
        return {
            "symbols": [symbol.as_payload() for symbol in selected],
            "count": len(selected),
            "total_symbols": len(snapshot.symbols),
            "truncated": len(symbols) > limit or snapshot.truncated,
            "snapshot": snapshot.signature,
        }

    def repo_skeleton(self, *, paths: Sequence[str] | None = None, max_files: int = 8) -> dict[str, object]:
        if isinstance(max_files, bool) or not isinstance(max_files, int) or not 1 <= max_files <= MAX_SKELETON_FILES:
            raise ValueError(f"max_files must be between 1 and {MAX_SKELETON_FILES}")
        snapshot = self.snapshot()
        by_path = snapshot.by_path
        if paths is not None:
            if isinstance(paths, (str, bytes)) or not isinstance(paths, Sequence):
                raise ValueError("paths must be an array")
            if len(paths) > MAX_SKELETON_FILES:
                raise ValueError(f"paths may contain at most {MAX_SKELETON_FILES} entries")
            selected_paths: list[str] = []
            for raw in paths:
                if not isinstance(raw, str) or not raw:
                    raise ValueError("each path must be non-empty text")
                normalized = raw.replace("\\", "/").lstrip("./")
                if normalized not in by_path:
                    raise ValueError(f"path is not indexed: {raw}")
                selected_paths.append(normalized)
        else:
            source_files = [item for item in snapshot.files if Path(item.path).suffix.lower() in SOURCE_EXTENSIONS]
            source_files.sort(key=lambda item: (-len(item.symbols), item.path))
            selected_paths = [item.path for item in source_files[:max_files]]
        selected_paths = selected_paths[:max_files]
        chunks: list[str] = []
        included: list[str] = []
        truncated = False
        for path in selected_paths:
            item = by_path[path]
            body = [
                f"- {symbol.kind} {symbol.qualname} @ {symbol.start_line}-{symbol.end_line}: {symbol.signature}"
                for symbol in item.symbols
            ] or ["- <no indexed symbols>"]
            candidate = f"## {path} [{item.language}]\n" + "\n".join(body)
            projected = "\n\n".join((*chunks, candidate))
            if len(projected) > MAX_SKELETON_CHARS:
                truncated = True
                break
            chunks.append(candidate)
            included.append(path)
        return {
            "skeleton": "\n\n".join(chunks),
            "paths": included,
            "truncated": truncated or len(included) < len(selected_paths),
            "snapshot": snapshot.signature,
        }

    def rank_relevant_files(self, *, query: str, limit: int = 8) -> dict[str, object]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_RANK_RESULTS:
            raise ValueError(f"limit must be between 1 and {MAX_RANK_RESULTS}")
        terms = _query_terms(query)
        snapshot = self.snapshot()
        searchable = [item for item in snapshot.files if item.text is not None]
        document_frequency = {term: 0 for term in terms}
        lowered: dict[str, str] = {}
        for item in searchable:
            haystack = f"{item.path}\n{item.text or ''}".casefold()
            lowered[item.path] = haystack
            for term in terms:
                if term in haystack:
                    document_frequency[term] += 1
        ranked: list[dict[str, object]] = []
        total_docs = max(1, len(searchable))
        for item in searchable:
            path_lower = item.path.casefold()
            basename = Path(item.path).name.casefold()
            stem = Path(item.path).stem.casefold()
            symbol_names = tuple({s.name.casefold() for s in item.symbols} | {s.qualname.casefold() for s in item.symbols})
            score = 0.0
            reasons: list[tuple[float, str]] = []
            for term in terms:
                idf = math.log((total_docs + 1) / (document_frequency[term] + 1)) + 1.0
                contribution = 0.0
                labels: list[str] = []
                if term == basename or term == stem:
                    contribution += 8.0 * idf
                    labels.append("filename")
                elif term in basename:
                    contribution += 4.0 * idf
                    labels.append("filename-part")
                elif term in path_lower:
                    contribution += 2.5 * idf
                    labels.append("path")
                if any(term == name for name in symbol_names):
                    contribution += 7.0 * idf
                    labels.append("symbol")
                elif any(term in name for name in symbol_names):
                    contribution += 3.5 * idf
                    labels.append("symbol-part")
                occurrences = lowered[item.path].count(term)
                if occurrences:
                    contribution += min(4.0, 1.0 + math.log2(occurrences + 1)) * idf
                    labels.append(f"text×{min(occurrences, 99)}")
                if contribution:
                    score += contribution
                    reasons.append((contribution, f"{term}:" + "+".join(labels)))
            if score <= 0:
                continue
            reasons.sort(key=lambda pair: (-pair[0], pair[1]))
            matching_symbols = sorted(
                {s.qualname for s in item.symbols if any(term in s.qualname.casefold() for term in terms)},
                key=str.casefold,
            )[:6]
            ranked.append(
                {
                    "path": item.path,
                    "score": score,
                    "reasons": [reason for _, reason in reasons[:5]],
                    "top_symbols": matching_symbols,
                }
            )
        ranked.sort(key=lambda item: (-float(item["score"]), str(item["path"])))
        selected = ranked[:limit]
        for item in selected:
            item["score"] = round(float(item["score"]), 3)
        return {
            "query_terms": list(terms),
            "candidates": selected,
            "indexed_files": len(searchable),
            "indexed_bytes": snapshot.indexed_bytes,
            "truncated": len(ranked) > limit or snapshot.truncated,
            "snapshot": snapshot.signature,
        }

    def inspect_symbol(
        self,
        *,
        symbol: str,
        path: str | None = None,
        context_lines: int = 12,
        max_references: int = 12,
    ) -> dict[str, object]:
        if not isinstance(symbol, str) or not symbol.strip():
            raise ValueError("symbol must be non-empty text")
        if isinstance(context_lines, bool) or not isinstance(context_lines, int) or not 0 <= context_lines <= 40:
            raise ValueError("context_lines must be between 0 and 40")
        if isinstance(max_references, bool) or not isinstance(max_references, int) or not 0 <= max_references <= MAX_REFERENCES:
            raise ValueError(f"max_references must be between 0 and {MAX_REFERENCES}")
        raw_symbol = symbol.strip()
        if "::" in raw_symbol and path is None:
            path, raw_symbol = raw_symbol.split("::", 1)
        normalized_path = path.replace("\\", "/").lstrip("./") if isinstance(path, str) and path else None
        needle = raw_symbol.casefold()
        snapshot = self.snapshot()
        matches = [
            candidate for candidate in snapshot.symbols
            if (normalized_path is None or candidate.path == normalized_path)
            and (candidate.name.casefold() == needle or candidate.qualname.casefold() == needle)
        ]
        if not matches:
            matches = [
                candidate for candidate in snapshot.symbols
                if (normalized_path is None or candidate.path == normalized_path)
                and (needle in candidate.name.casefold() or needle in candidate.qualname.casefold())
            ][:10]
        if not matches:
            return {"found": False, "symbol": raw_symbol, "path": normalized_path, "candidates": [], "snapshot": snapshot.signature}
        if len(matches) > 1:
            exact = [m for m in matches if m.qualname.casefold() == needle or m.name.casefold() == needle]
            if len(exact) == 1:
                matches = exact
            else:
                return {
                    "found": False,
                    "ambiguous": True,
                    "symbol": raw_symbol,
                    "candidates": [m.as_payload() for m in sorted(matches, key=lambda x: (x.path, x.start_line))[:10]],
                    "snapshot": snapshot.signature,
                }
        selected = matches[0]
        indexed = snapshot.by_path.get(selected.path)
        if indexed is None or indexed.text is None:
            raise ValueError(f"symbol source is not text-indexed: {selected.path}")
        lines = indexed.text.splitlines()
        first = max(1, selected.start_line - context_lines)
        last = min(len(lines), max(selected.end_line, selected.start_line) + context_lines, first + MAX_INSPECT_LINES - 1)
        source = _numbered(lines[first - 1:last], first)
        references: list[dict[str, object]] = []
        if max_references:
            reference_re = re.compile(rf"(?<![\w$]){re.escape(selected.name)}(?![\w$])")
            for item in snapshot.files:
                if item.text is None:
                    continue
                for lineno, line in enumerate(item.text.splitlines(), 1):
                    if not reference_re.search(line):
                        continue
                    if item.path == selected.path and selected.start_line <= lineno <= selected.end_line:
                        continue
                    references.append({"path": item.path, "line": lineno, "snippet": _bounded(line, MAX_SNIPPET_CHARS)})
                    if len(references) >= max_references:
                        break
                if len(references) >= max_references:
                    break
        return {
            "found": True,
            "symbol": selected.as_payload(),
            "source": {"start_line": first, "end_line": last, "content": source, "truncated": first > 1 or last < len(lines)},
            "references": references,
            "reference_count": len(references),
            "snapshot": snapshot.signature,
        }


DISTILLER_TOOL_SPECS = (
    ToolSpec(
        "repo_tree",
        "Compact bounded repository tree. Prefer it before broad file-by-file exploration.",
        {"max_depth": "integer=5", "max_entries": "integer=250"},
        ("audit", "fix", "forensics", "general"),
        CapabilityLevel.INSPECT,
        False,
        "repository-distiller",
    ),
    ToolSpec(
        "symbol_index",
        "Cross-language class/function/type/constant index. Use query to locate named code elements.",
        {"query": "string=''", "path": "string=.", "limit": "integer=100"},
        ("audit", "fix", "forensics", "general"),
        CapabilityLevel.INSPECT,
        False,
        "repository-distiller",
    ),
    ToolSpec(
        "repo_skeleton",
        "Compact signatures for selected source files without function bodies. Pass ranked paths.",
        {"paths": "string[] optional", "max_files": "integer=8"},
        ("audit", "fix", "forensics", "general"),
        CapabilityLevel.INSPECT,
        False,
        "repository-distiller",
    ),
    ToolSpec(
        "rank_relevant_files",
        "Rank repository files for a task/query using paths, symbols and bounded text evidence.",
        {"query": "string", "limit": "integer=8"},
        ("audit", "fix", "forensics", "general"),
        CapabilityLevel.ANALYZE,
        False,
        "repository-distiller",
    ),
    ToolSpec(
        "inspect_symbol",
        "Inspect one symbol with bounded source context and repository references. Supports path::Qualified.name.",
        {"symbol": "string", "path": "string optional", "context_lines": "integer=12", "max_references": "integer=12"},
        ("audit", "fix", "forensics", "general"),
        CapabilityLevel.INSPECT,
        False,
        "repository-distiller",
    ),
)


class RepositoryDistillerProvider:
    name = "repository-distiller"

    def __init__(self, workdir: Path | str):
        self.distiller = RepositoryDistiller(workdir)

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        return DISTILLER_TOOL_SPECS

    @staticmethod
    def _only(arguments: dict[str, Any], allowed: set[str], action: str) -> None:
        unknown = sorted(set(arguments) - allowed)
        if unknown:
            raise ValueError(f"unsupported {action} argument(s): {unknown}")

    def execute(self, action: AgentAction, context: ExecutionContext) -> ToolResult:
        try:
            arguments = action.arguments
            if not isinstance(arguments, dict):
                raise ValueError("action arguments must be an object")
            if action.name == "repo_tree":
                self._only(arguments, {"max_depth", "max_entries"}, action.name)
                data = self.distiller.repo_tree(max_depth=arguments.get("max_depth", 5), max_entries=arguments.get("max_entries", 250))
                return ToolResult(True, "repository tree distilled", data)
            if action.name == "symbol_index":
                self._only(arguments, {"query", "path", "limit"}, action.name)
                data = self.distiller.symbol_index(query=arguments.get("query", ""), path=arguments.get("path", "."), limit=arguments.get("limit", 100))
                return ToolResult(True, f"symbol index returned {data['count']} symbol(s)", data)
            if action.name == "repo_skeleton":
                self._only(arguments, {"paths", "max_files"}, action.name)
                data = self.distiller.repo_skeleton(paths=arguments.get("paths"), max_files=arguments.get("max_files", 8))
                return ToolResult(True, f"repository skeleton returned {len(data['paths'])} file(s)", data)
            if action.name == "rank_relevant_files":
                self._only(arguments, {"query", "limit"}, action.name)
                if "query" not in arguments:
                    raise ValueError("rank_relevant_files requires query")
                data = self.distiller.rank_relevant_files(query=arguments["query"], limit=arguments.get("limit", 8))
                return ToolResult(True, f"ranked {len(data['candidates'])} relevant repository file(s)", data)
            if action.name == "inspect_symbol":
                self._only(arguments, {"symbol", "path", "context_lines", "max_references"}, action.name)
                if "symbol" not in arguments:
                    raise ValueError("inspect_symbol requires symbol")
                data = self.distiller.inspect_symbol(
                    symbol=arguments["symbol"],
                    path=arguments.get("path"),
                    context_lines=arguments.get("context_lines", 12),
                    max_references=arguments.get("max_references", 12),
                )
                summary = f"inspected symbol {data['symbol']['qualname']}" if data.get("found") else "symbol lookup returned no unique match"
                return ToolResult(True, summary, data)
            return ToolResult(False, f"unknown repository distiller action: {action.name}")
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return ToolResult(False, f"{action.name} failed: {error}")
