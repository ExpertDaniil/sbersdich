"""Model-facing semantic namespace and compact repository guide.

The task workspace is never renamed.  Instead, the model sees stable semantic file
aliases (plus short Fxxx handles) while tools resolve them back to the original
workspace paths.  A compact virtual ``REPO_GUIDE.md`` is generated deterministically
from paths, symbols and tests so localization metadata costs no LLM call.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from agent.core.models import ToolResult

from .aci import CyberACIProvider
from .contracts import ExecutionContext, ToolSpec
from .distiller import IndexedFile, RepositoryDistiller


MAX_ALIAS_BYTES = 180
MAX_GUIDE_CHARS = 6_000
MAX_GUIDE_FILES = 18
MAX_CARD_SYMBOLS = 4
MAX_TEST_CONTRACTS = 6

_TEST_PARTS = frozenset({"test", "tests", "testing", "spec", "specs"})
_CONFIG_NAMES = frozenset(
    {
        "pyproject.toml",
        "package.json",
        "package-lock.json",
        "requirements.txt",
        "poetry.lock",
        "dockerfile",
        "compose.yml",
        "compose.yaml",
    }
)
_DOMAIN_TERMS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "authz",
        (
            "authorization",
            "authorisation",
            "permission",
            "permissions",
            "access_control",
            "accesscontrol",
            "can_delete",
            "can_edit",
            "can_write",
            "is_allowed",
            "is_authorized",
            "role",
        ),
    ),
    (
        "authn",
        (
            "authentication",
            "authenticate",
            "login",
            "signin",
            "password",
            "credential",
            "session",
            "token",
            "oauth",
        ),
    ),
    (
        "database",
        (
            "database",
            "postgres",
            "sqlite",
            "mysql",
            "sql",
            "query",
            "fetchrow",
            "execute",
            "repository",
        ),
    ),
    (
        "http",
        (
            "router",
            "route",
            "endpoint",
            "request",
            "response",
            "controller",
            "fastapi",
            "flask",
            "django",
        ),
    ),
    (
        "crypto",
        ("crypto", "encrypt", "decrypt", "cipher", "hash", "hmac", "jwt", "signature"),
    ),
    (
        "filesystem",
        ("upload", "download", "filename", "filepath", "filesystem", "read_file", "write_file"),
    ),
    (
        "process",
        ("subprocess", "shell", "command", "exec", "spawn", "popen", "system"),
    ),
    (
        "config",
        ("config", "settings", "environment", "dotenv", "secret", "credential"),
    ),
)
_SECURITY_TAGS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("authz", ("permission", "role", "authorization", "can_delete", "is_allowed")),
    ("authn", ("login", "password", "token", "session", "credential")),
    ("sql", ("select ", "insert ", "update ", "delete ", "execute(", "fetchrow(")),
    ("command", ("subprocess", "os.system", "shell=true", "shell = true", "popen")),
    ("deser", ("pickle.load", "yaml.load", "deserialize")),
    ("path", ("open(", "pathlib", "upload", "filename")),
)


def _is_test_path(path: str) -> bool:
    pure = Path(path)
    stem = pure.stem.casefold()
    return (
        bool({part.casefold() for part in pure.parts}.intersection(_TEST_PARTS))
        or stem.startswith("test_")
        or stem.endswith("_test")
    )


def _slug(value: str, *, limit: int = 44) -> str:
    out: list[str] = []
    previous_sep = False
    for char in value.casefold():
        if char.isalnum():
            out.append(char)
            previous_sep = False
        elif not previous_sep:
            out.append("_")
            previous_sep = True
        if len("".join(out).encode("utf-8")) >= limit:
            break
    result = "".join(out).strip("_")
    return result or "file"


def _bounded_alias(stem: str, suffix: str, *, salt: str) -> str:
    alias = stem + suffix
    if len(alias.encode("utf-8")) <= MAX_ALIAS_BYTES:
        return alias
    digest = hashlib.sha256(salt.encode("utf-8", "surrogatepass")).hexdigest()[:8]
    budget = max(24, MAX_ALIAS_BYTES - len(("__" + digest + suffix).encode("utf-8")))
    raw = stem.encode("utf-8")[:budget]
    safe = raw.decode("utf-8", "ignore").rstrip("_")
    return f"{safe}__{digest}{suffix}"


def _python_function_summaries(text: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ()
    result: list[str] = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = [arg.arg for arg in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs)]
        if node.args.vararg:
            args.append("*" + node.args.vararg.arg)
        if node.args.kwarg:
            args.append("**" + node.args.kwarg.arg)
        return_name = "?"
        if node.returns is not None:
            try:
                return_name = ast.unparse(node.returns)
            except (ValueError, TypeError):
                return_name = "?"
        result.append(f"{node.name}({','.join(args)})->{return_name}")
        if len(result) >= MAX_CARD_SYMBOLS:
            break
    return tuple(result)


def _literal_value(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int, float, bool, type(None))):
        return str(node.value).casefold() if isinstance(node.value, bool) else str(node.value)
    return None


def _call_contract(call: ast.Call, expected: bool) -> str | None:
    if isinstance(call.func, ast.Name):
        name = call.func.id
    elif isinstance(call.func, ast.Attribute):
        name = call.func.attr
    else:
        return None
    arguments: list[str] = []
    for arg in call.args[:2]:
        if isinstance(arg, ast.Dict):
            pairs: list[str] = []
            for key_node, value_node in zip(arg.keys, arg.values):
                if key_node is None:
                    continue
                key = _literal_value(key_node)
                value = _literal_value(value_node)
                if key is not None and value is not None:
                    pairs.append(f"{key}={value}")
            if pairs:
                arguments.append(",".join(pairs[:4]))
        else:
            value = _literal_value(arg)
            if value is not None:
                arguments.append(value)
    rendered = ";".join(arguments) if arguments else "..."
    return f"{name}({rendered})=>{'true' if expected else 'false'}"


def _python_test_contracts(text: str) -> tuple[str, ...]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return ()
    result: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assert):
            continue
        expression = node.test
        expected = True
        if isinstance(expression, ast.UnaryOp) and isinstance(expression.op, ast.Not):
            expected = False
            expression = expression.operand
        if not isinstance(expression, ast.Call):
            continue
        contract = _call_contract(expression, expected)
        if contract and contract not in result:
            result.append(contract)
        if len(result) >= MAX_TEST_CONTRACTS:
            break
    return tuple(result)


def _domain_for(item: IndexedFile) -> str:
    if _is_test_path(item.path):
        return "tests"
    basename = Path(item.path).name.casefold()
    if basename in _CONFIG_NAMES or Path(item.path).suffix.casefold() in {".toml", ".ini", ".cfg"}:
        return "config"
    symbols = " ".join(symbol.qualname for symbol in item.symbols)
    sample = (item.text or "")[:16_000]
    haystack = f"{item.path} {symbols} {sample}".casefold()
    for domain, terms in _DOMAIN_TERMS:
        if any(term in haystack for term in terms):
            return domain
    return "code" if item.symbols else "data"


def _kind_for(item: IndexedFile) -> str:
    if _is_test_path(item.path):
        return "tests"
    name = Path(item.path).name.casefold()
    suffix = Path(item.path).suffix.casefold()
    if name in _CONFIG_NAMES or suffix in {".toml", ".ini", ".cfg", ".yaml", ".yml"}:
        return "config"
    if suffix in {".json", ".xml"} and not item.symbols:
        return "data"
    if suffix == ".sql" and not item.symbols:
        return "schema"
    if suffix in {".md", ".rst", ".txt"}:
        return "document"
    if suffix in {".sh", ".ps1"}:
        return "script"
    return "impl"


def _purpose_for(item: IndexedFile) -> str:
    names = [symbol.name for symbol in item.symbols if symbol.kind != "constant"]
    if _is_test_path(item.path):
        test_names = [name.removeprefix("test_") for name in names if name.startswith("test_")]
        if test_names:
            return _slug("_".join(test_names[:2]), limit=52)
    if names:
        return _slug("_".join(names[:2]), limit=52)
    return _slug(Path(item.path).stem, limit=52)


def _security_tags(item: IndexedFile) -> tuple[str, ...]:
    haystack = f"{item.path}\n{item.text or ''}".casefold()
    result: list[str] = []
    for tag, terms in _SECURITY_TAGS:
        if any(term in haystack for term in terms):
            result.append(tag)
    return tuple(result[:4])


@dataclass(frozen=True)
class SemanticFileCard:
    handle: str
    real_path: str
    semantic_path: str
    role: str
    symbols: tuple[str, ...]
    signatures: tuple[str, ...]
    contracts: tuple[str, ...]
    security_tags: tuple[str, ...]
    tested_by: tuple[str, ...] = ()


class SemanticRepositoryContext:
    """Deterministic semantic aliases + virtual model-only REPO_GUIDE.md."""

    def __init__(self, workdir: Path | str, *, distiller: RepositoryDistiller):
        self.workdir = Path(workdir).resolve()
        self.distiller = distiller
        self._signature = ""
        self._output_paths: set[str] = set()
        self._stable_handles: dict[str, str] = {}
        self._cards: tuple[SemanticFileCard, ...] = ()
        self._by_real: dict[str, SemanticFileCard] = {}
        self._by_alias: dict[str, SemanticFileCard] = {}
        self._by_handle: dict[str, SemanticFileCard] = {}

    def set_output_paths(self, paths: tuple[Path, ...]) -> None:
        self._output_paths = {path.resolve().relative_to(self.workdir).as_posix() for path in paths}
        self._signature = ""

    def is_task_output(self, path: str) -> bool:
        return path in self._output_paths

    def _refresh(self) -> None:
        snapshot = self.distiller.snapshot()
        if snapshot.signature == self._signature:
            return

        draft: list[SemanticFileCard] = []
        used_aliases: set[str] = set()
        for index, item in enumerate(sorted(snapshot.files, key=lambda entry: entry.path), 1):
            domain = _domain_for(item)
            kind = "candidate_output" if self.is_task_output(item.path) else _kind_for(item)
            if item.path not in self._stable_handles:
                self._stable_handles[item.path] = f"F{len(self._stable_handles) + 1:03d}"
            purpose = _purpose_for(item)
            suffix = Path(item.path).suffix.casefold()
            alias = _bounded_alias(f"{domain}__{purpose}__{kind}", suffix, salt=item.path)
            if alias in used_aliases:
                digest = hashlib.sha256(item.path.encode("utf-8", "surrogatepass")).hexdigest()[:6]
                alias = _bounded_alias(
                    f"{Path(alias).stem}__{digest}", suffix, salt=item.path + digest
                )
            used_aliases.add(alias)
            symbols = tuple(symbol.qualname for symbol in item.symbols[:MAX_CARD_SYMBOLS])
            signatures = _python_function_summaries(item.text or "") if item.language == "python" else ()
            contracts = (
                _python_test_contracts(item.text or "")
                if item.language == "python" and _is_test_path(item.path)
                else ()
            )
            draft.append(
                SemanticFileCard(
                    handle=self._stable_handles[item.path],
                    real_path=item.path,
                    semantic_path=alias,
                    role=f"{domain}-{kind}",
                    symbols=symbols,
                    signatures=signatures,
                    contracts=contracts,
                    security_tags=_security_tags(item),
                )
            )

        tests = [card for card in draft if card.role.startswith("tests-")]
        by_path = snapshot.by_path
        related: dict[str, list[str]] = {card.real_path: [] for card in draft}
        for card in draft:
            if card.role.startswith("tests-") or not card.symbols:
                continue
            needles = {symbol.split(".")[-1] for symbol in card.symbols if len(symbol.split(".")[-1]) >= 3}
            if not needles:
                continue
            for test_card in tests:
                test_item = by_path.get(test_card.real_path)
                text = test_item.text if test_item is not None else None
                if text and any(needle in text for needle in needles):
                    related[card.real_path].append(test_card.handle)
                    if len(related[card.real_path]) >= 3:
                        break

        cards = tuple(
            replace(card, tested_by=tuple(related.get(card.real_path, ()))) for card in draft
        )
        self._cards = cards
        self._by_real = {card.real_path: card for card in cards}
        self._by_alias = {card.semantic_path: card for card in cards}
        self._by_handle = {card.handle.casefold(): card for card in cards}
        self._signature = snapshot.signature

    def card_for(self, path: object) -> SemanticFileCard | None:
        self._refresh()
        if not isinstance(path, str) or not path:
            return None
        normalized = path.replace("\\", "/").lstrip("./")
        return (
            self._by_real.get(normalized)
            or self._by_alias.get(normalized)
            or self._by_handle.get(normalized.casefold())
        )

    def resolve(self, path: object) -> object:
        if not isinstance(path, str) or path in {"", "."}:
            return path
        card = self.card_for(path)
        return card.real_path if card is not None else path

    def semantic_path(self, path: object) -> str:
        if not isinstance(path, str):
            return str(path)
        card = self.card_for(path)
        return card.semantic_path if card is not None else path

    def handle(self, path: object) -> str | None:
        card = self.card_for(path)
        return card.handle if card is not None else None

    def task_guide(self, instruction: str) -> str:
        self._refresh()
        selected_real: list[str] = []
        try:
            ranked = self.distiller.rank_relevant_files(query=instruction, limit=12)
            selected_real.extend(
                str(candidate["path"])
                for candidate in ranked.get("candidates", ())
                if str(candidate.get("path", "")) in self._by_real
            )
        except (OSError, UnicodeError, ValueError, RuntimeError):
            selected_real = []

        if not selected_real:
            selected_real.extend(
                card.real_path
                for card in self._cards
                if card.symbols or card.role.startswith("tests-")
            )
        if not selected_real:
            selected_real.extend(card.real_path for card in self._cards)

        selected: list[SemanticFileCard] = []
        seen: set[str] = set()
        for real_path in selected_real:
            card = self._by_real.get(real_path)
            if card is None or card.real_path in seen or self.is_task_output(card.real_path):
                continue
            selected.append(card)
            seen.add(card.real_path)
            for test_handle in card.tested_by:
                test_card = self._by_handle.get(test_handle.casefold())
                if test_card is not None and test_card.real_path not in seen:
                    selected.append(test_card)
                    seen.add(test_card.real_path)
            if len(selected) >= MAX_GUIDE_FILES:
                break
        selected = selected[:MAX_GUIDE_FILES]

        lines = [
            "# REPO_GUIDE.md (virtual; model-only)",
            "Fxxx handles and semantic paths are aliases resolved by the runtime; the workspace is not renamed.",
            "Use this as localization metadata, then trust source/tool/validator evidence for conclusions.",
        ]
        for card in selected:
            fields = [
                f"{card.handle} {card.semantic_path}",
                f"ROLE={card.role}",
                f"source_path={card.real_path}",
            ]
            if card.symbols:
                fields.append("DEF=" + ",".join(card.symbols[:MAX_CARD_SYMBOLS]))
            if card.signatures:
                fields.append("IO=" + ";".join(card.signatures[:3]))
            if card.contracts:
                fields.append("CONTRACT=" + ";".join(card.contracts[:MAX_TEST_CONTRACTS]))
            if card.tested_by:
                fields.append("TEST=" + ",".join(card.tested_by))
            if card.security_tags:
                fields.append("SEC=" + ",".join(card.security_tags))
            candidate = " | ".join(fields)
            projected = "\n".join((*lines, candidate))
            if len(projected) > MAX_GUIDE_CHARS:
                lines.append("... guide truncated ...")
                break
            lines.append(candidate)
        return "\n".join(lines)


class SemanticCyberACIProvider(CyberACIProvider):
    """Cyber ACI whose model-facing paths use the semantic namespace."""

    def __init__(
        self,
        workdir: Path | str,
        *,
        distiller: RepositoryDistiller,
        semantic_context: SemanticRepositoryContext,
    ):
        super().__init__(workdir, distiller=distiller)
        self.semantic_context = semantic_context
        self._git_available = (self.workdir / ".git").exists()

    def catalog(self, context: ExecutionContext) -> tuple[ToolSpec, ...]:
        specs = super().catalog(context)
        result: list[ToolSpec] = []
        for spec in specs:
            if spec.name in {"view_window", "checked_edit"}:
                result.append(
                    replace(
                        spec,
                        description=spec.description
                        + " Path accepts an Fxxx handle or semantic path from REPO_GUIDE.md.",
                    )
                )
            elif spec.name == "search_surface":
                result.append(
                    replace(
                        spec,
                        description=spec.description
                        + " Results expose semantic paths and compact Fxxx handles.",
                    )
                )
            elif spec.name == "run_check":
                profiles = "python-syntax or pytest"
                if self._git_available:
                    profiles += ", git-diff or git-status"
                result.append(
                    replace(
                        spec,
                        description=f"Run one structured proof/check profile: {profiles}. After a successful model-driven mutation the runtime performs final validation automatically.",
                    )
                )
            else:
                result.append(spec)
        return tuple(result)

    def _decorate_path(self, data: dict[str, Any], real_path: str) -> dict[str, Any]:
        payload = dict(data)
        payload["path"] = self.semantic_context.semantic_path(real_path)
        payload["source_path"] = real_path
        payload["provenance"] = ("task_output_candidate_not_evidence"
                                 if self.semantic_context.is_task_output(real_path) else "workspace_read")
        handle = self.semantic_context.handle(real_path)
        if handle:
            payload["handle"] = handle
        return payload

    def _search_surface(self, arguments: dict[str, Any]) -> ToolResult:
        mapped = dict(arguments)
        if "path" in mapped:
            mapped["path"] = self.semantic_context.resolve(mapped["path"])
        result = super()._search_surface(mapped)
        if not result.ok:
            return result
        data = dict(result.data)
        decorated: list[dict[str, Any]] = []
        for raw in data.get("results", []):
            item = dict(raw)
            real_path = str(item.get("path", ""))
            semantic = self.semantic_context.semantic_path(real_path)
            item["path"] = semantic
            item["source_path"] = real_path
            item["provenance"] = ("task_output_candidate_not_evidence"
                                  if self.semantic_context.is_task_output(real_path) else "workspace_read")
            handle = self.semantic_context.handle(real_path)
            if handle:
                item["handle"] = handle
            item["ref"] = f"{handle or semantic}:{item.get('line', 1)}"
            decorated.append(item)
        data["results"] = decorated
        return ToolResult(result.ok, result.summary, data)

    def _view_payload(
        self, *, path: object, start_line: object, max_lines: object
    ) -> dict[str, Any]:
        real = self.semantic_context.resolve(path)
        data = super()._view_payload(path=real, start_line=start_line, max_lines=max_lines)
        real_path = str(data["path"])
        return self._decorate_path(data, real_path)

    def _checked_edit(self, arguments: dict[str, Any]) -> ToolResult:
        mapped = dict(arguments)
        original_path = mapped.get("path")
        mapped["path"] = self.semantic_context.resolve(original_path)
        result = super()._checked_edit(mapped)
        if not result.data:
            return result
        data = dict(result.data)
        real_path = str(data.get("path", mapped.get("path", "")))
        semantic = self.semantic_context.semantic_path(real_path)
        data["path"] = semantic
        handle = self.semantic_context.handle(real_path)
        if handle:
            data["handle"] = handle
        if isinstance(data.get("diff"), str) and real_path:
            data["diff"] = str(data["diff"]).replace(f"a/{real_path}", f"a/{semantic}").replace(
                f"b/{real_path}", f"b/{semantic}"
            )
        summary = result.summary.replace(real_path, semantic) if real_path else result.summary
        return ToolResult(result.ok, summary, data)

    def _run_check(self, arguments: dict[str, Any]) -> ToolResult:
        profile = str(arguments.get("profile", "")).casefold()
        if profile in {"git-diff", "git-status"} and not self._git_available:
            return ToolResult(
                False,
                "git checks unavailable: workspace is not a Git repository",
                {"profile": profile, "available": False},
            )
        mapped = dict(arguments)
        if "target" in mapped and mapped["target"] not in {"", "."}:
            mapped["target"] = self.semantic_context.resolve(mapped["target"])
        return super()._run_check(mapped)
