#!/usr/bin/env python3
"""Conservative AST scanner for tainted data reaching Python SQL calls."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


SQL_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "fetch",
        "fetchall",
        "fetchone",
        "fetchrow",
        "query",
        "raw",
    }
)
SQL_KEYWORD_RE = re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|WITH)\b", re.IGNORECASE)
EXCLUDED_DIRECTORIES = frozenset(
    {".git", ".hg", ".mypy_cache", ".pytest_cache", ".tox", ".venv", "__pycache__", "node_modules", "tests", "test"}
)


class ScanError(RuntimeError):
    """Raised when a project cannot be scanned reliably."""


@dataclass(frozen=True)
class DynamicSql:
    kind: str
    expressions: tuple[str, ...]
    source_line: int


@dataclass(frozen=True)
class Finding:
    title: str
    severity: str
    category: str
    location: str
    evidence: str
    impact: str
    recommendation: str

    def as_report_item(self) -> dict[str, str]:
        return asdict(self)


def source_segment(source: str, node: ast.AST) -> str:
    return ast.get_source_segment(source, node) or ast.unparse(node)


def expression_uses_tainted(node: ast.AST, tainted_names: set[str]) -> bool:
    return any(
        isinstance(child, ast.Name) and child.id in tainted_names
        for child in ast.walk(node)
    )


def expression_is_injection_safe_scalar(node: ast.AST) -> bool:
    """Recognize conversions whose output cannot alter SQL token structure."""

    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"len"}
    )


def assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        names: set[str] = set()
        for element in node.elts:
            names.update(assigned_names(element))
        return names
    return set()


def function_argument_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = function.args
    names = {
        argument.arg
        for argument in (
            list(arguments.posonlyargs)
            + list(arguments.args)
            + list(arguments.kwonlyargs)
        )
        if argument.arg not in {"self", "cls"}
    }
    if arguments.vararg:
        names.add(arguments.vararg.arg)
    if arguments.kwarg:
        names.add(arguments.kwarg.arg)
    return names


class _FunctionScopeCollector(ast.NodeVisitor):
    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef):
        self.root = root
        self.nodes: list[ast.AST] = []

    def generic_visit(self, node: ast.AST) -> None:
        self.nodes.append(node)
        super().generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return


def function_scope_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    collector = _FunctionScopeCollector(function)
    collector.visit(function)
    return collector.nodes


def infer_tainted_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    """Treat function inputs and values derived from them as untrusted."""

    tainted = function_argument_names(function)
    changed = True
    scope_nodes = function_scope_nodes(function)
    while changed:
        changed = False
        for node in scope_nodes:
            targets: set[str] = set()
            value: ast.AST | None = None
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        targets.update(assigned_names(target))
                else:
                    targets.update(assigned_names(node.target))
                value = node.value
            elif isinstance(node, (ast.For, ast.AsyncFor)):
                targets.update(assigned_names(node.target))
                value = node.iter

            if value is None or not targets:
                continue
            if expression_uses_tainted(value, tainted):
                new_names = targets - tainted
                if new_names:
                    tainted.update(new_names)
                    changed = True
    return tainted


def static_sql_text(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        return "".join(
            value.value
            for value in node.values
            if isinstance(value, ast.Constant) and isinstance(value.value, str)
        )
    if isinstance(node, ast.BinOp):
        return f"{static_sql_text(node.left)} {static_sql_text(node.right)}"
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        return static_sql_text(node.func.value)
    return ""


def tainted_expression_sources(
    node: ast.AST, tainted_names: set[str], source: str
) -> tuple[str, ...]:
    expressions: list[str] = []
    if isinstance(node, ast.JoinedStr):
        candidates = [
            value.value for value in node.values if isinstance(value, ast.FormattedValue)
        ]
    elif (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
    ):
        candidates = list(node.args) + [keyword.value for keyword in node.keywords]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        candidates = [node.right]
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        candidates = [
            child
            for child in ast.walk(node)
            if isinstance(child, (ast.Name, ast.Attribute, ast.Subscript, ast.Call))
        ]
    else:
        candidates = []

    for candidate in candidates:
        if expression_is_injection_safe_scalar(candidate):
            continue
        if expression_uses_tainted(candidate, tainted_names):
            rendered = source_segment(source, candidate).strip()
            if rendered and rendered not in expressions:
                expressions.append(rendered)
    return tuple(expressions)


def dynamic_sql_from_expression(
    node: ast.AST,
    tainted_names: set[str],
    source: str,
) -> DynamicSql | None:
    sql_text = static_sql_text(node)
    if not SQL_KEYWORD_RE.search(sql_text):
        return None

    expressions = tainted_expression_sources(node, tainted_names, source)
    if not expressions:
        return None

    if isinstance(node, ast.JoinedStr):
        kind = "f-string"
    elif isinstance(node, ast.Call):
        kind = "str.format"
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
        kind = "percent-formatting"
    else:
        kind = "string-concatenation"
    return DynamicSql(kind=kind, expressions=expressions, source_line=node.lineno)


def function_display_name(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> str:
    return function.name


def call_method_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Attribute) and call.func.attr in SQL_METHODS:
        return call.func.attr
    return None


def audit_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    source: str,
    relative_path: Path,
) -> list[Finding]:
    tainted_names = infer_tainted_names(function)
    assignments: dict[str, DynamicSql] = {}
    scope_nodes = function_scope_nodes(function)
    for node in scope_nodes:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)):
            continue
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        info = dynamic_sql_from_expression(node.value, tainted_names, source)
        if info is None:
            continue
        for target in targets:
            for name in assigned_names(target):
                assignments[name] = info

    findings: list[Finding] = []
    seen_calls: set[tuple[int, int]] = set()
    for node in scope_nodes:
        if not isinstance(node, ast.Call) or not node.args:
            continue
        method = call_method_name(node)
        if method is None:
            continue
        first_argument = node.args[0]
        if isinstance(first_argument, ast.Name):
            info = assignments.get(first_argument.id)
        else:
            info = dynamic_sql_from_expression(first_argument, tainted_names, source)
        if info is None:
            continue
        call_key = (node.lineno, node.col_offset)
        if call_key in seen_calls:
            continue
        seen_calls.add(call_key)
        expression_list = ", ".join(info.expressions)
        findings.append(
            Finding(
                title="SQL injection through dynamic query construction",
                severity="high",
                category="CWE-89: SQL Injection",
                location=(
                    f"{relative_path.as_posix()}:{info.source_line} "
                    f"({function_display_name(function)})"
                ),
                evidence=(
                    f"Tainted expression(s) [{expression_list}] are interpolated via "
                    f"{info.kind} and reach database method {method}() at line {node.lineno}."
                ),
                impact=(
                    "An attacker may change the SQL statement, bypass authorization, "
                    "or read or modify database data."
                ),
                recommendation=(
                    "Keep the SQL statement constant and pass every untrusted value "
                    "through the database driver's parameter placeholders."
                ),
            )
        )
    return findings


def scan_python_source(source: str, relative_path: Path | str) -> list[Finding]:
    path = Path(relative_path)
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        raise ScanError(f"cannot parse {path}: {error}") from error

    findings: list[Finding] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            findings.extend(audit_function(node, source, path))
    return findings


def iter_python_files(root: Path, include_tests: bool = False) -> Iterable[Path]:
    candidates = [root] if root.is_file() else root.rglob("*.py")
    for path in sorted(candidates):
        if path.suffix != ".py" or not path.is_file():
            continue
        relative_parts = path.relative_to(root.parent if root.is_file() else root).parts
        excluded = EXCLUDED_DIRECTORIES - ({"test", "tests"} if include_tests else set())
        if any(part in excluded or part.startswith(".") for part in relative_parts[:-1]):
            continue
        yield path


def scan_project(root: Path | str, include_tests: bool = False) -> list[Finding]:
    project_root = Path(root).resolve()
    if not project_root.exists():
        raise ScanError(f"scan target does not exist: {project_root}")

    base = project_root.parent if project_root.is_file() else project_root
    findings: list[Finding] = []
    errors: list[str] = []
    for path in iter_python_files(project_root, include_tests=include_tests):
        try:
            source = path.read_text(encoding="utf-8")
            findings.extend(scan_python_source(source, path.relative_to(base)))
        except (OSError, UnicodeDecodeError, ScanError) as error:
            errors.append(str(error))
    if errors:
        raise ScanError("; ".join(errors))
    return sorted(findings, key=lambda item: (item.location, item.title))


def render_report(findings: Iterable[Finding]) -> str:
    payload = {"findings": [finding.as_report_item() for finding in findings]}
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", type=Path, default=Path("/app"))
    parser.add_argument("--output", type=Path, default=Path("/app/security_report.json"))
    parser.add_argument("--include-tests", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = scan_project(args.target, include_tests=args.include_tests)
        report = render_report(findings)
        write_utf8_lf(args.output, report)
    except (OSError, ScanError) as error:
        print(f"security scan failed: {error}", file=sys.stderr)
        return 2
    print(f"security scan: {len(findings)} finding(s); report={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
