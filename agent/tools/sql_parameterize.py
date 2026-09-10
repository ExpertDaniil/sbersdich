#!/usr/bin/env python3
"""Conservatively parameterize supported asyncpg SQL f-strings."""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    from .security_scan import (
        SQL_KEYWORD_RE,
        ScanError,
        call_method_name,
        expression_uses_tainted,
        function_scope_nodes,
        function_argument_names,
        infer_tainted_names,
        iter_python_files,
        source_segment,
    )
except ImportError:  # Direct execution from agent/tools.
    from security_scan import (  # type: ignore
        SQL_KEYWORD_RE,
        ScanError,
        call_method_name,
        expression_uses_tainted,
        function_scope_nodes,
        function_argument_names,
        infer_tainted_names,
        iter_python_files,
        source_segment,
    )


VALUE_CONTEXT_RE = re.compile(
    r"(?:=|<>|!=|<=|>=|<|>|\bLIKE|\bILIKE)\s*$",
    re.IGNORECASE,
)


class FixError(RuntimeError):
    """Raised when a requested rewrite cannot be completed safely."""


@dataclass(frozen=True)
class SourceEdit:
    start: int
    end: int
    replacement: str


@dataclass(frozen=True)
class FixChange:
    path: str
    line: int
    function: str
    database_method: str
    parameter_count: int


@dataclass(frozen=True)
class ParameterizedTemplate:
    sql_literal: str
    arguments: tuple[str, ...]


def python_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def position_offset(source: str, lineno: int, byte_column: int) -> int:
    lines = source.splitlines(keepends=True)
    if lineno < 1 or lineno > len(lines):
        raise FixError(f"invalid source position {lineno}:{byte_column}")
    line = lines[lineno - 1]
    try:
        character_column = len(line.encode("utf-8")[:byte_column].decode("utf-8"))
    except UnicodeDecodeError as error:
        raise FixError(f"invalid UTF-8 source position {lineno}:{byte_column}") from error
    return sum(len(item) for item in lines[: lineno - 1]) + character_column


def node_span(source: str, node: ast.AST) -> tuple[int, int]:
    if not all(
        hasattr(node, attribute)
        for attribute in ("lineno", "col_offset", "end_lineno", "end_col_offset")
    ):
        raise FixError("AST node has no complete source location")
    start = position_offset(source, node.lineno, node.col_offset)  # type: ignore[attr-defined]
    end = position_offset(source, node.end_lineno, node.end_col_offset)  # type: ignore[attr-defined]
    return start, end


def vulnerable_comment_edit(source: str, node: ast.AST) -> SourceEdit | None:
    lines = source.splitlines(keepends=True)
    previous_index = node.lineno - 2  # type: ignore[attr-defined]
    if previous_index < 0 or previous_index >= len(lines):
        return None
    previous = lines[previous_index]
    if not re.search(r"#.*\bVULNERABLE\b.*(?:SQL|f-string)", previous, re.IGNORECASE):
        return None
    indentation = previous[: len(previous) - len(previous.lstrip(" \t"))]
    if previous.endswith("\r\n"):
        newline = "\r\n"
    elif previous.endswith("\n"):
        newline = "\n"
    elif previous.endswith("\r"):
        newline = "\r"
    else:
        newline = ""
    start = sum(len(item) for item in lines[:previous_index])
    end = start + len(previous)
    return SourceEdit(
        start,
        end,
        f"{indentation}# SECURITY: untrusted SQL values use driver parameters{newline}",
    )


def formatted_parts(node: ast.JoinedStr) -> tuple[list[str], list[ast.FormattedValue]]:
    literals = [""]
    expressions: list[ast.FormattedValue] = []
    for value in node.values:
        if isinstance(value, ast.Constant) and isinstance(value.value, str):
            literals[-1] += value.value
        elif isinstance(value, ast.FormattedValue):
            expressions.append(value)
            literals.append("")
        else:
            raise FixError("unsupported f-string component")
    return literals, expressions


def render_argument(prefix: str, expression: str, suffix: str) -> str:
    if not prefix and not suffix:
        return expression
    return (
        f"({python_string(prefix)} + str({expression}) + {python_string(suffix)})"
    )


def parameterize_joined_string(
    node: ast.JoinedStr,
    source: str,
    tainted_names: set[str],
) -> ParameterizedTemplate | None:
    try:
        literals, formatted = formatted_parts(node)
    except FixError:
        return None
    if not formatted or not SQL_KEYWORD_RE.search("".join(literals)):
        return None
    if any(value.conversion != -1 or value.format_spec is not None for value in formatted):
        return None
    if any(not expression_uses_tainted(value.value, tainted_names) for value in formatted):
        return None

    arguments: list[str] = []
    for index, formatted_value in enumerate(formatted):
        previous = literals[index]
        following = literals[index + 1]
        open_quote = previous.rfind("'")
        close_quote = following.find("'")
        prefix = ""
        suffix = ""

        if open_quote >= 0 and close_quote >= 0:
            prefix = previous[open_quote + 1 :]
            suffix = following[:close_quote]
            if "'" in prefix or "'" in suffix:
                return None
            literals[index] = previous[:open_quote]
            literals[index + 1] = following[close_quote + 1 :]
        elif not VALUE_CONTEXT_RE.search(previous):
            # Placeholders cannot represent table names, column names or keywords.
            return None

        expression = source_segment(source, formatted_value.value).strip()
        if not expression:
            return None
        arguments.append(render_argument(prefix, expression, suffix))

    sql = "".join(
        literals[index] + f"${index + 1}" for index in range(len(formatted))
    ) + literals[-1]
    return ParameterizedTemplate(python_string(sql), tuple(arguments))


def assignment_targets(node: ast.Assign | ast.AnnAssign) -> list[str]:
    raw_targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    return [target.id for target in raw_targets if isinstance(target, ast.Name)]


def parameterize_source(
    source: str, relative_path: Path | str = Path("source.py")
) -> tuple[str, list[FixChange]]:
    path = Path(relative_path)
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as error:
        raise FixError(f"cannot parse {path}: {error}") from error

    edits: dict[tuple[int, int], SourceEdit] = {}
    changes: list[FixChange] = []
    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        tainted_names = infer_tainted_names(function)
        if not tainted_names and not function_argument_names(function):
            continue

        scope_nodes = function_scope_nodes(function)
        assignments: dict[str, tuple[ast.Assign | ast.AnnAssign, ast.JoinedStr]] = {}
        for node in scope_nodes:
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and isinstance(
                node.value, ast.JoinedStr
            ):
                for name in assignment_targets(node):
                    assignments[name] = (node, node.value)

        for call in scope_nodes:
            if not isinstance(call, ast.Call) or len(call.args) != 1 or call.keywords:
                continue
            method = call_method_name(call)
            if method is None:
                continue

            query_argument = call.args[0]
            assignment: ast.Assign | ast.AnnAssign | None = None
            joined_string: ast.JoinedStr | None = None
            if isinstance(query_argument, ast.JoinedStr):
                joined_string = query_argument
            elif isinstance(query_argument, ast.Name) and query_argument.id in assignments:
                assignment, joined_string = assignments[query_argument.id]

            if joined_string is None:
                continue
            template = parameterize_joined_string(joined_string, source, tainted_names)
            if template is None:
                continue

            if assignment is not None:
                value_start, value_end = node_span(source, assignment.value)
                edits[(value_start, value_end)] = SourceEdit(
                    value_start, value_end, template.sql_literal
                )
                call_start, call_end = node_span(source, query_argument)
                query_source = source[call_start:call_end]
                replacement = f"{query_source}, {', '.join(template.arguments)}"
            else:
                call_start, call_end = node_span(source, query_argument)
                replacement = (
                    f"{template.sql_literal}, {', '.join(template.arguments)}"
                )
            edits[(call_start, call_end)] = SourceEdit(call_start, call_end, replacement)
            comment_edit = vulnerable_comment_edit(
                source, assignment if assignment is not None else query_argument
            )
            if comment_edit is not None:
                edits[(comment_edit.start, comment_edit.end)] = comment_edit
            changes.append(
                FixChange(
                    path=path.as_posix(),
                    line=joined_string.lineno,
                    function=function.name,
                    database_method=method,
                    parameter_count=len(template.arguments),
                )
            )

    updated = source
    for edit in sorted(edits.values(), key=lambda item: item.start, reverse=True):
        updated = updated[: edit.start] + edit.replacement + updated[edit.end :]
    if edits:
        try:
            ast.parse(updated, filename=str(path))
        except SyntaxError as error:
            raise FixError(f"generated invalid Python for {path}: {error}") from error
    return updated, sorted(changes, key=lambda change: (change.path, change.line))


def parameterize_project(
    target: Path | str, *, apply: bool
) -> list[FixChange]:
    root = Path(target).resolve()
    if not root.exists():
        raise FixError(f"fix target does not exist: {root}")
    base = root.parent if root.is_file() else root
    all_changes: list[FixChange] = []
    for path in iter_python_files(root, include_tests=False):
        try:
            # Path.read_text() включает универсальную обработку переводов строк
            # и на Windows незаметно превращает CRLF в LF. Читаем с newline="",
            # чтобы точечное исправление не переписывало весь файл и совпадало
            # с политикой сохранения окончаний строк в workspace patch.
            with path.open("r", encoding="utf-8", newline="") as handle:
                source = handle.read()
        except (OSError, UnicodeDecodeError) as error:
            raise FixError(f"cannot read {path}: {error}") from error
        updated, changes = parameterize_source(source, path.relative_to(base))
        if changes and apply:
            with path.open("w", encoding="utf-8", newline="\n") as handle:
                handle.write(updated)
        all_changes.extend(changes)
    return sorted(all_changes, key=lambda change: (change.path, change.line))


def render_fix_report(mode: str, changes: list[FixChange]) -> str:
    return json.dumps(
        {
            "mode": mode,
            "changed": len(changes),
            "changes": [asdict(change) for change in changes],
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", nargs="?", type=Path, default=Path("/app"))
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="report supported rewrites")
    mode.add_argument("--apply", action="store_true", help="write supported rewrites")
    parser.add_argument("--output", type=Path, help="optional JSON change report")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    apply_changes = bool(args.apply)
    mode = "apply" if apply_changes else "check"
    try:
        changes = parameterize_project(args.target, apply=apply_changes)
        report = render_fix_report(mode, changes)
        if args.output:
            write_utf8_lf(args.output, report)
        else:
            print(report, end="")
    except (FixError, ScanError, OSError) as error:
        print(f"SQL parameterization failed: {error}", file=sys.stderr)
        return 2

    if apply_changes:
        print(f"SQL parameterization applied: {len(changes)} change(s)")
        return 0
    return 1 if changes else 0


if __name__ == "__main__":
    raise SystemExit(main())
