"""Conservative static leads for non-SQL security audits.

The SQL scanner remains an authoritative detector for the narrow flows it
supports.  This module intentionally returns *leads*: concrete source lines
that deserve model confirmation.  It never writes a report or claims that a
lead is a benchmark finding.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any, Iterable

from agent.validators import canonical_path, iter_python_files, protected_path


MAX_AUDIT_SIGNAL_FILES = 512
MAX_AUDIT_SIGNALS = 64


def _source(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (TypeError, ValueError):
        return type(node).__name__


def _call_name(node: ast.Call) -> str:
    return _source(node.func).casefold()


def _referenced_names(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _constant_bool(call: ast.Call, name: str) -> bool | None:
    for keyword in call.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant):
            if isinstance(keyword.value.value, bool):
                return keyword.value.value
    return None


def _truthy_return(nodes: Iterable[ast.stmt]) -> ast.Return | None:
    for statement in nodes:
        for node in ast.walk(statement):
            if (
                isinstance(node, ast.Return)
                and isinstance(node.value, ast.Constant)
                and node.value.value is True
            ):
                return node
    return None


def _formatted_literal(node: ast.JoinedStr) -> str:
    return "".join(
        value.value
        for value in node.values
        if isinstance(value, ast.Constant) and isinstance(value.value, str)
    )


def _lead(
    *, path: str, node: ast.AST, category: str, cwe: str, evidence: str
) -> dict[str, Any]:
    return {
        "category": category,
        "cwe_hint": cwe,
        "file": path,
        "line": int(getattr(node, "lineno", 1)),
        "evidence": evidence[:500],
        "status": "lead_requires_source_confirmation",
    }


def _function_tainted_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    tainted = {argument.arg for argument in (*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs)}
    changed = True
    while changed:
        changed = False
        for node in ast.walk(function):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            value = node.value
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            derives_from_taint = bool(_referenced_names(value).intersection(tainted))
            if isinstance(value, ast.Call) and _call_name(value).endswith(
                (".findtext", ".get", ".getlist", ".json")
            ):
                derives_from_taint = True
            if not derives_from_taint:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in tainted:
                    tainted.add(target.id)
                    changed = True
    return tainted


def _scan_function(
    function: ast.FunctionDef | ast.AsyncFunctionDef, relative: str
) -> list[dict[str, Any]]:
    leads: list[dict[str, Any]] = []
    tainted = _function_tainted_names(function)
    function_text = _source(function).casefold()
    auth_context = (
        any(word in function.name.casefold() for word in ("auth", "login", "verify", "permission"))
        or "password" in function_text and any(
            marker in function_text for marker in (".search(", "credential", "user")
        )
    )
    oauth_context = (
        "oauth" in function.name.casefold()
        or "request.query" in function_text
        and any(marker in function_text for marker in ("redirect", "next_url", "issue_code", "callback"))
    )
    awaits = sorted(
        int(node.lineno) for node in ast.walk(function) if isinstance(node, ast.Await)
    )
    resolved_names: dict[str, tuple[str, int]] = {}

    for node in ast.walk(function):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            call_name = _call_name(node.value)
            if call_name.endswith(".resolve") and isinstance(node.value.func, ast.Attribute):
                source_name = _source(node.value.func.value)
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        resolved_names[target.id] = (source_name, int(node.lineno))

        if isinstance(node, ast.JoinedStr):
            literal = _formatted_literal(node).casefold()
            if any(marker in literal for marker in ("(uid=", "userpassword=", "objectclass=")) and any(
                isinstance(value, ast.FormattedValue) for value in node.values
            ):
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="ldap-filter-interpolation",
                    cwe="CWE-90",
                    evidence="unescaped formatted values are embedded in an LDAP search filter",
                ))

        if (
            auth_context
            and isinstance(node, ast.ExceptHandler)
            and (truthy_return := _truthy_return(node.body)) is not None
        ):
            leads.append(_lead(
                path=relative,
                node=truthy_return,
                category="authentication-fail-open",
                cwe="CWE-287",
                evidence="exception handler returns a truthy authorization/authentication result",
            ))

        if isinstance(node, ast.Compare):
            text = _source(node).casefold()
            constants = [part.value for part in (*node.comparators, node.left)
                         if isinstance(part, ast.Constant) and isinstance(part.value, str)]
            if oauth_context and "state" in text and constants:
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="static-oauth-state",
                    cwe="CWE-352",
                    evidence="request state is compared with a fixed string rather than session-bound unpredictable state",
                ))

        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)

        if name.endswith(".endswith") and node.args and isinstance(node.args[0], ast.Constant):
            suffix = node.args[0].value
            receiver = _source(node.func.value).casefold() if isinstance(node.func, ast.Attribute) else ""
            if isinstance(suffix, str) and "." in suffix and not suffix.startswith(".") and any(
                token in receiver for token in ("host", "domain", "origin")
            ):
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="domain-suffix-allowlist-bypass",
                    cwe="CWE-601",
                    evidence="hostname allowlist uses an undelimited suffix and accepts sibling-prefix domains",
                ))

        if name.endswith("xmlparser"):
            dangerous = (
                _constant_bool(node, "resolve_entities") is True
                or _constant_bool(node, "load_dtd") is True
                or _constant_bool(node, "no_network") is False
            )
            if dangerous:
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="unsafe-xml-external-entities",
                    cwe="CWE-611",
                    evidence="XML parser enables entity/DTD processing or permits network access",
                ))

        if name.startswith(("requests.", "httpx.", "aiohttp.")) and node.args:
            destination = _source(node.args[0])
            if _referenced_names(node.args[0]).intersection(tainted):
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="untrusted-network-destination",
                    cwe="CWE-918",
                    evidence=f"network destination {destination!r} is derived from function/document input",
                ))

        if any(name.endswith(f".{method}") for method in ("debug", "info", "warning", "error", "critical")):
            leaked = [
                _source(argument)
                for argument in node.args[1:]
                if any(word in _source(argument).casefold() for word in ("token", "secret", "password", "credential"))
            ]
            if leaked:
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="secret-in-log",
                    cwe="CWE-532",
                    evidence="logging call includes secret-like value(s): " + ", ".join(leaked),
                ))

        if name.endswith(".open") and isinstance(node.func, ast.Attribute):
            opened = _source(node.func.value)
            for resolved, (source_name, validation_line) in resolved_names.items():
                if opened != source_name or not any(validation_line < line < int(node.lineno) for line in awaits):
                    continue
                leads.append(_lead(
                    path=relative,
                    node=node,
                    category="path-check-use-race",
                    cwe="CWE-367",
                    evidence=f"path validated through {resolved!r}, then an await occurs before opening mutable {opened!r}",
                ))

    return leads


def scan_audit_signals(target: Path | str) -> dict[str, Any]:
    root = canonical_path(target)
    leads: list[dict[str, Any]] = []
    files_scanned = 0
    for path in iter_python_files(root):
        relative = path.relative_to(root).as_posix()
        if protected_path(relative):
            continue
        files_scanned += 1
        if files_scanned > MAX_AUDIT_SIGNAL_FILES:
            break
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                leads.extend(_scan_function(node, relative))
                if len(leads) >= MAX_AUDIT_SIGNALS:
                    break
        if len(leads) >= MAX_AUDIT_SIGNALS:
            break

    unique: dict[tuple[str, int, str], dict[str, Any]] = {}
    for lead in leads:
        unique[(str(lead["file"]), int(lead["line"]), str(lead["category"]))] = lead
    selected = list(unique.values())[:MAX_AUDIT_SIGNALS]
    return {
        "lead_count": len(selected),
        "leads": selected,
        "files_scanned": files_scanned,
        "truncated": len(leads) > len(selected) or files_scanned > MAX_AUDIT_SIGNAL_FILES,
        "scope": "conservative non-SQL static leads; confirm reachability and task relevance from source",
    }
