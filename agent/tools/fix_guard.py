"""Instruction-driven post-edit guards for common non-SQL security properties."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from agent.validators import canonical_path, iter_python_files, protected_path


def _source(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except (TypeError, ValueError):
        return type(node).__name__


def _python_trees(root: Path) -> list[tuple[str, str, ast.Module]]:
    trees: list[tuple[str, str, ast.Module]] = []
    for path in iter_python_files(root):
        relative = path.relative_to(root).as_posix()
        if protected_path(relative):
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=relative)
        except (OSError, UnicodeError, SyntaxError, ValueError):
            continue
        trees.append((relative, text, tree))
    return trees


def _issue(requirement: str, path: str, node: ast.AST | None, detail: str) -> dict[str, Any]:
    return {
        "requirement": requirement,
        "file": path,
        "line": int(getattr(node, "lineno", 1)) if node is not None else 1,
        "detail": detail,
    }


def _path_containment_issues(trees: list[tuple[str, str, ast.Module]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for relative, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            has_resolve = any(
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"resolve", "absolute", "realpath", "abspath"}
                for node in ast.walk(function)
            )
            if not has_resolve:
                continue
            for node in ast.walk(function):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "startswith"
                ):
                    continue
                expression = _source(node)
                if "str(" not in expression and not any(
                    word in expression.casefold() for word in ("path", "root", "base", "dir")
                ):
                    continue
                issues.append(_issue(
                    "path-containment",
                    relative,
                    node,
                    "string prefix comparison is not path containment and accepts sibling-prefix paths; use relative_to/commonpath semantics",
                ))
    return issues


def _plaintext_token_issues(trees: list[tuple[str, str, ast.Module]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for relative, _text, tree in trees:
        for node in ast.walk(tree):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if not isinstance(target, ast.Subscript):
                    continue
                container_text = _source(target.value).casefold()
                if not any(marker in container_text for marker in (
                    "token", "reset", "store", "storage", "cache", "record", "db",
                )):
                    continue
                key_text = _source(target.slice).casefold()
                value_text = _source(node.value).casefold()
                raw_key = "token" in key_text and not any(
                    marker in key_text for marker in ("hash", "digest", "sha")
                )
                raw_value = "token" in value_text and not any(
                    marker in value_text for marker in ("hash", "digest", "sha")
                )
                if not raw_key and not raw_value:
                    continue
                issues.append(_issue(
                    "no-plaintext-token-storage",
                    relative,
                    target,
                    "a token-like raw value is persisted directly as a mapping key/value; store and look up a cryptographic digest instead",
                ))
    return issues


def _structured_credential_issues(trees: list[tuple[str, str, ast.Module]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for relative, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            function_text = _source(function).casefold()
            security_surface = (
                any(word in function_text for word in ("password", "credential", "username", "email"))
                and any(word in function_text for word in (
                    "find_one", "findone", "collection", "mongo", ".find(", "query",
                ))
            )
            if not security_surface:
                continue
            type_guards = [
                node for node in ast.walk(function)
                if isinstance(node, ast.If)
                and "isinstance" in _source(node.test)
                and "str" in _source(node.test)
            ]
            explicit_type_reject = any(
                isinstance(node, ast.Raise)
                and node.exc is not None
                and any(kind in _source(node.exc) for kind in ("TypeError", "ValueError"))
                for node in ast.walk(function)
            )
            if explicit_type_reject:
                continue
            for guard in type_guards:
                if any(
                    isinstance(node, ast.Return)
                    and (
                        node.value is None
                        or isinstance(node.value, ast.Constant) and node.value.value in {None, False}
                    )
                    for statement in guard.body
                    for node in ast.walk(statement)
                ):
                    issues.append(_issue(
                        "reject-structured-credentials",
                        relative,
                        guard,
                        "non-string credentials are silently treated as authentication failure; explicitly raise TypeError/ValueError before building the query",
                    ))
                    break
            else:
                if not type_guards:
                    issues.append(_issue(
                        "reject-structured-credentials",
                        relative,
                        function,
                        "credential query has no explicit scalar-string type rejection before database use",
                    ))
    return issues


def _webhook_hmac_issues(trees: list[tuple[str, str, ast.Module]]) -> list[dict[str, Any]]:
    combined = "\n".join(text for _path, text, _tree in trees).casefold()
    requirements = (
        ("hmac.new", "compute the expected signature with HMAC"),
        ("compare_digest", "compare signatures in constant time"),
        ("sha256", "use the requested SHA-256 digest"),
    )
    issues = [
        _issue("webhook-hmac", "<project>", None, detail)
        for marker, detail in requirements
        if marker not in combined
    ]
    symmetric_window = "abs(" in combined or (
        "now -" in combined and "now +" in combined
    )
    if not symmetric_window:
        issues.append(_issue(
            "webhook-hmac",
            "<project>",
            None,
            "enforce a symmetric absolute past/future timestamp freshness window",
        ))
    return issues


def _mass_assignment_issues(trees: list[tuple[str, str, ast.Module]]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for relative, _text, tree in trees:
        for function in (node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))):
            rejecting_guards = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.If)
                and any(isinstance(child, ast.Raise) for statement in node.body for child in ast.walk(statement))
            ]
            for node in ast.walk(function):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "update"
                    and node.args
                ):
                    continue
                argument = node.args[0]
                if isinstance(argument, (ast.DictComp, ast.Dict)):
                    continue
                argument_text = _source(argument).casefold()
                if any(word in argument_text for word in ("filtered", "allowed", "safe", "validated")):
                    continue
                allowlist_guarded = any(
                    int(getattr(guard, "lineno", 0)) < int(getattr(node, "lineno", 0))
                    and argument_text in _source(guard.test).casefold()
                    and any(marker in _source(guard.test) for marker in (".keys()", ".issubset(", "set("))
                    for guard in rejecting_guards
                )
                if allowlist_guarded:
                    continue
                if any(word in argument_text for word in ("payload", "body", "data", "changes", "request")):
                    issues.append(_issue(
                        "mass-assignment",
                        relative,
                        node,
                        "request-controlled mapping is passed directly to update without a preceding rejecting allowlist guard or allowlist projection",
                    ))
    return issues


def scan_fix_requirements(
    target: Path | str, requirements: tuple[str, ...]
) -> list[dict[str, Any]]:
    root = canonical_path(target)
    trees = _python_trees(root)
    return _scan_trees(trees, requirements)


def scan_fix_candidate(
    relative_path: str, source: str, requirements: tuple[str, ...]
) -> list[dict[str, Any]]:
    """Reject local anti-patterns before a checked edit reaches disk.

    Whole-project positive requirements such as complete webhook construction
    remain final-verifier checks because their implementation may span files.
    """

    try:
        tree = ast.parse(source, filename=relative_path)
    except (SyntaxError, ValueError):
        return []  # syntax is reported by the checked-edit parser itself
    local_requirements = tuple(
        requirement for requirement in requirements if requirement != "webhook-hmac"
    )
    return _scan_trees([(relative_path, source, tree)], local_requirements)


def _scan_trees(
    trees: list[tuple[str, str, ast.Module]], requirements: tuple[str, ...]
) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    for requirement in requirements:
        if requirement == "path-containment":
            issues.extend(_path_containment_issues(trees))
        elif requirement == "no-plaintext-token-storage":
            issues.extend(_plaintext_token_issues(trees))
        elif requirement == "reject-structured-credentials":
            issues.extend(_structured_credential_issues(trees))
        elif requirement == "webhook-hmac":
            issues.extend(_webhook_hmac_issues(trees))
        elif requirement == "mass-assignment":
            issues.extend(_mass_assignment_issues(trees))
    return issues
