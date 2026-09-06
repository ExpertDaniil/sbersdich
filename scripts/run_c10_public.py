#!/usr/bin/env python3
"""Exercise C-10 tools on disposable public-task inputs without answer files."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.core.workspace import (  # noqa: E402
    apply_workspace_patch,
    list_workspace_files,
    read_workspace_text,
    run_workspace_command,
    search_workspace_text,
)
from agent.tools.security_scan import scan_project  # noqa: E402
from agent.tools.sql_parameterize import parameterize_project  # noqa: E402


TASKS = {
    "audit": "find-sqli-login",
    "fix_login": "fix-sqli-login",
    "fix_search": "fix-sqli-search",
    "forensics": "incident-log-forensics",
}


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def source_path(public_repo: Path, key: str) -> Path:
    environment = public_repo / "local_task" / TASKS[key] / "environment"
    app = environment / "app"
    return app if app.is_dir() else environment


def generated_patch(original: Path, updated: Path, paths: set[str]) -> str:
    lines: list[str] = []
    for relative in sorted(paths):
        before = (original / relative).read_text(encoding="utf-8").splitlines()
        after = (updated / relative).read_text(encoding="utf-8").splitlines()
        lines.extend(
            difflib.unified_diff(
                before,
                after,
                fromfile=f"a/{relative}",
                tofile=f"b/{relative}",
                lineterm="",
            )
        )
    return "\n".join(lines) + "\n"


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_repo", type=Path)
    parser.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "evaluation" / "results" / "c10_public",
    )
    args = parser.parse_args()
    public_repo = args.public_repo.resolve()
    sources = {key: source_path(public_repo, key) for key in TASKS}
    missing = [str(path) for path in sources.values() if not path.is_dir()]
    if missing:
        print(f"public environment is missing: {', '.join(missing)}", file=sys.stderr)
        return 2

    before = {key: tree_digest(path) for key, path in sources.items()}
    summary: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="sbersdich-c10-") as tmp:
        temporary = Path(tmp)

        audit = temporary / "audit"
        shutil.copytree(sources["audit"], audit)
        audit_before = tree_digest(audit)
        audit_list = list_workspace_files(audit)
        audit_search = search_workspace_text(
            audit, query="fetchrow", glob="*.py", case_sensitive=True
        )
        if audit_search["matches"]:
            read_workspace_text(
                audit,
                path=audit_search["matches"][0]["path"],
                start_line=audit_search["matches"][0]["line"],
                max_lines=5,
            )
        summary["audit_read_only"] = {
            "listed_files": audit_list["count"],
            "search_matches": audit_search["match_count"],
            "unchanged": audit_before == tree_digest(audit),
        }

        for key in ("fix_login", "fix_search"):
            original = temporary / f"{key}_original"
            expected = temporary / f"{key}_expected"
            target = temporary / f"{key}_target"
            shutil.copytree(sources[key], original)
            shutil.copytree(sources[key], expected)
            shutil.copytree(sources[key], target)
            changes = parameterize_project(expected, apply=True)
            changed_paths = {change.path for change in changes}
            patch = generated_patch(original, expected, changed_paths)
            applied = apply_workspace_patch(target, patch=patch)
            command = run_workspace_command(
                target,
                argv=[sys.executable, "-m", "compileall", "-q", "."],
                timeout_seconds=30,
            )
            matches_expected = all(
                (target / path).read_bytes() == (expected / path).read_bytes()
                for path in changed_paths
            )
            summary[key] = {
                "patch_files": applied["file_count"],
                "patch_hunks": applied["hunk_count"],
                "syntax_exit_code": command["exit_code"],
                "findings_after": len(scan_project(target)),
                "matches_expected_transform": matches_expected,
            }

        forensic_app = temporary / "forensics"
        shutil.copytree(sources["forensics"], forensic_app / "incident")
        forensic_before = tree_digest(forensic_app)
        forensic_list = list_workspace_files(forensic_app)
        forensic_search = search_workspace_text(
            forensic_app, query="request_id", glob="*"
        )
        summary["forensics_read_only"] = {
            "listed_files": forensic_list["count"],
            "search_matches": forensic_search["match_count"],
            "unchanged": forensic_before == tree_digest(forensic_app),
        }

    after = {key: tree_digest(path) for key, path in sources.items()}
    summary["public_environments_unchanged"] = before == after
    summary["expected_or_solution_read"] = False
    write_json(args.results.resolve() / "summary.json", summary)

    audit_result = summary["audit_read_only"]
    login_result = summary["fix_login"]
    search_result = summary["fix_search"]
    forensic_result = summary["forensics_read_only"]
    passed = (
        isinstance(audit_result, dict)
        and audit_result["listed_files"] > 0
        and audit_result["search_matches"] > 0
        and audit_result["unchanged"] is True
        and all(
            isinstance(result, dict)
            and result["patch_files"] >= 1
            and result["patch_hunks"] >= 1
            and result["syntax_exit_code"] == 0
            and result["findings_after"] == 0
            and result["matches_expected_transform"] is True
            for result in (login_result, search_result)
        )
        and isinstance(forensic_result, dict)
        and forensic_result["listed_files"] > 0
        and forensic_result["search_matches"] > 0
        and forensic_result["unchanged"] is True
        and summary["public_environments_unchanged"] is True
    )
    rendered = json.dumps(summary, ensure_ascii=False, indent=2)
    print(rendered, file=sys.stdout if passed else sys.stderr)
    if not passed:
        return 1
    print(f"C-10 public workspace-tool verification passed. Results: {args.results.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
