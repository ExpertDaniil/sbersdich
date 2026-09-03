#!/usr/bin/env python3
"""Exercise C-06 audit/fix tools on disposable copies of public SQL tasks."""

from __future__ import annotations

import argparse
import compileall
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.tools.security_scan import render_report, scan_project  # noqa: E402
from agent.tools.sql_parameterize import (  # noqa: E402
    parameterize_project,
    render_fix_report,
)


PUBLIC_TASKS = {
    "audit": "find-sqli-login",
    "fix_login": "fix-sqli-login",
    "fix_search": "fix-sqli-search",
}


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        if "__pycache__" in path.parts:
            continue
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2)
        handle.write("\n")


def task_app(public_repo: Path, task: str) -> Path:
    return public_repo / "local_task" / task / "environment" / "app"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_repo", type=Path)
    parser.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "evaluation" / "results" / "c06_public",
    )
    args = parser.parse_args()
    public_repo = args.public_repo.resolve()
    results = args.results.resolve()

    sources = {
        key: task_app(public_repo, task) for key, task in PUBLIC_TASKS.items()
    }
    missing = [str(path) for path in sources.values() if not path.is_dir()]
    if missing:
        print(f"missing public task app: {', '.join(missing)}", file=sys.stderr)
        return 2

    original_before = {key: tree_digest(path) for key, path in sources.items()}
    summary: dict[str, object] = {}

    with tempfile.TemporaryDirectory(prefix="sbersdich-c06-") as tmp:
        temporary_root = Path(tmp)

        audit_copy = temporary_root / "audit"
        shutil.copytree(sources["audit"], audit_copy)
        audit_before = tree_digest(audit_copy)
        audit_findings = scan_project(audit_copy)
        audit_after = tree_digest(audit_copy)
        audit_unchanged = audit_before == audit_after
        (results / "audit_security_report.json").parent.mkdir(
            parents=True, exist_ok=True
        )
        with (results / "audit_security_report.json").open(
            "w", encoding="utf-8", newline="\n"
        ) as handle:
            handle.write(render_report(audit_findings))
        summary["audit"] = {
            "task": PUBLIC_TASKS["audit"],
            "findings": len(audit_findings),
            "source_unchanged": audit_unchanged,
        }

        for key in ("fix_login", "fix_search"):
            app_copy = temporary_root / key
            shutil.copytree(sources[key], app_copy)
            before_findings = scan_project(app_copy)
            changes = parameterize_project(app_copy, apply=True)
            after_findings = scan_project(app_copy)
            syntax_ok = compileall.compile_dir(app_copy, quiet=2)
            with (results / f"{key}_changes.json").open(
                "w", encoding="utf-8", newline="\n"
            ) as handle:
                handle.write(render_fix_report("apply", changes))
            summary[key] = {
                "task": PUBLIC_TASKS[key],
                "findings_before": len(before_findings),
                "supported_changes": len(changes),
                "findings_after": len(after_findings),
                "syntax_ok": syntax_ok,
            }

    original_after = {key: tree_digest(path) for key, path in sources.items()}
    originals_unchanged = original_before == original_after
    summary["public_repository_unchanged"] = originals_unchanged
    write_json(results / "summary.json", summary)

    audit = summary["audit"]
    fix_login = summary["fix_login"]
    fix_search = summary["fix_search"]
    passed = (
        isinstance(audit, dict)
        and audit["findings"] >= 1
        and audit["source_unchanged"] is True
        and all(
            isinstance(result, dict)
            and result["findings_before"] >= 1
            and result["supported_changes"] >= 1
            and result["findings_after"] == 0
            and result["syntax_ok"] is True
            for result in (fix_login, fix_search)
        )
        and originals_unchanged
    )
    if not passed:
        print(json.dumps(summary, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print(f"C-06 public verification passed. Results: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
