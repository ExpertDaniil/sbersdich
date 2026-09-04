#!/usr/bin/env python3
"""Exercise C-08 policies on disposable copies of public security tasks."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from agent.tools.forensics import analyze_incident, format_report  # noqa: E402
from agent.tools.security_scan import render_report, scan_project  # noqa: E402
from agent.tools.sql_parameterize import parameterize_project  # noqa: E402
from agent.validators import (  # noqa: E402
    ArtifactRule,
    ValidationPolicy,
    capture_snapshot,
    validate_task,
)


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


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def render_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def public_source(public_repo: Path, key: str) -> Path:
    task = public_repo / "local_task" / TASKS[key] / "environment"
    app = task / "app"
    return app if app.is_dir() else task


def report_summary(report) -> dict[str, object]:
    return {
        "passed": report.passed,
        "checks": {check.name: check.passed for check in report.checks},
        "changes": report.as_payload()["changes"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_repo", type=Path)
    parser.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "evaluation" / "results" / "c08_public",
    )
    args = parser.parse_args()
    public_repo = args.public_repo.resolve()
    results = args.results.resolve()
    sources = {key: public_source(public_repo, key) for key in TASKS}
    missing = [str(path) for path in sources.values() if not path.is_dir()]
    if missing:
        print(f"public task source missing: {', '.join(missing)}", file=sys.stderr)
        return 2

    public_before = {key: tree_digest(path) for key, path in sources.items()}
    summary: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="sbersdich-c08-") as tmp:
        temporary = Path(tmp)

        audit_app = temporary / "audit"
        shutil.copytree(sources["audit"], audit_app)
        audit_baseline = capture_snapshot(audit_app)
        security_report = audit_app / "security_report.json"
        write_utf8_lf(security_report, render_report(scan_project(audit_app)))
        audit_result = validate_task(
            ValidationPolicy(
                mode="audit",
                target=audit_app,
                baseline=audit_baseline,
                artifacts=(ArtifactRule("security-report", security_report),),
            )
        )
        summary["audit"] = report_summary(audit_result)

        for key in ("fix_login", "fix_search"):
            fix_app = temporary / key
            shutil.copytree(sources[key], fix_app)
            fix_baseline = capture_snapshot(fix_app)
            changes = parameterize_project(fix_app, apply=True)
            fix_result = validate_task(
                ValidationPolicy(mode="fix", target=fix_app, baseline=fix_baseline)
            )
            item = report_summary(fix_result)
            item["fixer_changes"] = len(changes)
            item["findings_after"] = len(scan_project(fix_app))
            summary[key] = item

        forensic_app = temporary / "forensic_app"
        incident = forensic_app / "incident"
        shutil.copytree(sources["forensics"], incident)
        forensic_baseline = capture_snapshot(forensic_app)
        incident_report = forensic_app / "incident_report.txt"
        write_utf8_lf(incident_report, format_report(analyze_incident(incident)))
        forensic_result = validate_task(
            ValidationPolicy(
                mode="forensics",
                target=forensic_app,
                baseline=forensic_baseline,
                artifacts=(ArtifactRule("incident-report", incident_report),),
                check_python_syntax=False,
            )
        )
        summary["forensics"] = report_summary(forensic_result)

    public_after = {key: tree_digest(path) for key, path in sources.items()}
    summary["public_repository_unchanged"] = public_before == public_after
    summary["expected_or_solution_read"] = False
    write_utf8_lf(results / "summary.json", render_json(summary))

    audit = summary["audit"]
    fix_login = summary["fix_login"]
    fix_search = summary["fix_search"]
    forensics = summary["forensics"]
    passed = (
        isinstance(audit, dict)
        and audit["passed"] is True
        and isinstance(fix_login, dict)
        and fix_login["passed"] is True
        and fix_login["fixer_changes"] >= 1
        and fix_login["findings_after"] == 0
        and isinstance(fix_search, dict)
        and fix_search["passed"] is True
        and fix_search["fixer_changes"] >= 1
        and fix_search["findings_after"] == 0
        and isinstance(forensics, dict)
        and forensics["passed"] is True
        and summary["public_repository_unchanged"] is True
    )
    if not passed:
        print(render_json(summary), file=sys.stderr, end="")
        return 1
    print(render_json(summary), end="")
    print(f"C-08 public validation passed. Results: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
