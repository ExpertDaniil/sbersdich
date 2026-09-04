#!/usr/bin/env python3
"""Exercise C-07 forensics tools without reading public expected answers."""

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

from agent.tools.forensics import (  # noqa: E402
    PROFILE_NAME,
    analyze_incident,
    evidence_graph,
    format_report,
    inventory_artifacts,
    inventory_digest,
    validate_report_text,
)


PUBLIC_TASK = "incident-log-forensics"


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("public_repo", type=Path)
    parser.add_argument(
        "--results",
        type=Path,
        default=REPO_ROOT / "evaluation" / "results" / "c07_public",
    )
    args = parser.parse_args()
    public_repo = args.public_repo.resolve()
    source = public_repo / "local_task" / PUBLIC_TASK / "environment"
    results = args.results.resolve()
    if not source.is_dir():
        print(f"public incident bundle not found: {source}", file=sys.stderr)
        return 2

    public_before = tree_digest(source)
    with tempfile.TemporaryDirectory(prefix="sbersdich-c07-") as tmp:
        incident_copy = Path(tmp) / "incident"
        shutil.copytree(source, incident_copy)
        inventory = inventory_artifacts(incident_copy)
        evidence_before = inventory_digest(inventory)
        conclusion = analyze_incident(incident_copy)
        report = format_report(conclusion)
        values = validate_report_text(report)
        graph = evidence_graph(conclusion, incident_copy)
        evidence_after = inventory_digest(inventory_artifacts(incident_copy))

    public_after = tree_digest(source)
    summary = {
        "task": PUBLIC_TASK,
        "profile": PROFILE_NAME,
        "artifact_count": len(inventory),
        "report_keys": list(values),
        "report_lines": len(report.splitlines()),
        "evidence_nodes": len(graph["nodes"]),
        "evidence_edges": len(graph["edges"]),
        "evidence_unchanged": evidence_before == evidence_after,
        "public_repository_unchanged": public_before == public_after,
        "expected_or_solution_read": False,
    }
    write_utf8_lf(results / "incident_report.txt", report)
    write_utf8_lf(results / "evidence_graph.json", render_json(graph))
    write_utf8_lf(results / "summary.json", render_json(summary))

    passed = (
        summary["profile"] == PROFILE_NAME
        and summary["report_keys"] == list(values)
        and summary["report_keys"] == [
            "attacker_ip",
            "compromised_user",
            "exfil_bytes",
            "first_malicious_event_utc",
        ]
        and summary["report_lines"] == 4
        and summary["evidence_nodes"] >= 3
        and summary["evidence_edges"] >= 2
        and summary["evidence_unchanged"] is True
        and summary["public_repository_unchanged"] is True
    )
    if not passed:
        print(render_json(summary), file=sys.stderr, end="")
        return 1
    print(render_json(summary), end="")
    print(f"C-07 public verification passed. Results: {results}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
