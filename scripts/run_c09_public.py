#!/usr/bin/env python3
"""Run the C-09 loop on disposable copies of all six public task profiles."""

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

from agent.core.loop import AgentLoop  # noqa: E402


TASKS = (
    "hello-file",
    "bye-file",
    "find-sqli-login",
    "fix-sqli-login",
    "fix-sqli-search",
    "incident-log-forensics",
)


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def public_input_digest(task_dir: Path) -> str:
    """Hash only data legitimately available to the running agent."""

    digest = hashlib.sha256()
    digest.update((task_dir / "instruction.md").read_bytes())
    digest.update(b"\0")
    digest.update(tree_digest(task_dir / "environment").encode("ascii"))
    return digest.hexdigest()


def task_workdir(task_dir: Path, temporary_root: Path) -> Path:
    environment = task_dir / "environment"
    app = environment / "app"
    workdir = temporary_root / task_dir.name
    if app.is_dir():
        shutil.copytree(app, workdir)
    elif task_dir.name == "incident-log-forensics":
        shutil.copytree(environment, workdir / "incident")
    else:
        workdir.mkdir(parents=True)
    return workdir


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
        default=REPO_ROOT / "evaluation" / "results" / "c09_public",
    )
    args = parser.parse_args()
    public_repo = args.public_repo.resolve()
    local_tasks = public_repo / "local_task"
    task_dirs = {name: local_tasks / name for name in TASKS}
    missing = [
        str(path)
        for path in task_dirs.values()
        if not (path / "instruction.md").is_file()
        or not (path / "environment").is_dir()
    ]
    if missing:
        print(f"public task is incomplete: {', '.join(missing)}", file=sys.stderr)
        return 2

    before = {name: public_input_digest(path) for name, path in task_dirs.items()}
    summary: dict[str, object] = {}
    traces: dict[str, object] = {}
    with tempfile.TemporaryDirectory(prefix="sbersdich-c09-") as tmp:
        temporary_root = Path(tmp)
        for name, task_dir in task_dirs.items():
            instruction = (task_dir / "instruction.md").read_text(encoding="utf-8")
            workdir = task_workdir(task_dir, temporary_root)
            result = AgentLoop(workdir=workdir).run(instruction)
            final_changes = (
                result.final_validation.report.as_payload()["changes"]
                if result.final_validation
                else None
            )
            summary[name] = {
                "status": result.status,
                "mode": result.decision.mode if result.decision else None,
                "steps": result.steps_used,
                "validations": result.validations_used,
                "changes": final_changes,
            }
            traces[name] = result.as_payload()

    after = {name: public_input_digest(path) for name, path in task_dirs.items()}
    summary["public_repository_unchanged"] = before == after
    summary["expected_or_solution_read"] = False
    write_json(args.results.resolve() / "summary.json", summary)
    write_json(args.results.resolve() / "traces.json", traces)

    passed = (
        all(
            isinstance(summary[name], dict)
            and summary[name]["status"] == "succeeded"  # type: ignore[index]
            for name in TASKS
        )
        and summary["public_repository_unchanged"] is True
    )
    rendered = json.dumps(summary, ensure_ascii=False, indent=2)
    print(rendered, file=sys.stdout if passed else sys.stderr)
    if not passed:
        return 1
    print(f"C-09 public agent-loop verification passed. Results: {args.results.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
