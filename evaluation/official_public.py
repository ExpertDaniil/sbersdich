"""Run the pinned public competition verifiers against a ZIP in offline ACP containers.

Preparation may download/build images. Execution uses immutable prepared image IDs,
--network none, and the original verifier scripts, uploaded only after the agent exits.
This is a Docker harness for the public tasks, not the closed benchmark or Harbor itself.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import time
import tomllib
import uuid
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath


PUBLIC_SHA = "b95c62fec81656e338af54045efa688fd4979615"
PUBLIC_REPOSITORY = "https://github.com/SecureIntelligent/UniversalAgenticCompetitionPublic"
BASE_IMAGE = "secureintelligent/acp:latest"
TASKS = ("hello-file", "bye-file", "find-sqli-login", "fix-sqli-login", "fix-sqli-search", "incident-log-forensics")
REMOTE_AGENT = "/opt/harbor/local-agent"
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}$")
BASE_DIGEST = re.compile(r"secureintelligent/acp@sha256:[0-9a-f]{64}$")
MAX_ARCHIVE_BYTES = 10_000_000
MAX_EXTRACTED_BYTES = 64_000_000
MAX_FILES = 4096


class HarnessError(RuntimeError):
    pass


@dataclass(frozen=True)
class Outcome:
    exit_code: int | None
    timed_out: bool
    duration_seconds: float
    log: str


def write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes((json.dumps(payload, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
    os.replace(temporary, path)


def file_sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_sha(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise HarnessError(f"symlink in prepared fixtures: {path}")
        if path.is_file():
            digest.update(path.relative_to(root).as_posix().encode("utf-8") + b"\x00")
            digest.update(bytes.fromhex(file_sha(path)))
    return digest.hexdigest()


def safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if not name or "\\" in name or path.is_absolute() or ".." in path.parts or ":" in name:
        raise HarnessError(f"unsafe archive path: {name!r}")
    return path


def inspect_submission(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE_BYTES:
        raise HarnessError("submission must be a regular ZIP no larger than 10 MB")
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        if len(members) > MAX_FILES or sum(item.file_size for item in members) > MAX_EXTRACTED_BYTES:
            raise HarnessError("submission exceeds extraction limits")
        seen: set[str] = set()
        for item in members:
            name = safe_member(item.filename).as_posix()
            if name in seen:
                raise HarnessError("duplicate submission member")
            seen.add(name)
            if stat.S_ISLNK(item.external_attr >> 16):
                raise HarnessError("submission must not contain symlinks")
            if name in {"agent.py", "agent/agent.py"} or any(part in {"tests", "evaluation", ".git"} for part in PurePosixPath(name).parts):
                raise HarnessError(f"development/wrapper file in submission: {name}")
            if PurePosixPath(name).name in {".env", ".env.local", "credentials.json", "secrets.json"} or PurePosixPath(name).suffix.lower() in {".pem", ".key", ".p12", ".pfx"}:
                raise HarnessError(f"secret-like file in submission: {name}")
        if "run.sh" not in seen or archive.getinfo("run.sh").is_dir():
            raise HarnessError("root run.sh is missing")
        if b"\r\n" in archive.read("run.sh"):
            raise HarnessError("submission run.sh contains CRLF; use the production ZIP builder")
        if archive.testzip() is not None:
            raise HarnessError("submission ZIP checksum failed")
    return {"sha256": file_sha(path), "size_bytes": path.stat().st_size, "members": len(members)}


def execute(argv: list[str], log: Path, *, timeout: float, cwd: Path | None = None) -> Outcome:
    log.parent.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    with log.open("wb") as output:
        try:
            process = subprocess.run(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=output,
                                     stderr=subprocess.STDOUT, timeout=timeout, check=False)
            code, timed_out = process.returncode, False
        except subprocess.TimeoutExpired:
            output.write(b"\n[harness] command timed out\n")
            code, timed_out = None, True
        except OSError as error:
            output.write(("\n[harness] " + str(error) + "\n").encode("utf-8", errors="replace"))
            code, timed_out = None, False
    return Outcome(code, timed_out, round(time.monotonic() - started, 3), str(log))


def tail(path: Path, limit: int = 8000) -> str:
    if not path.is_file():
        return ""
    with path.open("rb") as stream:
        stream.seek(max(0, path.stat().st_size - limit))
        return stream.read(limit).decode("utf-8", errors="replace")


def require(outcome: Outcome, stage: str) -> None:
    if outcome.timed_out or outcome.exit_code != 0:
        raise HarnessError(f"{stage} failed: exit={outcome.exit_code}, timeout={outcome.timed_out}; log={outcome.log}")


def docker_preflight(log_dir: Path) -> str:
    docker = shutil.which("docker")
    if not docker:
        raise HarnessError("Docker CLI is not installed; install/start Docker Desktop with Linux containers or use the C16 CI workflow")
    outcome = execute([docker, "info", "--format", "{{.OSType}}"], log_dir / "docker-info.log", timeout=20)
    require(outcome, "Docker daemon")
    if "linux" not in tail(Path(outcome.log)).splitlines():
        raise HarnessError("C16 requires a Linux Docker daemon")
    return docker


def export_public(public_root: Path, destination: Path) -> None:
    archive_path = destination.parent / "public-source.tar"
    log = destination.parent / "git-export.log"
    outcome = execute(["git", "-C", str(public_root), "archive", "--format=tar",
                       "--output=" + str(archive_path), PUBLIC_SHA, "local_task", "agent/agent.py"], log, timeout=30)
    require(outcome, "export pinned public fixtures")
    total = 0
    with tarfile.open(archive_path) as archive:
        members = archive.getmembers()
        if len(members) > MAX_FILES:
            raise HarnessError("public source export has too many files")
        for member in members:
            relative = safe_member(member.name)
            target = destination.joinpath(*relative.parts)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            elif member.isfile():
                total += member.size
                if total > MAX_EXTRACTED_BYTES:
                    raise HarnessError("public source export is too large")
                stream = archive.extractfile(member)
                if stream is None:
                    raise HarnessError("unreadable source archive member")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(stream.read())
                target.chmod(member.mode & 0o777)
            else:
                raise HarnessError("public source export contains a link or special file")
    archive_path.unlink()


def load_task(task_dir: Path) -> dict[str, object]:
    config = tomllib.loads((task_dir / "task.toml").read_text(encoding="utf-8"))
    def limit(section: str, key: str, maximum: float) -> float:
        value = config[section][key]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 < value <= maximum:
            raise HarnessError(f"invalid public task limit: {section}.{key}")
        return float(value)
    required = ("instruction.md", "environment/Dockerfile", "tests/test.sh")
    if any(not (task_dir / name).is_file() for name in required):
        raise HarnessError(f"incomplete public task: {task_dir.name}")
    return {
        "agent_timeout": limit("agent", "timeout_sec", 3600),
        "verifier_timeout": limit("verifier", "timeout_sec", 3600),
        "build_timeout": limit("environment", "build_timeout_sec", 3600),
        "cpus": limit("environment", "cpus", 16),
        "memory_mb": int(limit("environment", "memory_mb", 32768)),
        "has_service": (task_dir / "environment/entrypoint.sh").is_file(),
        "instruction_sha256": file_sha(task_dir / "instruction.md"),
        "verifier_sha256": file_sha(task_dir / "tests/test.sh"),
    }


def prepare(public_root: Path, output: Path) -> dict[str, object]:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "c16-prepared-v1", "status": "preparing",
        "public_repository": PUBLIC_REPOSITORY, "public_commit": PUBLIC_SHA, "tasks": {}}
    try:
        docker = docker_preflight(output)
        export_public(public_root.resolve(), output / "public")
        require(execute([docker, "pull", BASE_IMAGE], output / "base-pull.log", timeout=1200), "ACP image pull")
        inspect = execute([docker, "image", "inspect", BASE_IMAGE, "--format", "{{json .RepoDigests}}"],
                          output / "base-digest.log", timeout=20)
        require(inspect, "ACP digest lookup")
        # Docker warnings can be emitted on stderr alongside formatted stdout.
        digests = next((json.loads(line) for line in reversed(tail(Path(inspect.log)).splitlines())
                        if line.startswith("[")), [])
        digest = next((value for value in digests if isinstance(value, str) and BASE_DIGEST.fullmatch(value)), None)
        if digest is None:
            raise HarnessError("ACP pull did not expose a pinned repository digest")
        report["base_image"] = digest
        for task_id in TASKS:
            task_dir = output / "public/local_task" / task_id
            task = load_task(task_dir)
            context = output / "build_contexts" / task_id
            shutil.copytree(task_dir / "environment", context)
            original = (context / "Dockerfile").read_text(encoding="utf-8")
            if not original.startswith("FROM " + BASE_IMAGE + "\n"):
                raise HarnessError("unexpected organizer Dockerfile base")
            # Only the disposable build copy changes; all verifier/source bytes
            # in public/ remain the exact export of the pinned Git commit.
            (context / "Dockerfile").write_bytes(original.replace("FROM " + BASE_IMAGE, "FROM " + digest, 1).encode("utf-8"))
            iid = output / (task_id + ".iid")
            require(execute([docker, "build", "--iidfile", str(iid), str(context)],
                            output / (task_id + "-build.log"), timeout=float(task["build_timeout"])), "task image " + task_id)
            image_id = iid.read_text(encoding="ascii").strip()
            if not IMAGE_ID.fullmatch(image_id):
                raise HarnessError("Docker build returned an invalid image ID")
            report["tasks"][task_id] = {**task, "image_id": image_id}
            write_json(output / "prepared.json", report)
        report["public_tree_sha256"] = tree_sha(output / "public")
        report["status"] = "ready"
    except (HarnessError, OSError, ValueError, KeyError, tarfile.TarError) as error:
        report["status"] = "blocked"
        report["reason"] = str(error)
    write_json(output / "prepared.json", report)
    return report


INSTALL_CODE = """import os, zipfile
with zipfile.ZipFile('/tmp/submission.zip') as z:
    z.extractall('/opt/harbor/local-agent')
os.chmod('/opt/harbor/local-agent/run.sh', 0o755)
os.makedirs('/logs/agent', exist_ok=True)
os.makedirs('/logs/verifier', exist_ok=True)
assert not os.path.exists('/tests'), 'verifier files are visible before the agent'
"""
HEALTH_CODE = """import time, urllib.request
deadline = time.monotonic() + 55
while time.monotonic() < deadline:
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=1) as r:
            if r.status == 200: break
    except OSError:
        time.sleep(0.25)
else:
    raise SystemExit('task API was not ready before agent startup')
"""
RESET_VERIFIER_CODE = """import os, shutil
shutil.rmtree('/logs/verifier', ignore_errors=True)
os.makedirs('/logs/verifier')
assert not os.path.exists('/tests'), 'agent created an unexpected /tests path'
"""


def parse_reward(value: str) -> int:
    value = value.strip()
    if value not in {"0", "1"}:
        raise HarnessError("verifier reward is missing or is not exactly 0/1")
    return int(value)


def run_task(docker: str, prepared: Path, submission: Path, task_id: str,
             task: dict[str, object], output: Path) -> dict[str, object]:
    output.mkdir(parents=True)
    name = "sbersdich-c16-" + uuid.uuid4().hex[:16]
    image_id = str(task["image_id"])
    if not IMAGE_ID.fullmatch(image_id):
        raise HarnessError("prepared task has an invalid image ID")
    result: dict[str, object] = {"task_id": task_id, "status": "failed", "passed": False,
        "reward": None, "stage": "setup", "image_id": image_id, "network": "none"}
    started = time.monotonic()
    task_dir = prepared / "public/local_task" / task_id
    try:
        # No bind mounts, published ports, Docker socket or host credentials.
        command = "exec /entrypoint.sh" if task["has_service"] else "exec tail -f /dev/null"
        require(execute([docker, "run", "-d", "--pull=never", "--name", name,
            "--label", "sbersdich.c16=true", "--network", "none", "--cpus", str(task["cpus"]),
            "--memory", str(task["memory_mb"]) + "m", "--entrypoint", "sh", image_id, "-c", command],
            output / "container-start.log", timeout=30), "container start")
        require(execute([docker, "cp", str(submission), name + ":/tmp/submission.zip"],
                        output / "upload.log", timeout=30), "submission upload")
        require(execute([docker, "exec", name, "python3", "-c", INSTALL_CODE],
                        output / "install.log", timeout=30), "submission install")
        require(execute([docker, "cp", str(prepared / "public/agent/agent.py"), name + ":" + REMOTE_AGENT + "/agent.py"],
                        output / "wrapper-upload.log", timeout=30), "standard wrapper upload")
        if task["has_service"]:
            require(execute([docker, "exec", name, "python3", "-c", HEALTH_CODE],
                            output / "service-ready.log", timeout=60), "task API readiness")
        result["stage"] = "agent"
        instruction = (task_dir / "instruction.md").read_text(encoding="utf-8")
        agent = execute([docker, "exec", "--workdir", REMOTE_AGENT,
                        "--env", "OPENAI_API_KEY=", "--env", "OPENAI_BASE_URL=", "--env", "LOCAL_AGENT_MODEL=",
                        name, "./run.sh", instruction],
                        output / "agent.log", timeout=float(task["agent_timeout"]))
        result["agent"] = asdict(agent)
        if agent.timed_out or agent.exit_code != 0:
            raise HarnessError("agent timed out or returned a nonzero exit code")
        result["stage"] = "verifier"
        # Clear reward files the agent could have created. The official suite is
        # supplied only now, after the agent is finished, never in its build context.
        require(execute([docker, "exec", name, "python3", "-c", RESET_VERIFIER_CODE],
                        output / "verifier-reset.log", timeout=20), "verifier reset")
        require(execute([docker, "cp", str(task_dir / "tests"), name + ":/tests"],
                        output / "verifier-upload.log", timeout=30), "original verifier upload")
        verifier = execute([docker, "exec", "--workdir", "/app", name, "bash", "/tests/test.sh"],
                           output / "verifier-run.log", timeout=float(task["verifier_timeout"]))
        result["verifier"] = asdict(verifier)
        require(verifier, "original verifier")
        read = execute([docker, "exec", name, "cat", "/logs/verifier/reward.txt"],
                       output / "reward.txt", timeout=20)
        require(read, "read official reward")
        result["reward"] = parse_reward(tail(output / "reward.txt", 100))
        result["passed"] = result["reward"] == 1
        result["status"] = "succeeded" if result["passed"] else "failed"
        result["reason"] = "original public verifier awarded " + str(result["reward"])
    except (HarnessError, OSError, ValueError, KeyError) as error:
        result["reason"] = str(error)
        if result["stage"] == "setup":
            result["status"] = "blocked"
    finally:
        execute([docker, "logs", name], output / "container.log", timeout=10)
        execute([docker, "cp", name + ":/logs/verifier", str(output / "verifier")],
                output / "collect-verifier.log", timeout=20)
        cleanup = execute([docker, "rm", "-f", name], output / "cleanup.log", timeout=20)
        result["cleanup"] = asdict(cleanup)
        if result["passed"] and (cleanup.timed_out or cleanup.exit_code != 0):
            result["passed"] = False
            result["status"] = "failed"
            result["reason"] = "official reward was 1, but task container cleanup failed"
        result["duration_seconds"] = round(time.monotonic() - started, 3)
        write_json(output / "result.json", result)
    return result


def run_prepared(prepared: Path, submission: Path, output: Path, tasks: tuple[str, ...] = TASKS) -> dict[str, object]:
    prepared, submission, output = prepared.resolve(), submission.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, object] = {"schema": "c16-results-v1", "status": "running", "public_commit": PUBLIC_SHA,
        "harness": "docker-acp-original-public-verifiers", "real_llm_tested": False,
        "tasks": [], "selected_tasks": list(tasks), "solved": 0, "all_passed": False}
    try:
        if not tasks or len(tasks) != len(set(tasks)) or any(task not in TASKS for task in tasks):
            raise HarnessError("invalid or duplicate task selection")
        report["submission"] = inspect_submission(submission)
        manifest = json.loads((prepared / "prepared.json").read_text(encoding="utf-8"))
        if manifest.get("schema") != "c16-prepared-v1" or manifest.get("status") != "ready" or manifest.get("public_commit") != PUBLIC_SHA:
            raise HarnessError("prepared manifest is not ready or uses an unexpected public revision")
        if tree_sha(prepared / "public") != manifest.get("public_tree_sha256"):
            raise HarnessError("prepared organizer files changed after image preparation")
        report["base_image"] = manifest["base_image"]
        docker = docker_preflight(output)
        for task_id in tasks:
            task = manifest["tasks"][task_id]
            if load_task(prepared / "public/local_task" / task_id) != {k: v for k, v in task.items() if k != "image_id"}:
                raise HarnessError("prepared task metadata differs from the original task.toml")
            result = run_task(docker, prepared, submission, task_id, task, output / task_id)
            report["tasks"].append(result)
            report["solved"] = sum(bool(item["passed"]) for item in report["tasks"])
            write_json(output / "summary.json", report)
        if file_sha(submission) != report["submission"]["sha256"] or tree_sha(prepared / "public") != manifest["public_tree_sha256"]:
            raise HarnessError("submission or organizer files changed during the run")
        report["all_passed"] = all(item["passed"] for item in report["tasks"])
        report["status"] = "succeeded" if report["all_passed"] else "failed"
    except (HarnessError, OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        report["status"] = "blocked"
        report["reason"] = str(error)
    write_json(output / "summary.json", report)
    traces = {item["task_id"]: {"task_id": item["task_id"], "status": item["status"],
              "reward": item["reward"], "reason": item["reason"], "phase": item["stage"],
              "log": tail(output / item["task_id"] / "verifier/pytest_output.txt") or tail(output / item["task_id"] / "agent.log")}
              for item in report["tasks"]}
    if not traces and report["status"] == "blocked":
        traces["c16-preflight"] = {"task_id": "c16-preflight", "status": "failed",
            "reason": report.get("reason", "preflight blocked"), "phase": "setup", "no_task_executed": True}
    write_json(output / "traces.json", traces)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare", help="online setup: export pinned fixtures and build ACP task images")
    prepare_parser.add_argument("--public-root", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    run_parser = commands.add_parser("run", help="offline execution: run an existing submission ZIP with the prepared task images")
    run_parser.add_argument("--prepared", type=Path, required=True)
    run_parser.add_argument("--submission", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--task", choices=TASKS, action="append")
    args = parser.parse_args(argv)
    try:
        report = (prepare(args.public_root, args.output) if args.command == "prepare" else
                  run_prepared(args.prepared, args.submission, args.output, tuple(args.task) if args.task else TASKS))
    except (OSError, HarnessError) as error:
        print(json.dumps({"status": "blocked", "reason": str(error)}, ensure_ascii=False, indent=2))
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] == "blocked":
        return 2
    return 0 if report["status"] in {"ready", "succeeded"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
