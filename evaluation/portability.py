#!/usr/bin/env python3
"""Run the isolated C-12 portability and adversarial verification suite.

The suite creates every fixture in a temporary directory, never reads public
task answers and never mutates the repository.  It exercises the real scanner,
fixer, validators, workspace tools, forensics parser and C-11 failure journal.
"""

from __future__ import annotations

import argparse
import ast
import json
import socket
import sys
import tempfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from unittest import mock

from agent.core.workspace import (
    MAX_COMMAND_OUTPUT_BYTES,
    WorkspaceError,
    apply_workspace_patch,
    run_workspace_command,
)
from agent.tools.forensics import ForensicsError, analyze_incident, format_report
from agent.tools.security_scan import scan_python_source
from agent.tools.sql_parameterize import parameterize_source
from agent.validators import ArtifactRule, validate_artifact
from evaluation.failure_analysis import (
    MAX_EVIDENCE,
    MAX_EXCERPT_CHARS,
    AnalysisError,
    analyze_paths,
    redact_text,
    write_report,
)


SCHEMA_VERSION = 1
REPO_ROOT = Path(__file__).resolve().parents[1]


class PortabilityFailure(AssertionError):
    """Raised when a portability invariant is not satisfied."""


class OfflineNetworkUse(RuntimeError):
    """Raised if an in-process portability check attempts network access."""


@dataclass(frozen=True)
class CheckSpec:
    name: str
    area: str
    run: Callable[[], str]


@dataclass(frozen=True)
class CheckResult:
    name: str
    area: str
    passed: bool
    detail: str

    def as_payload(self) -> dict[str, object]:
        return asdict(self)


def require(condition: object, message: str) -> None:
    if not condition:
        raise PortabilityFailure(message)


def _write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def _write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    _write_bytes(path, content.encode(encoding))


def _json_line(payload: Mapping[str, object]) -> str:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def check_artifact_output_contracts() -> str:
    """Prove that host line endings cannot weaken exact output contracts."""

    expected = "status=готово\n"
    variants = (
        ("lf-unicode.txt", expected.encode("utf-8"), True),
        ("crlf.txt", expected.replace("\n", "\r\n").encode("utf-8"), False),
        ("extra-newline.txt", (expected + "\n").encode("utf-8"), False),
        ("spaces-around-equals.txt", "status = готово\n".encode("utf-8"), False),
    )
    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-artifacts-") as temporary:
        root = Path(temporary) / "каталог с пробелом"
        for name, content, expected_pass in variants:
            path = root / name
            _write_bytes(path, content)
            result = validate_artifact(
                ArtifactRule(kind="exact-text", path=path, expected_text=expected)
            )
            require(
                result.passed is expected_pass,
                f"{name}: expected passed={expected_pass}, got {result.passed}: {result.detail}",
            )

        missing = validate_artifact(
            ArtifactRule(
                kind="exact-text",
                path=root / "missing.txt",
                expected_text=expected,
            )
        )
        require(not missing.passed, "missing exact-text artifact was accepted")
    return "LF and Unicode accepted; CRLF, extra newline, whitespace drift and missing file rejected"


def check_sql_source_variations() -> str:
    """Exercise three unrelated SQL variants, including Unicode and CRLF."""

    variants = (
        (
            "unicode_crlf.py",
            "async def найти(db, имя):\r\n"
            "    запрос   =   f\"SELECT * FROM accounts WHERE owner = '{имя}'\"\r\n"
            "    return await db.fetchrow(запрос)\r\n",
            True,
        ),
        (
            "like_lf.py",
            "async def browse(db, term):\n"
            "    return await db.fetch("
            "f\"SELECT * FROM catalog WHERE title ILIKE '%{term}%'\")\n",
            False,
        ),
        (
            "numeric_lf.py",
            "async def load(db, external_id):\n"
            "    statement = f\"SELECT * FROM audit_log "
            "WHERE external_id={external_id}\"\n"
            "    return await db.fetch(statement)\n",
            False,
        ),
    )
    for name, source, has_crlf in variants:
        findings_before = scan_python_source(source, name)
        require(len(findings_before) == 1, f"{name}: expected one SQLi finding")
        updated, changes = parameterize_source(source, name)
        require(len(changes) == 1, f"{name}: expected one complete change")
        require(not scan_python_source(updated, name), f"{name}: finding remains after fix")
        ast.parse(updated, filename=name)
        require("$1" in updated, f"{name}: driver placeholder is missing")
        if has_crlf:
            require("\r\n" in updated, f"{name}: CRLF source was not preserved")
            require(
                "\n" not in updated.replace("\r\n", ""),
                f"{name}: mixed line endings were introduced",
            )
            require("найти" in updated and "имя" in updated, f"{name}: Unicode was lost")
    return "three SQL variants scan, parameterize, parse and rescan cleanly without newline drift"


def check_partial_security_fix() -> str:
    """A one-of-two SQL fix must remain visibly incomplete after rescan."""

    original = (
        "async def read_owner(db, user):\n"
        "    return await db.fetchrow("
        "f\"SELECT * FROM alpha WHERE owner = '{user}'\")\n\n"
        "async def search_label(db, term):\n"
        "    return await db.fetch("
        "f\"SELECT * FROM beta WHERE label ILIKE '%{term}%'\")\n"
    )
    partial = original.replace(
        "f\"SELECT * FROM alpha WHERE owner = '{user}'\"",
        "\"SELECT * FROM alpha WHERE owner = $1\", user",
        1,
    )
    require(len(scan_python_source(original, "service.py")) == 2, "fixture must have two findings")
    remaining = scan_python_source(partial, "service.py")
    require(len(remaining) == 1, "partial fix was not detected by the mandatory rescan")

    complete, changes = parameterize_source(original, "service.py")
    require(len(changes) == 2, "complete fixer did not change both vulnerable calls")
    require(not scan_python_source(complete, "service.py"), "complete fix did not rescan cleanly")
    return "partial one-of-two repair is rejected; complete repair removes both findings"


def _expect_patch_failure(root: Path, patch: str, before: dict[str, bytes]) -> None:
    try:
        apply_workspace_patch(root, patch=patch)
    except WorkspaceError:
        pass
    else:
        raise PortabilityFailure("adversarial patch was unexpectedly accepted")
    after = {name: (root / name).read_bytes() for name in before}
    require(after == before, "failed multi-file patch left a partial write")


def check_atomic_workspace_patch() -> str:
    """Reject bad patches before any file is replaced and preserve CRLF."""

    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-patch-") as temporary:
        root = Path(temporary) / "рабочая область"
        first = root / "first.py"
        second = root / "second.py"
        _write_bytes(first, b"value = 1\r\n")
        _write_bytes(second, b"value = 2\n")
        before = {"first.py": first.read_bytes(), "second.py": second.read_bytes()}

        invalid_second_hunk = (
            "--- a/first.py\n+++ b/first.py\n"
            "@@ -1 +1 @@\n-value = 1\n+value = 10\n"
            "--- a/second.py\n+++ b/second.py\n"
            "@@ -1 +1 @@\n-value = 999\n+value = 20\n"
        )
        _expect_patch_failure(root, invalid_second_hunk, before)

        traversal = (
            "--- a/../first.py\n+++ b/../first.py\n"
            "@@ -1 +1 @@\n-value = 1\n+value = 10\n"
        )
        _expect_patch_failure(root, traversal, before)

        malformed_counts = (
            "--- a/first.py\n+++ b/first.py\n"
            "@@ -1,2 +1,1 @@\n-value = 1\n+value = 10\n"
        )
        _expect_patch_failure(root, malformed_counts, before)

        valid = (
            "--- a/first.py\n+++ b/first.py\n"
            "@@ -1 +1 @@\n-value = 1\n+value = 3\n"
        )
        result = apply_workspace_patch(root, patch=valid)
        require(result["changed_paths"] == ["first.py"], "valid patch changed wrong paths")
        require(first.read_bytes() == b"value = 3\r\n", "valid patch did not preserve CRLF")
        require(second.read_bytes() == before["second.py"], "unlisted file was modified")
    return "three bad-diff variants are atomic; valid patch preserves CRLF and scope"


def _portable_incident(root: Path) -> Path:
    incident = root / "инцидент с пробелом"
    incident.mkdir(parents=True)
    _write_bytes(incident / "app_empty.jsonl", b"")
    _write_text(incident / "app_primary.jsonl", "{}\n{partial-record")
    selected = {
        "ts": "2040-04-04T12:00:00.123Z",
        "http": {"request_id": "portable-rid-7", "method": "POST"},
        "identity": {"subject": "portable-user"},
        "audit": {
            "event": "sensitive_export",
            "bytes": 3210,
            "payload_logical_bytes": 987654,
            "result": "ok",
        },
    }
    recovered = "\ufeff" + _json_line(selected) + "\r\n"
    _write_text(incident / "app_данные_02.jsonl", recovered)
    _write_text(
        incident / "edge_decisions_00.log",
        "request_id = decoy decision = WATCHLIST_ONLY\n",
    )
    _write_text(
        incident / "edge_decisions_данные_02.log",
        "request_id   =   portable-rid-7   decision = CONFIRM_SENSITIVE\r\n",
    )
    _write_text(incident / "proxy_access_00.log", "Z" * 128_000 + "\n")
    _write_text(
        incident / "proxy_access_данные_02.log",
        "10.0.0.5 - portable-user [04/Apr/2040:12:00:01 +0000] "
        '"POST /export HTTP/1.1" 200 3210 "-" "agent" '
        'rid = "portable-rid-7" xff = "203.0.113.77, 10.0.0.5"\r\n',
    )
    _write_text(
        incident / "auth_данные.log",
        "Apr 4 host sshd[7]: Accepted publickey for portable-user "
        "from 203.0.113.77 port 6000 ssh2\n",
    )
    return incident


def check_forensics_shards() -> str:
    """Correlate a varied incident across empty, large and Unicode shards."""

    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-forensics-") as temporary:
        incident = _portable_incident(Path(temporary))
        conclusion = analyze_incident(incident)
        require(conclusion.attacker_ip == "203.0.113.77", "wrong attributed IP")
        require(conclusion.compromised_user == "portable-user", "wrong compromised user")
        require(conclusion.exfil_bytes == 987654, "wrong logical export size")
        require(conclusion.request_id == "portable-rid-7", "wrong request correlation")
        require(conclusion.application_source.path.name == "app_данные_02.jsonl", "wrong app shard")
        require(len(conclusion.edge_sources) == 1, "edge confirmation was not unique")
        require(len(conclusion.auth_sources) == 1, "auth corroboration was not retained")
        report = format_report(conclusion)
        require("\r" not in report and report.endswith("\n"), "report is not canonical LF")
        require(len(report.splitlines()) == 4, "report field contract changed")
    return "empty JSONL, BOM/CRLF, whitespace, Unicode names, large line and log shards correlate"


def check_missing_inputs_fail_closed() -> str:
    """Missing task data must produce evidence-backed errors, never guesses."""

    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-missing-") as temporary:
        root = Path(temporary)
        missing_artifact = validate_artifact(
            ArtifactRule(kind="json", path=root / "missing.json")
        )
        require(not missing_artifact.passed, "missing JSON artifact was accepted")

        try:
            analyze_paths([root / "missing-run.json"])
        except AnalysisError as error:
            require("does not exist" in str(error), "missing run has unclear error")
        else:
            raise PortabilityFailure("missing failure-journal input was accepted")

        incident = root / "incident"
        event = {
            "ts": "2041-01-02T03:04:05.006Z",
            "http": {"request_id": "missing-proxy"},
            "identity": {"subject": "service-user"},
            "audit": {"event": "sensitive_export", "bytes": 42, "result": "ok"},
        }
        _write_text(incident / "app.jsonl", _json_line(event) + "\n")
        _write_text(
            incident / "edge_decisions.log",
            "request_id=missing-proxy decision=CONFIRM_SENSITIVE\n",
        )
        try:
            analyze_incident(incident)
        except ForensicsError as error:
            require("no proxy access logs" in str(error), "missing proxy has unclear error")
        else:
            raise PortabilityFailure("incident without proxy evidence was accepted")
    return "missing artifact, missing run input and incomplete evidence all fail closed"


def check_failure_journal_shards() -> str:
    """Aggregate several varied run shards without losing or inflating evidence."""

    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-journal-") as temporary:
        root = Path(temporary) / "журналы агента"
        _write_bytes(root / "00-empty.jsonl", b"")
        jsonl = (
            _json_line(
                {
                    "task_id": "бюджет-задача",
                    "status": "failed",
                    "reason": "step budget exhausted",
                }
            )
            + "\r\n"
            + _json_line({"task_id": "recovered", "status": "succeeded"})
            + "\r\n"
            + _json_line(
                {
                    "task_id": "deadline-case",
                    "status": "failed",
                    "reason": "deadline budget exhausted",
                }
            )
            + "\r\n"
        )
        _write_text(root / "01-runs.jsonl", jsonl)
        _write_text(
            root / "02-large-test.log",
            "noise " + "x" * 200_000 + "\nRan 7 tests\nFAILED (errors=2)\n",
        )
        _write_text(
            root / "03-success.json",
            json.dumps({"task_id": "clean", "status": "succeeded"}),
        )

        report = analyze_paths([root])
        require(report["input_file_count"] == 4, "not every shard was inventoried")
        require(report["analyzed_record_count"] == 5, "wrong run-record count")
        require(report["successful_record_count"] == 2, "successful runs were miscounted")
        require(report["failure_count"] == 3, "wrong failure count")
        require(report["unknown_failure_count"] == 0, "known failures became unknown")
        categories = {item["category"] for item in report["failures"]}
        require(categories == {"budget", "timeout", "regression"}, "wrong categories")
        task_ids = {item["task_id"] for item in report["failures"]}
        require("бюджет-задача" in task_ids, "Unicode task ID was lost")
        for failure in report["failures"]:
            evidence = failure["evidence"]
            require(1 <= len(evidence) <= MAX_EVIDENCE, "evidence count is unbounded")
            require(
                all(len(item["excerpt"]) <= MAX_EXCERPT_CHARS + 2 for item in evidence),
                "large log escaped the evidence bound",
            )
    return "empty/CRLF JSONL, Unicode IDs, large logs and four shards yield three exact failures"


def check_bounded_processes() -> str:
    """Verify large stdout, timeout and invalid cwd behavior on this host."""

    with tempfile.TemporaryDirectory(prefix="sbersdich-c12-process-") as temporary:
        root = Path(temporary)
        _write_text(
            root / "test_noise.py",
            "import unittest\n\n"
            "class Noise(unittest.TestCase):\n"
            "    def test_output(self):\n"
            "        print('N' * 50000)\n",
        )
        noisy = run_workspace_command(
            root,
            argv=[sys.executable, "-m", "unittest", "test_noise.Noise.test_output"],
            timeout_seconds=10,
        )
        require(noisy["exit_code"] == 0, "bounded noisy test failed")
        require(noisy["output_truncated"] is True, "large stdout was not marked truncated")
        require(len(noisy["output"].encode("utf-8")) <= MAX_COMMAND_OUTPUT_BYTES, "stdout cap failed")
        require(noisy["total_output_bytes"] > MAX_COMMAND_OUTPUT_BYTES, "fixture was not large")

        _write_text(
            root / "test_hang.py",
            "import time\nimport unittest\n\n"
            "class Slow(unittest.TestCase):\n"
            "    def test_wait(self):\n"
            "        time.sleep(30)\n",
        )
        hanging = run_workspace_command(
            root,
            argv=[sys.executable, "-m", "unittest", "test_hang.Slow.test_wait"],
            timeout_seconds=1,
        )
        require(hanging["timed_out"] is True, "hanging command ignored timeout")

        try:
            run_workspace_command(
                root,
                argv=[sys.executable, "-m", "unittest", "test_noise"],
                cwd="../outside",
                timeout_seconds=5,
            )
        except WorkspaceError:
            pass
        else:
            raise PortabilityFailure("command escaped through an invalid cwd")
    return "large stdout is capped, hanging process is killed and external cwd is rejected"


def _import_roots(path: Path) -> set[str]:
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".", 1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".", 1)[0])
    return roots


def check_stdlib_runtime_dependencies() -> str:
    """Ensure the checked runtime path needs no third-party installation."""

    paths = (
        REPO_ROOT / "agent" / "local_agent.py",
        REPO_ROOT / "agent" / "core" / "config.py",
        REPO_ROOT / "agent" / "core" / "llm.py",
        REPO_ROOT / "agent" / "core" / "loop.py",
        REPO_ROOT / "agent" / "core" / "workspace.py",
        REPO_ROOT / "agent" / "tools" / "forensics.py",
        REPO_ROOT / "agent" / "tools" / "security_scan.py",
        REPO_ROOT / "agent" / "tools" / "sql_parameterize.py",
        REPO_ROOT / "agent" / "validators.py",
        REPO_ROOT / "evaluation" / "failure_analysis.py",
        Path(__file__).resolve(),
    )
    local_roots = {"agent", "evaluation", "security_scan", "tools"}
    allowed = set(sys.stdlib_module_names) | local_roots | {"__future__"}
    external: dict[str, list[str]] = {}
    for path in paths:
        unknown = sorted(_import_roots(path) - allowed)
        if unknown:
            external[path.relative_to(REPO_ROOT).as_posix()] = unknown
    require(not external, f"third-party runtime imports detected: {external}")

    entrypoint = (REPO_ROOT / "run.sh").read_text(encoding="utf-8").casefold()
    forbidden_installers = ("pip install", "apt install", "apk add", "curl ", "wget ")
    require(
        not any(command in entrypoint for command in forbidden_installers),
        "run.sh attempts installation or download",
    )
    return f"{len(paths)} runtime modules use only stdlib/local imports; run.sh installs nothing"


PORTABILITY_CHECKS = (
    CheckSpec("artifact-output-contracts", "format", check_artifact_output_contracts),
    CheckSpec("sql-source-variations", "audit-fix", check_sql_source_variations),
    CheckSpec("partial-security-fix", "audit-fix", check_partial_security_fix),
    CheckSpec("atomic-workspace-patch", "workspace", check_atomic_workspace_patch),
    CheckSpec("forensics-log-shards", "forensics", check_forensics_shards),
    CheckSpec("missing-inputs-fail-closed", "validation", check_missing_inputs_fail_closed),
    CheckSpec("failure-journal-shards", "triage", check_failure_journal_shards),
    CheckSpec("bounded-processes", "execution", check_bounded_processes),
    CheckSpec("stdlib-runtime-dependencies", "offline", check_stdlib_runtime_dependencies),
)


def _deny_network(*_args: object, **_kwargs: object) -> None:
    raise OfflineNetworkUse("network access attempted during the C-12 offline suite")


@contextmanager
def network_disabled() -> Iterator[None]:
    """Block common in-process socket entrypoints for deterministic checks."""

    with (
        mock.patch("socket.create_connection", side_effect=_deny_network),
        mock.patch.object(socket.socket, "connect", new=_deny_network),
        mock.patch.object(socket.socket, "connect_ex", new=_deny_network),
    ):
        yield


def execute_checks(checks: Sequence[CheckSpec]) -> list[CheckResult]:
    results: list[CheckResult] = []
    with network_disabled():
        for check in checks:
            try:
                detail = check.run()
            except Exception as error:  # Keep the report when one adversarial case fails.
                rendered = redact_text(f"{type(error).__name__}: {error}")
                results.append(CheckResult(check.name, check.area, False, rendered[:1000]))
            else:
                results.append(CheckResult(check.name, check.area, True, detail))
    return results


def run_portability_suite(
    checks: Sequence[CheckSpec] = PORTABILITY_CHECKS,
) -> dict[str, object]:
    results = execute_checks(checks)
    passed_count = sum(result.passed for result in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": "c12-portability-adversarial",
        "offline_parent_network_guard": True,
        "passed": bool(results) and passed_count == len(results),
        "check_count": len(results),
        "passed_count": passed_count,
        "failed_count": len(results) - passed_count,
        "checks": [result.as_payload() for result in results],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evaluation/results/c12_portability.json"),
        help="JSON report path (default: evaluation/results/c12_portability.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_portability_suite()
    try:
        write_report(args.output, report)
    except AnalysisError as error:
        print(f"C-12 report error: {error}", file=sys.stderr)
        return 2
    stream = sys.stdout if report["passed"] else sys.stderr
    print(
        f"C-12 portability: {report['passed_count']}/{report['check_count']} passed; "
        f"output={args.output.resolve()}",
        file=stream,
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
