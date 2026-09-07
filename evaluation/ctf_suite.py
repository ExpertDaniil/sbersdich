#!/usr/bin/env python3
"""Run generated offline CTF variations through the real agent loop."""

from __future__ import annotations

import argparse
import base64
import codecs
import gzip
import hashlib
import json
import re
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Sequence

from agent.core.loop import AgentLoop
from agent.core.models import AgentAction, DriverContext, LoopLimits
from agent.validators import normalize_relative_path
from evaluation.failure_analysis import AnalysisError, redact_text, write_report
from evaluation.portability import network_disabled


SCHEMA_VERSION = 1


@dataclass(frozen=True)
class CtfCase:
    task_id: str
    instruction: str
    input_path: str
    input_content: bytes
    reader: str
    operations: tuple[dict[str, str], ...]
    output_path: str
    expected: str


@dataclass(frozen=True)
class CtfCaseResult:
    task_id: str
    passed: bool
    agent_status: str
    mode: str | None
    steps_used: int
    validations_used: int
    evidence_unchanged: bool
    artifact_sha256: str | None
    reason: str

    def as_payload(self) -> dict[str, object]:
        return asdict(self)


def _derived_flag(prefix: str, label: str) -> str:
    suffix = hashlib.sha256(f"sbersdich-c13:{label}".encode()).hexdigest()[:18]
    return f"{prefix}{{{suffix}}}"


def _xor_bytes(value: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(value))


def build_ctf_cases() -> tuple[CtfCase, ...]:
    """Create deterministic tasks whose answers are absent from their workspaces."""

    layered_flag = _derived_flag("CTF", "layered-text")
    rotated = codecs.encode(layered_flag, "rot_13").encode("utf-8")
    layered_payload = base64.b64encode(rotated)

    xor_flag = _derived_flag("SBER", "repeating-xor")
    xor_key = b"forest-key"
    xor_payload = _xor_bytes(xor_flag.encode("utf-8"), xor_key)

    compressed_flag = _derived_flag("FLAG", "compressed-token")
    compressed_payload = base64.urlsafe_b64encode(
        gzip.compress(compressed_flag.encode("utf-8"), mtime=0)
    ).rstrip(b"=")

    return (
        CtfCase(
            task_id="layered-text",
            instruction=(
                "Offline CTF challenge. The file `encoded clues/слой.txt` contains "
                "Base64 text; the decoded value uses ROT13. Recover the flag and "
                "write the flag to `/app/flag.txt`. Do not modify challenge evidence."
            ),
            input_path="encoded clues/слой.txt",
            input_content=layered_payload,
            reader="text",
            operations=({"operation": "base64"}, {"operation": "rot13"}),
            output_path="flag.txt",
            expected=layered_flag,
        ),
        CtfCase(
            task_id="binary-xor",
            instruction=(
                "CTF task: `binary/blob.bin` is encrypted with repeating XOR key "
                "forest-key. Recover the flag and save the answer to "
                "`/app/result.txt`; preserve the binary evidence."
            ),
            input_path="binary/blob.bin",
            input_content=xor_payload,
            reader="bytes",
            operations=(
                {"operation": "hex"},
                {"operation": "xor", "key_text": xor_key.decode("ascii")},
            ),
            output_path="result.txt",
            expected=xor_flag,
        ),
        CtfCase(
            task_id="compressed-base64url",
            instruction=(
                "Capture the flag from `compressed/archive token.txt`. The token is "
                "unpadded Base64URL containing a gzip stream. Write the recovered "
                "flag to `/app/answer.txt` without changing input files."
            ),
            input_path="compressed/archive token.txt",
            input_content=compressed_payload,
            reader="text",
            operations=({"operation": "base64url"}, {"operation": "gzip"}),
            output_path="answer.txt",
            expected=compressed_flag,
        ),
    )


class PipelineCtfDriver:
    """Replay an evidence-derived transform plan without knowing the answer."""

    def __init__(
        self,
        *,
        input_path: str,
        input_size: int,
        reader: str,
        operations: tuple[dict[str, str], ...],
        output_path: str,
    ):
        if reader not in {"text", "bytes"}:
            raise ValueError(f"unsupported CTF reader: {reader}")
        self.input_path = input_path
        self.input_size = input_size
        self.reader = reader
        self.operations = operations
        self.output_path = output_path
        self.candidate: str | None = None

    @staticmethod
    def _successful_events(context: DriverContext):
        return [
            event
            for event in context.events
            if event.action is not None
            and event.tool_result is not None
            and event.tool_result.ok
        ]

    def next_action(self, context: DriverContext) -> AgentAction:
        failed = [
            event
            for event in context.events
            if event.tool_result is not None and not event.tool_result.ok
        ]
        if failed:
            return AgentAction(
                "abort",
                rationale=f"CTF pipeline tool failed: {failed[-1].tool_result.summary}",  # type: ignore[union-attr]
            )

        events = self._successful_events(context)
        names = [event.action.name for event in events]  # type: ignore[union-attr]
        if not events:
            if self.reader == "text":
                return AgentAction("read_file", {"path": self.input_path})
            return AgentAction(
                "read_bytes",
                {"path": self.input_path, "offset": 0, "length": self.input_size},
            )

        latest = events[-1]
        assert latest.action is not None and latest.tool_result is not None
        if latest.action.name in {"read_file", "read_bytes"} and "write_exact_text" not in names:
            data = latest.tool_result.data
            if latest.action.name == "read_file":
                value = data.get("content")
            else:
                if data.get("truncated"):
                    return AgentAction("abort", rationale="binary evidence read was truncated")
                value = data.get("hex")
            if not isinstance(value, str) or not value:
                return AgentAction("abort", rationale="CTF evidence produced no transform input")
            return AgentAction(
                "ctf_transform",
                {"value": value, "steps": [dict(step) for step in self.operations]},
            )

        if latest.action.name == "ctf_transform":
            value = latest.tool_result.data.get("text")
            candidates = latest.tool_result.data.get("flag_candidates")
            if (
                not isinstance(value, str)
                or not isinstance(candidates, list)
                or candidates != [value]
            ):
                return AgentAction(
                    "abort",
                    rationale="transform did not yield one exact supported flag candidate",
                )
            self.candidate = value
            return AgentAction(
                "write_exact_text",
                {"path": self.output_path, "content": value},
            )

        if latest.action.name == "write_exact_text":
            return AgentAction("read_file", {"path": self.output_path})

        if latest.action.name == "read_file" and "write_exact_text" in names:
            if latest.tool_result.data.get("content") != self.candidate:
                return AgentAction("abort", rationale="written CTF answer failed read-back")
            return AgentAction("finish", rationale="CTF answer passed exact read-back")

        return AgentAction("abort", rationale="unexpected CTF pipeline state")


def _evidence_digest(root: Path, output_path: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        relative = path.relative_to(root).as_posix()
        if relative == output_path:
            continue
        digests[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return digests


def run_ctf_case(case: CtfCase) -> CtfCaseResult:
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", case.task_id):
        raise ValueError("CTF task_id must be a bounded lowercase identifier")
    input_relative = normalize_relative_path(case.input_path)
    output_relative = normalize_relative_path(case.output_path)
    if input_relative == output_relative:
        raise ValueError("CTF input and output paths must differ")
    with tempfile.TemporaryDirectory(prefix=f"sbersdich-c13-{case.task_id}-") as temporary:
        root = Path(temporary) / "app"
        input_path = root / input_relative
        input_path.parent.mkdir(parents=True, exist_ok=True)
        input_path.write_bytes(case.input_content)
        before = _evidence_digest(root, output_relative)

        driver = PipelineCtfDriver(
            input_path=input_relative,
            input_size=len(case.input_content),
            reader=case.reader,
            operations=case.operations,
            output_path=output_relative,
        )
        result = AgentLoop(
            workdir=root,
            driver=driver,
            limits=LoopLimits(
                max_steps=8,
                max_validations=2,
                max_repeated_action=2,
                deadline_seconds=20,
            ),
        ).run(case.instruction)
        after = _evidence_digest(root, output_relative)
        evidence_unchanged = before == after

        artifact = root / output_relative
        if artifact.is_file() and not artifact.is_symlink():
            artifact_bytes = artifact.read_bytes()
            artifact_sha256 = hashlib.sha256(artifact_bytes).hexdigest()
        else:
            artifact_bytes = None
            artifact_sha256 = None
        expected_bytes = case.expected.encode("utf-8")

        if not result.succeeded:
            reason = result.reason
        elif not evidence_unchanged:
            reason = "challenge evidence changed"
        elif artifact_bytes != expected_bytes:
            reason = "answer artifact does not match the external exact verifier"
        else:
            reason = "agent loop and external exact verifier passed"
        passed = (
            result.succeeded
            and evidence_unchanged
            and artifact_bytes == expected_bytes
        )
        return CtfCaseResult(
            task_id=case.task_id,
            passed=passed,
            agent_status=result.status,
            mode=result.decision.mode if result.decision else None,
            steps_used=result.steps_used,
            validations_used=result.validations_used,
            evidence_unchanged=evidence_unchanged,
            artifact_sha256=artifact_sha256,
            reason=redact_text(reason)[:1000],
        )


def run_ctf_suite(cases: Sequence[CtfCase] | None = None) -> dict[str, Any]:
    selected = tuple(build_ctf_cases() if cases is None else cases)
    results: list[CtfCaseResult] = []
    with network_disabled():
        for case in selected:
            try:
                results.append(run_ctf_case(case))
            except Exception as error:  # Keep later independent cases observable.
                results.append(
                    CtfCaseResult(
                        task_id=case.task_id,
                        passed=False,
                        agent_status="failed",
                        mode=None,
                        steps_used=0,
                        validations_used=0,
                        evidence_unchanged=False,
                        artifact_sha256=None,
                        reason=redact_text(f"{type(error).__name__}: {error}")[:1000],
                    )
                )
    solved = sum(result.passed for result in results)
    return {
        "schema_version": SCHEMA_VERSION,
        "suite": "c13-generated-ctf",
        "offline_parent_network_guard": True,
        "passed": bool(results) and solved == len(results),
        "task_count": len(results),
        "solved_count": solved,
        "failed_count": len(results) - solved,
        "tasks": [result.as_payload() for result in results],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("evaluation/results/c13_ctf.json"),
        help="JSON report path (default: evaluation/results/c13_ctf.json)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    report = run_ctf_suite()
    try:
        write_report(args.output, report)
    except AnalysisError as error:
        print(f"C-13 report error: {error}", file=sys.stderr)
        return 2
    stream = sys.stdout if report["passed"] else sys.stderr
    print(
        f"C-13 CTF: {report['solved_count']}/{report['task_count']} solved; "
        f"output={args.output.resolve()}",
        file=stream,
    )
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
