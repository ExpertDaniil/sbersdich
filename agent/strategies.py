#!/usr/bin/env python3
"""Deterministic first-pass routing for supported cybersecurity task modes."""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class StrategyDecision:
    mode: str
    should_modify_project: bool
    expected_artifacts: tuple[str, ...]
    playbook: str
    confidence: str
    reason: str


def contains_any(text: str, patterns: tuple[str, ...]) -> bool:
    return any(re.search(pattern, text, flags=re.IGNORECASE) for pattern in patterns)


def classify_instruction(instruction: str) -> StrategyDecision:
    normalized = " ".join(instruction.split())
    no_modify = contains_any(
        normalized,
        (
            r"\bdo not modify\b",
            r"\bwithout modifying\b",
            r"\bне (?:изменяй|изменять|модифицируй)\b",
        ),
    )
    asks_report = contains_any(
        normalized,
        (r"security_report\.json", r"bug bounty report", r"machine-readable.*report"),
    )
    asks_fix = contains_any(
        normalized,
        (
            r"\bfix (?:it|them|the|security|vulnerab)",
            r"\bremediate\b",
            r"\bpatch\b",
            r"\bисправ(?:ь|ить|ьте)\b",
            r"\bустран(?:и|ить|ите)\b",
        ),
    )
    asks_forensics = contains_any(
        normalized,
        (
            r"incident_report\.txt",
            r"\bincident\b.*\blogs?\b",
            r"\bforensics?\b",
            r"\bфорензик",
        ),
    )
    asks_ctf = contains_any(
        normalized,
        (
            r"\bctf\b",
            r"\bcapture\s+the\s+flag\b",
            r"\b(?:find|recover|extract|decode|submit|write)\b.{0,80}\bflag\b",
            r"\bflag\b.{0,80}\b(?:challenge|file|path|answer)\b",
            r"\b(?:найди|извлеки|декодируй|восстанови|запиши|сохрани)\w*\b"
            r".{0,80}\bфлаг\w*\b",
            r"\bфлаг\w*\b.{0,80}\b(?:ctf|задач|файл|ответ)\w*\b",
        ),
    )
    describes_non_ctf_flag = contains_any(
        normalized,
        (
            r"\bfeature\s+flags?\b",
            r"\bconfiguration\s+flags?\b",
            r"\bcommand[- ]line\s+flags?\b",
            r"\bфлаг\w*\s+(?:функц|конфигурац|командн\w*\s+строк)",
        ),
    )

    if (
        asks_ctf
        and not describes_non_ctf_flag
        and not asks_fix
        and not asks_forensics
        and not asks_report
    ):
        return StrategyDecision(
            mode="ctf",
            should_modify_project=True,
            expected_artifacts=(),
            playbook="agent/playbooks/ctf.md",
            confidence="high",
            reason="instruction requests an offline CTF flag or answer artifact",
        )
    if no_modify or (asks_report and not asks_fix):
        return StrategyDecision(
            mode="audit",
            should_modify_project=False,
            expected_artifacts=("security_report.json",),
            playbook="agent/playbooks/audit.md",
            confidence="high",
            reason="instruction requests a security report and forbids code modification",
        )
    if asks_fix:
        return StrategyDecision(
            mode="fix",
            should_modify_project=True,
            expected_artifacts=(),
            playbook="agent/playbooks/fix.md",
            confidence="high",
            reason="instruction explicitly requests remediation of project code",
        )
    if asks_forensics:
        return StrategyDecision(
            mode="forensics",
            should_modify_project=False,
            expected_artifacts=("incident_report.txt",),
            playbook="agent/playbooks/forensics.md",
            confidence="high",
            reason="instruction requests correlation of incident evidence",
        )
    return StrategyDecision(
        mode="general",
        should_modify_project=True,
        expected_artifacts=(),
        playbook="",
        confidence="low",
        reason="no high-confidence audit, fix, forensics or CTF contract was detected",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instruction")
    args = parser.parse_args()
    print(json.dumps(asdict(classify_instruction(args.instruction)), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
