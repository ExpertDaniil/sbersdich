#!/usr/bin/env python3
"""Deterministic first-pass routing for audit, fix and forensics tasks."""

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
            playbook="",
            confidence="medium",
            reason="instruction describes incident evidence; C-07 will attach its playbook",
        )
    return StrategyDecision(
        mode="general",
        should_modify_project=True,
        expected_artifacts=(),
        playbook="",
        confidence="low",
        reason="no high-confidence audit, fix or forensics contract was detected",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instruction")
    args = parser.parse_args()
    print(json.dumps(asdict(classify_instruction(args.instruction)), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
