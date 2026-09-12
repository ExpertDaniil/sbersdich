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
            r"\bdo not (?:modify|fix|change)(?:\s+or\s+(?:modify|fix|change))?\s+(?:(?:the|any)\s+)?(?:anything|code|source|project|application|files?\b(?!\s+(?:under|in)\s+tests))",
            r"\bwithout (?:modifying|fixing|changing)\s+(?:(?:the|any)\s+)?(?:anything|code|source|project|application|files?\b(?!\s+(?:under|in)\s+tests))",
            r"\bdo not fix(?=\s*[.;,]|$)",
            r"\b(?:do not|don't|never|must not)\s+(?:fix|harden|secure|repair|remediate|patch|correct)\s+"
            r"(?:it|anything|the\s+(?:code|source|project|application))\b",
            r"\bне (?:изменяй|изменять|модифицируй|исправляй|исправлять)\b",
        ),
    )
    asks_report = contains_any(
        normalized,
        (r"security_report\.json", r"bug bounty report", r"machine-readable.*report", r"\baudit\b", r"security[_ ]findings"),
    )
    asks_fix = contains_any(
        normalized,
        (
            # Treat an imperative remediation verb as the intent, not the noun
            # that happens to follow it.  The old ``fix the/security/...``
            # whitelist misrouted ordinary requests such as ``Fix mass
            # assignment`` and ``Fix NoSQL operator injection`` to general.
            # Explicit non-mutation language is handled separately by
            # ``no_modify`` and retains precedence below.
            r"(?:^|[.;:!?]\s+)(?:please\s+)?(?:fix|harden|secure|repair|remediate|patch|correct)\b",
            r"\b(?:please|must|should|need\s+to|task\s+is\s+to)\s+"
            r"(?:fix|harden|secure|repair|remediate|patch|correct)\b",
            r"\bfix\s+(?:it|them)\b",
            r"\bfix\b.{0,80}\b(?:bug|issue|security|vulnerab\w*|authorization|access[- ]control|permission)\b",
            r"\b(?:bug|issue|vulnerab\w*|authorization|access[- ]control|permission)\b.{0,120}\bfix\b",
            r"\bmake\b.{0,50}\bfix\b",
            r"\bисправ(?:ь|ить|ьте)\b",
            r"\bустран(?:и|ить|ите)\b",
            r"\b(?:защит(?:и|ить|ите)|укреп(?:и|ить|ите)|почин(?:и|ить|ите))\b",
        ),
    )
    # Security repair tasks commonly express the contract through immutable
    # tests and an explicit project suite even when the remediation verb is an
    # unseen synonym.  This is stronger evidence than any vulnerability noun.
    asks_fix = asks_fix or (
        contains_any(normalized, (r"\bpytest\b", r"\bpython\s+-m\s+unittest\b", r"\brun\s+the\s+tests?\b"))
        and contains_any(
            normalized,
            (
                r"\bdo not (?:modify|change|edit)\s+(?:the\s+)?tests?\b",
                r"\bwithout (?:modifying|changing|editing)\s+(?:the\s+)?tests?\b",
            ),
        )
    )
    forensic_action = contains_any(
        normalized,
        (
            r"\b(?:investigat\w*|reconstruct\w*|correlat\w*|deduplicat\w*|"
            r"analy[sz]\w*|determine|attribute|trace)\b",
            r"\b(?:расслед\w*|реконстру\w*|коррел\w*|дедуплиц\w*|"
            r"проанализ\w*|определ\w*)\b",
        ),
    )
    forensic_subject = contains_any(
        normalized,
        (
            r"\b(?:logs?|events?|incident|timeline|compromise|exfiltrat\w*|"
            r"dns|pcap|network|cloudtrail|kubernetes|evidence|artifact)\b",
            r"\b(?:лог\w*|событи\w*|инцидент\w*|таймлайн\w*|"
            r"эксфильтр\w*|днс|сетев\w*|доказательств\w*|артефакт\w*)\b",
        ),
    )
    asks_forensics = contains_any(
        normalized,
        (
            r"incident_report\.txt",
            r"\bincident\b.*\blogs?\b",
            r"\bforensics?\b",
            r"\binvestigat\w*\b.{0,100}\bevidence\b",
            r"\bфорензик",
            r"\b(?:investigat\w*|reconstruct\w*|correlat\w*|analy[sz]\w*|determine)\b.{0,160}\b(?:logs?|incident|timeline|compromise|exfiltrat\w*|cloudtrail|kubernetes|evidence)\b",
        ),
    ) or (forensic_action and forensic_subject)
    explicit_forensics = contains_any(
        normalized,
        (
            r"incident_report\.txt",
            r"\bforensics?\b",
            r"\bincident\b.{0,100}\blogs?\b",
            r"\bkubernetes\b.{0,80}\baudit\s+logs?\b",
            r"\baudit\s+logs?\b.{0,80}\bkubernetes\b",
            r"\bdns\b.{0,80}\bexfiltrat\w*\b",
            r"\bexfiltrat\w*\b.{0,80}\bdns\b",
        ),
    )
    asks_ctf = contains_any(
        normalized,
        (
            r"\bctf\b",
            r"\bcapture\s+the\s+flag\b",
            r"\b(?:find|recover|extract|decode|submit|write|store|save)\b.{0,80}\bflag\b",
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
    if (no_modify and not asks_forensics) or (
        asks_report and not asks_fix and not explicit_forensics
    ):
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
