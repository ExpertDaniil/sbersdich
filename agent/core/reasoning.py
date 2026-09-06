"""Evidence-gated hypothesis search for the autonomous security agent.

The LLM may propose hypotheses and experiments, but only tool and validator
observations can become evidence.  The controller keeps this state bounded and
surfaces recovery/backtracking signals when a branch stops producing progress.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable

from .models import LoopEvent, ToolDefinition


MAX_HYPOTHESES = 8
MAX_EVIDENCE = 32
MAX_TEXT_CHARS = 320
MAX_PREVIEW_CHARS = 480
RECENT_EVIDENCE = 6
RECOVERY_STAGNANT_STEPS = 2

SPECIALIST_BY_MODE = {
    "audit": "code_auditor",
    "fix": "remediation_engineer",
    "forensics": "forensics_analyst",
    "general": "general_security_investigator",
}

# Escalation cost, not trust. Lower levels gather cheap evidence; mutation is
# deliberately last. Level 3 is reserved for persistent interactive tools.
CAPABILITY_LEVELS = {
    "list_files": 0,
    "read_file": 0,
    "read_bytes": 0,
    "search_text": 0,
    "security_scan": 1,
    "forensics_analyze": 1,
    "run_command": 2,
    "debug_start": 3,
    "debug_exec": 3,
    "connect_start": 3,
    "connect_send": 3,
    "apply_patch": 4,
    "sql_parameterize": 4,
    "write_exact_text": 4,
}

ALLOWED_STRATEGIES = frozenset(
    {"continue", "branch", "backtrack", "verify", "escalate"}
)


def _bounded(value: object, limit: int = MAX_TEXT_CHARS) -> str:
    text = str(value).strip()
    return text if len(text) <= limit else text[:limit] + "…"


def _stable_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _digest(value: object) -> str:
    return hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:16]


@dataclass
class HypothesisNode:
    hypothesis_id: str
    statement: str
    confidence: float
    parent_id: str | None = None
    status: str = "active"
    attempts: int = 0
    last_step: int = 0
    expected_evidence: str = ""
    evidence_ids: list[str] = field(default_factory=list)

    def as_payload(self) -> dict[str, object]:
        return {
            "id": self.hypothesis_id,
            "statement": self.statement,
            "confidence": round(self.confidence, 3),
            "parent_id": self.parent_id,
            "status": self.status,
            "attempts": self.attempts,
            "last_step": self.last_step,
            "expected_evidence": self.expected_evidence,
            "evidence_ids": list(self.evidence_ids[-8:]),
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    step: int
    source: str
    action: str
    ok: bool
    summary: str
    data_digest: str
    data_preview: str
    hypothesis_id: str | None

    def as_payload(self) -> dict[str, object]:
        return {
            "id": self.evidence_id,
            "step": self.step,
            "source": self.source,
            "action": self.action,
            "ok": self.ok,
            "summary": self.summary,
            "data_digest": self.data_digest,
            "data_preview": self.data_preview,
            "hypothesis_id": self.hypothesis_id,
        }


class EvidenceGatedReasoning:
    """Bounded hypothesis graph and trusted evidence ledger for one run."""

    def __init__(self, goal: str, mode: str):
        self.goal = _bounded(goal, 4_000)
        self.mode = mode
        self.specialist = SPECIALIST_BY_MODE.get(mode, "general_security_investigator")
        self._hypotheses: dict[str, HypothesisNode] = {}
        self._statement_to_id: dict[str, str] = {}
        self._evidence: list[EvidenceRecord] = []
        self._evidence_fingerprints: set[str] = set()
        self._evidence_sequence = 0
        self._action_hypotheses: dict[str, str | None] = {}
        self._current_hypothesis_id: str | None = None
        self._last_sequence = 0
        self._stagnant_steps = 0
        self._last_progress_reason = "no trusted evidence collected yet"
        self._highest_used_capability = 0

    @property
    def recovery_required(self) -> bool:
        return self._stagnant_steps >= RECOVERY_STAGNANT_STEPS

    @property
    def evidence_count(self) -> int:
        return len(self._evidence)

    def propose(
        self,
        *,
        action_fingerprint: str,
        action_name: str,
        hypothesis: str = "",
        confidence: float = 0.5,
        expected_evidence: str = "",
        strategy: str = "continue",
        step: int = 0,
    ) -> None:
        """Store an LLM hypothesis as speculation, never as trusted evidence."""

        if strategy not in ALLOWED_STRATEGIES:
            raise ValueError(f"unsupported reasoning strategy: {strategy}")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("hypothesis confidence must be between 0 and 1")

        statement = _bounded(hypothesis)
        selected_id = self._current_hypothesis_id
        if statement:
            key = " ".join(statement.casefold().split())
            matching_id = self._statement_to_id.get(key)
            created = False
            if matching_id is None and len(self._hypotheses) < MAX_HYPOTHESES:
                matching_id = f"H{len(self._hypotheses) + 1:02d}"
                parent = (
                    self._current_hypothesis_id
                    if strategy in {"branch", "backtrack"}
                    else None
                )
                self._hypotheses[matching_id] = HypothesisNode(
                    hypothesis_id=matching_id,
                    statement=statement,
                    confidence=confidence,
                    parent_id=parent,
                )
                self._statement_to_id[key] = matching_id
                created = True
            if matching_id is not None:
                selected_id = matching_id
                node = self._hypotheses[selected_id]
                node.confidence = confidence
                node.attempts += 1
                node.last_step = step
                if expected_evidence:
                    node.expected_evidence = _bounded(expected_evidence)
                if node.status == "deprioritized":
                    node.status = "active"
            elif not created:
                # Hypothesis budget exhausted: keep the current branch rather than
                # silently mutating it into a different statement.
                selected_id = self._current_hypothesis_id

        if strategy == "backtrack" and self._current_hypothesis_id:
            previous = self._hypotheses.get(self._current_hypothesis_id)
            if previous is not None and previous.hypothesis_id != selected_id:
                previous.status = "deprioritized"

        self._current_hypothesis_id = selected_id
        self._action_hypotheses[action_fingerprint] = selected_id
        self._highest_used_capability = max(
            self._highest_used_capability, CAPABILITY_LEVELS.get(action_name, 2)
        )

    def _record_evidence(
        self,
        *,
        step: int,
        source: str,
        action: str,
        ok: bool,
        summary: str,
        data: object,
        hypothesis_id: str | None,
    ) -> None:
        summary_text = _bounded(summary)
        data_digest = _digest(data)
        fingerprint = _digest(
            {
                "source": source,
                "action": action,
                "ok": ok,
                "summary": summary_text,
                "data_digest": data_digest,
            }
        )
        novel = fingerprint not in self._evidence_fingerprints
        if novel:
            self._evidence_fingerprints.add(fingerprint)
            self._evidence_sequence += 1
            record = EvidenceRecord(
                evidence_id=f"E{self._evidence_sequence:02d}",
                step=step,
                source=source,
                action=action,
                ok=ok,
                summary=summary_text,
                data_digest=data_digest,
                data_preview=_bounded(_stable_json(data), MAX_PREVIEW_CHARS),
                hypothesis_id=hypothesis_id,
            )
            self._evidence.append(record)
            self._evidence = self._evidence[-MAX_EVIDENCE:]
            if hypothesis_id in self._hypotheses:
                node = self._hypotheses[hypothesis_id]
                node.evidence_ids.append(record.evidence_id)
                if not ok:
                    node.status = "challenged"

        if ok and novel:
            self._stagnant_steps = 0
            self._last_progress_reason = f"new trusted {source} evidence"
        else:
            self._stagnant_steps += 1
            self._last_progress_reason = (
                f"{source} failed to produce evidence"
                if not ok
                else f"{source} repeated already-known evidence"
            )

    def sync(self, events: Iterable[LoopEvent]) -> None:
        """Ingest only tool/validator observations newer than the last sync."""

        for event in events:
            if event.sequence <= self._last_sequence:
                continue
            action_name = event.action.name if event.action else "unknown"
            fingerprint = event.action.fingerprint() if event.action else ""
            hypothesis_id = self._action_hypotheses.get(
                fingerprint, self._current_hypothesis_id
            )
            if event.tool_result is not None:
                self._record_evidence(
                    step=event.sequence,
                    source="tool",
                    action=action_name,
                    ok=event.tool_result.ok,
                    summary=event.tool_result.summary,
                    data=event.tool_result.data,
                    hypothesis_id=hypothesis_id,
                )
            elif event.validation is not None:
                self._record_evidence(
                    step=event.sequence,
                    source="validation",
                    action=action_name,
                    ok=event.validation.passed,
                    summary=event.validation.reason,
                    data=event.validation.report.as_payload(),
                    hypothesis_id=hypothesis_id,
                )
            self._last_sequence = max(self._last_sequence, event.sequence)

    @staticmethod
    def _capability_ladder(
        available_tools: tuple[ToolDefinition, ...]
    ) -> tuple[list[dict[str, object]], list[int]]:
        levels: dict[int, list[str]] = {}
        for tool in available_tools:
            levels.setdefault(CAPABILITY_LEVELS.get(tool.name, 2), []).append(tool.name)
        ordered_levels = sorted(levels)
        ladder = [
            {"level": level, "tools": sorted(levels[level])}
            for level in ordered_levels
        ]
        return ladder, ordered_levels

    def snapshot(self, available_tools: Iterable[ToolDefinition]) -> dict[str, object]:
        tools = tuple(available_tools)
        ladder, levels = self._capability_ladder(tools)
        if self.recovery_required:
            higher = [level for level in levels if level > self._highest_used_capability]
            recommended = min(higher) if higher else (max(levels) if levels else 0)
        else:
            recommended = min(levels) if levels else 0

        hypotheses = sorted(
            self._hypotheses.values(),
            key=lambda item: (-item.confidence, -item.last_step, item.hypothesis_id),
        )
        backtrack_candidates = [
            item.hypothesis_id
            for item in hypotheses
            if item.hypothesis_id != self._current_hypothesis_id
            and item.status in {"active", "challenged"}
        ][:4]

        return {
            "goal": self.goal,
            "specialist": self.specialist,
            "current_hypothesis_id": self._current_hypothesis_id,
            "hypotheses": [item.as_payload() for item in hypotheses],
            "evidence": [
                item.as_payload() for item in self._evidence[-RECENT_EVIDENCE:]
            ],
            "backtrack_candidates": backtrack_candidates,
            "recovery_required": self.recovery_required,
            "stagnant_steps": self._stagnant_steps,
            "last_progress_reason": self._last_progress_reason,
            "recommended_capability_level": recommended,
            "capability_ladder": ladder,
        }
