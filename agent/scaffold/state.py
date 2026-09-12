"""Bounded hypothesis graph and evidence ledger for the scaffold."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from agent.core.models import AgentAction, LoopEvent, ToolResult, ValidationFeedback

from .contracts import PlanDecision, ToolSpec


MAX_HYPOTHESES = 12
MAX_EVIDENCE = 32
RECENT_EVIDENCE = 12
RECENT_EVENTS = 6
RECOVERY_AFTER_DUPLICATES = 2
MAX_TEXT = 900
MAX_DATA_PREVIEW = 1_400


def _bounded(value: object, limit: int = MAX_TEXT) -> str:
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

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "statement": self.statement,
            "confidence": round(self.confidence, 3),
            "parent_id": self.parent_id,
            # Do not collide with the root run "status" consumed by benchmark
            # adapters that flatten JSON fields.
            "hypothesis_status": self.status,
            "attempts": self.attempts,
            "last_step": self.last_step,
            "expected_evidence": self.expected_evidence,
            "evidence_ids": self.evidence_ids[-8:],
        }


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    sequence: int
    source: str
    action: str
    ok: bool
    summary: str
    data_digest: str
    data_preview: str
    hypothesis_id: str | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "sequence": self.sequence,
            "source": self.source,
            "action": self.action,
            "ok": self.ok,
            "summary": self.summary,
            "data_digest": self.data_digest,
            "data_preview": self.data_preview,
            "hypothesis_id": self.hypothesis_id,
        }


class AgentState:
    """Model proposals are speculation; only environment/verifier output is evidence."""

    def __init__(self, goal: str, mode: str):
        self.goal = _bounded(goal, 4_000)
        self.mode = mode
        self.events: list[LoopEvent] = []
        self._hypotheses: dict[str, HypothesisNode] = {}
        self._statement_index: dict[str, str] = {}
        self._current_hypothesis_id: str | None = None
        self._action_hypothesis: dict[str, str | None] = {}
        self._evidence: list[EvidenceRecord] = []
        self._evidence_fingerprints: set[str] = set()
        self._duplicate_observations = 0
        self._last_progress_reason = "no trusted observation yet"
        self._control_rejections = 0
        self._last_control_feedback: dict[str, Any] | None = None
        self._planner_feedback: str | None = None
        self._evidence_sequence = 0
        self._latest_by_path: dict[str, dict[str, Any]] = {}
        self._listed_files: set[str] = set()
        self._read_files: set[str] = set()

    def record_planner_error(self, reason: str) -> None:
        self._planner_feedback = _bounded(reason, 900)

    @property
    def current_hypothesis_id(self) -> str | None:
        return self._current_hypothesis_id

    @property
    def recovery_required(self) -> bool:
        return self._duplicate_observations >= RECOVERY_AFTER_DUPLICATES

    def record_control_rejection(
        self,
        *,
        reason: str,
        required_strategy: str | None,
        minimum_capability: int | None,
    ) -> None:
        self._control_rejections += 1
        self._last_control_feedback = {
            "reason": _bounded(reason, 700),
            "required_strategy": required_strategy,
            "minimum_capability": minimum_capability,
        }
        self._last_progress_reason = "runtime controller rejected non-progressing plan"

    def register_plan(self, plan: PlanDecision, *, step: int) -> None:
        statement = _bounded(plan.hypothesis)
        selected = self._current_hypothesis_id
        if statement:
            key = " ".join(statement.casefold().split())
            # Hxx is a reference to an existing runtime hypothesis, not a new
            # hypothesis whose statement happens to be "Hxx".
            selected = next((hid for hid in self._hypotheses if hid.casefold() == key), None)
            selected = selected or self._statement_index.get(key)
            if selected is None and len(self._hypotheses) < MAX_HYPOTHESES:
                selected = f"H{len(self._hypotheses) + 1:02d}"
                parent = (
                    self._current_hypothesis_id
                    if plan.strategy.value in {"branch", "backtrack"}
                    else None
                )
                self._hypotheses[selected] = HypothesisNode(
                    hypothesis_id=selected,
                    statement=statement,
                    confidence=plan.confidence,
                    parent_id=parent,
                )
                self._statement_index[key] = selected
            if selected in self._hypotheses:
                node = self._hypotheses[selected]
                node.confidence = plan.confidence
                node.attempts += 1
                node.last_step = step
                if plan.expected_evidence:
                    node.expected_evidence = _bounded(plan.expected_evidence)
                if node.status == "deprioritized":
                    node.status = "active"

        if plan.strategy.value == "backtrack" and self._current_hypothesis_id:
            previous = self._hypotheses.get(self._current_hypothesis_id)
            if previous is not None and previous.hypothesis_id != selected:
                previous.status = "deprioritized"

        self._current_hypothesis_id = selected
        self._action_hypothesis[plan.action.fingerprint()] = selected
        self._last_control_feedback = None
        self._planner_feedback = None

    def _record_evidence(
        self,
        *,
        sequence: int,
        source: str,
        action: AgentAction,
        ok: bool,
        summary: str,
        data: object,
    ) -> None:
        hypothesis_id = self._action_hypothesis.get(
            action.fingerprint(), self._current_hypothesis_id
        )
        summary_text = _bounded(summary)
        data_digest = _digest(data)
        fingerprint = _digest(
            {
                "source": source,
                "action": action.name,
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
                sequence=sequence,
                source=source,
                action=action.name,
                ok=ok,
                summary=summary_text,
                data_digest=data_digest,
                data_preview=_bounded(_stable_json(data), MAX_DATA_PREVIEW),
                hypothesis_id=hypothesis_id,
            )
            self._evidence.append(record)
            self._evidence = self._evidence[-MAX_EVIDENCE:]
            if source == "tool" and ok and isinstance(data, dict):
                path = data.get("path")
                if isinstance(path, str):
                    self._latest_by_path.pop(path, None)
                    self._latest_by_path[path] = record.as_payload()
                    while len(self._latest_by_path) > 8:
                        self._latest_by_path.pop(next(iter(self._latest_by_path)))
            if hypothesis_id in self._hypotheses:
                node = self._hypotheses[hypothesis_id]
                node.evidence_ids.append(record.evidence_id)
                if not ok:
                    node.status = "challenged"
            self._duplicate_observations = 0
            self._last_progress_reason = f"new trusted {source} evidence"
        else:
            self._duplicate_observations += 1
            self._last_progress_reason = f"repeated {source} observation"

    def record_tool_event(
        self, sequence: int, action: AgentAction, result: ToolResult
    ) -> LoopEvent:
        event = LoopEvent(
            sequence,
            "acting" if result.ok else "tool-failed",
            action=action,
            tool_result=result,
        )
        self.events.append(event)
        if result.ok:
            if action.name == "list_files":
                self._listed_files.update(str(item["path"]) for item in result.data.get("entries", [])
                                          if isinstance(item, dict) and "path" in item)
                self._listed_files = set(sorted(self._listed_files)[:512])
            if action.name in {"read_file", "view_window", "read_events", "read_bytes"}:
                path = result.data.get("source_path", result.data.get("path"))
                if isinstance(path, str):
                    self._read_files.add(path)
        self._record_evidence(
            sequence=sequence,
            source="tool",
            action=action,
            ok=result.ok,
            summary=result.summary,
            data=result.data,
        )
        return event

    def record_validation_event(
        self, sequence: int, action: AgentAction, feedback: ValidationFeedback
    ) -> LoopEvent:
        event = LoopEvent(
            sequence,
            "succeeded" if feedback.passed else "retrying",
            action=action,
            validation=feedback,
        )
        self.events.append(event)
        self._record_evidence(
            sequence=sequence,
            source="validation",
            action=action,
            ok=feedback.passed,
            summary=feedback.reason,
            data=feedback.report.as_payload(),
        )
        if self._current_hypothesis_id in self._hypotheses:
            self._hypotheses[self._current_hypothesis_id].status = (
                "confirmed" if feedback.passed else "challenged"
            )
        return event

    def record_terminal_event(self, sequence: int, action: AgentAction) -> LoopEvent:
        event = LoopEvent(sequence, "failed", action=action)
        self.events.append(event)
        return event

    @staticmethod
    def _event_payload(event: LoopEvent) -> dict[str, Any]:
        payload: dict[str, Any] = {"step": event.sequence, "phase": event.phase}
        if event.action:
            payload["action"] = {
                "name": event.action.name,
                "arguments": event.action.arguments,
                "rationale": _bounded(event.action.rationale, 500),
            }
        if event.tool_result:
            payload["result"] = {
                "ok": event.tool_result.ok,
                "summary": _bounded(event.tool_result.summary, 700),
            }
        if event.validation:
            payload["validation"] = {
                "passed": event.validation.passed,
                "reason": _bounded(event.validation.reason, 700),
            }
        return payload

    def snapshot(self, tools: tuple[ToolSpec, ...]) -> dict[str, Any]:
        hypotheses = sorted(
            self._hypotheses.values(),
            key=lambda item: (-item.confidence, -item.last_step, item.hypothesis_id),
        )
        ladder: dict[int, list[str]] = {}
        for tool in tools:
            ladder.setdefault(int(tool.capability), []).append(tool.name)
        highest = max(ladder, default=0)
        current_level = 0
        if self.events and self.events[-1].action:
            last_name = self.events[-1].action.name
            for tool in tools:
                if tool.name == last_name:
                    current_level = int(tool.capability)
                    break
        recommended = min(highest, current_level + 1) if self.recovery_required else 0
        return {
            "goal": self.goal,
            "mode": self.mode,
            "current_hypothesis_id": self._current_hypothesis_id,
            "hypotheses": [item.as_payload() for item in hypotheses],
            "evidence": [item.as_payload() for item in self._evidence[-RECENT_EVIDENCE:]],
            "recent_events": [
                self._event_payload(item) for item in self.events[-RECENT_EVENTS:]
            ],
            "recovery_required": self.recovery_required,
            "duplicate_observations": self._duplicate_observations,
            "last_progress_reason": self._last_progress_reason,
            "recommended_capability_level": recommended,
            "control_rejections": self._control_rejections,
            "last_control_feedback": self._last_control_feedback,
            "planner_feedback": self._planner_feedback,
            "latest_by_path": list(self._latest_by_path.values()),
            "inventory_not_opened_by_tools": sorted(self._listed_files - self._read_files)[:32],
            "inventory_note": "These listed files have no explicit read action; source windows may also show content. A partial read is not complete investigation.",
            "capability_ladder": [
                {"level": level, "tools": sorted(names)}
                for level, names in sorted(ladder.items())
            ],
        }
