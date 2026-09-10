"""Deterministic fast path plus evidence-aware local-model planner."""

from __future__ import annotations

import json
from typing import Any

from agent.core.config import ModelConfig
from agent.core.llm import ModelRequestError, ModelUsage, OpenAICompatibleClient
from agent.core.loop import DeterministicDriver
from agent.core.models import AgentAction, DriverContext, ToolDefinition

from .contracts import PlanDecision, PlanningContext, PlanStrategy


MAX_STATE_CHARS = 24_000
MAX_GUIDANCE_CHARS = 8_000
FORBIDDEN_MODEL_OWNED_EVIDENCE_KEYS = frozenset(
    {"observation", "evidence", "facts", "confirmed_facts", "tool_result"}
)


def _raw_json_object_at_or_after(text: str, start: int = 0) -> tuple[dict[str, Any], int, int] | None:
    """Return the first decodable JSON object embedded in *text*.

    Small local/reasoning models sometimes wrap an otherwise valid action in a
    short preamble or a thinking tag even when instructed to emit JSON only.
    We tolerate that presentation noise, but still require exactly one JSON
    object so that two competing actions can never be executed ambiguously.
    """

    decoder = json.JSONDecoder()
    cursor = max(0, start)
    while True:
        object_start = text.find("{", cursor)
        if object_start < 0:
            return None
        try:
            payload, object_end = decoder.raw_decode(text, object_start)
        except json.JSONDecodeError:
            cursor = object_start + 1
            continue
        if isinstance(payload, dict):
            return payload, object_start, object_end
        cursor = object_start + 1


def _extract_json_object(text: str) -> dict[str, Any]:
    stripped = text.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if len(lines) >= 3 and lines[-1].strip() == "```":
            stripped = "\n".join(lines[1:-1])
            if stripped.lstrip().lower().startswith("json\n"):
                stripped = stripped.lstrip()[5:]

    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        embedded = _raw_json_object_at_or_after(stripped)
        if embedded is None:
            raise ModelRequestError("scaffold planner expected one JSON object")
        payload, _object_start, object_end = embedded
        if _raw_json_object_at_or_after(stripped, object_end) is not None:
            raise ModelRequestError("scaffold planner returned multiple JSON objects")

    if not isinstance(payload, dict):
        raise ModelRequestError("scaffold planner response must be an object")
    return payload


def _tool_definition(spec) -> ToolDefinition:
    return ToolDefinition(
        spec.name,
        spec.description,
        spec.parameters,
        spec.mutates_workspace,
    )


class DeterministicFastPath:
    """Reuse already-proven deterministic flows before spending LLM tokens."""

    def __init__(self):
        self.driver = DeterministicDriver()

    def try_plan(self, context: PlanningContext) -> PlanDecision | None:
        if context.last_validation is not None and not context.last_validation.passed:
            return None
        driver_context = DriverContext(
            instruction=context.instruction,
            workdir=context.workdir,
            decision=context.decision,
            task_playbook=context.task_playbook,
            validation_playbook=context.validation_playbook,
            contract=context.contract,
            available_tools=tuple(_tool_definition(tool) for tool in context.tools),
            events=context.events,
            last_validation=context.last_validation,
            remaining_seconds=context.remaining_seconds,
        )
        action = self.driver.next_action(driver_context)
        if action.name == "abort" and "future LLM driver" in action.rationale:
            return None
        return PlanDecision(action=action, strategy=PlanStrategy.DETERMINISTIC)


class LazyLocalModelPlanner:
    """Instantiate the local OpenAI-compatible client only when the fast path stalls."""

    def __init__(self):
        self._client: OpenAICompatibleClient | None = None
        self._unused_usage = ModelUsage()

    @property
    def usage(self) -> ModelUsage:
        return self._client.usage if self._client is not None else self._unused_usage

    def _ensure_client(self) -> OpenAICompatibleClient:
        if self._client is None:
            self._client = OpenAICompatibleClient(ModelConfig.from_env())
        return self._client

    def next_plan(self, context: PlanningContext) -> PlanDecision:
        allowed = sorted({tool.name for tool in context.tools} | {"finish", "abort"})
        state = {
            "instruction": context.instruction,
            "mode": context.decision.mode,
            "allowed_actions": allowed,
            "available_tools": [tool.as_payload() for tool in context.tools],
            "task_state": context.state_snapshot,
            "artifacts": [str(rule.path) for rule in context.contract.artifacts],
            "last_validation": (
                {
                    "passed": context.last_validation.passed,
                    "reason": context.last_validation.reason,
                }
                if context.last_validation
                else None
            ),
        }
        encoded_state = json.dumps(state, ensure_ascii=False, separators=(",", ":"))
        if len(encoded_state) > MAX_STATE_CHARS:
            encoded_state = encoded_state[:MAX_STATE_CHARS] + "…"
        system = (
            "You are the planning policy for an offline autonomous cybersecurity agent. "
            "Choose exactly one next action. Return only one JSON object. Required keys: "
            "name, arguments, rationale. Optional planning keys: hypothesis, confidence, "
            "expected_evidence, strategy. strategy is one of continue, branch, backtrack, "
            "verify, escalate. The model may propose hypotheses, but observations and evidence "
            "belong only to tools and validators. Never emit observation/evidence/facts/tool_result "
            "fields and never invent tool output. Prefer the lowest capability level that can "
            "discriminate the current hypothesis. If task_state.recovery_required is true, materially "
            "change the hypothesis, tool family, or capability level instead of repeating the same probe. "
            "For repository work, use the compact ACI whenever it can answer the question: "
            "search_surface for ranked natural-language localization, then view_window for a bounded "
            "numbered view. For a single obvious high-confidence edit, pass the exact SHA-256 from "
            "view_window into checked_edit; stale-SHA and static-parse rejection are authoritative. "
            "When a fix is uncertain or there are multiple plausible repairs, do NOT trial-and-error on "
            "the real workspace. Generate distinct unified-diff alternatives and call arena_evaluate. "
            "Pass your current hypothesis confidence: the runtime enforces an adaptive 1..4 branch budget. "
            "Candidate branches are isolated; cheap static checks, security-signal deltas and optional "
            "pytest produce deterministic scores. If arena_evaluate returns a winner, use arena_promote; "
            "only that winner may mutate the real workspace and promotion fails if source files changed "
            "since evaluation. Never merge candidate patches or manually promote a losing branch. "
            "After any mutation, use the reopened ACI view and run_check to prove syntax/tests before finish. "
            "Repository Distiller remains available for structure: rank_relevant_files for unknown file "
            "location, repo_tree for architecture, repo_skeleton for compact signatures, and inspect_symbol "
            "for focused source plus references. Legacy read_file/search_text/apply_patch/run_command are "
            "fallback interfaces only when the compact ACI or Candidate Arena cannot express the operation. "
            "Use finish only when the result is ready for deterministic verification.\n\n"
            + context.task_playbook[:MAX_GUIDANCE_CHARS]
            + "\n\nValidation guidance:\n"
            + context.validation_playbook[:MAX_GUIDANCE_CHARS]
            + "\n\nExtension guidance:\n"
            + context.extension_guidance[:MAX_GUIDANCE_CHARS]
        )
        response = self._ensure_client().complete(
            (
                {"role": "system", "content": system},
                {"role": "user", "content": encoded_state},
            ),
            max_tokens=700,
            timeout_seconds=max(0.1, context.remaining_seconds - 1.0),
        )
        payload = _extract_json_object(response)
        forbidden = sorted(FORBIDDEN_MODEL_OWNED_EVIDENCE_KEYS.intersection(payload))
        if forbidden:
            raise ModelRequestError(
                f"model attempted to own trusted evidence fields: {forbidden}"
            )
        name = payload.get("name")
        arguments = payload.get("arguments", {})
        rationale = payload.get("rationale", "")
        hypothesis = payload.get("hypothesis", "")
        confidence = payload.get("confidence", 0.5)
        expected_evidence = payload.get("expected_evidence", "")
        strategy_raw = payload.get("strategy", "continue")
        if not isinstance(name, str) or name not in allowed:
            raise ModelRequestError("model selected an unavailable scaffold action")
        if not isinstance(arguments, dict):
            raise ModelRequestError("scaffold action arguments must be an object")
        if not isinstance(rationale, str):
            raise ModelRequestError("scaffold rationale must be text")
        if not isinstance(hypothesis, str):
            raise ModelRequestError("hypothesis must be text")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ModelRequestError("confidence must be numeric")
        if not isinstance(expected_evidence, str):
            raise ModelRequestError("expected_evidence must be text")
        try:
            strategy = PlanStrategy(strategy_raw)
        except (ValueError, TypeError) as error:
            raise ModelRequestError("unsupported scaffold planning strategy") from error
        return PlanDecision(
            action=AgentAction(name, arguments, rationale),
            strategy=strategy,
            hypothesis=hypothesis[:1_000],
            confidence=float(confidence),
            expected_evidence=expected_evidence[:1_000],
        )


class HybridPlanner:
    def __init__(
        self,
        deterministic: DeterministicFastPath | None = None,
        model: LazyLocalModelPlanner | None = None,
    ):
        self.deterministic = deterministic or DeterministicFastPath()
        self.model = model or LazyLocalModelPlanner()

    @property
    def usage(self) -> ModelUsage:
        return self.model.usage

    def next_plan(self, context: PlanningContext) -> PlanDecision:
        fast = self.deterministic.try_plan(context)
        if fast is not None:
            return fast
        return self.model.next_plan(context)
