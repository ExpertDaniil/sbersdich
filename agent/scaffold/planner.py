"""Deterministic fast path plus evidence-aware local-model planner."""

from __future__ import annotations

import copy
import json
from typing import Any

from agent.core.config import ModelConfig
from agent.core.llm import ModelRequestError, ModelUsage, OpenAICompatibleClient
from agent.core.loop import DeterministicDriver
from agent.core.models import AgentAction, DriverContext, LoopEvent, ToolDefinition
from agent.validators import SECURITY_FINDING_FIELDS, SECURITY_SEVERITIES

from .contracts import PlanDecision, PlanningContext, PlanStrategy
from .context_compiler import _pytest_feedback


MAX_STATE_CHARS = 24_000
MAX_GUIDANCE_CHARS = 8_000
MAX_REPO_GUIDE_CHARS = 6_000
FORBIDDEN_MODEL_OWNED_EVIDENCE_KEYS = frozenset(
    {"observation", "evidence", "facts", "confirmed_facts", "tool_result"}
)


def _encode_state(state: dict[str, Any]) -> str:
    """Drop optional history structurally; never send sliced, invalid JSON.

    The contract, tool schemas and actionable recovery feedback take precedence
    over old observations. Full events remain in the runtime trace.
    """
    compact = copy.deepcopy(state)

    def encode() -> str:
        return json.dumps(compact, ensure_ascii=False, separators=(",", ":"))

    snapshot = compact["task_state"]
    for key in ("goal", "capability_ladder"):
        snapshot.pop(key, None)  # already represented by instruction/tool catalog
    encoded = encode()
    for key, minimum in (("evidence", 2), ("recent_events", 1), ("latest_by_path", 0)):
        items = snapshot.get(key, [])
        while len(encoded) > MAX_STATE_CHARS and len(items) > minimum:
            items.pop(0)
            encoded = encode()
    if len(encoded) > MAX_STATE_CHARS:
        current = snapshot.get("current_hypothesis_id")
        snapshot["hypotheses"] = [h for h in snapshot.get("hypotheses", []) if h.get("id") == current]
        encoded = encode()
    if len(encoded) > MAX_STATE_CHARS:
        # An omitted packet can be fetched again through bounded file tools.
        compact["repository_guide"] = "Source packet omitted for budget; use view_window/read_file."
        encoded = encode()
    if len(encoded) > MAX_STATE_CHARS:
        for event in snapshot.get("recent_events", []):
            if "action" in event:
                event["action"].pop("arguments", None)
        for item in snapshot.get("evidence", []):
            item.pop("data_preview", None)
        encoded = encode()
    if len(encoded) > MAX_STATE_CHARS:
        raise ModelRequestError("required planner context exceeds budget")
    return encoded


def _raw_json_object_at_or_after(
    text: str, start: int = 0
) -> tuple[dict[str, Any], int, int] | None:
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


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _deterministic_fix_supported(events: tuple[LoopEvent, ...]) -> bool:
    """Keep the SQL fast path only while its own evidence supports it.

    The legacy deterministic fix policy is intentionally narrow: it recognizes
    tainted SQL construction and applies sql_parameterize. A generic ``fix``
    classification must not make that policy run SQL tooling on unrelated bugs.
    Once the first SQL scan is clean, or the rewriter cannot make a change, the
    scaffold yields immediately to the model with the observations preserved.
    """

    tool_events = [
        event
        for event in events
        if event.action is not None
        and event.tool_result is not None
        and event.tool_result.ok
    ]
    scans = [event for event in tool_events if event.action.name == "security_scan"]
    rewrites = [event for event in tool_events if event.action.name == "sql_parameterize"]

    # One cheap scan is allowed to determine whether this narrow fast path fits.
    if not scans:
        return True

    latest_scan_count = scans[-1].tool_result.data.get("finding_count")  # type: ignore[union-attr]
    if not rewrites:
        return _positive_int(latest_scan_count)

    latest_change_count = rewrites[-1].tool_result.data.get("change_count")  # type: ignore[union-attr]
    if not _positive_int(latest_change_count):
        return False

    # After a real rewrite, allow exactly the confirming scan and deterministic
    # finish only when that scan is clean. If supported findings remain, the
    # model must decide what to inspect next instead of blindly finishing.
    if len(scans) >= 2:
        return latest_scan_count == 0
    return True


class DeterministicFastPath:
    """Reuse already-proven deterministic flows before spending LLM tokens."""

    def __init__(self):
        self.driver = DeterministicDriver()

    def try_plan(self, context: PlanningContext) -> PlanDecision | None:
        if context.last_validation is not None and not context.last_validation.passed:
            return None
        # A deterministic action has already failed, so repeating the same
        # fixed policy cannot add information. Leave recovery to the model;
        # the failed ToolResult remains in events/state_snapshot as evidence.
        if any(
            event.tool_result is not None and not event.tool_result.ok
            for event in context.events
        ):
            return None
        if context.decision.mode == "fix" and not _deterministic_fix_supported(
            context.events
        ):
            return None
        if context.decision.mode == "audit":
            scans = [event.tool_result for event in context.events
                     if event.action and event.action.name == "security_scan" and event.tool_result]
            if scans:
                # SQL findings are leads, never proof of audit completeness.
                return None
            return PlanDecision(
                action=AgentAction("security_scan", {"write_report": False}),
                strategy=PlanStrategy.DETERMINISTIC,
            )
        if context.decision.mode == "forensics" and any(
            rule.kind != "incident-report" for rule in context.contract.artifacts
        ):
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
            "artifact_rules": [
                {"path": str(rule.path), "kind": rule.kind,
                 "required_keys": list(rule.required_keys), "nonempty_findings": rule.nonempty_findings,
                 **({"schema": {"top_level_keys": ["findings"], "findings": "array of objects",
                                 "finding_fields": sorted(SECURITY_FINDING_FIELDS),
                                 "field_types": "all fields are non-empty strings; no extra fields",
                                 "severity_values": sorted(SECURITY_SEVERITIES)}}
                    if rule.kind == "security-report" else {})}
                for rule in context.contract.artifacts
            ],
            "last_validation": (
                {
                    "passed": context.last_validation.passed,
                    "reason": context.last_validation.reason,
                    "failed_checks": [
                        {"name": check.name,
                         **(_pytest_feedback(check.detail, passed=False)
                            if check.name.startswith("project-tests") else {"detail": check.detail[:1600]})}
                        for check in context.last_validation.report.checks if not check.passed
                    ],
                }
                if context.last_validation
                else None
            ),
        }
        if context.repository_guide:
            state["repository_guide"] = context.repository_guide[:MAX_REPO_GUIDE_CHARS]
        encoded_state = _encode_state(state)
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
            "Read planner_feedback and last_control_feedback before retrying. A hypothesis may be a new "
            "statement or an existing Hxx identifier; backtrack must select a different hypothesis. "
            "Correct invalid action names/arguments using available_tools; do not repeat rejected calls. "
            "Read authoritative format documentation before decoding; use binary_records for exact record offsets. "
            "For binary transforms use ctf_transform path+offset+length+steps, never manually copy hex "
            "from read_bytes. Use reverse_bytes for binary reversal, key_text/key_hex for XOR. "
            "On decompression failure check exact byte range and encoding before changing documented order. "
            "security_scan only covers dynamic SQL: its counts do not establish absence of other bugs. "
            "Audit/forensics write_file is restricted to declared artifact paths. "
            "The user state may contain a virtual REPO_GUIDE.md. Its Fxxx handles and semantic paths are "
            "runtime aliases for real workspace files; use them directly in path arguments when useful. "
            "REPO_GUIDE card metadata is localization help, not vulnerability proof. If the packet also "
            "contains TRUSTED_SOURCE_WINDOWS, those windows are direct runtime source reads: their numbered "
            "lines reflect current bytes and the SHA may be passed directly to checked_edit. "
            "A runtime read proves file contents, NEVER correctness of its claims. Task outputs are model "
            "candidates, not schemas, expected answers or independent corroboration. Report locations must "
            "use source_path (the original workspace path), never an Fxxx handle or semantic alias. "
            "Do not spend a view_window call re-reading a trusted window when the intended edit is fully "
            "visible and unambiguous. Use search_surface/view_window only for missing, truncated, stale, or "
            "ambiguous context. For a single obvious high-confidence edit, pass the exact SHA-256 from either "
            "a trusted source window or view_window into checked_edit; stale-SHA and static-parse rejection "
            "are authoritative. If pytest tool feedback contains typed_feedback, prioritize failed_tests, "
            "error_types_found, and counts over noisy raw process text. "
            "When a fix is uncertain or there are multiple plausible repairs, do NOT trial-and-error on "
            "the real workspace. Generate distinct unified-diff alternatives and call arena_evaluate. "
            "Pass your current hypothesis confidence: the runtime enforces an adaptive 1..4 branch budget. "
            "Candidate branches are isolated; cheap static checks, security-signal deltas and optional "
            "pytest produce deterministic scores. If arena_evaluate returns a winner, use arena_promote; "
            "only that winner may mutate the real workspace and promotion fails if source files changed "
            "since evaluation. Never merge candidate patches or manually promote a losing branch. "
            "After a successful model-driven checked_edit or arena promotion, the runtime automatically runs "
            "the deterministic final validation gate. Do not spend a separate action on pytest, git-diff, "
            "or finish merely to prove a successful transactional edit; if automatic validation fails, use "
            "its failed_checks and assertion_lines to recover. Compare replacement code with the actual "
            "failed assertion; a rationale claiming a correction is not a correction. Repository Distiller remains available for structure: "
            "rank_relevant_files for unknown file location, repo_tree for architecture, repo_skeleton for "
            "compact signatures, and inspect_symbol for focused source plus references. Legacy "
            "read_file/search_text/apply_patch/run_command are fallback interfaces only when the compact ACI "
            "or Candidate Arena cannot express the operation. Use finish only when the result is ready for "
            "deterministic verification and no automatic post-mutation validation is pending.\n\n"
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
            json_object=True,
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
            raise ModelRequestError(f"unavailable action {str(name)[:100]!r}; choose exactly one of: {', '.join(allowed)}")
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
