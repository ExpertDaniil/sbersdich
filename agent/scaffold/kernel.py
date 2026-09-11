"""Composable evidence-gated kernel for the experimental scaffold."""

from __future__ import annotations

import time
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from agent.core.contracts import build_task_contract
from agent.core.llm import ModelRequestError
from agent.core.models import AgentAction
from agent.core.playbooks import load_playbook, load_validation_playbook
from agent.strategies import StrategyDecision, classify_instruction
from agent.validators import canonical_path, capture_snapshot

from .contracts import (
    ExecutionContext,
    KernelLimits,
    PlanningContext,
    ScaffoldRunResult,
    VerificationContext,
    VerificationResult,
)
from .hypothesis_controller import RuntimeHypothesisController
from .interfaces import Planner, Verifier
from .registry import RESERVED_ACTIONS, ToolBus
from .state import AgentState

if TYPE_CHECKING:
    from .semantic_namespace import SemanticRepositoryContext


class ScaffoldKernelError(RuntimeError):
    pass


def _confirmed_model_mutation(action: AgentAction, result) -> bool:
    """Return true only for mutation tools whose result proves a real write.

    ToolSpec.mutates_workspace means a tool *may* mutate. Some tools are conditional
    (for example security_scan can optionally write a report), so using the catalog
    flag alone can accidentally trigger final validation after a read-only action.
    Auto-finalization is intentionally limited to the two transactional model-facing
    mutation paths that return explicit write evidence.
    """

    if not result.ok:
        return False
    if action.name == "checked_edit":
        return result.data.get("written") is True
    if action.name == "arena_promote":
        return result.data.get("promoted") is True
    return False


class AgentKernel:
    """Scientific-search loop: hypothesize -> probe -> observe -> verify/backtrack."""

    def __init__(
        self,
        *,
        workdir: Path | str,
        tool_bus: ToolBus,
        planner: Planner,
        verifier: Verifier,
        limits: KernelLimits | None = None,
        extension_guidance: str = "",
        clock: Callable[[], float] = time.monotonic,
        hypothesis_controller: RuntimeHypothesisController | None = None,
        repository_context: SemanticRepositoryContext | None = None,
    ):
        self.workdir = canonical_path(workdir)
        self.tool_bus = tool_bus
        self.planner = planner
        self.verifier = verifier
        self.limits = limits or KernelLimits()
        self.extension_guidance = extension_guidance
        self.clock = clock
        self.hypothesis_controller = hypothesis_controller or RuntimeHypothesisController()
        self.repository_context = repository_context

    def _result(
        self,
        *,
        status: str,
        reason: str,
        decision: StrategyDecision | None,
        steps: int,
        validations: int,
        state: AgentState,
        tools,
        final_validation: VerificationResult | None,
    ) -> ScaffoldRunResult:
        return ScaffoldRunResult(
            status=status,
            reason=reason,
            decision=decision,
            steps_used=steps,
            validations_used=validations,
            events=tuple(state.events),
            final_validation=final_validation,
            state=state.snapshot(tuple(tools)),
        )

    def _verify(
        self,
        *,
        decision: StrategyDecision,
        contract,
        baseline,
        state: AgentState,
        started: float,
    ) -> VerificationResult:
        return self.verifier.verify(
            VerificationContext(
                workdir=self.workdir,
                decision=decision,
                contract=contract,
                baseline=baseline,
                events=tuple(state.events),
                remaining_seconds=max(
                    0.0,
                    self.limits.deadline_seconds - (self.clock() - started),
                ),
            )
        )

    def run(self, instruction: str) -> ScaffoldRunResult:
        decision: StrategyDecision | None = None
        state = AgentState(instruction, "unknown")
        steps = 0
        validations = 0
        last_validation = None
        final_verification: VerificationResult | None = None
        repeated_actions: Counter[str] = Counter()
        control_rejections = 0
        planner_errors = 0
        contract = None
        baseline = None
        started = self.clock()
        tools = ()

        try:
            if not instruction.strip():
                raise ScaffoldKernelError("instruction must not be empty")
            if not self.workdir.is_dir():
                raise ScaffoldKernelError(f"workdir is not a directory: {self.workdir}")

            baseline = capture_snapshot(self.workdir)
            decision = classify_instruction(instruction)
            state = AgentState(instruction, decision.mode)
            contract = build_task_contract(decision, instruction, self.workdir)
            if self.repository_context is not None:
                self.repository_context.set_output_paths(tuple(rule.path for rule in contract.artifacts))
            task_playbook = load_playbook(decision.playbook)
            validation_playbook = load_validation_playbook()
            execution_context = ExecutionContext(
                self.workdir,
                decision,
                self.limits.max_capability,
                tuple(rule.path for rule in contract.artifacts),
            )
            tools = self.tool_bus.catalog(execution_context)
            allowed = {tool.name for tool in tools} | RESERVED_ACTIONS

            while True:
                elapsed = self.clock() - started
                if elapsed >= self.limits.deadline_seconds:
                    raise ScaffoldKernelError("deadline budget exhausted")
                if steps >= self.limits.max_steps:
                    raise ScaffoldKernelError("step budget exhausted")

                remaining = max(0.0, self.limits.deadline_seconds - elapsed)
                reserve = min(10.0, self.limits.deadline_seconds * 0.1)
                if remaining <= reserve:
                    raise ScaffoldKernelError("planning budget exhausted; reserved final verification time")
                snapshot = state.snapshot(tools)
                repository_guide = (
                    self.repository_context.task_guide(instruction)
                    if self.repository_context is not None
                    else ""
                )
                planning_context = PlanningContext(
                    instruction=instruction,
                    workdir=self.workdir,
                    decision=decision,
                    task_playbook=task_playbook,
                    validation_playbook=validation_playbook,
                    contract=contract,
                    tools=tools,
                    state_snapshot=snapshot,
                    events=tuple(state.events),
                    last_validation=last_validation,
                    remaining_seconds=remaining - reserve,
                    extension_guidance=self.extension_guidance,
                    repository_guide=repository_guide,
                )
                try:
                    plan = self.planner.next_plan(planning_context)
                except ModelRequestError as error:
                    planner_errors += 1
                    state.record_planner_error(str(error))
                    if planner_errors > self.limits.max_repeated_action:
                        raise
                    continue
                planner_errors = 0
                action = plan.action
                if action.name not in allowed:
                    raise ScaffoldKernelError(
                        f"planner selected unavailable action {action.name!r}"
                    )
                if action.name in RESERVED_ACTIONS and action.arguments:
                    raise ScaffoldKernelError(
                        f"{action.name} action must not have arguments"
                    )
                if not isinstance(action.arguments, dict):
                    raise ScaffoldKernelError("action arguments must be an object")

                control = self.hypothesis_controller.evaluate(
                    plan,
                    state_snapshot=snapshot,
                    tools=tools,
                )
                if not control.allowed:
                    control_rejections += 1
                    state.record_control_rejection(
                        reason=control.reason,
                        required_strategy=(
                            control.required_strategy.value
                            if control.required_strategy is not None
                            else None
                        ),
                        minimum_capability=(
                            int(control.minimum_capability)
                            if control.minimum_capability is not None
                            else None
                        ),
                    )
                    if control_rejections > self.limits.max_repeated_action:
                        raise ScaffoldKernelError(
                            f"runtime control rejected planner repeatedly: {control.reason}"
                        )
                    continue
                control_rejections = 0

                if action.name not in RESERVED_ACTIONS:
                    fingerprint = action.fingerprint()
                    repeated_actions[fingerprint] += 1
                    if repeated_actions[fingerprint] > self.limits.max_repeated_action:
                        raise ScaffoldKernelError(
                            f"repeated-action budget exhausted for {action.name!r}"
                        )

                steps += 1
                state.register_plan(plan, step=steps)

                if action.name == "abort":
                    state.record_terminal_event(steps, action)
                    return self._result(
                        status="failed",
                        reason=action.rationale or "planner aborted the task",
                        decision=decision,
                        steps=steps,
                        validations=validations,
                        state=state,
                        tools=tools,
                        final_validation=final_verification,
                    )

                if action.name == "finish":
                    if validations >= self.limits.max_validations:
                        raise ScaffoldKernelError("validation-attempt budget exhausted")
                    validations += 1
                    final_verification = self._verify(
                        decision=decision,
                        contract=contract,
                        baseline=baseline,
                        state=state,
                        started=started,
                    )
                    if final_verification.feedback is None:
                        raise ScaffoldKernelError(
                            "verifier must return ValidationFeedback for scaffold accounting"
                        )
                    last_validation = final_verification.feedback
                    state.record_validation_event(steps, action, last_validation)
                    if final_verification.passed:
                        return self._result(
                            status="succeeded",
                            reason=final_verification.reason,
                            decision=decision,
                            steps=steps,
                            validations=validations,
                            state=state,
                            tools=tools,
                            final_validation=final_verification,
                        )
                    if validations >= self.limits.max_validations:
                        raise ScaffoldKernelError(
                            f"validation failed: {final_verification.reason}"
                        )
                    continue

                result = self.tool_bus.execute(action, execution_context)
                state.record_tool_event(steps, action, result)

                # A transactional model edit gets its deterministic proof immediately.
                # This removes edit -> model -> pytest -> model -> finish on the happy path.
                # Conditional tools are not auto-finalized merely because their catalog says
                # they may mutate; the ToolResult must explicitly prove a source write.
                project_checks = contract.project_checks
                should_auto_verify = (
                    decision.mode == "fix"
                    and _confirmed_model_mutation(action, result)
                    and plan.strategy.value != "deterministic"
                    and project_checks is not None
                    and bool(project_checks.commands)
                )
                if should_auto_verify:
                    if validations >= self.limits.max_validations:
                        raise ScaffoldKernelError("validation-attempt budget exhausted")
                    validations += 1
                    final_verification = self._verify(
                        decision=decision,
                        contract=contract,
                        baseline=baseline,
                        state=state,
                        started=started,
                    )
                    if final_verification.feedback is None:
                        raise ScaffoldKernelError(
                            "verifier must return ValidationFeedback for scaffold accounting"
                        )
                    last_validation = final_verification.feedback
                    auto_finish = AgentAction(
                        "finish",
                        rationale="automatic deterministic validation after successful model-driven mutation",
                    )
                    if steps < self.limits.max_steps:
                        steps += 1
                    state.record_validation_event(steps, auto_finish, last_validation)
                    if final_verification.passed:
                        return self._result(
                            status="succeeded",
                            reason=final_verification.reason,
                            decision=decision,
                            steps=steps,
                            validations=validations,
                            state=state,
                            tools=tools,
                            final_validation=final_verification,
                        )
                    if validations >= self.limits.max_validations:
                        raise ScaffoldKernelError(
                            f"validation failed: {final_verification.reason}"
                        )
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            stop_reason = str(error)
            # EnIGMA/SWE-agent-inspired recovery: a planner failure does not erase
            # work already performed. Reserve one bounded deterministic check;
            # never fabricate an artifact or bypass a failed gate to claim success.
            remaining = self.limits.deadline_seconds - (self.clock() - started)
            changed_since_check = False
            for event in reversed(state.events):
                if event.validation is not None:
                    break
                if (event.tool_result and event.tool_result.ok and event.action
                        and event.action.name in {
                            "write_file", "append_file", "write_exact_text",
                            "checked_edit", "arena_promote", "apply_patch", "sql_parameterize",
                        }):
                    changed_since_check = True
                    break
            if (decision is not None and contract is not None and baseline is not None
                    and remaining > 0 and validations < self.limits.max_validations
                    and changed_since_check):
                try:
                    validations += 1
                    final_verification = self._verify(
                        decision=decision, contract=contract, baseline=baseline,
                        state=state, started=started,
                    )
                    if final_verification.feedback is not None:
                        if steps < self.limits.max_steps:
                            steps += 1
                        state.record_validation_event(
                            steps,
                            AgentAction("finish", rationale=f"final verification after planner stop: {error}"),
                            final_verification.feedback,
                        )
                        if final_verification.passed:
                            return self._result(
                                status="succeeded", reason="existing result passed final recovery verification",
                                decision=decision, steps=steps, validations=validations,
                                state=state, tools=tools, final_validation=final_verification,
                            )
                except (OSError, UnicodeError, ValueError, RuntimeError) as recovery_error:
                    stop_reason += f"; recovery verification failed: {recovery_error}"
            return self._result(
                status="failed",
                reason=stop_reason,
                decision=decision,
                steps=steps,
                validations=validations,
                state=state,
                tools=tools,
                final_validation=final_verification,
            )
