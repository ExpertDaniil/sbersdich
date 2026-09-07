#!/usr/bin/env python3
"""Bounded autonomous loop connecting routing, playbooks, tools and validation."""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, deque
from pathlib import Path
from typing import Callable, Iterable

from agent.strategies import StrategyDecision, classify_instruction
from agent.validators import (
    CommandSpec,
    ValidationPolicy,
    capture_snapshot,
    canonical_path,
    validate_task,
)

from .contracts import build_task_contract
from .models import (
    ActionDriver,
    AgentAction,
    AgentRunResult,
    DriverContext,
    LoopEvent,
    LoopLimits,
    TaskContract,
    ToolResult,
    ValidationFeedback,
)
from .playbooks import load_playbook, load_validation_playbook
from .tools import RESERVED_ACTIONS, SecurityToolRegistry


class LoopError(RuntimeError):
    """Raised for an invalid or exhausted autonomous run."""


class ScriptedDriver:
    """Finite action driver used by tests and offline loop simulations."""

    def __init__(self, actions: Iterable[AgentAction]):
        self._actions = deque(actions)

    def next_action(self, context: DriverContext) -> AgentAction:
        if not self._actions:
            return AgentAction("abort", rationale="scripted action queue is exhausted")
        return self._actions.popleft()


class DeterministicDriver:
    """Low-token fallback for task profiles already supported by local tools."""

    @staticmethod
    def _tool_events(context: DriverContext) -> list[LoopEvent]:
        return [event for event in context.events if event.tool_result is not None]

    def next_action(self, context: DriverContext) -> AgentAction:
        tool_events = self._tool_events(context)
        failed = [event for event in tool_events if not event.tool_result.ok]  # type: ignore[union-attr]
        if failed:
            return AgentAction(
                "abort",
                rationale=f"deterministic tool failed: {failed[-1].tool_result.summary}",  # type: ignore[union-attr]
            )

        names = [event.action.name for event in tool_events if event.action]
        mode = context.decision.mode
        if mode == "audit":
            if "security_scan" not in names:
                return AgentAction(
                    "security_scan",
                    {"write_report": True},
                    "produce a structured audit deliverable",
                )
            return AgentAction("finish", rationale="audit report is ready for validation")

        if mode == "fix":
            scan_count = names.count("security_scan")
            if scan_count == 0:
                return AgentAction(
                    "security_scan",
                    {"write_report": False},
                    "capture the supported vulnerability signal before editing",
                )
            if "sql_parameterize" not in names:
                return AgentAction(
                    "sql_parameterize",
                    rationale="apply the conservative supported SQL value rewrite",
                )
            if scan_count == 1:
                return AgentAction(
                    "security_scan",
                    {"write_report": False},
                    "verify the supported SQL injection signal is removed",
                )
            return AgentAction("finish", rationale="fix is ready for validation")

        if mode == "forensics":
            if "forensics_analyze" not in names:
                return AgentAction(
                    "forensics_analyze",
                    rationale="correlate the supported evidence profile",
                )
            return AgentAction("finish", rationale="incident report is ready for validation")

        if mode == "general" and context.contract.exact_writes:
            completed: set[str] = set()

            for event in tool_events:
                if event.action and event.action.name == "write_exact_text":
                    assert event.tool_result is not None
                    completed.add(str(event.tool_result.data.get("path")))

            for path, value in context.contract.exact_writes:
                if str(path) not in completed:
                    return AgentAction(
                        "write_exact_text",
                        {"path": str(path), "content": value},
                        "satisfy the exact-file instruction contract",
                    )

            return AgentAction(
                "finish",
                rationale="exact-file artifacts are ready",
            )

        return AgentAction(
            "abort",
            rationale="task needs the future LLM driver or an additional tool profile",
        )


class AgentLoop:
    """State machine that never reports success before deterministic validation."""

    def __init__(
        self,
        *,
        workdir: Path | str,
        driver: ActionDriver | None = None,
        limits: LoopLimits | None = None,
        validation_commands: Iterable[CommandSpec] = (),
        clock: Callable[[], float] = time.monotonic,
    ):
        self.workdir = canonical_path(workdir)
        self.driver = driver or DeterministicDriver()
        self.limits = limits or LoopLimits()
        self.validation_commands = tuple(validation_commands)
        self.clock = clock

    @staticmethod
    def _last_clean_scan(events: list[LoopEvent]) -> bool | None:
        scans = [
            event.tool_result
            for event in events
            if event.action
            and event.action.name == "security_scan"
            and event.tool_result
            and event.tool_result.ok
        ]
        if not scans:
            return None
        return scans[-1].data.get("finding_count") == 0

    @staticmethod
    def _completion_guard(
        decision: StrategyDecision,
        contract: TaskContract,
        events: list[LoopEvent],
        feedback: ValidationFeedback,
    ) -> tuple[bool, str]:
        if not feedback.report.passed:
            return False, "deterministic validator reported failed checks"
        successful_tools = [
            event
            for event in events
            if event.tool_result is not None and event.tool_result.ok
        ]
        if decision.mode == "fix":
            changes = feedback.report.changes.all_paths()
            if not changes:
                return False, "fix mode produced no project change"
            clean_scan = AgentLoop._last_clean_scan(events)
            if clean_scan is False:
                return False, "post-fix security scan still has supported findings"
            if clean_scan is None:
                return False, "fix mode has no successful post-action security scan"
        elif decision.mode == "ctf":
            if not contract.artifacts:
                return False, "CTF task has no explicit answer artifact contract"
            changed = set(feedback.report.changes.all_paths())
            validation_root = canonical_path(feedback.report.target)
            expected = {
                canonical_path(artifact.path).relative_to(validation_root).as_posix()
                for artifact in contract.artifacts
            }
            if not expected.issubset(changed):
                return False, "CTF answer artifact was not produced during this run"
            if not any(
                event.action and event.action.name == "write_exact_text"
                for event in successful_tools
            ):
                return False, "CTF task has no successful answer write"
        elif decision.mode == "general" and not contract.artifacts:
            return False, "general task has no verifiable artifact contract"
        elif not successful_tools:
            return False, "no successful task action was executed"
        return True, "all deterministic checks and completion guards passed"

    def _result(
        self,
        *,
        status: str,
        reason: str,
        decision: StrategyDecision | None,
        steps: int,
        validations: int,
        events: list[LoopEvent],
        final_validation: ValidationFeedback | None,
    ) -> AgentRunResult:
        return AgentRunResult(
            status=status,
            reason=reason,
            decision=decision,
            steps_used=steps,
            validations_used=validations,
            events=tuple(events),
            final_validation=final_validation,
        )

    def run(self, instruction: str) -> AgentRunResult:
        events: list[LoopEvent] = []
        decision: StrategyDecision | None = None
        last_validation: ValidationFeedback | None = None
        steps = 0
        validations = 0
        repeated_actions: Counter[str] = Counter()
        started = self.clock()

        try:
            if not instruction.strip():
                raise LoopError("instruction must not be empty")
            if not self.workdir.is_dir():
                raise LoopError(f"workdir is not a directory: {self.workdir}")
            baseline = capture_snapshot(self.workdir)
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, self.workdir)
            task_playbook = load_playbook(decision.playbook)
            validation_playbook = load_validation_playbook()
            registry = SecurityToolRegistry(self.workdir)

            while True:
                if self.clock() - started >= self.limits.deadline_seconds:
                    raise LoopError("deadline budget exhausted")
                if steps >= self.limits.max_steps:
                    raise LoopError("step budget exhausted")

                context = DriverContext(
                    instruction=instruction,
                    workdir=self.workdir,
                    decision=decision,
                    task_playbook=task_playbook,
                    validation_playbook=validation_playbook,
                    contract=contract,
                    available_tools=registry.catalog(decision),
                    events=tuple(events),
                    last_validation=last_validation,
                    remaining_seconds=max(
                        0.0,
                        self.limits.deadline_seconds - (self.clock() - started),
                    ),
                )
                action = self.driver.next_action(context)
                if not isinstance(action, AgentAction):
                    raise LoopError("driver returned an invalid action object")
                if not isinstance(action.name, str) or not action.name.strip():
                    raise LoopError("action name must be non-empty text")
                if not isinstance(action.arguments, dict):
                    raise LoopError("action arguments must be an object")
                if not isinstance(action.rationale, str):
                    raise LoopError("action rationale must be text")
                if action.name in RESERVED_ACTIONS and action.arguments:
                    raise LoopError(f"{action.name} action must not have arguments")
                fingerprint = action.fingerprint()
                if action.name not in RESERVED_ACTIONS:
                    repeated_actions[fingerprint] += 1
                    if repeated_actions[fingerprint] > self.limits.max_repeated_action:
                        raise LoopError(
                            f"repeated-action budget exhausted for {action.name!r}"
                        )
                steps += 1

                if action.name == "abort":
                    reason = action.rationale or "driver aborted the task"
                    events.append(LoopEvent(steps, "failed", action=action))
                    return self._result(
                        status="failed",
                        reason=reason,
                        decision=decision,
                        steps=steps,
                        validations=validations,
                        events=events,
                        final_validation=last_validation,
                    )

                if action.name == "finish":
                    if validations >= self.limits.max_validations:
                        raise LoopError("validation-attempt budget exhausted")
                    validations += 1
                    report = validate_task(
                        ValidationPolicy(
                            mode=decision.mode,
                            target=self.workdir,
                            baseline=baseline,
                            artifacts=contract.artifacts,
                            commands=self.validation_commands,
                            # CTF evidence may deliberately contain malformed or
                            # partial source; the mode cannot edit it, so syntax
                            # validation would reject a correct flag for the
                            # wrong reason.
                            check_python_syntax=decision.mode != "ctf",
                        )
                    )
                    provisional = ValidationFeedback(
                        passed=report.passed,
                        reason=(
                            "deterministic validator passed"
                            if report.passed
                            else "deterministic validator reported failed checks"
                        ),
                        report=report,
                    )
                    passed, reason = self._completion_guard(
                        decision, contract, events, provisional
                    )
                    last_validation = ValidationFeedback(passed, reason, report)
                    events.append(
                        LoopEvent(
                            steps,
                            "succeeded" if passed else "retrying",
                            action=action,
                            validation=last_validation,
                        )
                    )
                    if passed:
                        return self._result(
                            status="succeeded",
                            reason=reason,
                            decision=decision,
                            steps=steps,
                            validations=validations,
                            events=events,
                            final_validation=last_validation,
                        )
                    if validations >= self.limits.max_validations:
                        raise LoopError(f"validation failed: {reason}")
                    continue

                tool_result = registry.execute(action, decision)
                events.append(
                    LoopEvent(
                        steps,
                        "acting" if tool_result.ok else "tool-failed",
                        action=action,
                        tool_result=tool_result,
                    )
                )
        except (OSError, UnicodeError, ValueError, RuntimeError) as error:
            return self._result(
                status="failed",
                reason=str(error),
                decision=decision,
                steps=steps,
                validations=validations,
                events=events,
                final_validation=last_validation,
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("instruction", help="complete task instruction")
    parser.add_argument("--workdir", type=Path, default=Path("/app"))
    parser.add_argument("--max-steps", type=int, default=LoopLimits.max_steps)
    parser.add_argument(
        "--max-validations", type=int, default=LoopLimits.max_validations
    )
    parser.add_argument(
        "--deadline-seconds", type=float, default=LoopLimits.deadline_seconds
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        limits = LoopLimits(
            max_steps=args.max_steps,
            max_validations=args.max_validations,
            deadline_seconds=args.deadline_seconds,
        )
        result = AgentLoop(workdir=args.workdir, limits=limits).run(args.instruction)
    except ValueError as error:
        print(f"agent loop configuration failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result.as_payload(), ensure_ascii=False, indent=2))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
