"""Deterministic verification adapter for the scaffold."""

from __future__ import annotations

from agent.core.models import ValidationFeedback
from agent.validators import ValidationPolicy, validate_task

from .contracts import VerificationContext, VerificationResult


class LegacyTaskVerifier:
    """Keep the existing validator as a hard success gate."""

    @staticmethod
    def _last_clean_scan(context: VerificationContext) -> bool | None:
        scans = [
            event.tool_result
            for event in context.events
            if event.action
            and event.action.name == "security_scan"
            and event.tool_result
            and event.tool_result.ok
        ]
        if not scans:
            return None
        return scans[-1].data.get("finding_count") == 0

    def verify(self, context: VerificationContext) -> VerificationResult:
        report = validate_task(
            ValidationPolicy(
                mode=context.decision.mode,
                target=context.workdir,
                baseline=context.baseline,
                artifacts=context.contract.artifacts,
                commands=(),
                check_python_syntax=True,
            )
        )
        if not report.passed:
            reason = "deterministic validator reported failed checks"
            feedback = ValidationFeedback(False, reason, report)
            return VerificationResult(False, reason, feedback)

        successful_tools = [
            event
            for event in context.events
            if event.tool_result is not None and event.tool_result.ok
        ]
        passed = True
        reason = "all deterministic checks and completion guards passed"
        if context.decision.mode == "fix":
            changes = report.changes.all_paths()
            if not changes:
                passed = False
                reason = "fix mode produced no project change"
            else:
                clean_scan = self._last_clean_scan(context)
                if clean_scan is False:
                    passed = False
                    reason = "post-fix security scan still has supported findings"
                elif clean_scan is None:
                    passed = False
                    reason = "fix mode has no successful post-action security scan"
        elif context.decision.mode == "general" and not context.contract.artifacts:
            passed = False
            reason = "general task has no deterministic artifact contract"
        elif not successful_tools:
            passed = False
            reason = "no successful task action was executed"

        feedback = ValidationFeedback(passed, reason, report)
        return VerificationResult(
            passed,
            reason,
            feedback,
            {"changed_paths": list(report.changes.all_paths())},
        )
