"""Deterministic verification adapter for the scaffold."""

from __future__ import annotations

import json
from dataclasses import replace

from agent.core.ctf_completion import check_ctf_completion
from agent.core.fix_validation import failed_validation_reason, validate_fix_task
from agent.core.models import ValidationFeedback
from agent.tools.security_scan import finding_observation, scan_project
from agent.validators import CheckResult, ValidationPolicy, validate_task

from .contracts import VerificationContext, VerificationResult


class LegacyTaskVerifier:
    """Keep the existing validator as a hard success gate."""

    def verify(self, context: VerificationContext) -> VerificationResult:
        policy = ValidationPolicy(
            mode=context.decision.mode,
            target=context.workdir,
            baseline=context.baseline,
            artifacts=context.contract.artifacts,
            commands=(),
            check_python_syntax=context.decision.mode != "ctf",
        )
        report = (
            validate_fix_task(policy, context.contract.project_checks,
                              remaining_seconds=context.remaining_seconds)
            if context.decision.mode == "fix" else validate_task(policy)
        )
        if not report.passed:
            reason = (failed_validation_reason(report) if context.decision.mode == "fix"
                      else "deterministic validator reported failed checks")
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
                # A pre-edit scan is not evidence about the current file version.
                # Run the same scanner on the actual candidate, and expose details
                # in trusted validation feedback so the planner can act on them.
                findings = scan_project(context.workdir, include_tests=False)
                scan_detail = json.dumps(finding_observation(findings), ensure_ascii=False)
                report = replace(
                    report, passed=not findings,
                    checks=report.checks + (CheckResult("post-fix-security-scan", not findings, scan_detail),),
                )
                if findings:
                    passed = False
                    reason = "post-fix security scan still has supported findings: " + scan_detail[:2500]
        elif context.decision.mode == "ctf":
            passed, reason = check_ctf_completion(
                context.contract, context.events, report
            )
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
