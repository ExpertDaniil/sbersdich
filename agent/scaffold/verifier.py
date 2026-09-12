"""Deterministic verification adapter for the scaffold."""

from __future__ import annotations

import json
from dataclasses import replace

from agent.core.contracts import map_instruction_path
from agent.core.ctf_completion import check_ctf_completion
from agent.core.fix_validation import failed_validation_reason, validate_fix_task
from agent.core.models import ValidationFeedback
from agent.tools.security_scan import finding_observation, scan_project
from agent.tools.fix_guard import scan_fix_requirements
from agent.validators import CheckResult, ValidationPolicy, validate_task

from .contracts import VerificationContext, VerificationResult


def _confirmed_written_paths(context: VerificationContext) -> set[str]:
    """Return artifact-relative paths proven by successful mutation results."""

    root = context.workdir
    written: set[str] = set()
    for event in context.events:
        action = event.action
        result = event.tool_result
        if action is None or result is None or not result.ok:
            continue

        candidates: list[object] = []
        if action.name in {"write_file", "append_file", "write_exact_text"}:
            candidates.append(result.data.get("path"))
        elif action.name in {"security_scan", "forensics_analyze"}:
            candidates.append(result.data.get("report"))
        elif action.name == "checked_edit" and result.data.get("written") is True:
            candidates.append(result.data.get("source_path", result.data.get("path")))
        elif action.name in {"apply_patch", "arena_promote"}:
            if action.name != "arena_promote" or result.data.get("promoted") is True:
                changed = result.data.get("changed_paths", ())
                if isinstance(changed, (list, tuple)):
                    candidates.extend(changed)

        for raw_path in candidates:
            if not isinstance(raw_path, str) or not raw_path:
                continue
            try:
                path = map_instruction_path(raw_path, root)
                written.add(path.relative_to(root).as_posix())
            except (OSError, ValueError, RuntimeError):
                continue
    return written


def _artifact_freshness_check(context: VerificationContext, report) -> CheckResult:
    """Reject fixture outputs and require every declared artifact to be written now."""

    root = context.workdir
    expected = {
        rule.path.relative_to(root).as_posix()
        for rule in context.contract.artifacts
    }
    changed = set(report.changes.all_paths())
    written = _confirmed_written_paths(context)
    stale = sorted(expected - changed)
    unproven = sorted(expected - written)
    if stale or unproven:
        details: list[str] = []
        if stale:
            details.append("not produced or changed during this run: " + ", ".join(stale))
        if unproven:
            details.append("no successful artifact writer evidence: " + ", ".join(unproven))
        return CheckResult("artifact-freshness", False, "; ".join(details))
    return CheckResult(
        "artifact-freshness",
        True,
        f"all {len(expected)} declared artifact(s) are fresh and writer-confirmed",
    )


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
            reason = failed_validation_reason(report)
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
                property_issues = scan_fix_requirements(
                    context.workdir, context.contract.security_requirements
                )
                property_detail = json.dumps(
                    {
                        "requirements": list(context.contract.security_requirements),
                        "issue_count": len(property_issues),
                        "issues": property_issues,
                    },
                    ensure_ascii=False,
                )
                report = replace(
                    report,
                    passed=not findings and not property_issues,
                    checks=report.checks + (
                        CheckResult("post-fix-security-scan", not findings, scan_detail),
                        CheckResult(
                            "post-fix-security-properties",
                            not property_issues,
                            property_detail,
                        ),
                    ),
                )
                if findings:
                    passed = False
                    reason = "post-fix security scan still has supported findings: " + scan_detail[:2500]
                elif property_issues:
                    passed = False
                    reason = (
                        "post-fix instruction-derived security properties still fail: "
                        + property_detail[:2500]
                    )
        elif context.decision.mode == "ctf":
            passed, reason = check_ctf_completion(
                context.contract, context.events, report
            )
        elif context.contract.artifacts:
            freshness = _artifact_freshness_check(context, report)
            report = replace(
                report,
                passed=report.passed and freshness.passed,
                checks=report.checks + (freshness,),
            )
            if not freshness.passed:
                passed = False
                reason = "required artifact was not produced by this run: " + freshness.detail
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
