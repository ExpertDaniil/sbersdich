from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction, LoopEvent, TaskContract, ToolResult
from agent.scaffold.bootstrap import build_default_application
from agent.scaffold.contracts import KernelLimits, PlanDecision, PlanningContext
from agent.scaffold.kernel import AgentKernel
from agent.scaffold.planner import HybridPlanner
from agent.scaffold.providers import LegacySecurityProvider, WorkspaceFileProvider
from agent.scaffold.registry import ToolBus
from agent.scaffold.verifier import LegacyTaskVerifier
from agent.strategies import classify_instruction


class ScriptPlanner:
    def __init__(self, plans):
        self.plans = list(plans)

    def next_plan(self, context):
        if not self.plans:
            return PlanDecision(AgentAction("abort", rationale="script exhausted"))
        return self.plans.pop(0)


class RecordingModelPlanner:
    def __init__(self):
        self.contexts = []

    def next_plan(self, context):
        self.contexts.append(context)
        return PlanDecision(
            AgentAction("finish", rationale="recover with the local model"),
        )


class ScaffoldKernelTests(unittest.TestCase):
    def test_failed_deterministic_tool_is_delegated_to_model(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            instruction = "Inspect the workspace and report the result."
            failed_event = LoopEvent(
                sequence=1,
                phase="tool-failed",
                action=AgentAction("read_file", {"path": "missing.txt"}),
                tool_result=ToolResult(False, "file is unavailable"),
            )
            context = PlanningContext(
                instruction=instruction,
                workdir=root,
                decision=classify_instruction(instruction),
                task_playbook="",
                validation_playbook="",
                contract=TaskContract(),
                tools=(),
                state_snapshot={"evidence": [failed_event.as_payload()]},
                events=(failed_event,),
                last_validation=None,
                remaining_seconds=20,
            )
            model = RecordingModelPlanner()

            plan = HybridPlanner(model=model).next_plan(context)

            self.assertEqual(plan.action.name, "finish")
            self.assertEqual(len(model.contexts), 1)
            self.assertEqual(
                model.contexts[0].events[0].tool_result.summary,
                "file is unavailable",
            )

    def test_default_application_keeps_zero_llm_fast_path_for_exact_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            app = build_default_application(
                workdir=root,
                limits=KernelLimits(deadline_seconds=20),
            )
            result = app.run(
                "Create a file at `/app/result.txt` whose content is exactly `done`."
            )
            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual((root / "result.txt").read_text(encoding="utf-8"), "done")
            self.assertEqual(app.model_usage.requests, 0)

    def test_generic_write_provider_can_satisfy_exact_artifact_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            planner = ScriptPlanner(
                [
                    PlanDecision(
                        AgentAction(
                            "write_file",
                            {"path": "/app/result.txt", "content": "done"},
                            "write the requested artifact",
                        ),
                        hypothesis="the task is an exact artifact request",
                    ),
                    PlanDecision(AgentAction("finish", rationale="artifact is ready")),
                ]
            )
            kernel = AgentKernel(
                workdir=root,
                tool_bus=ToolBus(
                    (LegacySecurityProvider(root), WorkspaceFileProvider(root))
                ),
                planner=planner,
                verifier=LegacyTaskVerifier(),
                limits=KernelLimits(deadline_seconds=20),
            )
            result = kernel.run(
                "Create a file at `/app/result.txt` whose content is exactly `done`."
            )
            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual((root / "result.txt").read_text(encoding="utf-8"), "done")
            self.assertTrue(result.state["evidence"])


if __name__ == "__main__":
    unittest.main()
