from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.contracts import ExecutionContext, KernelLimits, PlanDecision
from agent.scaffold.kernel import AgentKernel
from agent.scaffold.providers import LegacySecurityProvider
from agent.scaffold.registry import ToolBus
from agent.scaffold.security_relevance import SecurityAwareRepositoryDistiller
from agent.scaffold.semantic_namespace import (
    SemanticCyberACIProvider,
    SemanticRepositoryContext,
)
from agent.scaffold.verifier import LegacyTaskVerifier
from agent.strategies import classify_instruction


AUTH_BUG_INSTRUCTION = (
    "There is an authorization bug in this project. Find the root cause, "
    "make the smallest safe fix, and prove the fix using the existing tests."
)


class ScriptPlanner:
    def __init__(self, plans):
        self.plans = list(plans)

    def next_plan(self, context):
        if not self.plans:
            return PlanDecision(AgentAction("abort", rationale="script exhausted"))
        return self.plans.pop(0)


class SemanticNamespaceTests(unittest.TestCase):
    @staticmethod
    def _workspace(root: Path) -> None:
        (root / "access.py").write_text(
            'def can_delete(user):\n    return user.get("role") != "guest"\n',
            encoding="utf-8",
        )
        (root / "test_access.py").write_text(
            "from access import can_delete\n\n"
            "def test_admin_can_delete():\n"
            '    assert can_delete({"role": "admin"})\n\n'
            "def test_viewer_cannot_delete():\n"
            '    assert not can_delete({"role": "viewer"})\n\n'
            "def test_guest_cannot_delete():\n"
            '    assert not can_delete({"role": "guest"})\n',
            encoding="utf-8",
        )

    def test_virtual_guide_encodes_role_io_and_test_contract_without_renaming_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root)
            distiller = SecurityAwareRepositoryDistiller(root)
            semantic = SemanticRepositoryContext(root, distiller=distiller)

            guide = semantic.task_guide(AUTH_BUG_INSTRUCTION)
            card = semantic.card_for("access.py")

            self.assertIsNotNone(card)
            assert card is not None
            self.assertEqual(card.semantic_path, "authz__can_delete__impl.py")
            self.assertEqual(semantic.resolve(card.handle), "access.py")
            self.assertEqual(semantic.resolve(card.semantic_path), "access.py")
            self.assertIn("# REPO_GUIDE.md (virtual; model-only)", guide)
            self.assertIn("ROLE=authz-impl", guide)
            self.assertIn("IO=can_delete(user)->?", guide)
            self.assertIn("CONTRACT=can_delete(role=admin)=>true", guide)
            self.assertIn("can_delete(role=viewer)=>false", guide)
            self.assertTrue((root / "access.py").is_file())
            self.assertFalse((root / card.semantic_path).exists())

    def test_aci_accepts_semantic_path_and_returns_semantic_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root)
            distiller = SecurityAwareRepositoryDistiller(root)
            semantic = SemanticRepositoryContext(root, distiller=distiller)
            provider = SemanticCyberACIProvider(
                root,
                distiller=distiller,
                semantic_context=semantic,
            )
            decision = classify_instruction(AUTH_BUG_INSTRUCTION)
            execution = ExecutionContext(root, decision, KernelLimits().max_capability)
            card = semantic.card_for("access.py")
            assert card is not None

            viewed = provider.execute(
                AgentAction("view_window", {"path": card.semantic_path}), execution
            )

            self.assertTrue(viewed.ok, viewed.summary)
            self.assertEqual(viewed.data["path"], card.semantic_path)
            self.assertEqual(viewed.data["handle"], card.handle)
            self.assertIn('return user.get("role") != "guest"', viewed.data["content"])

            edited = provider.execute(
                AgentAction(
                    "checked_edit",
                    {
                        "path": card.handle,
                        "start_line": 2,
                        "end_line": 2,
                        "replacement": '    return user.get("role") == "admin"',
                        "expected_sha256": viewed.data["sha256"],
                    },
                ),
                execution,
            )

            self.assertTrue(edited.ok, edited.summary)
            self.assertEqual(edited.data["path"], card.semantic_path)
            self.assertEqual(
                (root / "access.py").read_text(encoding="utf-8"),
                'def can_delete(user):\n    return user.get("role") == "admin"\n',
            )

    def test_non_git_workspace_does_not_advertise_git_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root)
            distiller = SecurityAwareRepositoryDistiller(root)
            semantic = SemanticRepositoryContext(root, distiller=distiller)
            provider = SemanticCyberACIProvider(
                root,
                distiller=distiller,
                semantic_context=semantic,
            )
            decision = classify_instruction(AUTH_BUG_INSTRUCTION)
            execution = ExecutionContext(root, decision, KernelLimits().max_capability)
            run_check = next(spec for spec in provider.catalog(execution) if spec.name == "run_check")

            self.assertNotIn("git-diff", run_check.description)
            result = provider.execute(
                AgentAction("run_check", {"profile": "git-diff", "target": "."}),
                execution,
            )
            self.assertFalse(result.ok)
            self.assertIn("not a Git repository", result.summary)

    def test_model_driven_fix_is_auto_verified_without_extra_finish_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._workspace(root)
            distiller = SecurityAwareRepositoryDistiller(root)
            semantic = SemanticRepositoryContext(root, distiller=distiller)
            provider = SemanticCyberACIProvider(
                root,
                distiller=distiller,
                semantic_context=semantic,
            )
            sha = hashlib.sha256((root / "access.py").read_bytes()).hexdigest()
            planner = ScriptPlanner(
                [
                    PlanDecision(
                        AgentAction(
                            "security_scan",
                            {"write_report": False},
                            "establish supported scanner evidence",
                        )
                    ),
                    PlanDecision(
                        AgentAction(
                            "checked_edit",
                            {
                                "path": semantic.card_for("access.py").handle,  # type: ignore[union-attr]
                                "start_line": 2,
                                "end_line": 2,
                                "replacement": '    return user.get("role") == "admin"',
                                "expected_sha256": sha,
                            },
                            "apply the minimal authorization repair",
                        ),
                        hypothesis="only admin should be allowed to delete",
                        confidence=0.95,
                        expected_evidence="the existing authorization tests pass",
                    ),
                ]
            )
            kernel = AgentKernel(
                workdir=root,
                tool_bus=ToolBus((provider, LegacySecurityProvider(root))),
                planner=planner,
                verifier=LegacyTaskVerifier(),
                limits=KernelLimits(deadline_seconds=20),
                repository_context=semantic,
            )

            result = kernel.run(AUTH_BUG_INSTRUCTION)

            self.assertTrue(result.succeeded, result.reason)
            self.assertEqual(result.validations_used, 1)
            self.assertEqual(len(planner.plans), 0)
            self.assertEqual(result.events[-1].action.name, "finish")
            self.assertIn("automatic deterministic validation", result.events[-1].action.rationale)
            self.assertEqual(
                (root / "access.py").read_text(encoding="utf-8"),
                'def can_delete(user):\n    return user.get("role") == "admin"\n',
            )


if __name__ == "__main__":
    unittest.main()
