from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.candidate_arena import CandidateArena, CandidateArenaProvider, adaptive_branch_budget
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext
from agent.scaffold.registry import ToolBus
from agent.strategies import classify_instruction


VULNERABLE = '''\nasync def login(conn, username: str, password: str):\n    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"\n    return await conn.fetchrow(query)\n'''.lstrip()

GOOD_PATCH = '''\n--- a/auth.py\n+++ b/auth.py\n@@ -1,3 +1,5 @@\n async def login(conn, username: str, password: str):\n-    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"\n-    return await conn.fetchrow(query)\n+    query = "SELECT id FROM users WHERE username = $1 AND password = $2"\n+    return await conn.fetchrow(query, username, password)\n'''.lstrip()

BAD_SYNTAX_PATCH = '''\n--- a/auth.py\n+++ b/auth.py\n@@ -1,3 +1,3 @@\n async def login(conn, username: str, password: str):\n-    query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"\n+    query = (\n     return await conn.fetchrow(query)\n'''.lstrip()

NO_FIX_PATCH = '''\n--- a/auth.py\n+++ b/auth.py\n@@ -1,3 +1,4 @@\n async def login(conn, username: str, password: str):\n+    # keep behavior unchanged\n     query = f"SELECT id FROM users WHERE username = '{username}' AND password = '{password}'"\n     return await conn.fetchrow(query)\n'''.lstrip()


class CandidateArenaTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "auth.py").write_text(VULNERABLE, encoding="utf-8")
        (root / "README.md").write_text("task repository\n", encoding="utf-8")
        (root / "verifier").mkdir()
        (root / "verifier" / "expected.txt").write_text("SECRET\n", encoding="utf-8")

    def _context(self, root: Path, capability: CapabilityLevel = CapabilityLevel.MUTATE):
        return ExecutionContext(
            workdir=root,
            decision=classify_instruction("Fix the security vulnerability in project code"),
            max_capability=capability,
        )

    def test_adaptive_branch_budget_spends_more_only_when_uncertain(self):
        self.assertEqual(adaptive_branch_budget(0.95), 1)
        self.assertEqual(adaptive_branch_budget(0.70), 2)
        self.assertEqual(adaptive_branch_budget(0.40), 3)
        self.assertEqual(adaptive_branch_budget(0.10), 4)

    def test_provider_capabilities_gate_evaluate_and_promote(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            provider = CandidateArenaProvider(root)
            execute_bus = ToolBus((provider,))
            execute_names = {
                tool.name
                for tool in execute_bus.catalog(self._context(root, CapabilityLevel.EXECUTE))
            }
            self.assertEqual(execute_names, {"arena_evaluate"})
            mutate_names = {
                tool.name
                for tool in execute_bus.catalog(self._context(root, CapabilityLevel.MUTATE))
            }
            self.assertEqual(mutate_names, {"arena_evaluate", "arena_promote"})

    def test_evaluation_is_isolated_and_security_improving_patch_wins(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            before = (root / "auth.py").read_text(encoding="utf-8")
            arena = CandidateArena(root)
            data = arena.evaluate(
                confidence=0.60,
                candidates=[
                    {"id": "no_fix", "patch": NO_FIX_PATCH},
                    {"id": "parameterize", "patch": GOOD_PATCH},
                ],
            )
            self.assertEqual(data["branch_budget"], 2)
            self.assertEqual(data["evaluated_count"], 2)
            self.assertEqual(data["winner_id"], "parameterize")
            by_id = {item["candidate_id"]: item for item in data["candidates"]}
            self.assertEqual(by_id["parameterize"]["findings_delta"], -1)
            self.assertGreater(by_id["parameterize"]["score"], by_id["no_fix"]["score"])
            # Candidate branches are private: evaluation alone cannot mutate /app/workdir.
            self.assertEqual((root / "auth.py").read_text(encoding="utf-8"), before)
            self.assertEqual((root / "verifier" / "expected.txt").read_text(), "SECRET\n")

    def test_broken_candidate_is_filtered_before_selection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            arena = CandidateArena(root)
            data = arena.evaluate(
                confidence=0.60,
                candidates=[
                    {"id": "broken", "patch": BAD_SYNTAX_PATCH},
                    {"id": "good", "patch": GOOD_PATCH},
                ],
            )
            by_id = {item["candidate_id"]: item for item in data["candidates"]}
            self.assertFalse(by_id["broken"]["eligible"])
            self.assertFalse(by_id["broken"]["syntax_passed"])
            self.assertEqual(data["winner_id"], "good")

    def test_high_confidence_runtime_enforces_single_branch_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            arena = CandidateArena(root)
            data = arena.evaluate(
                confidence=0.90,
                candidates=[
                    {"id": "first", "patch": GOOD_PATCH},
                    {"id": "ignored", "patch": NO_FIX_PATCH},
                ],
            )
            self.assertEqual(data["branch_budget"], 1)
            self.assertEqual(data["evaluated_count"], 1)
            self.assertEqual(data["ignored_candidate_ids"], ["ignored"])
            self.assertEqual(data["winner_id"], "first")

    def test_only_winner_can_be_promoted_and_promotion_changes_real_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            arena = CandidateArena(root)
            data = arena.evaluate(
                confidence=0.60,
                candidates=[
                    {"id": "no_fix", "patch": NO_FIX_PATCH},
                    {"id": "good", "patch": GOOD_PATCH},
                ],
            )
            arena_id = data["arena_id"]
            with self.assertRaisesRegex(ValueError, "only deterministic winner"):
                arena.promote(arena_id=arena_id, candidate_id="no_fix")
            promoted = arena.promote(arena_id=arena_id, candidate_id="good")
            self.assertTrue(promoted["promoted"])
            rendered = (root / "auth.py").read_text(encoding="utf-8")
            self.assertIn("$1", rendered)
            self.assertIn("username, password", rendered)

    def test_stale_workspace_blocks_promotion(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            arena = CandidateArena(root)
            data = arena.evaluate(
                confidence=0.90,
                candidates=[{"id": "good", "patch": GOOD_PATCH}],
            )
            (root / "auth.py").write_text(VULNERABLE + "\n# concurrent change\n", encoding="utf-8")
            result = arena.promote(arena_id=data["arena_id"])
            self.assertFalse(result["promoted"])
            self.assertEqual(result["reason"], "workspace changed after arena evaluation")
            self.assertEqual(result["stale_paths"][0]["path"], "auth.py")
            self.assertIn("concurrent change", (root / "auth.py").read_text(encoding="utf-8"))

    def test_provider_returns_failed_observation_when_every_branch_is_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            provider = CandidateArenaProvider(root)
            context = self._context(root)
            result = provider.execute(
                AgentAction(
                    "arena_evaluate",
                    {
                        "confidence": 0.9,
                        "candidates": [{"id": "broken", "patch": BAD_SYNTAX_PATCH}],
                    },
                ),
                context,
            )
            self.assertFalse(result.ok)
            self.assertIsNone(result.data["winner_id"])
            self.assertFalse(result.data["promotion_ready"])


if __name__ == "__main__":
    unittest.main()
