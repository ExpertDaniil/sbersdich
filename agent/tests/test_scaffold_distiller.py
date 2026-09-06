from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.core.models import AgentAction
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext
from agent.scaffold.distiller import RepositoryDistiller, RepositoryDistillerProvider
from agent.strategies import classify_instruction


AUTH_SOURCE = '''\nfrom db import get_user\n\nTOKEN_TTL = 300\n\nclass AuthService:\n    def login(self, username: str, password: str) -> bool:\n        user = get_user(username)\n        return bool(user and user.password == password)\n\ndef authenticate_request(token: str) -> bool:\n    return token.startswith("Bearer ")\n'''.lstrip()

DB_SOURCE = '''\ndef get_user(username: str):\n    return {"username": username}\n\ndef list_invoices():\n    return []\n'''.lstrip()

JS_SOURCE = '''\nexport class HealthController {\n  ping() { return "ok"; }\n}\nexport function healthCheck() { return true; }\n'''.lstrip()


class RepositoryDistillerTests(unittest.TestCase):
    def _repo(self, root: Path) -> None:
        (root / "app").mkdir()
        (root / "app" / "auth.py").write_text(AUTH_SOURCE, encoding="utf-8")
        (root / "app" / "db.py").write_text(DB_SOURCE, encoding="utf-8")
        (root / "web").mkdir()
        (root / "web" / "health.js").write_text(JS_SOURCE, encoding="utf-8")
        (root / "README.md").write_text("authentication service\n", encoding="utf-8")
        (root / "verifier").mkdir()
        (root / "verifier" / "expected.txt").write_text("DO_NOT_READ\n", encoding="utf-8")
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("secret\n", encoding="utf-8")

    def test_tree_is_bounded_and_excludes_answer_and_git_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            data = RepositoryDistiller(root).repo_tree(max_depth=4, max_entries=100)
            tree = data["tree"]
            self.assertIn("app/", tree)
            self.assertIn("auth.py", tree)
            self.assertNotIn("verifier", tree)
            self.assertNotIn(".git", tree)

    def test_symbol_index_extracts_python_and_javascript_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            distiller = RepositoryDistiller(root)
            login = distiller.symbol_index(query="login")
            self.assertTrue(any(item["qualname"] == "AuthService.login" for item in login["symbols"]))
            health = distiller.symbol_index(query="healthCheck")
            self.assertTrue(any(item["path"] == "web/health.js" and item["name"] == "healthCheck" for item in health["symbols"]))

    def test_skeleton_contains_signatures_but_not_function_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            data = RepositoryDistiller(root).repo_skeleton(paths=["app/auth.py"])
            skeleton = data["skeleton"]
            self.assertIn("AuthService.login", skeleton)
            self.assertIn("authenticate_request", skeleton)
            self.assertNotIn("user.password == password", skeleton)

    def test_relevant_file_ranking_uses_path_symbols_and_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            data = RepositoryDistiller(root).rank_relevant_files(
                query="authentication login password token",
                limit=3,
            )
            self.assertGreaterEqual(len(data["candidates"]), 1)
            self.assertEqual(data["candidates"][0]["path"], "app/auth.py")
            self.assertTrue(data["candidates"][0]["reasons"])

    def test_inspect_symbol_returns_focused_source_and_references(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            (root / "app" / "routes.py").write_text(
                "from app.auth import authenticate_request\n"
                "def endpoint(token):\n"
                "    return authenticate_request(token)\n",
                encoding="utf-8",
            )
            data = RepositoryDistiller(root).inspect_symbol(
                symbol="app/auth.py::authenticate_request",
                context_lines=1,
                max_references=5,
            )
            self.assertTrue(data["found"])
            self.assertIn("def authenticate_request", data["source"]["content"])
            self.assertTrue(any(ref["path"] == "app/routes.py" for ref in data["references"]))

    def test_provider_exposes_distiller_through_tool_bus_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            provider = RepositoryDistillerProvider(root)
            context = ExecutionContext(
                workdir=root,
                decision=classify_instruction("inspect the code for vulnerabilities"),
                max_capability=CapabilityLevel.MUTATE,
            )
            names = {spec.name for spec in provider.catalog(context)}
            self.assertEqual(
                names,
                {"repo_tree", "symbol_index", "repo_skeleton", "rank_relevant_files", "inspect_symbol"},
            )
            result = provider.execute(AgentAction("rank_relevant_files", {"query": "login password"}), context)
            self.assertTrue(result.ok)
            self.assertEqual(result.data["candidates"][0]["path"], "app/auth.py")

    def test_index_refreshes_after_workspace_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            distiller = RepositoryDistiller(root)
            self.assertEqual(distiller.symbol_index(query="new_security_gate")["count"], 0)
            auth = root / "app" / "auth.py"
            auth.write_text(AUTH_SOURCE + "\ndef new_security_gate():\n    return True\n", encoding="utf-8")
            data = distiller.symbol_index(query="new_security_gate")
            self.assertEqual(data["count"], 1)
            self.assertEqual(data["symbols"][0]["name"], "new_security_gate")


if __name__ == "__main__":
    unittest.main()
