from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agent.scaffold.security_relevance import SecurityAwareRepositoryDistiller


VULNERABLE_LOGIN = '''\nfrom db import get_pool\n\nasync def login(req):\n    pool = await get_pool()\n    async with pool.acquire() as conn:\n        query = (\n            f"SELECT id FROM users "\n            f"WHERE username = '{req.username}' AND password = '{req.password}'"\n        )\n        return await conn.fetchrow(query)\n'''.lstrip()

SAFE_ITEMS = '''\nfrom db import get_pool\n\nasync def list_items(status=None):\n    pool = await get_pool()\n    async with pool.acquire() as conn:\n        params = []\n        conditions = []\n        if status:\n            params.append(status)\n            conditions.append(f"status = ${len(params)}")\n        query = "SELECT * FROM items"\n        if conditions:\n            query += " WHERE " + " AND ".join(conditions)\n        return await conn.fetch(query, *params)\n'''.lstrip()

VULNERABLE_SEARCH = '''\nfrom db import get_pool\n\nasync def search(q: str = ""):\n    pool = await get_pool()\n    async with pool.acquire() as conn:\n        query = f"SELECT * FROM items WHERE name LIKE '%{q}%'"\n        return await conn.fetch(query)\n'''.lstrip()


class SecurityAwareRepositoryDistillerTests(unittest.TestCase):
    def _repo(self, root: Path, *, search_bug: bool = False) -> None:
        (root / "routers").mkdir()
        (root / "routers" / "auth.py").write_text(VULNERABLE_LOGIN, encoding="utf-8")
        (root / "routers" / "items.py").write_text(
            VULNERABLE_SEARCH if search_bug else SAFE_ITEMS,
            encoding="utf-8",
        )
        (root / "db.py").write_text(
            "async def get_pool():\n    raise NotImplementedError\n",
            encoding="utf-8",
        )
        (root / "AGENTS.md").write_text(
            "Run pytest tests. This service is a FastAPI PostgreSQL security challenge.\n",
            encoding="utf-8",
        )
        (root / "tests").mkdir()
        (root / "tests" / "test_api.py").write_text(
            "def test_security_login_api():\n    assert True\n",
            encoding="utf-8",
        )
        (root / "pyproject.toml").write_text(
            "[project]\nname='demo'\ndependencies=['fastapi','asyncpg']\n",
            encoding="utf-8",
        )

    def test_generic_security_instruction_prefers_tainted_sql_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            data = SecurityAwareRepositoryDistiller(root).rank_relevant_files(
                query=(
                    "Analyse the code, identify the most critical security issues, and fix them. "
                    "Run pytest tests and do not introduce new dependencies."
                ),
                limit=5,
            )
            self.assertTrue(data["security_intent"])
            self.assertEqual(data["candidates"][0]["path"], "routers/auth.py")
            self.assertGreater(data["candidates"][0]["security_score"], 200)

    def test_search_input_in_dynamic_sql_beats_docs_and_tests(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root, search_bug=True)
            # Remove the login bug so this fixture has one obvious risky file.
            (root / "routers" / "auth.py").write_text(
                "async def login(req):\n    return True\n",
                encoding="utf-8",
            )
            data = SecurityAwareRepositoryDistiller(root).rank_relevant_files(
                query="Perform a security audit of this FastAPI application and report critical vulnerabilities.",
                limit=5,
            )
            self.assertEqual(data["candidates"][0]["path"], "routers/items.py")
            paths = [item["path"] for item in data["candidates"]]
            self.assertLess(paths.index("routers/items.py"), paths.index("AGENTS.md") if "AGENTS.md" in paths else len(paths))

    def test_safe_parameter_placeholder_construction_is_not_treated_as_external_sql_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            (root / "routers" / "auth.py").write_text(
                "async def login(req):\n    return True\n",
                encoding="utf-8",
            )
            data = SecurityAwareRepositoryDistiller(root).rank_relevant_files(
                query="security audit critical vulnerabilities",
                limit=10,
            )
            item = next(candidate for candidate in data["candidates"] if candidate["path"] == "routers/items.py")
            self.assertFalse(any("external-input-in-sql" in reason for reason in item["reasons"]))

    def test_non_security_query_preserves_generic_ranking_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._repo(root)
            data = SecurityAwareRepositoryDistiller(root).rank_relevant_files(
                query="where is get_pool defined",
                limit=3,
            )
            self.assertNotIn("security_intent", data)
            self.assertEqual(data["candidates"][0]["path"], "db.py")


if __name__ == "__main__":
    unittest.main()
