from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNER = REPO_ROOT / "agent" / "tools" / "security_scan.py"
FIXER = REPO_ROOT / "agent" / "tools" / "sql_parameterize.py"

sys.path.insert(0, str(REPO_ROOT))

from agent.strategies import classify_instruction  # noqa: E402
from agent.tools.security_scan import render_report, scan_python_source  # noqa: E402
from agent.tools.sql_parameterize import (  # noqa: E402
    parameterize_project,
    parameterize_source,
)


VULNERABLE_LOGIN = '''
async def login(conn, req):
    query = (
        f"SELECT id FROM users "
        f"WHERE username = '{req.username}' AND password = '{req.password}'"
    )
    return await conn.fetchrow(query)
'''.lstrip()

VULNERABLE_SEARCH = '''
async def search(conn, q):
    return await conn.fetch(
        f"SELECT * FROM items WHERE name LIKE '%{q}%' ORDER BY id ASC"
    )
'''.lstrip()


class SecurityScannerTests(unittest.TestCase):
    def test_assigned_fstring_reaching_fetchrow_is_reported(self):
        findings = scan_python_source(VULNERABLE_LOGIN, "routers/auth.py")
        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.category, "CWE-89: SQL Injection")
        self.assertIn("req.username", finding.evidence)
        self.assertIn("req.password", finding.evidence)
        self.assertIn("routers/auth.py:3", finding.location)

    def test_safe_parameter_values_and_local_query_structure_are_not_flagged(self):
        safe = '''
async def update(conn, item_id):
    params = ["closed", item_id]
    updates = ["status = $1", "updated_at = now()"]
    query = f"UPDATE items SET {', '.join(updates)} WHERE id = ${len(params)}"
    return await conn.fetchrow(query, *params)
'''.lstrip()
        self.assertEqual(scan_python_source(safe, "items.py"), [])

    def test_format_and_identifier_interpolation_are_reported(self):
        source = '''
async def by_name(conn, username):
    query = "SELECT id FROM users WHERE username = '{}'".format(username)
    return await conn.fetchone(query)

async def from_table(conn, table):
    return await conn.fetch(f"SELECT * FROM {table}")
'''.lstrip()
        findings = scan_python_source(source, "queries.py")
        self.assertEqual(len(findings), 2)
        evidence = "\n".join(finding.evidence for finding in findings)
        self.assertIn("str.format", evidence)
        self.assertIn("table", evidence)

    def test_nested_function_is_not_duplicated_under_outer_scope(self):
        source = '''
async def outer(conn):
    async def inner(user_input):
        return await conn.fetch(f"SELECT * FROM users WHERE name = '{user_input}'")
    return inner
'''.lstrip()
        findings = scan_python_source(source, "nested.py")
        self.assertEqual(len(findings), 1)
        self.assertIn("(inner)", findings[0].location)

    def test_report_has_machine_readable_contract(self):
        report = json.loads(
            render_report(scan_python_source(VULNERABLE_LOGIN, "auth.py"))
        )
        self.assertEqual(set(report), {"findings"})
        self.assertEqual(
            set(report["findings"][0]),
            {
                "title",
                "severity",
                "category",
                "location",
                "evidence",
                "impact",
                "recommendation",
            },
        )


class SqlParameterizerTests(unittest.TestCase):
    def test_project_apply_preserves_crlf_line_endings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_file = root / "auth.py"
            original = VULNERABLE_LOGIN.replace("\n", "\r\n").encode("utf-8")
            source_file.write_bytes(original)

            changes = parameterize_project(root, apply=True)
            updated = source_file.read_bytes()

        self.assertEqual(len(changes), 1)
        self.assertIn(b"\r\n", updated)
        self.assertNotIn(b"\n", updated.replace(b"\r\n", b""))
        self.assertEqual(
            scan_python_source(updated.decode("utf-8"), "auth.py"),
            [],
        )

    def test_login_query_is_parameterized_and_payload_stays_data(self):
        updated, changes = parameterize_source(VULNERABLE_LOGIN, "auth.py")
        self.assertEqual(len(changes), 1)
        self.assertIn("username = $1 AND password = $2", updated)
        self.assertIn("fetchrow(query, req.username, req.password)", updated)
        self.assertNotIn("VULNERABLE", updated)
        self.assertEqual(scan_python_source(updated, "auth.py"), [])

        namespace: dict[str, object] = {}
        exec(updated, namespace)

        class Request:
            username = "admin' OR '1'='1"
            password = "x'--"

        class Connection:
            def __init__(self):
                self.call = None

            async def fetchrow(self, query, *args):
                self.call = (query, args)
                return None

        connection = Connection()
        asyncio.run(namespace["login"](connection, Request()))  # type: ignore[index,operator]
        query, arguments = connection.call
        self.assertNotIn("admin", query)
        self.assertEqual(arguments, (Request.username, Request.password))

    def test_like_wildcards_move_into_parameter_value(self):
        updated, changes = parameterize_source(VULNERABLE_SEARCH, "items.py")
        self.assertEqual(len(changes), 1)
        self.assertIn("name LIKE $1", updated)
        self.assertNotIn("LIKE '%", updated)
        self.assertEqual(scan_python_source(updated, "items.py"), [])

        namespace: dict[str, object] = {}
        exec(updated, namespace)

        class Connection:
            def __init__(self):
                self.call = None

            async def fetch(self, query, *args):
                self.call = (query, args)
                return []

        connection = Connection()
        payload = "%' OR 1=1--"
        asyncio.run(namespace["search"](connection, payload))  # type: ignore[index,operator]
        query, arguments = connection.call
        self.assertNotIn(payload, query)
        self.assertEqual(arguments, (f"%{payload}%",))

    def test_identifier_interpolation_is_left_for_manual_fix(self):
        source = '''
async def from_table(conn, table):
    return await conn.fetch(f"SELECT * FROM {table}")
'''.lstrip()
        updated, changes = parameterize_source(source, "dynamic.py")
        self.assertEqual(updated, source)
        self.assertEqual(changes, [])
        self.assertEqual(len(scan_python_source(source, "dynamic.py")), 1)


class ToolCliTests(unittest.TestCase):
    def test_audit_does_not_modify_source_and_fix_reaches_clean_rescan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_file = root / "routers" / "auth.py"
            source_file.parent.mkdir()
            source_file.write_text(VULNERABLE_LOGIN, encoding="utf-8")
            before = hashlib.sha256(source_file.read_bytes()).hexdigest()
            security_report = root / "security_report.json"

            audit = subprocess.run(
                [
                    sys.executable,
                    str(SCANNER),
                    str(root),
                    "--output",
                    str(security_report),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            self.assertEqual(audit.returncode, 0, audit.stdout + audit.stderr)
            self.assertEqual(before, hashlib.sha256(source_file.read_bytes()).hexdigest())
            self.assertEqual(len(json.loads(security_report.read_text())["findings"]), 1)

            check = subprocess.run(
                [sys.executable, str(FIXER), str(root), "--check"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            self.assertEqual(check.returncode, 1, check.stdout + check.stderr)
            self.assertEqual(before, hashlib.sha256(source_file.read_bytes()).hexdigest())

            apply = subprocess.run(
                [sys.executable, str(FIXER), str(root), "--apply"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            self.assertEqual(apply.returncode, 0, apply.stdout + apply.stderr)
            self.assertNotEqual(before, hashlib.sha256(source_file.read_bytes()).hexdigest())
            self.assertEqual(scan_python_source(source_file.read_text(), "auth.py"), [])


class StrategyRoutingTests(unittest.TestCase):
    def test_audit_contract_prevents_project_modification(self):
        decision = classify_instruction(
            "Perform a security audit. Do not modify application code. "
            "Write /app/security_report.json."
        )
        self.assertEqual(decision.mode, "audit")
        self.assertFalse(decision.should_modify_project)
        self.assertEqual(decision.playbook, "agent/playbooks/audit.md")

    def test_fix_contract_allows_minimal_project_change(self):
        decision = classify_instruction(
            "Analyse the code, identify the most critical security issues, and fix them."
        )
        self.assertEqual(decision.mode, "fix")
        self.assertTrue(decision.should_modify_project)
        self.assertEqual(decision.playbook, "agent/playbooks/fix.md")

    def test_forensics_contract_selects_implemented_playbook(self):
        decision = classify_instruction(
            "Review the incident logs and write /app/incident_report.txt."
        )
        self.assertEqual(decision.mode, "forensics")
        self.assertFalse(decision.should_modify_project)
        self.assertEqual(decision.playbook, "agent/playbooks/forensics.md")


if __name__ == "__main__":
    unittest.main()
