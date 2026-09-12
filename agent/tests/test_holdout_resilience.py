"""Distribution-shift regressions derived from failure classes, not task answers."""

from __future__ import annotations

import base64
import codecs
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from agent.core.contracts import build_task_contract
from agent.core.models import AgentAction, TaskContract
from agent.core.playbooks import load_validation_playbook
from agent.core.tools import SecurityToolRegistry
from agent.scaffold.aci import CyberACIProvider
from agent.scaffold.contracts import CapabilityLevel, ExecutionContext, PlanningContext
from agent.scaffold.planner import LazyLocalModelPlanner
from agent.scaffold.contracts import VerificationContext
from agent.scaffold.verifier import LegacyTaskVerifier
from agent.strategies import classify_instruction
from agent.tools.audit_signals import scan_audit_signals
from agent.tools.ctf import transform_ctf_data
from agent.tools.dns_exfil import correlate_dns_exfil
from agent.tools.fix_guard import scan_fix_requirements
from agent.validators import capture_snapshot, validate_artifact


class RoutingDistributionTests(unittest.TestCase):
    def test_imperative_security_paraphrases_do_not_fall_into_general(self) -> None:
        cases = {
            "Fix mass assignment while preserving authorization.": "fix",
            "Fix NoSQL operator injection and run pytest.": "fix",
            "Harden webhook signature verification without changing tests.": "fix",
            "Secure reset token storage and preserve the API.": "fix",
            "Investigate possible DNS exfiltration; deduplicate queries and correlate the host.": "forensics",
            "Correlate network events with inventory and reconstruct the timeline.": "forensics",
            "Find patch files in the repository.": "general",
            "Audit the handler and do not patch the code.": "audit",
            "Perform a security audit. Trace untrusted network input to the sink, include evidence, and do not change source.": "audit",
        }
        for instruction, expected in cases.items():
            with self.subTest(instruction=instruction):
                self.assertEqual(classify_instruction(instruction).mode, expected)


class InstructionNativeSchemaTests(unittest.TestCase):
    INSTRUCTION = (
        "Audit the service. Write `/app/reports/result.json` as JSON with exactly one "
        "top-level key `findings`. `findings` must be a non-empty array. Every item "
        "must contain exactly `id`, `title`, `severity`, `cwe`, `file`, `line`, "
        "`evidence`, `impact`, and `remediation`. Use lowercase `critical`, `high`, "
        "`medium`, or `low` for severity, canonical `CWE-NNN`, an `/app`-relative "
        "source path, and a positive integer source line. Do not change source."
    )

    def test_declared_item_schema_overrides_generic_report_schema(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contract = build_task_contract(
                classify_instruction(self.INSTRUCTION), self.INSTRUCTION, root
            )
            rule = contract.artifacts[0]
            self.assertEqual(rule.required_keys, ("findings",))
            self.assertEqual(rule.array_item_key, "findings")
            self.assertEqual(
                rule.item_required_keys,
                ("id", "title", "severity", "cwe", "file", "line", "evidence", "impact", "remediation"),
            )
            rule.path.parent.mkdir(parents=True)
            payload = {
                "findings": [{
                    "id": "R-1",
                    "title": "Concrete issue",
                    "severity": "high",
                    "cwe": "CWE-79",
                    "file": "src/handler.py",
                    "line": 8,
                    "evidence": "source reaches sink",
                    "impact": "security boundary crossed",
                    "remediation": "separate untrusted data",
                }]
            }
            rule.path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertTrue(validate_artifact(rule).passed)

            payload["findings"][0]["category"] = "generic-field-must-not-be-added"
            rule.path.write_text(json.dumps(payload), encoding="utf-8")
            rejected = validate_artifact(rule)
            self.assertFalse(rejected.passed)
            self.assertIn("extra=['category']", rejected.detail)

    def test_declared_types_enums_and_formats_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rule = build_task_contract(
                classify_instruction(self.INSTRUCTION), self.INSTRUCTION, root
            ).artifacts[0]
            rule.path.parent.mkdir(parents=True)
            base = {
                "id": "R-2", "title": "Issue", "severity": "high", "cwe": "CWE-89",
                "file": "src/query.py", "line": 3, "evidence": "flow", "impact": "impact",
                "remediation": "fix",
            }
            for field, invalid in (("line", "3"), ("severity", "HIGH"), ("cwe", "89"), ("file", "/etc/passwd")):
                with self.subTest(field=field):
                    candidate = dict(base)
                    candidate[field] = invalid
                    rule.path.write_text(json.dumps({"findings": [candidate]}), encoding="utf-8")
                    self.assertFalse(validate_artifact(rule).passed)

    def test_planner_receives_only_instruction_native_schema(self) -> None:
        class StubClient:
            def __init__(self) -> None:
                self.messages = None

            def complete(self, messages, **_kwargs):
                self.messages = messages
                return '{"rationale":"stop","name":"abort","arguments":{}}'

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decision = classify_instruction(self.INSTRUCTION)
            contract = build_task_contract(decision, self.INSTRUCTION, root)
            planner = LazyLocalModelPlanner()
            client = StubClient()
            planner._client = client  # type: ignore[assignment]
            planner.next_plan(PlanningContext(
                instruction=self.INSTRUCTION,
                workdir=root,
                decision=decision,
                task_playbook="",
                validation_playbook=load_validation_playbook(),
                contract=contract,
                tools=(),
                state_snapshot={},
                events=(),
                last_validation=None,
                remaining_seconds=30,
            ))
            state = json.loads(client.messages[1]["content"])
        schema = state["artifact_rules"][0]["schema"]
        self.assertEqual(schema["source"], "task_instruction")
        self.assertIn("cwe", schema["item_fields"])
        self.assertIn("line", schema["field_types"])
        self.assertNotIn("category", schema["item_fields"])
        validation_guidance = load_validation_playbook()
        self.assertIn("Планировщик не должен", validation_guidance)
        self.assertNotIn("snapshot /app --output", validation_guidance)


class StaticSecurityLeadTests(unittest.TestCase):
    def test_non_sql_audit_leads_cover_distinct_data_flows(self) -> None:
        source = '''
from lxml import etree
import logging
import requests
logger = logging.getLogger(__name__)

def bind(client, identity, password):
    query = f"(&(uid={identity})(userPassword={password}))"
    try:
        return client.search(query)
    except TimeoutError:
        return True

def oauth(state, host):
    if state != "desktop":
        raise ValueError
    if not host.endswith("trusted.example"):
        raise ValueError

def parse(raw):
    parser = etree.XMLParser(resolve_entities=True, load_dtd=True, no_network=False)
    root = etree.fromstring(raw, parser)
    callback = root.findtext("notify")
    requests.post(callback)

async def upload(path, upload_secret):
    checked = path.resolve()
    logger.info("secret=%s", upload_secret)
    await checkpoint()
    path.open("wb")
'''.lstrip()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "surface.py").write_text(source, encoding="utf-8")
            categories = {
                lead["category"] for lead in scan_audit_signals(root)["leads"]
            }
        self.assertEqual(
            categories,
            {
                "ldap-filter-interpolation",
                "authentication-fail-open",
                "static-oauth-state",
                "domain-suffix-allowlist-bypass",
                "unsafe-xml-external-entities",
                "untrusted-network-destination",
                "secret-in-log",
                "path-check-use-race",
            },
        )


class FixPropertyGuardTests(unittest.TestCase):
    def _issues(self, source: str, requirement: str) -> list[dict[str, object]]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "subject.py").write_text(source, encoding="utf-8")
            return scan_fix_requirements(root, (requirement,))

    def test_guards_reject_known_unsafe_shapes(self) -> None:
        cases = (
            (
                "path-containment",
                "from pathlib import Path\nROOT=Path('/srv/docs')\ndef read(name):\n p=(ROOT/name).resolve()\n if not str(p).startswith(str(ROOT.resolve())): raise ValueError\n return p.read_text()\n",
            ),
            (
                "no-plaintext-token-storage",
                "TOKENS={}\ndef issue(token, user):\n TOKENS[token]=(user, 1)\n",
            ),
            (
                "reject-structured-credentials",
                "def login(db, username, password):\n if not isinstance(password, str): return None\n return db.find_one({'username': username, 'password': password})\n",
            ),
            (
                "mass-assignment",
                "def update(profile, payload):\n profile.update(payload)\n return profile\n",
            ),
        )
        for requirement, source in cases:
            with self.subTest(requirement=requirement):
                self.assertTrue(self._issues(source, requirement))

    def test_fix_requirements_are_extracted_from_properties_not_task_names(self) -> None:
        cases = (
            (
                "Fix directory traversal including sibling-prefix confusion. Run pytest.",
                ("path-containment",),
            ),
            (
                "Repair recovery tokens: they must not be stored in plaintext.",
                ("no-plaintext-token-storage",),
            ),
            (
                "Fix Mongo operator injection; structured credential objects must be rejected.",
                ("reject-structured-credentials",),
            ),
            (
                "Harden webhook HMAC signature validation.",
                ("webhook-hmac",),
            ),
            (
                "Fix over-posting mass assignment while preserving authorization.",
                ("mass-assignment",),
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for instruction, expected in cases:
                with self.subTest(instruction=instruction):
                    contract = build_task_contract(
                        classify_instruction(instruction), instruction, root
                    )
                    self.assertEqual(contract.security_requirements, expected)

    def test_guards_accept_property_preserving_shapes(self) -> None:
        safe_sources = (
            (
                "path-containment",
                "from pathlib import Path\nROOT=Path('/srv/docs')\ndef read(name):\n p=(ROOT/name).resolve()\n p.relative_to(ROOT.resolve())\n return p.read_text()\n",
            ),
            (
                "no-plaintext-token-storage",
                "TOKENS={}\ndef issue(token, user):\n token_digest=sha256(token.encode()).hexdigest()\n TOKENS[token_digest]=(user, 1)\n",
            ),
            (
                "reject-structured-credentials",
                "def login(db, username, password):\n if not isinstance(password, str): raise TypeError('plain string required')\n return db.find_one({'username': username, 'password': password})\n",
            ),
            (
                "mass-assignment",
                "def update(profile, payload):\n allowed={'name','zone'}\n if not payload.keys() <= allowed: raise ValueError\n profile.update(payload)\n return profile\n",
            ),
        )
        for requirement, source in safe_sources:
            with self.subTest(requirement=requirement):
                self.assertEqual(self._issues(source, requirement), [])

    def test_final_verifier_blocks_an_unsafe_non_sql_patch(self) -> None:
        instruction = (
            "Fix directory traversal and sibling-prefix confusion without changing tests."
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "reader.py"
            source.write_text(
                "from pathlib import Path\nROOT=Path('/srv/files')\n"
                "def read(name):\n return (ROOT/name).read_text()\n",
                encoding="utf-8",
            )
            decision = classify_instruction(instruction)
            contract = build_task_contract(decision, instruction, root)
            baseline = capture_snapshot(root)
            source.write_text(
                "from pathlib import Path\nROOT=Path('/srv/files')\n"
                "def read(name):\n p=(ROOT/name).resolve()\n"
                " if not str(p).startswith(str(ROOT.resolve())): raise ValueError\n"
                " return p.read_text()\n",
                encoding="utf-8",
            )
            result = LegacyTaskVerifier().verify(
                VerificationContext(root, decision, contract, baseline, (), 10)
            )
        self.assertFalse(result.passed)
        self.assertIn("sibling-prefix", result.reason)

    def test_checked_edit_rejects_unsafe_property_before_write(self) -> None:
        original = (
            "from pathlib import Path\nROOT=Path('/srv/files')\n"
            "def read(name):\n return (ROOT/name).read_text()\n"
        )
        unsafe = (
            "def read(name):\n p=(ROOT/name).resolve()\n"
            " if not str(p).startswith(str(ROOT.resolve())): raise ValueError\n"
            " return p.read_text()"
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "reader.py"
            source.write_text(original, encoding="utf-8")
            decision = classify_instruction(
                "Fix directory traversal and sibling-prefix confusion."
            )
            context = ExecutionContext(
                root,
                decision,
                CapabilityLevel.MUTATE,
                security_requirements=("path-containment",),
            )
            result = CyberACIProvider(root).execute(
                AgentAction("checked_edit", {
                    "path": "reader.py",
                    "start_line": 3,
                    "end_line": 4,
                    "replacement": unsafe,
                    "expected_sha256": hashlib.sha256(original.encode()).hexdigest(),
                }),
                context,
            )
            self.assertFalse(result.ok)
            self.assertEqual(result.data["guard"], "instruction-security-properties")
            self.assertEqual(source.read_text(encoding="utf-8"), original)


class CompositionalDataflowTests(unittest.TestCase):
    @staticmethod
    def _xor(raw: bytes, key: bytes) -> bytes:
        return bytes(value ^ key[index % len(key)] for index, value in enumerate(raw))

    def test_complete_file_jwt_json_chain_never_copies_encoded_blob(self) -> None:
        expected = "CTF{structured_handle_chain}"
        key = b"violet"
        blob = base64.urlsafe_b64encode(self._xor(expected.encode(), key)).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"blob": blob}).encode()).rstrip(b"=").decode()
        token = "ignored." + payload + ".decoy"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "token.txt").write_text(token, encoding="utf-8")
            result = SecurityToolRegistry(root).execute(
                AgentAction("ctf_transform", {
                    "path": "token.txt",
                    "steps": [
                        {"operation": "split", "separator": ".", "index": 1},
                        {"operation": "base64url"},
                        {"operation": "json_get", "path": "blob"},
                        {"operation": "base64url"},
                        {"operation": "xor", "key_text": key.decode()},
                    ],
                }),
                classify_instruction("Recover the CTF flag"),
            )
        self.assertTrue(result.ok, result.summary)
        self.assertEqual(result.data["text"], expected)

    def test_manifest_ordered_batch_transforms_each_part_before_concat(self) -> None:
        expected = "SBER{ordered_decoded_parts}"
        chunks = (expected[:8], expected[8:17], expected[17:])
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            paths: list[str] = []
            for index, chunk in enumerate(chunks):
                path = f"piece-{index}.dat"
                encoded = base64.b64encode(codecs.encode(chunk, "rot_13").encode()).decode()
                (root / path).write_text(encoded, encoding="utf-8")
                paths.append(path)
            result = SecurityToolRegistry(root).execute(
                AgentAction("ctf_batch_transform", {
                    "paths": paths,
                    "steps": [{"operation": "base64"}, {"operation": "rot13"}],
                }),
                classify_instruction("Recover the CTF flag"),
            )
        self.assertTrue(result.ok, result.summary)
        self.assertEqual(result.data["text"], expected)
        self.assertEqual(result.data["flag_candidates"], [expected])

    def test_control_bytes_are_not_flag_candidates(self) -> None:
        raw = b"SBER{looks-valid\x01but-is-not}"
        result = transform_ctf_data(raw.hex(), [{"operation": "hex"}])
        self.assertEqual(result["flag_candidates"], [])


class DnsCorrelationTests(unittest.TestCase):
    def test_dns_pipeline_deduplicates_orders_decodes_and_correlates(self) -> None:
        decoded = b"archive.dat"
        encoded = base64.b32encode(decoded).decode().rstrip("=")
        chunks = (encoded[:7], encoded[7:14], encoded[14:])
        resolver = (
            f"2027-01-01T00:00:03Z client=192.0.2.4 q=03.{chunks[2]}.leak.invalid type=A\n"
            f"2027-01-01T00:00:01Z client=192.0.2.4 q=01.{chunks[0]}.leak.invalid type=A\n"
            f"2027-01-01T00:00:02Z client=192.0.2.4 q=02.{chunks[1]}.leak.invalid type=A\n"
            f"2027-01-01T00:00:04Z client=192.0.2.4 q=02.{chunks[1]}.leak.invalid type=A\n"
        ).encode()
        inventory = b"ip,host,owner\n192.0.2.4,lab-client,ops\n"
        processes = b'{"ts":"2027-01-01T00:00:00Z","src":"192.0.2.4","process":"shell"}\n'
        result = correlate_dns_exfil(
            resolver_raw=resolver,
            inventory_raw=inventory,
            process_raw=processes,
            domain="leak.invalid",
        )
        self.assertEqual(result["host"], "lab-client")
        self.assertEqual(result["process"], "shell")
        self.assertEqual(result["exfil_bytes"], len(decoded))
        self.assertEqual(result["deduplicated_retry_count"], 1)
        self.assertEqual(result["first_query_utc"], "2027-01-01T00:00:01Z")


class PlannerRepairTests(unittest.TestCase):
    def test_malformed_action_gets_one_compact_structural_repair(self) -> None:
        class StubClient:
            def __init__(self) -> None:
                self.responses = iter((
                    '{"rationale":"done","name":"finish","arguments":',
                    '{"rationale":"done","name":"finish","arguments":{}}',
                ))
                self.calls = 0

            def complete(self, *_args, **_kwargs):
                self.calls += 1
                return next(self.responses)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            decision = classify_instruction("Inspect the repository")
            planner = LazyLocalModelPlanner()
            client = StubClient()
            planner._client = client  # type: ignore[assignment]
            plan = planner.next_plan(PlanningContext(
                instruction="Inspect the repository",
                workdir=root,
                decision=decision,
                task_playbook="",
                validation_playbook="",
                contract=TaskContract(),
                tools=(),
                state_snapshot={},
                events=(),
                last_validation=None,
                remaining_seconds=30,
            ))
        self.assertEqual(plan.action.name, "finish")
        self.assertEqual(client.calls, 2)


if __name__ == "__main__":
    unittest.main()
