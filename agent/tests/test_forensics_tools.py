from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
FORENSICS = REPO_ROOT / "agent" / "tools" / "forensics.py"
sys.path.insert(0, str(REPO_ROOT))

from agent.tools.forensics import (  # noqa: E402
    ForensicsError,
    analyze_incident,
    evidence_graph,
    format_report,
    inventory_artifacts,
    inventory_digest,
    validate_report_text,
    xff_attributed_client,
)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def json_line(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"))


def app_event(
    *,
    timestamp: str,
    request_id: str,
    user: str,
    wire_bytes: int,
    logical_bytes: int | None,
    result: str = "ok",
) -> dict:
    audit = {
        "event": "sensitive_export",
        "bytes": wire_bytes,
        "result": result,
    }
    if logical_bytes is not None:
        audit["payload_logical_bytes"] = logical_bytes
    return {
        "ts": timestamp,
        "http": {"request_id": request_id, "method": "POST"},
        "identity": {"subject": user},
        "audit": audit,
    }


def build_fixture(
    root: Path,
    *,
    attacker_ip: str,
    user: str,
    exfil_bytes: int,
    timestamp: str,
    request_id: str,
    logical_bytes: bool = True,
) -> Path:
    incident = root / "incident"
    incident.mkdir(parents=True)
    wire_bytes = 19001 if logical_bytes else exfil_bytes
    earlier_id = f"earlier-{request_id}"
    primary = [
        {
            "ts": "2030-01-01T00:00:00.000Z",
            "http": {"request_id": "health"},
            "identity": {"subject": "monitor"},
            "audit": {"event": "request", "bytes": 10, "result": "ok"},
        },
        app_event(
            timestamp="2030-01-01T00:02:00.000Z",
            request_id=earlier_id,
            user="scheduled-worker",
            wire_bytes=7000,
            logical_bytes=max(1, exfil_bytes - 1),
        ),
        app_event(
            timestamp="2030-01-01T00:03:00.000Z",
            request_id="unconfirmed-large",
            user="decoy",
            wire_bytes=999999,
            logical_bytes=99999999,
        ),
    ]
    write_text(
        incident / "app.jsonl",
        "\n".join(json_line(row) for row in primary) + "\n{partial",
    )
    selected = app_event(
        timestamp=timestamp,
        request_id=request_id,
        user=user,
        wire_bytes=wire_bytes,
        logical_bytes=exfil_bytes if logical_bytes else None,
    )
    write_text(incident / "app_recovered_03.jsonl", json_line(selected) + "\n")
    write_text(
        incident / "edge_decisions.log",
        f"request_id={earlier_id} decision=CONFIRM_SENSITIVE rule=scheduled\n",
    )
    write_text(
        incident / "edge_decisions_shard_09.log",
        f"request_id= {request_id} decision=CONFIRM_SENSITIVE rule=dlp\n",
    )
    write_text(
        incident / "proxy_access_part_2.log",
        f'10.1.0.8 - {user} [02/Feb/2030:03:04:05 +0000] '
        f'"POST /export HTTP/1.1" 200 123 "-" "agent" '
        f'rid={request_id} xff="198.18.0.1, 10.1.0.8"\n'
        f'10.1.0.8 - {user} [02/Feb/2030:03:04:05 +0000] '
        f'"POST /export HTTP/1.1" 200 {wire_bytes} "-" "agent" '
        f'rid="{request_id}"\n'
        f'\txff="unknown, {attacker_ip}, 10.1.0.8"\n'
        f'10.1.0.8 - {user} [02/Feb/2030:03:04:05 +0000] '
        f'"POST /export HTTP/1.1" 304 0 "-" "agent" '
        f'rid={request_id} xff="{attacker_ip}, 10.1.0.8"\n',
    )
    write_text(
        incident / "auth_primary.log",
        f"Feb 2 host sshd[42]: Accepted publickey for {user} "
        f"from {attacker_ip} port 6000 ssh2\n",
    )
    write_text(incident / "collector_note.txt", "primary stream was truncated\n")
    return incident


class ArtifactInventoryTests(unittest.TestCase):
    def test_inventory_is_bounded_hashed_and_excludes_answer_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "incident" / "events.jsonl", "{}\n")
            write_text(root / "incident" / "proxy.log", "line\n")
            write_text(root / "tests" / "expected.txt", "secret expected value\n")
            write_text(root / "expected_direct.txt", "another expected value\n")
            write_text(root / "verifier_output.json", "{}\n")
            inventory = inventory_artifacts(root)
            self.assertEqual([item.path for item in inventory], [
                "incident/events.jsonl",
                "incident/proxy.log",
            ])
            self.assertEqual([item.kind for item in inventory], ["jsonl", "log"])
            self.assertTrue(all(item.sha256 for item in inventory))
            self.assertEqual(inventory_digest(inventory), inventory_digest(inventory))

    def test_inventory_rejects_unbounded_file_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            write_text(root / "one.log", "1\n")
            write_text(root / "two.log", "2\n")
            with self.assertRaises(ForensicsError):
                inventory_artifacts(root, max_files=1)


class IncidentCorrelationTests(unittest.TestCase):
    def test_values_are_derived_across_changed_bundles(self):
        cases = [
            ("203.0.113.91", "backup-agent", 543210, "2031-04-05T06:07:08.009Z", "exp-a9"),
            ("9.9.9.9", "release-user", 8800123, "2032-08-09T10:11:12.131Z", "trace-z77"),
        ]
        for attacker_ip, user, size, timestamp, request_id in cases:
            with self.subTest(request_id=request_id), tempfile.TemporaryDirectory() as tmp:
                incident = build_fixture(
                    Path(tmp),
                    attacker_ip=attacker_ip,
                    user=user,
                    exfil_bytes=size,
                    timestamp=timestamp,
                    request_id=request_id,
                )
                conclusion = analyze_incident(incident.parent)
                self.assertEqual(conclusion.attacker_ip, attacker_ip)
                self.assertEqual(conclusion.compromised_user, user)
                self.assertEqual(conclusion.exfil_bytes, size)
                self.assertEqual(conclusion.first_malicious_event_utc, timestamp)
                self.assertEqual(len(conclusion.edge_sources), 1)
                self.assertEqual(len(conclusion.auth_sources), 1)

    def test_wire_bytes_is_fallback_when_logical_size_is_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = build_fixture(
                Path(tmp),
                attacker_ip="8.8.8.8",
                user="api-runtime",
                exfil_bytes=321654,
                timestamp="2033-02-03T04:05:06.007Z",
                request_id="wire-only-6",
                logical_bytes=False,
            )
            self.assertEqual(analyze_incident(incident).exfil_bytes, 321654)

    def test_unconfirmed_export_does_not_become_a_conclusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = Path(tmp)
            write_text(
                incident / "app.jsonl",
                json_line(
                    app_event(
                        timestamp="2030-01-01T00:00:00.000Z",
                        request_id="not-confirmed",
                        user="some-user",
                        wire_bytes=100,
                        logical_bytes=200,
                    )
                )
                + "\n",
            )
            write_text(
                incident / "edge_decisions.log",
                "request_id=not-confirmed decision=WATCHLIST_ONLY\n",
            )
            with self.assertRaises(ForensicsError):
                analyze_incident(incident)

    def test_latest_timestamp_breaks_equal_size_tie(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = Path(tmp)
            earlier = app_event(
                timestamp="2038-01-01T01:00:00.000Z",
                request_id="tie-earlier",
                user="earlier-user",
                wire_bytes=500,
                logical_bytes=1000,
            )
            later = app_event(
                timestamp="2038-01-01T02:00:00.000Z",
                request_id="tie-later",
                user="later-user",
                wire_bytes=600,
                logical_bytes=1000,
            )
            write_text(
                incident / "app.jsonl",
                json_line(earlier) + "\n" + json_line(later) + "\n",
            )
            write_text(
                incident / "edge_decisions.log",
                "request_id=tie-earlier decision=CONFIRM_SENSITIVE\n"
                "request_id=tie-later decision=CONFIRM_SENSITIVE\n",
            )
            write_text(
                incident / "proxy_access.log",
                '10.0.0.2 - user [01/Jan/2038:02:00:00 +0000] '
                '"POST /export HTTP/1.1" 200 600 "-" "agent" '
                'rid=tie-later xff="203.0.113.101, 10.0.0.2"\n',
            )
            conclusion = analyze_incident(incident)
            self.assertEqual(conclusion.request_id, "tie-later")
            self.assertEqual(conclusion.compromised_user, "later-user")

    def test_xff_supports_ipv6_and_walks_from_proxy_side(self):
        self.assertEqual(
            xff_attributed_client("bad, 2001:4860:4860::8844, fd00::1"),
            "2001:4860:4860::8844",
        )

    def test_evidence_graph_connects_every_normative_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = build_fixture(
                Path(tmp),
                attacker_ip="1.1.1.1",
                user="incident-user",
                exfil_bytes=909090,
                timestamp="2034-03-04T05:06:07.008Z",
                request_id="graph-11",
            )
            conclusion = analyze_incident(incident)
            graph = evidence_graph(conclusion, incident)
            node_types = {node["type"] for node in graph["nodes"]}
            relations = {edge["relation"] for edge in graph["edges"]}
            self.assertEqual(
                node_types,
                {"application_event", "proxy_event", "edge_confirmation", "auth_event"},
            )
            self.assertEqual(
                relations,
                {"same_request_id", "confirms_export", "corroborates_user_and_ip"},
            )


class ForensicsContractTests(unittest.TestCase):
    VALID = (
        "attacker_ip=203.0.113.8\n"
        "compromised_user=service-user\n"
        "exfil_bytes=123456\n"
        "first_malicious_event_utc=2035-06-07T08:09:10.111Z\n"
    )

    def test_report_contract_accepts_only_canonical_machine_format(self):
        self.assertEqual(validate_report_text(self.VALID)["exfil_bytes"], "123456")
        invalid = [
            self.VALID + "comment=not-allowed\n",
            self.VALID.replace("attacker_ip=", "attacker_ip ="),
            self.VALID.replace("\n", "\r\n"),
            self.VALID.replace("exfil_bytes=123456", "exfil_bytes=-1"),
            self.VALID.replace(
                "attacker_ip=203.0.113.8\ncompromised_user=service-user",
                "compromised_user=service-user\nattacker_ip=203.0.113.8",
            ),
        ]
        for report in invalid:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report_text(report)

    def test_cli_analyzes_validates_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            incident = build_fixture(
                root,
                attacker_ip="208.67.222.222",
                user="cli-user",
                exfil_bytes=707070,
                timestamp="2036-07-08T09:10:11.012Z",
                request_id="cli-rid-70",
            )
            report = root / "incident_report.txt"
            trace = root / "evidence_trace.json"
            before = {
                item.path: item.sha256 for item in inventory_artifacts(incident)
            }
            process = subprocess.run(
                [
                    sys.executable,
                    str(FORENSICS),
                    "analyze",
                    str(root),
                    "--output",
                    str(report),
                    "--trace",
                    str(trace),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(
                report.read_text(encoding="utf-8"),
                "attacker_ip=208.67.222.222\n"
                "compromised_user=cli-user\n"
                "exfil_bytes=707070\n"
                "first_malicious_event_utc=2036-07-08T09:10:11.012Z\n",
            )
            self.assertEqual(
                {item.path: item.sha256 for item in inventory_artifacts(incident)},
                before,
            )
            trace_data = json.loads(trace.read_text(encoding="utf-8"))
            self.assertEqual(trace_data["profile"], "confirmed-sensitive-export-v1")
            self.assertEqual(trace_data["report"]["compromised_user"], "cli-user")

            validation = subprocess.run(
                [sys.executable, str(FORENSICS), "validate", str(report)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                validation.returncode, 0, validation.stdout + validation.stderr
            )

    def test_cli_refuses_to_write_into_evidence_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = build_fixture(
                Path(tmp),
                attacker_ip="4.2.2.2",
                user="read-only-user",
                exfil_bytes=112233,
                timestamp="2037-01-02T03:04:05.006Z",
                request_id="immutable-3",
            )
            forbidden = incident / "incident_report.txt"
            process = subprocess.run(
                [
                    sys.executable,
                    str(FORENSICS),
                    "analyze",
                    str(incident),
                    "--output",
                    str(forbidden),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(process.returncode, 2)
            self.assertIn("inside evidence directory", process.stderr)
            self.assertFalse(forbidden.exists())

    def test_cli_discovers_nested_incident_and_uses_default_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            incident = build_fixture(
                root,
                attacker_ip="8.26.56.26",
                user="default-output-user",
                exfil_bytes=456789,
                timestamp="2039-02-03T04:05:06.007Z",
                request_id="default-output-4",
            )
            inventory = subprocess.run(
                [sys.executable, str(FORENSICS), "inventory", str(incident)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(inventory.returncode, 0, inventory.stderr)
            inventory_data = json.loads(inventory.stdout)
            self.assertGreaterEqual(len(inventory_data["files"]), 6)

            analysis = subprocess.run(
                [sys.executable, str(FORENSICS), "analyze", str(root)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(analysis.returncode, 0, analysis.stdout + analysis.stderr)
            report = root / "incident_report.txt"
            self.assertTrue(report.is_file())
            self.assertEqual(
                validate_report_text(report.read_text(encoding="utf-8"))[
                    "compromised_user"
                ],
                "default-output-user",
            )


if __name__ == "__main__":
    unittest.main()
