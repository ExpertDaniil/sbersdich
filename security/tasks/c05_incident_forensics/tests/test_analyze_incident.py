from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parents[1]
ANALYZER = PACKAGE_DIR / "analyze_incident.py"
VALIDATOR = PACKAGE_DIR / "validate_report.py"
sys.path.insert(0, str(PACKAGE_DIR))

from analyze_incident import (  # noqa: E402
    AnalysisError,
    analyze_incident,
    format_report,
    validate_report_text,
)


def json_line(payload: dict) -> str:
    return json.dumps(payload, separators=(",", ":"))


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def app_event(
    *,
    timestamp: str,
    request_id: str,
    user: str,
    audit_bytes: int,
    logical_bytes: int | None,
) -> dict:
    audit = {
        "event": "sensitive_export",
        "bytes": audit_bytes,
        "transport": "gzip+protobuf",
        "result": "ok",
    }
    if logical_bytes is not None:
        audit["payload_logical_bytes"] = logical_bytes
    return {
        "ts": timestamp,
        "http": {
            "request_id": request_id,
            "path": "/api/v1/telemetry/batch",
            "method": "POST",
        },
        "identity": {"subject": user, "realm": "corp"},
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
    shard_name: str,
    use_logical_bytes: bool = True,
) -> Path:
    incident = root / "incident"
    incident.mkdir()
    wire_bytes = 18432 if use_logical_bytes else exfil_bytes
    earlier_request = f"earlier-{request_id}"

    base_rows = [
        {
            "ts": "2026-05-01T12:00:00.000Z",
            "http": {"request_id": "noise", "path": "/health", "method": "GET"},
            "identity": {"subject": "healthcheck", "realm": "infra"},
            "audit": {"event": "request", "bytes": 32, "result": "ok"},
        },
        app_event(
            timestamp="2026-05-01T14:03:42.500Z",
            request_id=earlier_request,
            user="decoy-service",
            audit_bytes=512000,
            logical_bytes=exfil_bytes,
        ),
        app_event(
            timestamp="2026-05-01T15:05:01.000Z",
            request_id="unconfirmed-huge-export",
            user="decoy-user",
            audit_bytes=9999999,
            logical_bytes=9999999,
        ),
    ]
    write_text(
        incident / "app.jsonl",
        "\n".join(json_line(row) for row in base_rows) + "\n{truncated",
    )
    selected = app_event(
        timestamp=timestamp,
        request_id=request_id,
        user=user,
        audit_bytes=wire_bytes,
        logical_bytes=exfil_bytes if use_logical_bytes else None,
    )
    write_text(incident / "app_audit_recovered.jsonl", json_line(selected) + "\n")

    write_text(
        incident / "edge_decisions.log",
        "# primary shard\n"
        f"2026-05-01T10:03:42.500-04:00 request_id={earlier_request} "
        "decision=CONFIRM_SENSITIVE rule=scheduled\n",
    )
    write_text(
        incident / shard_name,
        "# late shard\n"
        f"2026-05-01T10:03:44.900-04:00 request_id= {request_id} "
        "decision=CONFIRM_SENSITIVE rule=replay\n",
    )

    proxy = (
        "# tz=UTC\n"
        f'10.0.0.5 - {user} [01/May/2026:14:03:44 +0000] '
        f'"POST /api/v1/telemetry/batch HTTP/1.1" 200 5001 "-" "curl" '
        f'rid={request_id} xff="10.0.0.3, 192.0.2.9, 10.0.0.5"\n'
        f'10.0.0.5 - {user} [01/May/2026:14:03:44 +0000] '
        f'"POST /api/v1/telemetry/batch HTTP/1.1" 200 {wire_bytes} "-" "python" '
        f'rid={request_id}\n'
        f'\txff=" 198.51.100.1 , unknown , {attacker_ip} , 10.0.0.5 "\n'
        f'10.0.0.5 - {user} [01/May/2026:14:03:44 +0000] '
        f'"POST /api/v1/telemetry/batch HTTP/1.1" 304 0 "-" "python" '
        f'rid={request_id} xff="198.51.100.1, {attacker_ip}, 10.0.0.5"\n'
    )
    write_text(incident / "proxy_access.log", proxy)
    write_text(
        incident / "auth.log",
        f"May  1 10:03:40 prod sshd[1008]: Accepted password for {user} "
        f"from {attacker_ip} port 5555 ssh2\n",
    )
    write_text(incident / "dns_ptr_hints.txt", "# non-authoritative\n")
    return incident


class IncidentAnalyzerTests(unittest.TestCase):
    def test_values_are_derived_across_variations(self):
        cases = [
            {
                "attacker_ip": "203.0.113.50",
                "user": "deploysvc",
                "exfil_bytes": 2457600,
                "timestamp": "2026-05-01T14:03:44.900Z",
                "request_id": "telemetry-lolt-441",
                "shard_name": "edge_decisions_fragment.log",
            },
            {
                "attacker_ip": "8.8.4.4",
                "user": "release-bot",
                "exfil_bytes": 7654321,
                "timestamp": "2027-07-08T09:10:11.123456Z",
                "request_id": "changed-rid-992",
                "shard_name": "edge_decisions_shard_17.log",
            },
        ]
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                incident = build_fixture(Path(tmp), **case)
                conclusion = analyze_incident(incident)
                self.assertEqual(conclusion.attacker_ip, case["attacker_ip"])
                self.assertEqual(conclusion.compromised_user, case["user"])
                self.assertEqual(conclusion.exfil_bytes, case["exfil_bytes"])
                self.assertEqual(
                    conclusion.first_malicious_event_utc, case["timestamp"]
                )
                self.assertEqual(len(conclusion.auth_sources), 1)

    def test_audit_bytes_is_used_when_logical_size_is_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = build_fixture(
                Path(tmp),
                attacker_ip="9.9.9.9",
                user="api-worker",
                exfil_bytes=987654,
                timestamp="2028-01-02T03:04:05.006Z",
                request_id="plain-export-7",
                shard_name="edge_decisions_02.log",
                use_logical_bytes=False,
            )
            conclusion = analyze_incident(incident)
            self.assertEqual(conclusion.exfil_bytes, 987654)
            self.assertIn("exfil_bytes=987654\n", format_report(conclusion))

    def test_cli_writes_report_and_trace_outside_incident_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            case = {
                "attacker_ip": "203.0.113.77",
                "user": "ops-user",
                "exfil_bytes": 424242,
                "timestamp": "2026-06-02T11:22:33.444Z",
                "request_id": "ops-export-404",
                "shard_name": "edge_decisions_fragment.log",
            }
            incident = build_fixture(root, **case)
            report = root / "incident_report.txt"
            trace = root / "trace.json"
            process = subprocess.run(
                [
                    sys.executable,
                    str(ANALYZER),
                    str(incident),
                    "--output",
                    str(report),
                    "--trace",
                    str(trace),
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=15,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
            self.assertEqual(
                report.read_text(encoding="utf-8"),
                "attacker_ip=203.0.113.77\n"
                "compromised_user=ops-user\n"
                "exfil_bytes=424242\n"
                "first_malicious_event_utc=2026-06-02T11:22:33.444Z\n",
            )
            trace_payload = json.loads(trace.read_text(encoding="utf-8"))
            self.assertEqual(trace_payload["request_id"], "ops-export-404")
            self.assertEqual(
                trace_payload["fields"]["attacker_ip"]["source"]["file"],
                "proxy_access.log",
            )

    def test_unconfirmed_export_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            incident = Path(tmp) / "incident"
            incident.mkdir()
            event = app_event(
                timestamp="2026-05-01T14:03:44.900Z",
                request_id="not-confirmed",
                user="user",
                audit_bytes=100,
                logical_bytes=200,
            )
            write_text(incident / "app.jsonl", json_line(event) + "\n")
            write_text(
                incident / "edge_decisions.log",
                "request_id=not-confirmed decision=WATCHLIST_ONLY rule=x\n",
            )
            with self.assertRaises(AnalysisError):
                analyze_incident(incident)


class ReportValidatorTests(unittest.TestCase):
    VALID_REPORT = (
        "attacker_ip=203.0.113.50\n"
        "compromised_user=deploysvc\n"
        "exfil_bytes=2457600\n"
        "first_malicious_event_utc=2026-05-01T14:03:44.900Z\n"
    )

    def test_valid_report_is_accepted(self):
        values = validate_report_text(self.VALID_REPORT)
        self.assertEqual(values["exfil_bytes"], "2457600")

    def test_format_mutations_are_rejected(self):
        invalid_reports = [
            self.VALID_REPORT + "comment=forbidden\n",
            self.VALID_REPORT.replace("attacker_ip=", "attacker_ip ="),
            self.VALID_REPORT.replace("\ncompromised_user", "\r\ncompromised_user"),
            self.VALID_REPORT.replace("exfil_bytes=2457600", "exfil_bytes=-1"),
            self.VALID_REPORT.replace(
                "attacker_ip=203.0.113.50\ncompromised_user=deploysvc",
                "compromised_user=deploysvc\nattacker_ip=203.0.113.50",
            ),
        ]
        for report in invalid_reports:
            with self.subTest(report=report), self.assertRaises(ValueError):
                validate_report_text(report)

    def test_validator_cli_rejects_crlf(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.txt"
            report.write_bytes(self.VALID_REPORT.replace("\n", "\r\n").encode())
            process = subprocess.run(
                [sys.executable, str(VALIDATOR), str(report)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
            )
            self.assertEqual(process.returncode, 1)
            self.assertIn("LF line endings", process.stderr)


if __name__ == "__main__":
    unittest.main()
