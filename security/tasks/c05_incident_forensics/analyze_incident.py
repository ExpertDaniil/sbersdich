#!/usr/bin/env python3
"""Correlate incident logs and write the strict four-line incident report."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


REPORT_KEYS = (
    "attacker_ip",
    "compromised_user",
    "exfil_bytes",
    "first_malicious_event_utc",
)

ASCII_WHITESPACE = " \t\n\r\v\f"
EDGE_REQUEST_ID_RE = re.compile(
    r"\brequest_id\s*=\s*(?P<request_id>.*?)\s+decision\s*=",
    re.IGNORECASE,
)
EDGE_DECISION_RE = re.compile(r"\bdecision\s*=\s*(?P<decision>\S+)", re.IGNORECASE)
PROXY_STATUS_SIZE_RE = re.compile(
    r'"\s+(?P<status>\d{3})\s+(?P<size>\d+)(?:\s|$)'
)
PROXY_REQUEST_ID_RE = re.compile(
    r"\brid\s*=\s*(?:\"(?P<quoted>[^\"]+)\"|(?P<plain>[^\s]+))",
    re.IGNORECASE,
)
PROXY_XFF_RE = re.compile(r'\bxff\s*=\s*"(?P<xff>[^\"]*)"', re.IGNORECASE)
PROXY_TIMESTAMP_RE = re.compile(r"\[(?P<timestamp>[^\]]+)\]")
AUTH_ACCEPTED_RE = re.compile(
    r"\bAccepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b"
)

# XFF is traversed from the trusted proxy side (right to left). These ranges are
# infrastructure/non-client ranges. Documentation ranges intentionally remain
# eligible because the public task uses them as anonymized external addresses.
NON_CLIENT_NETWORKS = tuple(
    ipaddress.IPv4Network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


class AnalysisError(RuntimeError):
    """Raised when the evidence cannot support one deterministic conclusion."""


@dataclass(frozen=True)
class EvidenceLocation:
    path: Path
    line: int


@dataclass(frozen=True)
class ApplicationEvent:
    timestamp_raw: str
    timestamp: datetime
    request_id: str
    subject: str
    audit_bytes: int
    exfil_bytes: int
    transport: str | None
    source: EvidenceLocation


@dataclass(frozen=True)
class ProxyEvent:
    timestamp_raw: str | None
    timestamp: datetime | None
    request_id: str
    status: int
    response_bytes: int
    xff: str
    attacker_ip: str
    source: EvidenceLocation


@dataclass(frozen=True)
class IncidentConclusion:
    attacker_ip: str
    compromised_user: str
    exfil_bytes: int
    first_malicious_event_utc: str
    request_id: str
    application_source: EvidenceLocation
    edge_sources: tuple[EvidenceLocation, ...]
    proxy_source: EvidenceLocation
    proxy_xff: str
    audit_bytes: int
    auth_sources: tuple[EvidenceLocation, ...]


def strip_ascii(value: str) -> str:
    return value.strip(ASCII_WHITESPACE)


def parse_iso_timestamp(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp has no timezone: {value!r}")
    return parsed


def nonnegative_int(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    parsed = int(value)
    if parsed < 0:
        raise ValueError(f"{field} must not be negative")
    return parsed


def load_sensitive_exports(incident_dir: Path) -> list[ApplicationEvent]:
    paths = sorted(path for path in incident_dir.glob("app*.jsonl") if path.is_file())
    if not paths:
        raise AnalysisError(f"no application JSONL files found under {incident_dir}")

    events: list[ApplicationEvent] = []
    for path in paths:
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                line = strip_ascii(raw_line)
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    # A containment copy may end with an incomplete JSON record.
                    continue

                audit = row.get("audit")
                http = row.get("http")
                identity = row.get("identity")
                if not all(isinstance(part, dict) for part in (audit, http, identity)):
                    continue
                if audit.get("event") != "sensitive_export":
                    continue
                if str(audit.get("result", "ok")).lower() in {
                    "blocked",
                    "denied",
                    "error",
                    "failed",
                    "failure",
                    "rejected",
                }:
                    continue

                try:
                    timestamp_raw = str(row["ts"])
                    timestamp = parse_iso_timestamp(timestamp_raw)
                    request_id = strip_ascii(str(http["request_id"]))
                    subject = strip_ascii(str(identity["subject"]))
                    audit_bytes = nonnegative_int(audit["bytes"], "audit.bytes")
                    exfil_bytes = nonnegative_int(
                        audit.get("payload_logical_bytes", audit_bytes),
                        "audit.payload_logical_bytes",
                    )
                except (KeyError, TypeError, ValueError):
                    continue

                if not request_id or not subject:
                    continue
                transport_value = audit.get("transport")
                transport = str(transport_value) if transport_value is not None else None
                events.append(
                    ApplicationEvent(
                        timestamp_raw=timestamp_raw,
                        timestamp=timestamp,
                        request_id=request_id,
                        subject=subject,
                        audit_bytes=audit_bytes,
                        exfil_bytes=exfil_bytes,
                        transport=transport,
                        source=EvidenceLocation(path, line_number),
                    )
                )
    return events


def load_edge_confirmations(
    incident_dir: Path,
) -> dict[str, tuple[EvidenceLocation, ...]]:
    found: dict[str, list[EvidenceLocation]] = {}
    for path in sorted(incident_dir.glob("edge_decisions*.log")):
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                line = strip_ascii(raw_line)
                if not line or line.startswith("#"):
                    continue
                decision_match = EDGE_DECISION_RE.search(line)
                request_match = EDGE_REQUEST_ID_RE.search(line)
                if not decision_match or not request_match:
                    continue
                if decision_match.group("decision").upper() != "CONFIRM_SENSITIVE":
                    continue
                request_id = strip_ascii(request_match.group("request_id"))
                if request_id:
                    found.setdefault(request_id, []).append(
                        EvidenceLocation(path, line_number)
                    )
    return {request_id: tuple(locations) for request_id, locations in found.items()}


def choose_application_event(
    events: Iterable[ApplicationEvent],
    confirmations: dict[str, tuple[EvidenceLocation, ...]],
) -> ApplicationEvent:
    candidates = [event for event in events if event.request_id in confirmations]
    if not candidates:
        raise AnalysisError("no CONFIRM_SENSITIVE application export was found")

    # Primary exfiltration is the largest confirmed logical payload. A later
    # application timestamp deterministically resolves equal-size replay records.
    return max(
        candidates,
        key=lambda event: (event.exfil_bytes, event.timestamp, event.request_id),
    )


def merge_proxy_lines(path: Path) -> list[tuple[int, str]]:
    records: list[tuple[int, str]] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            line = raw_line.rstrip("\r\n")
            if not line or line.startswith("#"):
                continue
            if line[:1].isspace() and records:
                first_line, previous = records[-1]
                records[-1] = (first_line, f"{previous} {strip_ascii(line)}")
            else:
                records.append((line_number, line))
    return records


def xff_attributed_client(xff: str) -> str:
    valid_hops: list[ipaddress.IPv4Address] = []
    for segment in xff.split(","):
        candidate = strip_ascii(segment)
        try:
            valid_hops.append(ipaddress.IPv4Address(candidate))
        except ipaddress.AddressValueError:
            continue

    for address in reversed(valid_hops):
        if not any(address in network for network in NON_CLIENT_NETWORKS):
            return str(address)
    raise AnalysisError(f"XFF has no attributable external IPv4 hop: {xff!r}")


def parse_proxy_timestamp(logical_line: str) -> tuple[str | None, datetime | None]:
    match = PROXY_TIMESTAMP_RE.search(logical_line)
    if not match:
        return None, None
    raw = match.group("timestamp")
    try:
        return raw, datetime.strptime(raw, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return raw, None


def load_proxy_events(incident_dir: Path, request_id: str) -> list[ProxyEvent]:
    path = incident_dir / "proxy_access.log"
    if not path.is_file():
        raise AnalysisError(f"missing proxy log: {path}")

    events: list[ProxyEvent] = []
    for line_number, logical_line in merge_proxy_lines(path):
        request_match = PROXY_REQUEST_ID_RE.search(logical_line)
        status_match = PROXY_STATUS_SIZE_RE.search(logical_line)
        xff_match = PROXY_XFF_RE.search(logical_line)
        if not request_match or not status_match or not xff_match:
            continue
        parsed_request_id = strip_ascii(
            request_match.group("quoted") or request_match.group("plain") or ""
        )
        if parsed_request_id != request_id:
            continue
        try:
            attacker_ip = xff_attributed_client(xff_match.group("xff"))
        except AnalysisError:
            continue
        timestamp_raw, timestamp = parse_proxy_timestamp(logical_line)
        events.append(
            ProxyEvent(
                timestamp_raw=timestamp_raw,
                timestamp=timestamp,
                request_id=parsed_request_id,
                status=int(status_match.group("status")),
                response_bytes=int(status_match.group("size")),
                xff=xff_match.group("xff"),
                attacker_ip=attacker_ip,
                source=EvidenceLocation(path, line_number),
            )
        )
    return events


def choose_proxy_event(
    events: Iterable[ProxyEvent], application_event: ApplicationEvent
) -> ProxyEvent:
    successful = [event for event in events if 200 <= event.status < 300]
    if not successful:
        raise AnalysisError(
            f"no successful proxy request with rid={application_event.request_id!r} and XFF"
        )

    exact_size = [
        event for event in successful if event.response_bytes == application_event.audit_bytes
    ]
    candidates = exact_size or successful

    def rank(event: ProxyEvent) -> tuple[float, int]:
        if event.timestamp is None:
            distance = float("inf")
        else:
            distance = abs((event.timestamp - application_event.timestamp).total_seconds())
        return distance, event.source.line

    return min(candidates, key=rank)


def find_auth_corroboration(
    incident_dir: Path, user: str, attacker_ip: str
) -> tuple[EvidenceLocation, ...]:
    path = incident_dir / "auth.log"
    if not path.is_file():
        return ()
    matches: list[EvidenceLocation] = []
    with path.open("r", encoding="utf-8-sig") as handle:
        for line_number, raw_line in enumerate(handle, 1):
            match = AUTH_ACCEPTED_RE.search(raw_line)
            if match and match.group("user") == user and match.group("ip") == attacker_ip:
                matches.append(EvidenceLocation(path, line_number))
    return tuple(matches)


def analyze_incident(incident_dir: Path | str) -> IncidentConclusion:
    directory = Path(incident_dir).resolve()
    if not directory.is_dir():
        raise AnalysisError(f"incident directory does not exist: {directory}")

    events = load_sensitive_exports(directory)
    confirmations = load_edge_confirmations(directory)
    winner = choose_application_event(events, confirmations)
    proxy = choose_proxy_event(load_proxy_events(directory, winner.request_id), winner)
    auth_sources = find_auth_corroboration(directory, winner.subject, proxy.attacker_ip)

    return IncidentConclusion(
        attacker_ip=proxy.attacker_ip,
        compromised_user=winner.subject,
        exfil_bytes=winner.exfil_bytes,
        first_malicious_event_utc=winner.timestamp_raw,
        request_id=winner.request_id,
        application_source=winner.source,
        edge_sources=confirmations[winner.request_id],
        proxy_source=proxy.source,
        proxy_xff=proxy.xff,
        audit_bytes=winner.audit_bytes,
        auth_sources=auth_sources,
    )


def report_values(conclusion: IncidentConclusion) -> dict[str, str]:
    return {
        "attacker_ip": conclusion.attacker_ip,
        "compromised_user": conclusion.compromised_user,
        "exfil_bytes": str(conclusion.exfil_bytes),
        "first_malicious_event_utc": conclusion.first_malicious_event_utc,
    }


def validate_report_text(text: str) -> dict[str, str]:
    if "\r" in text:
        raise ValueError("report must use LF line endings")
    lines = text.splitlines()
    if len(lines) != 4 or any(not line for line in lines):
        raise ValueError("report must contain exactly four non-empty lines")

    values: dict[str, str] = {}
    keys: list[str] = []
    for line in lines:
        if line.count("=") != 1:
            raise ValueError(f"invalid key=value line: {line!r}")
        key, value = line.split("=", 1)
        if key != strip_ascii(key) or value != strip_ascii(value):
            raise ValueError("spaces around keys or values are forbidden")
        if key in values:
            raise ValueError(f"duplicate key: {key}")
        keys.append(key)
        values[key] = value

    if tuple(keys) != REPORT_KEYS:
        raise ValueError(f"keys must appear once in canonical order: {REPORT_KEYS}")
    ipaddress.IPv4Address(values["attacker_ip"])
    if not values["compromised_user"]:
        raise ValueError("compromised_user must not be empty")
    if not values["exfil_bytes"].isdigit():
        raise ValueError("exfil_bytes must be an unsigned decimal integer")
    if not values["first_malicious_event_utc"].endswith("Z"):
        raise ValueError("first_malicious_event_utc must be UTC with a Z suffix")
    parse_iso_timestamp(values["first_malicious_event_utc"])
    return values


def format_report(conclusion: IncidentConclusion) -> str:
    values = report_values(conclusion)
    text = "\n".join(f"{key}={values[key]}" for key in REPORT_KEYS) + "\n"
    validate_report_text(text)
    return text


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def relative_evidence(location: EvidenceLocation, incident_dir: Path) -> dict[str, Any]:
    try:
        path = location.path.relative_to(incident_dir)
    except ValueError:
        path = location.path
    return {"file": str(path), "line": location.line}


def trace_payload(
    conclusion: IncidentConclusion, incident_dir: Path
) -> dict[str, Any]:
    return {
        "selection_rule": (
            "largest CONFIRM_SENSITIVE sensitive_export; latest application timestamp "
            "breaks equal-size ties"
        ),
        "request_id": conclusion.request_id,
        "fields": {
            "attacker_ip": {
                "value": conclusion.attacker_ip,
                "source": relative_evidence(conclusion.proxy_source, incident_dir),
                "xff": conclusion.proxy_xff,
                "rule": "rightmost valid non-infrastructure IPv4 hop",
            },
            "compromised_user": {
                "value": conclusion.compromised_user,
                "source": relative_evidence(conclusion.application_source, incident_dir),
                "json_path": "identity.subject",
            },
            "exfil_bytes": {
                "value": conclusion.exfil_bytes,
                "source": relative_evidence(conclusion.application_source, incident_dir),
                "json_path": "audit.payload_logical_bytes or audit.bytes",
                "transport_bytes": conclusion.audit_bytes,
            },
            "first_malicious_event_utc": {
                "value": conclusion.first_malicious_event_utc,
                "source": relative_evidence(conclusion.application_source, incident_dir),
                "json_path": "ts",
                "copied_verbatim": True,
            },
        },
        "edge_confirmations": [
            relative_evidence(location, incident_dir)
            for location in conclusion.edge_sources
        ],
        "auth_corroboration": [
            relative_evidence(location, incident_dir)
            for location in conclusion.auth_sources
        ],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "incident_dir",
        nargs="?",
        type=Path,
        default=Path("/app/incident"),
        help="directory containing the incident artifacts (default: /app/incident)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="report path (default: INCIDENT_DIR/../incident_report.txt)",
    )
    parser.add_argument(
        "--trace",
        type=Path,
        help="optional JSON evidence trace for development; not part of the deliverable",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    incident_dir = args.incident_dir.resolve()
    output = args.output or incident_dir.parent / "incident_report.txt"
    try:
        conclusion = analyze_incident(incident_dir)
        write_utf8_lf(output, format_report(conclusion))
        if args.trace:
            trace = json.dumps(
                trace_payload(conclusion, incident_dir),
                ensure_ascii=False,
                indent=2,
            ) + "\n"
            write_utf8_lf(args.trace, trace)
    except (AnalysisError, OSError, ValueError) as error:
        print(f"C-05 analysis failed: {error}", file=sys.stderr)
        return 2

    print(f"C-05 report written: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
