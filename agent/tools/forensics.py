#!/usr/bin/env python3
"""Inventory incident artifacts and correlate a confirmed export evidence chain."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


PROFILE_NAME = "confirmed-sensitive-export-v1"
REPORT_KEYS = (
    "attacker_ip",
    "compromised_user",
    "exfil_bytes",
    "first_malicious_event_utc",
)
ASCII_WHITESPACE = " \t\n\r\v\f"
IGNORED_PARTS = frozenset(
    {".git", "__pycache__", "solution", "solutions", "test", "tests"}
)
IGNORED_FILE_PREFIXES = ("expected", "solution", "verifier")
MAX_INVENTORY_FILES = 256
MAX_HASH_BYTES = 16 * 1024 * 1024

EDGE_REQUEST_ID_RE = re.compile(
    r"\brequest_id\s*=\s*(?P<request_id>.*?)\s+decision\s*=",
    re.IGNORECASE,
)
EDGE_DECISION_RE = re.compile(r"\bdecision\s*=\s*(?P<decision>\S+)", re.IGNORECASE)
PROXY_STATUS_SIZE_RE = re.compile(r'"\s+(?P<status>\d{3})\s+(?P<size>\d+)(?:\s|$)')
PROXY_REQUEST_ID_RE = re.compile(
    r"\brid\s*=\s*(?:\"(?P<quoted>[^\"]+)\"|(?P<plain>[^\s]+))",
    re.IGNORECASE,
)
PROXY_XFF_RE = re.compile(r'\bxff\s*=\s*"(?P<xff>[^\"]*)"', re.IGNORECASE)
PROXY_TIMESTAMP_RE = re.compile(r"\[(?P<timestamp>[^\]]+)\]")
AUTH_ACCEPTED_RE = re.compile(
    r"\bAccepted\s+\S+\s+for\s+(?P<user>\S+)\s+from\s+"
    r"(?P<ip>[0-9A-Fa-f:.]+)\b"
)

# Documentation networks deliberately remain attributable because anonymized
# security exercises commonly use them as external client addresses.
NON_CLIENT_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
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
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)


class ForensicsError(RuntimeError):
    """Raised when evidence cannot support one deterministic conclusion."""


@dataclass(frozen=True)
class EvidenceLocation:
    path: Path
    line: int


@dataclass(frozen=True)
class ArtifactSummary:
    path: str
    kind: str
    size_bytes: int
    sha256: str | None


@dataclass(frozen=True)
class ApplicationEvent:
    timestamp_raw: str
    timestamp: datetime
    request_id: str
    subject: str
    audit_bytes: int
    exfil_bytes: int
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


def is_ignored(path: Path, root: Path) -> bool:
    relative = path.relative_to(root)
    ignored_part = any(
        part in IGNORED_PARTS or part.startswith(".") for part in relative.parts
    )
    ignored_name = path.name.lower().startswith(IGNORED_FILE_PREFIXES)
    return ignored_part or ignored_name


def classify_artifact(path: Path) -> str:
    return {
        ".jsonl": "jsonl",
        ".json": "json",
        ".log": "log",
        ".txt": "text",
        ".csv": "csv",
    }.get(path.suffix.lower(), "binary-or-unknown")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def inventory_artifacts(
    target: Path | str,
    *,
    max_files: int = MAX_INVENTORY_FILES,
    max_hash_bytes: int = MAX_HASH_BYTES,
) -> list[ArtifactSummary]:
    root = Path(target).resolve()
    if not root.is_dir():
        raise ForensicsError(f"artifact directory does not exist: {root}")
    paths = [
        path
        for path in sorted(root.rglob("*"))
        if path.is_file() and not is_ignored(path, root)
    ]
    if len(paths) > max_files:
        raise ForensicsError(
            f"artifact inventory exceeds limit: {len(paths)} files > {max_files}"
        )
    summaries: list[ArtifactSummary] = []
    for path in paths:
        size = path.stat().st_size
        summaries.append(
            ArtifactSummary(
                path=path.relative_to(root).as_posix(),
                kind=classify_artifact(path),
                size_bytes=size,
                sha256=sha256_file(path) if size <= max_hash_bytes else None,
            )
        )
    return summaries


def inventory_digest(inventory: Iterable[ArtifactSummary]) -> str:
    digest = hashlib.sha256()
    for item in inventory:
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item.size_bytes).encode("ascii"))
        digest.update(b"\0")
        digest.update((item.sha256 or "unhashed").encode("ascii"))
        digest.update(b"\0")
    return digest.hexdigest()


def resolve_incident_directory(target: Path | str) -> Path:
    root = Path(target).resolve()
    if not root.is_dir():
        raise ForensicsError(f"forensics target does not exist: {root}")
    nested = root / "incident"
    if nested.is_dir():
        return nested
    return root


def load_sensitive_exports(incident_dir: Path) -> list[ApplicationEvent]:
    paths = sorted(path for path in incident_dir.glob("app*.jsonl") if path.is_file())
    if not paths:
        raise ForensicsError(f"no application JSONL files found under {incident_dir}")

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
                    # Containment copies may end with a partially written record.
                    continue
                if not isinstance(row, dict):
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
                if request_id and subject:
                    events.append(
                        ApplicationEvent(
                            timestamp_raw=timestamp_raw,
                            timestamp=timestamp,
                            request_id=request_id,
                            subject=subject,
                            audit_bytes=audit_bytes,
                            exfil_bytes=exfil_bytes,
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
                request_match = EDGE_REQUEST_ID_RE.search(line)
                decision_match = EDGE_DECISION_RE.search(line)
                if not request_match or not decision_match:
                    continue
                if decision_match.group("decision").upper() != "CONFIRM_SENSITIVE":
                    continue
                request_id = strip_ascii(request_match.group("request_id"))
                if request_id:
                    found.setdefault(request_id, []).append(
                        EvidenceLocation(path, line_number)
                    )
    return {key: tuple(value) for key, value in found.items()}


def choose_application_event(
    events: Iterable[ApplicationEvent],
    confirmations: dict[str, tuple[EvidenceLocation, ...]],
) -> ApplicationEvent:
    candidates = [event for event in events if event.request_id in confirmations]
    if not candidates:
        raise ForensicsError("no CONFIRM_SENSITIVE application export was found")
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


def is_non_client_address(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(
        address.version == network.version and address in network
        for network in NON_CLIENT_NETWORKS
    )


def xff_attributed_client(xff: str) -> str:
    hops: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    for segment in xff.split(","):
        candidate = strip_ascii(segment)
        try:
            hops.append(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    for address in reversed(hops):
        if not is_non_client_address(address):
            return str(address)
    raise ForensicsError(f"XFF has no attributable external IP hop: {xff!r}")


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
    paths = sorted(path for path in incident_dir.glob("proxy_access*.log") if path.is_file())
    if not paths:
        raise ForensicsError(f"no proxy access logs found under {incident_dir}")
    events: list[ProxyEvent] = []
    for path in paths:
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
            except ForensicsError:
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
        raise ForensicsError(
            f"no successful proxy request for rid={application_event.request_id!r}"
        )
    exact_size = [
        event for event in successful if event.response_bytes == application_event.audit_bytes
    ]
    candidates = exact_size or successful

    def rank(event: ProxyEvent) -> tuple[float, int, str]:
        distance = (
            float("inf")
            if event.timestamp is None
            else abs((event.timestamp - application_event.timestamp).total_seconds())
        )
        return distance, event.source.line, event.source.path.as_posix()

    return min(candidates, key=rank)


def find_auth_corroboration(
    incident_dir: Path, user: str, attacker_ip: str
) -> tuple[EvidenceLocation, ...]:
    matches: list[EvidenceLocation] = []
    for path in sorted(incident_dir.glob("auth*.log")):
        if not path.is_file():
            continue
        with path.open("r", encoding="utf-8-sig") as handle:
            for line_number, raw_line in enumerate(handle, 1):
                match = AUTH_ACCEPTED_RE.search(raw_line)
                if not match or match.group("user") != user:
                    continue
                try:
                    parsed_ip = str(ipaddress.ip_address(match.group("ip")))
                except ValueError:
                    continue
                if parsed_ip == attacker_ip:
                    matches.append(EvidenceLocation(path, line_number))
    return tuple(matches)


def analyze_incident(target: Path | str) -> IncidentConclusion:
    incident_dir = resolve_incident_directory(target)
    events = load_sensitive_exports(incident_dir)
    confirmations = load_edge_confirmations(incident_dir)
    application = choose_application_event(events, confirmations)
    proxy = choose_proxy_event(
        load_proxy_events(incident_dir, application.request_id), application
    )
    return IncidentConclusion(
        attacker_ip=proxy.attacker_ip,
        compromised_user=application.subject,
        exfil_bytes=application.exfil_bytes,
        first_malicious_event_utc=application.timestamp_raw,
        request_id=application.request_id,
        application_source=application.source,
        edge_sources=confirmations[application.request_id],
        proxy_source=proxy.source,
        proxy_xff=proxy.xff,
        audit_bytes=application.audit_bytes,
        auth_sources=find_auth_corroboration(
            incident_dir, application.subject, proxy.attacker_ip
        ),
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
    ipaddress.ip_address(values["attacker_ip"])
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


def relative_evidence(location: EvidenceLocation, incident_dir: Path) -> dict[str, Any]:
    # On Windows the same existing directory may arrive as either a long path
    # (``C:\\Users\\Name``) or an 8.3 alias (``C:\\Users\\NAME~1``). Resolving
    # both sides expands aliases before the lexical relative-path comparison.
    evidence_path = location.path.resolve()
    evidence_root = incident_dir.resolve()
    try:
        rendered_path = evidence_path.relative_to(evidence_root).as_posix()
    except ValueError:
        # Keep a useful trace for a deliberately external source instead of
        # failing the complete analysis while formatting diagnostic metadata.
        rendered_path = evidence_path.as_posix()
    return {
        "file": rendered_path,
        "line": location.line,
    }


def evidence_graph(
    conclusion: IncidentConclusion, incident_dir: Path
) -> dict[str, Any]:
    application_id = "application:selected-export"
    proxy_id = "proxy:matched-request"
    nodes: list[dict[str, Any]] = [
        {
            "id": application_id,
            "type": "application_event",
            "source": relative_evidence(conclusion.application_source, incident_dir),
            "request_id": conclusion.request_id,
            "subject": conclusion.compromised_user,
            "logical_bytes": conclusion.exfil_bytes,
        },
        {
            "id": proxy_id,
            "type": "proxy_event",
            "source": relative_evidence(conclusion.proxy_source, incident_dir),
            "request_id": conclusion.request_id,
            "attacker_ip": conclusion.attacker_ip,
            "xff": conclusion.proxy_xff,
        },
    ]
    edges: list[dict[str, str]] = [
        {"from": application_id, "to": proxy_id, "relation": "same_request_id"}
    ]
    for index, location in enumerate(conclusion.edge_sources, 1):
        node_id = f"edge:confirmation-{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "edge_confirmation",
                "source": relative_evidence(location, incident_dir),
                "request_id": conclusion.request_id,
            }
        )
        edges.append(
            {"from": node_id, "to": application_id, "relation": "confirms_export"}
        )
    for index, location in enumerate(conclusion.auth_sources, 1):
        node_id = f"auth:accepted-{index}"
        nodes.append(
            {
                "id": node_id,
                "type": "auth_event",
                "source": relative_evidence(location, incident_dir),
            }
        )
        edges.append(
            {"from": node_id, "to": proxy_id, "relation": "corroborates_user_and_ip"}
        )
    return {
        "profile": PROFILE_NAME,
        "selection_rule": (
            "largest confirmed sensitive export; latest application timestamp "
            "breaks equal-size ties"
        ),
        "nodes": nodes,
        "edges": edges,
        "report": report_values(conclusion),
    }


def ensure_output_outside_evidence(output: Path, incident_dir: Path) -> None:
    resolved_output = output.resolve()
    try:
        resolved_output.relative_to(incident_dir.resolve())
    except ValueError:
        return
    raise ForensicsError(f"refusing to write output inside evidence directory: {output}")


def write_utf8_lf(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def render_json(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    inventory = commands.add_parser("inventory", help="list bounded artifact metadata")
    inventory.add_argument("target", nargs="?", type=Path, default=Path("/app"))
    inventory.add_argument("--output", type=Path)

    analyze = commands.add_parser("analyze", help="correlate a supported incident bundle")
    analyze.add_argument("target", nargs="?", type=Path, default=Path("/app"))
    analyze.add_argument("--output", type=Path)
    analyze.add_argument("--trace", type=Path)

    validate = commands.add_parser("validate", help="validate a strict incident report")
    validate.add_argument("report", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inventory":
            root = Path(args.target).resolve()
            inventory = inventory_artifacts(root)
            payload = {
                "root": str(root),
                "files": [asdict(item) for item in inventory],
                "digest": inventory_digest(inventory),
            }
            rendered = render_json(payload)
            if args.output:
                ensure_output_outside_evidence(args.output, root)
                write_utf8_lf(args.output, rendered)
            else:
                print(rendered, end="")
            return 0

        if args.command == "validate":
            text = args.report.read_bytes().decode("utf-8")
            validate_report_text(text)
            print(f"forensics report is valid: {args.report}")
            return 0

        incident_dir = resolve_incident_directory(args.target)
        output = args.output or incident_dir.parent / "incident_report.txt"
        ensure_output_outside_evidence(output, incident_dir)
        if args.trace:
            ensure_output_outside_evidence(args.trace, incident_dir)
        before_inventory = inventory_artifacts(incident_dir)
        before_digest = inventory_digest(before_inventory)
        conclusion = analyze_incident(incident_dir)
        write_utf8_lf(output, format_report(conclusion))
        if args.trace:
            write_utf8_lf(args.trace, render_json(evidence_graph(conclusion, incident_dir)))
        after_digest = inventory_digest(inventory_artifacts(incident_dir))
        if after_digest != before_digest:
            raise ForensicsError("evidence changed during analysis")
        print(f"forensics report written: {output}")
        return 0
    except (ForensicsError, OSError, UnicodeError, ValueError) as error:
        print(f"forensics failed: {error}", file=sys.stderr)
        return 2 if args.command != "validate" else 1


if __name__ == "__main__":
    raise SystemExit(main())
