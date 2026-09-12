"""Deterministic correlation for sequenced DNS exfiltration evidence."""

from __future__ import annotations

import base64
import binascii
import csv
import hashlib
import io
import json
import re
from datetime import datetime
from typing import Any


MAX_DNS_ROWS = 10_000
RESOLVER_RE = re.compile(
    r"^(?P<ts>\S+)\s+.*?\bclient=(?P<client>\S+)\s+.*?\bq=(?P<query>\S+)",
    re.IGNORECASE,
)


class DnsExfilError(RuntimeError):
    pass


def _utf8(raw: bytes, label: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise DnsExfilError(f"{label} must be UTF-8 text") from error


def _iso8601(value: str) -> datetime:
    rendered = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(rendered)
    except ValueError as error:
        raise DnsExfilError(f"invalid timestamp {value!r}") from error
    if parsed.tzinfo is None:
        raise DnsExfilError(f"timestamp lacks timezone: {value!r}")
    return parsed


def _base32_once(value: str) -> bytes:
    compact = "".join(value.split()).upper()
    if not compact or re.fullmatch(r"[A-Z2-7]+", compact) is None:
        raise DnsExfilError("sequenced payload is not unpadded Base32")
    padded = compact + "=" * (-len(compact) % 8)
    try:
        return base64.b32decode(padded, casefold=True)
    except binascii.Error as error:
        raise DnsExfilError("sequenced payload is invalid Base32") from error


def correlate_dns_exfil(
    *,
    resolver_raw: bytes,
    inventory_raw: bytes,
    process_raw: bytes,
    domain: str,
    client: str | None = None,
) -> dict[str, Any]:
    """Deduplicate, order, decode and correlate one explicit DNS domain."""

    if not isinstance(domain, str):
        raise DnsExfilError("domain must be text")
    if client is not None and (not isinstance(client, str) or not client):
        raise DnsExfilError("client must be non-empty text when provided")
    normalized_domain = domain.strip().strip(".").casefold()
    if not normalized_domain or "." not in normalized_domain:
        raise DnsExfilError("domain must be a concrete multi-label DNS name")
    domain_labels = normalized_domain.split(".")
    grouped: dict[str, dict[int, tuple[str, str]]] = {}
    seen: set[tuple[str, str]] = set()
    matched_rows = 0
    for line_number, line in enumerate(_utf8(resolver_raw, "resolver log").splitlines(), 1):
        if line_number > MAX_DNS_ROWS:
            raise DnsExfilError("resolver log exceeds row limit")
        match = RESOLVER_RE.search(line)
        if not match:
            continue
        query = match.group("query").rstrip(".")
        labels = query.split(".")
        if len(labels) < len(domain_labels) + 2 or [part.casefold() for part in labels[-len(domain_labels):]] != domain_labels:
            continue
        row_client = match.group("client")
        if client is not None and row_client != client:
            continue
        sequence_raw, chunk = labels[0], labels[1]
        if not sequence_raw.isdecimal() or not chunk:
            continue
        matched_rows += 1
        dedupe_key = (row_client, query.casefold())
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        sequence = int(sequence_raw)
        current = grouped.setdefault(row_client, {}).get(sequence)
        value = (chunk, match.group("ts"))
        if current is not None and current[0].casefold() != chunk.casefold():
            raise DnsExfilError(
                f"client {row_client} has conflicting chunks for sequence {sequence}"
            )
        grouped[row_client][sequence] = value

    if not grouped:
        raise DnsExfilError("no sequenced queries matched the selected domain/client")
    if len(grouped) != 1:
        raise DnsExfilError(
            "multiple clients matched the domain; pass the evidence-supported client explicitly: "
            + ", ".join(sorted(grouped))
        )
    selected_client, chunks = next(iter(grouped.items()))
    sequences = sorted(chunks)
    if sequences != list(range(sequences[0], sequences[-1] + 1)) or sequences[0] != 1:
        raise DnsExfilError(f"sequence is incomplete or does not start at 1: {sequences}")
    encoded = "".join(chunks[index][0] for index in sequences)
    decoded = _base32_once(encoded)
    first_query = min((chunks[index][1] for index in sequences), key=_iso8601)
    first_query_time = _iso8601(first_query)

    inventory_text = _utf8(inventory_raw, "inventory")
    try:
        inventory_rows = list(csv.DictReader(io.StringIO(inventory_text)))
    except csv.Error as error:
        raise DnsExfilError("inventory is not valid CSV") from error
    hosts = {
        str(row.get("host", "")).strip()
        for row in inventory_rows
        if str(row.get("ip", "")).strip() == selected_client
        and str(row.get("host", "")).strip()
    }
    if len(hosts) != 1:
        raise DnsExfilError(
            f"inventory must map client {selected_client} to exactly one host"
        )
    host = next(iter(hosts))

    process_events: list[tuple[datetime, str]] = []
    for line_number, line in enumerate(_utf8(process_raw, "process events").splitlines(), 1):
        if line_number > MAX_DNS_ROWS:
            raise DnsExfilError("process event file exceeds row limit")
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise DnsExfilError(f"process event line {line_number} is invalid JSON") from error
        if not isinstance(row, dict) or row.get("src") != selected_client:
            continue
        timestamp = row.get("ts")
        process = row.get("process")
        if isinstance(timestamp, str) and isinstance(process, str) and process:
            parsed = _iso8601(timestamp)
            if parsed <= first_query_time:
                process_events.append((parsed, process))
    if not process_events:
        raise DnsExfilError(
            f"no process event for client {selected_client} at or before first query"
        )
    process_events.sort(key=lambda item: item[0])
    process = process_events[-1][1]

    return {
        "domain": normalized_domain,
        "client": selected_client,
        "host": host,
        "process": process,
        "exfil_bytes": len(decoded),
        "first_query_utc": first_query_time.isoformat().replace("+00:00", "Z"),
        "sequence_numbers": sequences,
        "unique_query_count": len(sequences),
        "deduplicated_retry_count": matched_rows - len(sequences),
        "encoded_length": len(encoded),
        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
        "decoded_text_preview": decoded.decode("utf-8", errors="replace")[:256],
    }
