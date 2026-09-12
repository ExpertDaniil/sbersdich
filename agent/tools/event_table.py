"""Bounded JSONL observations with explicit clock correction, no answer inference."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be ISO-8601 text with a timezone")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp needs an explicit timezone")
    return parsed.astimezone(timezone.utc)


def event_table(raw: bytes, *, time_field: str, clock_offset_seconds: int = 0,
                offset_start: str | None = None, offset_end: str | None = None,
                start_line: int = 1, max_rows: int = 50) -> dict:
    if not isinstance(time_field, str) or not time_field or len(time_field) > 100:
        raise ValueError("time_field must be a field name")
    if type(clock_offset_seconds) is not int or abs(clock_offset_seconds) > 86400:
        raise ValueError("clock_offset_seconds must be an integer within one day")
    if type(start_line) is not int or start_line < 1:
        raise ValueError("start_line must be a positive integer")
    if type(max_rows) is not int or not 1 <= max_rows <= 100:
        raise ValueError("max_rows must be 1..100")
    if (offset_start is None) != (offset_end is None):
        raise ValueError("provide both offset_start and offset_end, or neither")
    start = _timestamp(offset_start) if offset_start is not None else None
    end = _timestamp(offset_end) if offset_end is not None else None
    if start is not None and end < start:
        raise ValueError("clock interval ends before it starts")
    if len(raw) > 512 * 1024:
        raise ValueError("JSONL source exceeds 512 KiB")
    lines = raw.decode("utf-8").splitlines()
    rows = []
    rendered_size = 0
    last_line = start_line - 1
    for lineno, line in enumerate(lines[start_line - 1:], start_line):
        if not line.strip():
            last_line = lineno
            continue
        if len(rows) >= max_rows:
            break
        try:
            event = json.loads(line)
            if not isinstance(event, dict):
                raise ValueError("event must be a JSON object")
            observed = _timestamp(event.get(time_field))
            offset = clock_offset_seconds if start is None or start <= observed <= end else 0
            utc = observed - timedelta(seconds=offset)
        except (ValueError, TypeError, OverflowError) as error:
            raise ValueError(f"source line {lineno}: {error}") from error
        row = {"source_line": lineno, "event": event,
               "utc": utc.isoformat().replace("+00:00", "Z"),
               "offset_applied_seconds": offset}
        row_size = len(json.dumps(row, ensure_ascii=False))
        if rendered_size + row_size > 8000:
            if not rows:
                raise ValueError("single event exceeds 8000-character observation limit")
            break
        rows.append(row)
        rendered_size += row_size
        last_line = lineno
    return {"rows": rows, "start_line": start_line, "end_line": last_line,
            "total_lines": len(lines), "truncated": last_line < len(lines),
            "clock_rule": "UTC = recorded timestamp - clock_offset_seconds; interval uses recorded timestamps",
            "clock_offset_seconds": clock_offset_seconds,
            "offset_start": offset_start, "offset_end": offset_end}
