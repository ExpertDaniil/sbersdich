"""Read-only record carving from an explicit magic and integer header schema."""
from __future__ import annotations

import hashlib
import re
import struct


def carve_records(raw: bytes, *, magic_hex: str, header_format: str | None = None,
                  length_field: int, max_records: int = 32,
                  field_sizes: list[int] | None = None, byte_order: str = "big") -> dict:
    """Locate candidate records; never infer a target kind or decoding order.

    header_format describes bytes immediately after magic. Payload starts after
    this header, with length in the zero-based field selected by the caller.
    All offsets are absolute in raw. Invalid/truncated candidates are reported.
    """
    if field_sizes is not None:
        if header_format is not None:
            raise ValueError("choose field_sizes OR header_format, not both")
        if (not isinstance(field_sizes, list) or not 1 <= len(field_sizes) <= 16
                or any(type(size) is not int or size not in {1, 2, 4, 8} for size in field_sizes)):
            raise ValueError("field_sizes must contain 1..16 widths of 1, 2, 4 or 8 bytes")
        if byte_order not in {"big", "little"}:
            raise ValueError("byte_order must be big or little")
        codes = {1: "B", 2: "H", 4: "I", 8: "Q"}
        header_format = (">" if byte_order == "big" else "<") + "".join(codes[size] for size in field_sizes)
    if len(raw) > 512 * 1024:
        raise ValueError("binary source exceeds 512 KiB")
    if not isinstance(magic_hex, str) or len(magic_hex) > 192:
        raise ValueError("magic_hex must encode 1..64 bytes")
    magic = bytes.fromhex(magic_hex)
    if not 1 <= len(magic) <= 64:
        raise ValueError("magic_hex must encode 1..64 bytes")
    if not isinstance(header_format, str) or not re.fullmatch(r"[<>!][bBhHiIqQ]{1,16}", header_format):
        raise ValueError("header_format needs explicit endian <, > or ! and 1..16 integer fields, e.g. >BH")
    if type(length_field) is not int or not 0 <= length_field < len(header_format) - 1:
        raise ValueError("length_field must index a header integer")
    if type(max_records) is not int or not 1 <= max_records <= 64:
        raise ValueError("max_records must be 1..64")
    header = struct.Struct(header_format)
    layout = [{"field": i, "width_bytes": struct.calcsize(header_format[0] + code)}
              for i, code in enumerate(header_format[1:])]
    records = []
    cursor = 0
    while len(records) < max_records:
        offset = raw.find(magic, cursor)
        if offset < 0:
            break
        cursor = offset + 1  # report all candidates, including overlapping signatures
        payload_offset = offset + len(magic) + header.size
        entry = {"record_offset": offset, "payload_offset": payload_offset}
        if payload_offset > len(raw):
            entry.update(valid=False, error="truncated header")
        else:
            fields = list(header.unpack_from(raw, offset + len(magic)))
            length = fields[length_field]
            entry.update(header_values=fields, payload_length=length,
                         available_payload_bytes=len(raw) - payload_offset)
            if length < 0 or payload_offset + length > len(raw):
                entry.update(valid=False, error="invalid length or truncated payload")
            else:
                entry.update(valid=True, payload_end=payload_offset + length,
                             payload_sha256=hashlib.sha256(raw[payload_offset:payload_offset + length]).hexdigest())
        records.append(entry)
    valid_count = sum(record["valid"] for record in records)
    return {"header_format": header_format, "header_bytes_after_magic": header.size,
            "layout": layout, "valid_count": valid_count,
            "records": records, "count": len(records), "total_bytes": len(raw),
            "input_sha256": hashlib.sha256(raw).hexdigest(),
            "truncated": raw.find(magic, cursor) >= 0}
