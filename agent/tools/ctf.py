#!/usr/bin/env python3
"""Bounded, deterministic transforms for common offline CTF artifacts."""

from __future__ import annotations

import argparse
import base64
import binascii
import codecs
import gzip
import hashlib
import io
import json
import re
import sys
import zlib
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import unquote_to_bytes


MAX_INPUT_CHARS = 32_768
MAX_TRANSFORM_BYTES = 4_096
MAX_TRANSFORM_STEPS = 8
MAX_XOR_KEY_BYTES = 256
MAX_PREVIEW_CHARS = 512
SUPPORTED_OPERATIONS = frozenset(
    {
        "base32",
        "base64",
        "base64url",
        "gzip",
        "hex",
        "reverse",
        "reverse_bytes",
        "rot13",
        "url",
        "xor",
        "zlib",
    }
)
FLAG_RE = re.compile(
    r"(?i)(?:flag|ctf|sber)[{][^{}\r\n]{1,256}[}]"
)
INVALID_PERCENT_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class CtfTransformError(RuntimeError):
    """Raised when a requested transform is malformed, unsafe or too large."""


def _compact_ascii(data: bytes, operation: str) -> bytes:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise CtfTransformError(f"{operation} input must be ASCII text") from error
    return "".join(text.split()).encode("ascii")


def _bounded(data: bytes, operation: str) -> bytes:
    if len(data) > MAX_TRANSFORM_BYTES:
        raise CtfTransformError(
            f"{operation} output exceeds {MAX_TRANSFORM_BYTES} bytes"
        )
    return data


def _decode_base64(data: bytes, *, urlsafe: bool) -> bytes:
    compact = _compact_ascii(data, "base64url" if urlsafe else "base64")
    if not compact:
        raise CtfTransformError("base64 input must not be empty")
    if urlsafe:
        if not re.fullmatch(rb"[A-Za-z0-9_-]*={0,2}", compact):
            raise CtfTransformError("base64url input contains invalid characters")
        unpadded = compact.rstrip(b"=")
        if len(unpadded) % 4 == 1:
            raise CtfTransformError("base64url input has invalid length")
        padded = unpadded + b"=" * (-len(unpadded) % 4)
        if b"=" in compact and compact != padded:
            raise CtfTransformError("base64url input has non-canonical padding")
        try:
            return base64.b64decode(padded, altchars=b"-_", validate=True)
        except binascii.Error as error:
            raise CtfTransformError("invalid base64url input") from error
    try:
        return base64.b64decode(compact, validate=True)
    except binascii.Error as error:
        raise CtfTransformError("invalid base64 input") from error


def _decode_base32(data: bytes) -> bytes:
    compact = _compact_ascii(data, "base32")
    if not compact:
        raise CtfTransformError("base32 input must not be empty")
    unpadded = compact.rstrip(b"=")
    if len(unpadded) % 8 in {1, 3, 6}:
        raise CtfTransformError("base32 input has invalid length")
    padded = unpadded + b"=" * (-len(unpadded) % 8)
    if b"=" in compact and compact != padded:
        raise CtfTransformError("base32 input has non-canonical padding")
    try:
        return base64.b32decode(padded, casefold=True)
    except binascii.Error as error:
        raise CtfTransformError("invalid base32 input") from error


def _decode_hex(data: bytes) -> bytes:
    compact = _compact_ascii(data, "hex")
    if compact.lower().startswith(b"0x"):
        compact = compact[2:]
    if not compact or len(compact) % 2:
        raise CtfTransformError("hex input must contain complete bytes")
    try:
        return bytes.fromhex(compact.decode("ascii"))
    except ValueError as error:
        raise CtfTransformError("invalid hexadecimal input") from error


def _decode_url(data: bytes) -> bytes:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise CtfTransformError("url input must be ASCII text") from error
    if INVALID_PERCENT_RE.search(text):
        raise CtfTransformError("url input contains an invalid percent escape")
    return unquote_to_bytes(text.replace("+", " "))


def _text_transform(data: bytes, operation: str) -> bytes:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CtfTransformError(f"{operation} input must be valid UTF-8") from error
    if operation == "rot13":
        return codecs.decode(text, "rot_13").encode("utf-8")
    return text[::-1].encode("utf-8")


def _xor_key(step: Mapping[str, object]) -> bytes:
    allowed = {"operation", "key_text", "key_hex"}
    unknown = sorted(set(step) - allowed)
    if unknown:
        raise CtfTransformError(f"xor has unsupported fields: {unknown}")
    has_text = "key_text" in step
    has_hex = "key_hex" in step
    if has_text == has_hex:
        raise CtfTransformError("xor requires exactly one of key_text or key_hex")
    raw_key = step["key_text"] if has_text else step["key_hex"]
    if not isinstance(raw_key, str) or not raw_key:
        raise CtfTransformError("xor key must be non-empty text")
    if has_text:
        key = raw_key.encode("utf-8")
    else:
        try:
            key = bytes.fromhex("".join(raw_key.split()))
        except ValueError as error:
            raise CtfTransformError("xor key_hex is invalid") from error
    if not key or len(key) > MAX_XOR_KEY_BYTES:
        raise CtfTransformError(
            f"xor key must contain 1..{MAX_XOR_KEY_BYTES} bytes"
        )
    return key


def _xor(data: bytes, step: Mapping[str, object]) -> bytes:
    key = _xor_key(step)
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _gzip_decompress(data: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as archive:
            decoded = archive.read(MAX_TRANSFORM_BYTES + 1)
    except (EOFError, OSError, zlib.error) as error:
        raise CtfTransformError("invalid gzip stream") from error
    return _bounded(decoded, "gzip")


def _zlib_decompress(data: bytes) -> bytes:
    decoder = zlib.decompressobj()
    try:
        decoded = decoder.decompress(data, MAX_TRANSFORM_BYTES + 1)
    except zlib.error as error:
        raise CtfTransformError("invalid zlib stream") from error
    if len(decoded) > MAX_TRANSFORM_BYTES or decoder.unconsumed_tail:
        raise CtfTransformError(
            f"zlib output exceeds {MAX_TRANSFORM_BYTES} bytes"
        )
    if not decoder.eof:
        raise CtfTransformError("incomplete zlib stream")
    if decoder.unused_data:
        raise CtfTransformError("zlib stream contains trailing data")
    try:
        decoded += decoder.flush()
    except zlib.error as error:
        raise CtfTransformError("invalid zlib stream") from error
    return _bounded(decoded, "zlib")


def _parse_steps(steps: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(steps, list) or not 1 <= len(steps) <= MAX_TRANSFORM_STEPS:
        raise CtfTransformError(
            f"steps must be an array of 1..{MAX_TRANSFORM_STEPS} objects"
        )
    parsed: list[Mapping[str, object]] = []
    for index, raw_step in enumerate(steps):
        if not isinstance(raw_step, dict):
            raise CtfTransformError(f"step {index} must be an object")
        operation = raw_step.get("operation")
        if not isinstance(operation, str) or operation not in SUPPORTED_OPERATIONS:
            raise CtfTransformError(f"step {index} has unsupported operation")
        if operation != "xor" and set(raw_step) != {"operation"}:
            raise CtfTransformError(
                f"{operation} step accepts only the operation field"
            )
        parsed.append(raw_step)
    return tuple(parsed)


def transform_ctf_data(value: object, steps: object) -> dict[str, Any]:
    """Apply an explicit bounded transform chain and return safe observations."""

    if not isinstance(value, str) or not value or "\x00" in value:
        raise CtfTransformError("value must be non-empty text without NUL")
    if len(value) > MAX_INPUT_CHARS:
        raise CtfTransformError(f"value exceeds {MAX_INPUT_CHARS} characters")
    return transform_ctf_bytes(value.encode("utf-8"), steps)


def transform_ctf_bytes(data: bytes, steps: object) -> dict[str, Any]:
    """Transform exact runtime bytes; never route binary input through model text."""

    if not isinstance(data, bytes) or not data or len(data) > MAX_INPUT_CHARS:
        raise CtfTransformError("input must be bounded non-empty bytes")
    parsed_steps = _parse_steps(steps)
    input_size = len(data)
    input_sha256 = hashlib.sha256(data).hexdigest()

    applied: list[str] = []
    for step in parsed_steps:
        operation = str(step["operation"])
        if operation == "base64":
            data = _decode_base64(data, urlsafe=False)
        elif operation == "base64url":
            data = _decode_base64(data, urlsafe=True)
        elif operation == "base32":
            data = _decode_base32(data)
        elif operation == "hex":
            data = _decode_hex(data)
        elif operation == "url":
            data = _decode_url(data)
        elif operation in {"rot13", "reverse"}:
            data = _text_transform(data, operation)
        elif operation == "reverse_bytes":
            data = data[::-1]
        elif operation == "xor":
            data = _xor(data, step)
        elif operation == "gzip":
            data = _gzip_decompress(data)
        elif operation == "zlib":
            data = _zlib_decompress(data)
        data = _bounded(data, operation)
        applied.append(operation)

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    candidates = list(dict.fromkeys(FLAG_RE.findall(text or "")))
    ascii_preview = "".join(
        chr(byte) if 32 <= byte <= 126 else "." for byte in data[:MAX_PREVIEW_CHARS]
    )
    return {
        "input_size_bytes": input_size,
        "input_sha256": input_sha256,
        "operations": applied,
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text": text,
        "hex": data.hex(),
        "ascii_preview": ascii_preview,
        "flag_candidates": candidates,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("value", help="textual transform input")
    parser.add_argument(
        "--steps-json",
        required=True,
        help='JSON array such as [{"operation":"base64"}]',
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        steps = json.loads(args.steps_json)
        result = transform_ctf_data(args.value, steps)
    except (json.JSONDecodeError, CtfTransformError) as error:
        print(f"CTF transform failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
