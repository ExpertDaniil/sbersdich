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
        "json_get",
        "reverse",
        "reverse_bytes",
        "rot13",
        "split",
        "strip",
        "url",
        "xor",
        "zlib",
    }
)
FLAG_RE = re.compile(
    r"(?i)(?:flag|ctf|sber)[{][^{}\x00-\x1f\x7f-\x9f\r\n]{1,256}[}]"
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
    if operation == "strip":
        return text.strip().encode("utf-8")
    return text[::-1].encode("utf-8")


def _split(data: bytes, step: Mapping[str, object]) -> bytes:
    if set(step) != {"operation", "separator", "index"}:
        raise CtfTransformError("split requires exactly operation, separator and index")
    separator = step.get("separator")
    index = step.get("index")
    if not isinstance(separator, str) or not separator or len(separator) > 32:
        raise CtfTransformError("split separator must be 1..32 text characters")
    if isinstance(index, bool) or not isinstance(index, int):
        raise CtfTransformError("split index must be an integer")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CtfTransformError("split input must be valid UTF-8") from error
    parts = text.split(separator)
    if not -len(parts) <= index < len(parts):
        raise CtfTransformError(
            f"split index {index} is outside {len(parts)} component(s)"
        )
    return parts[index].encode("utf-8")


def _json_get(data: bytes, step: Mapping[str, object]) -> bytes:
    if set(step) != {"operation", "path"}:
        raise CtfTransformError("json_get requires exactly operation and path")
    raw_path = step.get("path")
    if isinstance(raw_path, str) and raw_path:
        components: list[object] = raw_path.split(".")
    elif isinstance(raw_path, list) and raw_path and all(
        isinstance(item, (str, int)) and not isinstance(item, bool) for item in raw_path
    ):
        components = list(raw_path)
    else:
        raise CtfTransformError("json_get path must be a non-empty dotted string or string/integer array")
    try:
        value: object = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CtfTransformError("json_get input must be valid UTF-8 JSON") from error
    for component in components:
        if isinstance(component, int):
            if not isinstance(value, list) or not -len(value) <= component < len(value):
                raise CtfTransformError(f"json_get list index {component!r} is unavailable")
            value = value[component]
        else:
            if not isinstance(value, dict) or component not in value:
                raise CtfTransformError(f"json_get object key {component!r} is unavailable")
            value = value[component]
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (dict, list, int, float, bool)) or value is None:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    raise CtfTransformError("json_get selected an unsupported value")


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
        if operation == "split":
            if set(raw_step) != {"operation", "separator", "index"}:
                raise CtfTransformError("split requires exactly operation, separator and index")
            separator = raw_step.get("separator")
            index_value = raw_step.get("index")
            if not isinstance(separator, str) or not separator or len(separator) > 32:
                raise CtfTransformError("split separator must be 1..32 text characters")
            if isinstance(index_value, bool) or not isinstance(index_value, int):
                raise CtfTransformError("split index must be an integer")
        elif operation == "json_get":
            allowed = {"operation", "path"}
            if set(raw_step) != allowed:
                raise CtfTransformError("json_get requires exactly operation and path")
            path = raw_step.get("path")
            if not (
                isinstance(path, str) and path
                or isinstance(path, list) and path and all(
                    isinstance(item, (str, int)) and not isinstance(item, bool)
                    for item in path
                )
            ):
                raise CtfTransformError("json_get path must be a non-empty dotted string or string/integer array")
        elif operation != "xor" and set(raw_step) != {"operation"}:
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


def describe_ctf_bytes(
    data: bytes,
    *,
    input_size_bytes: int,
    input_sha256: str,
    operations: Sequence[str],
) -> dict[str, Any]:
    """Build the bounded observation shared by scalar and batch transforms."""

    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    candidates = list(dict.fromkeys(FLAG_RE.findall(text or "")))
    ascii_preview = "".join(
        chr(byte) if 32 <= byte <= 126 else "." for byte in data[:MAX_PREVIEW_CHARS]
    )
    return {
        "input_size_bytes": input_size_bytes,
        "input_sha256": input_sha256,
        "operations": list(operations),
        "size_bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "text": text,
        "hex": data.hex(),
        "ascii_preview": ascii_preview,
        "flag_candidates": candidates,
    }


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
        elif operation in {"rot13", "reverse", "strip"}:
            data = _text_transform(data, operation)
        elif operation == "split":
            data = _split(data, step)
        elif operation == "json_get":
            data = _json_get(data, step)
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

    return describe_ctf_bytes(
        data,
        input_size_bytes=input_size,
        input_sha256=input_sha256,
        operations=applied,
    )


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
