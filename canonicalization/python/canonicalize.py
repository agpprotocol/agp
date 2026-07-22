#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 1_048_576
MAX_DEPTH = 64
MIN_SAFE_INTEGER = -(2**53 - 1)
MAX_SAFE_INTEGER = 2**53 - 1


class CanonicalizationError(ValueError):
    def __init__(self, code: str, detail: str = "") -> None:
        super().__init__(detail or code)
        self.code = code
        self.detail = detail


def _reject_constant(value: str) -> Any:
    raise CanonicalizationError("INVALID_NUMBER", value)


def _parse_integer(value: str) -> int:
    number = int(value, 10)
    if number < MIN_SAFE_INTEGER or number > MAX_SAFE_INTEGER:
        raise CanonicalizationError("INTEGER_OUT_OF_RANGE", value)
    return number


def _reject_decimal(value: str) -> Any:
    raise CanonicalizationError("DECIMAL_NOT_SUPPORTED", value)


def _normalize_string(value: str) -> str:
    output: list[str] = []
    index = 0

    while index < len(value):
        codepoint = ord(value[index])

        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 >= len(value):
                raise CanonicalizationError(
                    "INVALID_UNICODE",
                    f"unpaired high surrogate U+{codepoint:04X}",
                )

            low = ord(value[index + 1])
            if not 0xDC00 <= low <= 0xDFFF:
                raise CanonicalizationError(
                    "INVALID_UNICODE",
                    f"unpaired high surrogate U+{codepoint:04X}",
                )

            combined = (
                0x10000
                + ((codepoint - 0xD800) << 10)
                + (low - 0xDC00)
            )
            output.append(chr(combined))
            index += 2
            continue

        if 0xDC00 <= codepoint <= 0xDFFF:
            raise CanonicalizationError(
                "INVALID_UNICODE",
                f"unpaired low surrogate U+{codepoint:04X}",
            )

        output.append(value[index])
        index += 1

    return "".join(output)


def _normalize_value(value: Any) -> Any:
    if isinstance(value, str):
        return _normalize_string(value)

    if isinstance(value, list):
        return [_normalize_value(item) for item in value]

    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, item in value.items():
            normalized_key = _normalize_string(key)
            if normalized_key in normalized:
                raise CanonicalizationError(
                    "DUPLICATE_KEY",
                    normalized_key,
                )
            normalized[normalized_key] = _normalize_value(item)
        return normalized

    return value


def _object_from_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        normalized_key = _normalize_string(key)
        if normalized_key in result:
            raise CanonicalizationError("DUPLICATE_KEY", normalized_key)
        result[normalized_key] = value
    return result


def _validate_string(value: str) -> None:
    _normalize_string(value)


def _validate_value(value: Any, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        raise CanonicalizationError("MAX_DEPTH_EXCEEDED")

    if value is None or isinstance(value, bool):
        return

    if isinstance(value, int):
        if value < MIN_SAFE_INTEGER or value > MAX_SAFE_INTEGER:
            raise CanonicalizationError("INTEGER_OUT_OF_RANGE")
        return

    if isinstance(value, float):
        raise CanonicalizationError("DECIMAL_NOT_SUPPORTED")

    if isinstance(value, str):
        _validate_string(value)
        return

    if isinstance(value, list):
        for item in value:
            _validate_value(item, depth + 1)
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("NON_STRING_KEY")
            _validate_string(key)
            _validate_value(item, depth + 1)
        return

    raise CanonicalizationError("UNSUPPORTED_TYPE", type(value).__name__)


def parse_json_bytes(raw: bytes) -> Any:
    if len(raw) > MAX_INPUT_BYTES:
        raise CanonicalizationError("INPUT_TOO_LARGE")

    if raw.startswith(b"\xef\xbb\xbf"):
        raise CanonicalizationError("UTF8_BOM_NOT_ALLOWED")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CanonicalizationError("INVALID_UTF8", str(error)) from error

    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_from_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_decimal,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise CanonicalizationError("INVALID_JSON", str(error)) from error

    value = _normalize_value(value)
    _validate_value(value)
    return value


def _escape_string(value: str) -> str:
    _validate_string(value)
    output: list[str] = ['"']

    short_escapes = {
        0x08: r"\b",
        0x09: r"\t",
        0x0A: r"\n",
        0x0C: r"\f",
        0x0D: r"\r",
    }

    for character in value:
        codepoint = ord(character)

        if character == '"':
            output.append(r"\"")
        elif character == "\\":
            output.append(r"\\")
        elif codepoint in short_escapes:
            output.append(short_escapes[codepoint])
        elif codepoint <= 0x1F:
            output.append(f"\\u{codepoint:04x}")
        else:
            output.append(character)

    output.append('"')
    return "".join(output)


def canonical_text(value: Any) -> str:
    _validate_value(value)

    if value is None:
        return "null"

    if value is True:
        return "true"

    if value is False:
        return "false"

    if isinstance(value, int):
        return str(value)

    if isinstance(value, str):
        return _escape_string(value)

    if isinstance(value, list):
        return "[" + ",".join(canonical_text(item) for item in value) + "]"

    if isinstance(value, dict):
        entries = (
            _escape_string(key) + ":" + canonical_text(value[key])
            for key in sorted(value)
        )
        return "{" + ",".join(entries) + "}"

    raise CanonicalizationError("UNSUPPORTED_TYPE", type(value).__name__)


def canonical_bytes(value: Any) -> bytes:
    return canonical_text(value).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def make_receipt(raw: bytes) -> dict[str, Any]:
    try:
        value = parse_json_bytes(raw)
        encoded = canonical_bytes(value)
        return {
            "accepted": True,
            "canonical": encoded.decode("utf-8"),
            "digest": "sha256:" + hashlib.sha256(encoded).hexdigest(),
            "error_codes": [],
        }
    except CanonicalizationError as error:
        return {
            "accepted": False,
            "canonical": None,
            "digest": None,
            "error_codes": [error.code],
        }


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: canonicalize.py INPUT.json OUTPUT.json",
            file=sys.stderr,
        )
        return 2

    source = Path(sys.argv[1])
    target = Path(sys.argv[2])

    try:
        raw = source.read_bytes()
    except OSError as error:
        print(f"cannot read input: {error}", file=sys.stderr)
        return 2

    receipt = make_receipt(raw)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_bytes(receipt) + b"\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
