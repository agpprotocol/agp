#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "canonicalization" / "vectors"
OUT.mkdir(parents=True, exist_ok=True)


def nested_array(depth: int) -> bytes:
    return ("[" * depth + "0" + "]" * depth + "\n").encode("ascii")


VECTORS: list[tuple[str, bytes, bool, str | None]] = [
    ("object_key_order", b'{ "z": 3, "a": 1, "m": 2 }\n', True, None),
    ("whitespace_removed", b'{\n  "a" : [ 1, true, null ]\n}\n', True, None),
    ("utf8_text", '{"message":"áéíóú"}\n'.encode("utf-8"), True, None),
    (
        "escaped_characters",
        b'{"value":"quote: \\" slash: \\\\ newline: \\n tab: \\t"}\n',
        True,
        None,
    ),
    ("valid_surrogate_pair", b'{"value":"\\ud83d\\ude00"}\n', True, None),
    ("array_order_preserved", b'{"value":[3,1,2]}\n', True, None),
    ("safe_integer_min", b'{"value":-9007199254740991}\n', True, None),
    ("safe_integer_max", b'{"value":9007199254740991}\n', True, None),
    ("duplicate_key", b'{"a":1,"a":2}\n', False, "DUPLICATE_KEY"),
    (
        "escaped_duplicate_key",
        b'{"a":1,"\\u0061":2}\n',
        False,
        "DUPLICATE_KEY",
    ),
    ("decimal_rejected", b'{"value":1.5}\n', False, "DECIMAL_NOT_SUPPORTED"),
    ("exponent_rejected", b'{"value":1e3}\n', False, "DECIMAL_NOT_SUPPORTED"),
    ("nan_rejected", b'{"value":NaN}\n', False, "INVALID_NUMBER"),
    ("infinity_rejected", b'{"value":Infinity}\n', False, "INVALID_NUMBER"),
    (
        "negative_infinity_rejected",
        b'{"value":-Infinity}\n',
        False,
        "INVALID_NUMBER",
    ),
    (
        "nonfinite_words_in_strings",
        b'{"a":"NaN","b":"Infinity","c":"-Infinity"}\n',
        True,
        None,
    ),
    (
        "integer_above_range",
        b'{"value":9007199254740992}\n',
        False,
        "INTEGER_OUT_OF_RANGE",
    ),
    (
        "integer_below_range",
        b'{"value":-9007199254740992}\n',
        False,
        "INTEGER_OUT_OF_RANGE",
    ),
    (
        "unpaired_high_surrogate",
        b'{"value":"\\ud800"}\n',
        False,
        "INVALID_UNICODE",
    ),
    (
        "unpaired_low_surrogate",
        b'{"value":"\\udc00"}\n',
        False,
        "INVALID_UNICODE",
    ),
    (
        "utf8_bom_rejected",
        b'\xef\xbb\xbf{"a":1}\n',
        False,
        "UTF8_BOM_NOT_ALLOWED",
    ),
    ("invalid_utf8", b'{"value":"\xff"}\n', False, "INVALID_UTF8"),
    ("trailing_data", b'{"a":1}{"b":2}\n', False, "INVALID_JSON"),
    ("invalid_json", b'{"a":}\n', False, "INVALID_JSON"),
    ("maximum_depth", nested_array(64), True, None),
    ("depth_exceeded", nested_array(65), False, "MAX_DEPTH_EXCEEDED"),
    (
        "maximum_input_size",
        b'"' + b"a" * (1_048_576 - 3) + b'"\n',
        True,
        None,
    ),
    (
        "input_too_large",
        b'"' + b"a" * (1_048_576 - 2) + b'"\n',
        False,
        "INPUT_TOO_LARGE",
    ),
]


def main() -> None:
    for path in OUT.glob("*"):
        if path.is_file():
            path.unlink()

    manifest = []

    for index, (name, raw, expected, error_code) in enumerate(VECTORS, start=1):
        input_name = f"{index:03d}_{name}.input.json"
        meta_name = f"{index:03d}_{name}.meta.json"

        (OUT / input_name).write_bytes(raw)
        metadata = {
            "name": name,
            "input": input_name,
            "expected": expected,
            "expected_error": error_code,
        }
        (OUT / meta_name).write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifest.append(metadata)

    (OUT / "manifest.json").write_text(
        json.dumps(
            {
                "profile": "AGP-Canonicalization-0.7",
                "vectors": manifest,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"Generated {len(VECTORS)} canonicalization vectors")


if __name__ == "__main__":
    main()
