#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

SAFE_INTEGER_MAX = 9007199254740991
VALID_STATUSES = {"active", "deprecated", "reserved"}
COLLECTIONS = (
    "objects",
    "canonicalization_algorithms",
    "digest_algorithms",
    "signature_algorithms",
)
TOP_LEVEL = {"registry_version", *COLLECTIONS}
ID_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._/-]{1,94}[a-z0-9])$")
OBJECT_ID_RE = re.compile(r"^agp\.[a-z0-9][a-z0-9._-]*/([1-9][0-9]*)$")


class RegistryError(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def fail(code: str, detail: str) -> None:
    raise RegistryError(code, detail)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            fail("INVALID_JSON", f"duplicate JSON member: {key}")
        result[key] = value
    return result


def reject_decimal(_: str) -> None:
    fail("INVALID_JSON", "decimal and exponent numbers are not supported")


def reject_nonfinite(token: str) -> None:
    fail("INVALID_JSON", f"non-finite number is not supported: {token}")


def parse_registry_json(raw: bytes) -> Any:
    if raw.startswith(b"\xef\xbb\xbf"):
        fail("INVALID_JSON", "UTF-8 BOM is not allowed")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        fail("INVALID_JSON", f"invalid UTF-8: {exc}")

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_float=reject_decimal,
            parse_constant=reject_nonfinite,
        )
    except RegistryError:
        raise
    except Exception as exc:
        fail("INVALID_JSON", str(exc))


def safe_positive_integer(value: Any, field: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        fail("INVALID_SAFE_INTEGER", f"{field} must be an integer")
    if value < 1 or value > SAFE_INTEGER_MAX:
        fail("INVALID_SAFE_INTEGER", f"{field} is outside the safe positive range")


def validate_common(entry: Any, collection: str, index: int) -> str:
    where = f"{collection}[{index}]"
    if not isinstance(entry, dict):
        fail("INVALID_ENTRY", f"{where} must be an object")

    required = {"id", "status", "spec", "description"}
    if not required.issubset(entry):
        fail("INVALID_ENTRY", f"{where} is missing common fields")

    identifier = entry["id"]
    if not isinstance(identifier, str) or not ID_RE.fullmatch(identifier):
        fail("INVALID_IDENTIFIER", f"{where}.id is invalid")
    if len(identifier.encode("utf-8")) > 96:
        fail("INVALID_IDENTIFIER", f"{where}.id is too long")

    if entry["status"] not in VALID_STATUSES:
        fail("INVALID_STATUS", f"{where}.status is invalid")

    for field in ("spec", "description"):
        if not isinstance(entry[field], str) or not entry[field]:
            fail("INVALID_ENTRY", f"{where}.{field} must be a non-empty string")

    return identifier


def validate_registry(data: Any) -> None:
    if not isinstance(data, dict):
        fail("INVALID_REGISTRY", "registry must be an object")

    unknown = set(data) - TOP_LEVEL
    if unknown:
        fail("UNKNOWN_TOP_LEVEL_MEMBER", f"unknown members: {sorted(unknown)}")
    if set(data) != TOP_LEVEL:
        fail("INVALID_REGISTRY", "registry is missing required top-level members")
    if data["registry_version"] != "0.8":
        fail("INVALID_REGISTRY_VERSION", "registry_version must be 0.8")

    all_ids: set[str] = set()
    ids_by_collection: dict[str, set[str]] = {}

    for collection in COLLECTIONS:
        entries = data[collection]
        if not isinstance(entries, list):
            fail("INVALID_COLLECTION", f"{collection} must be an array")

        ids: list[str] = []
        seen_local: set[str] = set()

        for index, entry in enumerate(entries):
            identifier = validate_common(entry, collection, index)
            if identifier in seen_local or identifier in all_ids:
                fail("DUPLICATE_IDENTIFIER", f"duplicate identifier: {identifier}")
            seen_local.add(identifier)
            all_ids.add(identifier)
            ids.append(identifier)

            if collection == "objects":
                expected = {
                    "id", "status", "spec", "description", "schema_version",
                    "canonicalization", "digest", "schema",
                }
                if set(entry) != expected:
                    fail("INVALID_ENTRY", f"{collection}[{index}] has invalid fields")
                safe_positive_integer(entry["schema_version"], "schema_version")
                match = OBJECT_ID_RE.fullmatch(identifier)
                if not match or int(match.group(1)) != entry["schema_version"]:
                    fail("INVALID_OBJECT_ID", f"invalid object id/version: {identifier}")
                for field in ("canonicalization", "digest", "schema"):
                    if not isinstance(entry[field], str) or not entry[field]:
                        fail("INVALID_ENTRY", f"{collection}[{index}].{field} is invalid")

            elif collection == "canonicalization_algorithms":
                expected = {"id", "status", "spec", "description", "receipt_version"}
                if set(entry) != expected:
                    fail("INVALID_ENTRY", f"{collection}[{index}] has invalid fields")
                safe_positive_integer(entry["receipt_version"], "receipt_version")

            elif collection == "digest_algorithms":
                expected = {"id", "status", "spec", "description", "output_bits"}
                if set(entry) != expected:
                    fail("INVALID_ENTRY", f"{collection}[{index}] has invalid fields")
                safe_positive_integer(entry["output_bits"], "output_bits")

            elif collection == "signature_algorithms":
                expected = {
                    "id", "status", "spec", "description",
                    "key_type", "signature_encoding",
                }
                if set(entry) != expected:
                    fail("INVALID_ENTRY", f"{collection}[{index}] has invalid fields")
                for field in ("key_type", "signature_encoding"):
                    if not isinstance(entry[field], str) or not entry[field]:
                        fail("INVALID_ENTRY", f"{collection}[{index}].{field} is invalid")

        if ids != sorted(ids):
            fail("UNSORTED_COLLECTION", f"{collection} is not sorted by id")
        ids_by_collection[collection] = set(ids)

    c14n = {e["id"]: e for e in data["canonicalization_algorithms"]}
    digests = {e["id"]: e for e in data["digest_algorithms"]}

    for entry in data["objects"]:
        c14n_id = entry["canonicalization"]
        digest_id = entry["digest"]
        if c14n_id not in ids_by_collection["canonicalization_algorithms"]:
            fail("MISSING_REFERENCE", f"missing canonicalization reference: {c14n_id}")
        if digest_id not in ids_by_collection["digest_algorithms"]:
            fail("MISSING_REFERENCE", f"missing digest reference: {digest_id}")
        if entry["status"] == "active":
            if c14n[c14n_id]["status"] == "reserved":
                fail("RESERVED_REFERENCE", f"active object uses reserved: {c14n_id}")
            if digests[digest_id]["status"] == "reserved":
                fail("RESERVED_REFERENCE", f"active object uses reserved: {digest_id}")


def validate_bytes(raw: bytes) -> dict[str, Any]:
    try:
        data = parse_registry_json(raw)
        validate_registry(data)
    except RegistryError as exc:
        return {"accepted": False, "error_code": exc.code, "detail": exc.detail}

    return {"accepted": True, "error_code": None, "detail": None}


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_registry.py <registry.json>", file=sys.stderr)
        return 2
    result = validate_bytes(Path(sys.argv[1]).read_bytes())
    print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
    return 0 if result["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
