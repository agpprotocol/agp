#!/usr/bin/env python3
"""Stage 1 structural validator for agp.signed-decision-context/1."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

try:
    from jsonschema import Draft202012Validator, RefResolver
except ImportError as exc:
    raise SystemExit("jsonschema is required: pip install jsonschema") from exc

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,126}[a-z0-9]$")

ROOT = Path(__file__).resolve().parents[2]
CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

try:
    from canonicalize import CanonicalizationError, canonical_bytes, parse_json_bytes
except ImportError as exc:
    raise SystemExit(
        "unable to import canonicalization/python/canonicalize.py"
    ) from exc


class ValidationFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def load_json(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ValidationFailure("INVALID_JSON", str(exc)) from exc

    try:
        return parse_json_bytes(raw)
    except CanonicalizationError as exc:
        detail = exc.code + (f": {exc.detail}" if exc.detail else "")
        raise ValidationFailure("INVALID_JSON", detail) from exc


def schema_validator(schema_dir: Path, schema_name: str) -> Draft202012Validator:
    schema_path = schema_dir / schema_name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))

    store = {}
    for p in schema_dir.glob("*.schema.json"):
        loaded = json.loads(p.read_text(encoding="utf-8"))
        if "$id" in loaded:
            store[loaded["$id"]] = loaded
        store[p.name] = loaded

    resolver = RefResolver(
        base_uri=schema_path.resolve().as_uri(),
        referrer=schema,
        store=store,
    )
    return Draft202012Validator(schema, resolver=resolver)


def first_schema_error(validator: Draft202012Validator, value: Any):
    errors = sorted(validator.iter_errors(value), key=lambda e: list(e.absolute_path))
    return errors[0] if errors else None


def structural_validate(value: Any, schema_dir: Path) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationFailure("INVALID_OBJECT_TYPE", "top level must be object")

    if value.get("object_type") != "agp.signed-decision-context/1":
        raise ValidationFailure("INVALID_OBJECT_TYPE", "unexpected object_type")

    allowed = {"object_type", "context", "context_digest", "signatures"}
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise ValidationFailure(
            "UNKNOWN_TOP_LEVEL_MEMBER",
            f"unknown top-level member: {unknown[0]}",
        )

    context_validator = schema_validator(
        schema_dir, "agp.decision-context-1.schema.json"
    )
    error = first_schema_error(context_validator, value.get("context"))
    if error:
        raise ValidationFailure("INVALID_CONTEXT", error.message)

    digest_obj = value.get("context_digest")
    if (
        not isinstance(digest_obj, dict)
        or digest_obj.get("algorithm") != "sha-256"
        or not isinstance(digest_obj.get("value"), str)
        or len(digest_obj["value"]) != 64
        or any(c not in "0123456789abcdef" for c in digest_obj["value"])
    ):
        raise ValidationFailure("INVALID_CONTEXT_DIGEST", "invalid context digest")

    try:
        context_encoded = canonical_bytes(value["context"])
    except CanonicalizationError as exc:
        raise ValidationFailure("INVALID_CONTEXT", exc.code) from exc

    computed = hashlib.sha256(context_encoded).hexdigest()
    if digest_obj["value"] != computed:
        raise ValidationFailure(
            "CONTEXT_DIGEST_MISMATCH",
            f"declared={digest_obj['value']} computed={computed}",
        )

    signatures = value.get("signatures")
    if not isinstance(signatures, list):
        raise ValidationFailure(
            "INVALID_SIGNATURE_COLLECTION", "signatures must be an array"
        )
    if not signatures:
        raise ValidationFailure(
            "EMPTY_SIGNATURE_COLLECTION", "at least one signature is required"
        )

    statement_validator = schema_validator(
        schema_dir, "agp.signature-statement-1.schema.json"
    )

    order_keys: list[tuple[str, str, str, str, str]] = []
    seen_ids: set[str] = set()
    seen_attestations: set[tuple[str, str, str, str, str, str]] = set()
    seen_exact: set[tuple[bytes, str]] = set()

    for index, entry in enumerate(signatures):
        if not isinstance(entry, dict):
            raise ValidationFailure(
                "INVALID_SIGNATURE_ENTRY", f"signature[{index}] must be object"
            )
        if set(entry) != {"signature_id", "statement", "signature"}:
            raise ValidationFailure(
                "INVALID_SIGNATURE_ENTRY",
                f"signature[{index}] has missing or unknown members",
            )

        signature_id = entry["signature_id"]
        statement = entry["statement"]
        signature = entry["signature"]

        if (
            not isinstance(signature_id, str)
            or not IDENTIFIER_RE.fullmatch(signature_id)
        ):
            raise ValidationFailure(
                "INVALID_SIGNATURE_ENTRY",
                f"signature[{index}].signature_id is invalid",
            )

        if not isinstance(statement, dict):
            raise ValidationFailure(
                "INVALID_SIGNATURE_STATEMENT",
                f"signature[{index}].statement must be object",
            )

        if (
            "context_object_type" in statement
            and statement["context_object_type"] != "agp.decision-context/1"
        ):
            raise ValidationFailure(
                "STATEMENT_CONTEXT_TYPE_MISMATCH",
                f"signature[{index}] context type mismatch",
            )

        error = first_schema_error(statement_validator, statement)
        if error:
            raise ValidationFailure(
                "INVALID_SIGNATURE_STATEMENT",
                f"signature[{index}]: {error.message}",
            )

        if statement["context_digest"] != digest_obj:
            raise ValidationFailure(
                "STATEMENT_CONTEXT_DIGEST_MISMATCH",
                f"signature[{index}] context digest mismatch",
            )

        if (
            not isinstance(signature, str)
            or not signature
            or any(
                c not in
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
                for c in signature
            )
        ):
            raise ValidationFailure(
                "INVALID_SIGNATURE_ENCODING",
                f"signature[{index}] is not unpadded base64url",
            )

        order_keys.append(
            (
                statement["signer_id"],
                statement["key_id"],
                statement["algorithm"],
                statement["signed_at"],
                signature_id,
            )
        )

        if signature_id in seen_ids:
            raise ValidationFailure(
                "DUPLICATE_SIGNATURE_ID", f"duplicate signature_id: {signature_id}"
            )
        seen_ids.add(signature_id)

        try:
            exact = (canonical_bytes(statement), signature)
        except CanonicalizationError as exc:
            raise ValidationFailure(
                "INVALID_SIGNATURE_STATEMENT",
                f"signature[{index}]: {exc.code}",
            ) from exc

        if exact in seen_exact:
            raise ValidationFailure(
                "DUPLICATE_SIGNATURE_ENTRY",
                f"duplicate statement and signature at signature[{index}]",
            )
        seen_exact.add(exact)

        attestation = (
            statement["context_digest"]["algorithm"],
            statement["context_digest"]["value"],
            statement["signer_id"],
            statement["key_id"],
            statement["algorithm"],
            statement["signed_at"],
        )
        if attestation in seen_attestations:
            raise ValidationFailure(
                "DUPLICATE_ATTESTATION",
                f"duplicate semantic attestation at signature[{index}]",
            )
        seen_attestations.add(attestation)

    if order_keys != sorted(order_keys):
        raise ValidationFailure(
            "UNSORTED_SIGNATURES",
            "signatures are not in deterministic order",
        )

    return {
        "status": "valid",
        "object_type": value["object_type"],
        "context_digest": digest_obj,
        "signature_count": len(signatures),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path("registry/schemas"),
    )
    args = parser.parse_args()

    try:
        value = load_json(args.input)
        result = structural_validate(value, args.schema_dir)
    except ValidationFailure as exc:
        print(json.dumps({
            "status": "invalid",
            "error_code": exc.code,
            "detail": exc.detail,
        }, separators=(",", ":")))
        return 1

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
