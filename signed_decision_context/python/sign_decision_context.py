#!/usr/bin/env python3
"""Create a deterministic AGP Signed Decision Context 1.0."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
except ImportError as exc:
    raise SystemExit(
        "cryptography is required: pip install 'cryptography>=42.0'"
    ) from exc


ROOT = Path(__file__).resolve().parents[2]

CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

DECISION_CONTEXT_PYTHON = ROOT / "decision_context" / "python"
if str(DECISION_CONTEXT_PYTHON) not in sys.path:
    sys.path.insert(0, str(DECISION_CONTEXT_PYTHON))

SIGNED_CONTEXT_PYTHON = ROOT / "signed_decision_context" / "python"
if str(SIGNED_CONTEXT_PYTHON) not in sys.path:
    sys.path.insert(0, str(SIGNED_CONTEXT_PYTHON))

from canonicalize import CanonicalizationError, canonical_bytes
from validate_decision_context import (
    ValidationError as DecisionContextValidationError,
    parse_bytes as parse_decision_context_bytes,
    validate_object as validate_decision_context_object,
)
from validate_signed_decision_context import (
    ValidationFailure,
    structural_validate,
)


SUPPORTED_ALGORITHM = "ed25519"


class SigningFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def b64url_unpadded(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def decode_private_key(value: Any) -> bytes:
    if not isinstance(value, str) or not value:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_ENCODING",
            "private_key must be a non-empty base64url string",
        )

    allowed = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_"
    )

    if "=" in value or any(character not in allowed for character in value):
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_ENCODING",
            "private_key must use unpadded base64url",
        )

    padding = "=" * ((4 - len(value) % 4) % 4)

    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_ENCODING",
            "private_key is not valid base64url",
        ) from exc

    canonical = b64url_unpadded(decoded)
    if canonical != value:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_ENCODING",
            "private_key is not canonical base64url",
        )

    if len(decoded) != 32:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_LENGTH",
            (
                f"private_key has {len(decoded)} bytes; "
                "expected a 32-byte Ed25519 seed"
            ),
        )

    return decoded


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_FILE",
            str(exc),
        ) from exc

    if not isinstance(value, dict):
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_FILE",
            "private key file must contain an object",
        )

    required = {"algorithm", "private_key"}

    if set(value) != required:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_FILE",
            (
                "private key file must contain exactly "
                "algorithm and private_key"
            ),
        )

    if value["algorithm"] != SUPPORTED_ALGORITHM:
        raise SigningFailure(
            "UNSUPPORTED_SIGNATURE_ALGORITHM",
            f"algorithm={value['algorithm']}",
        )

    seed = decode_private_key(value["private_key"])

    try:
        return Ed25519PrivateKey.from_private_bytes(seed)
    except ValueError as exc:
        raise SigningFailure(
            "INVALID_PRIVATE_KEY_ENCODING",
            str(exc),
        ) from exc


def load_context(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise SigningFailure(
            "CONTEXT_READ_FAILED",
            str(exc),
        ) from exc

    try:
        value = parse_decision_context_bytes(raw)
        validate_decision_context_object(value)
    except DecisionContextValidationError as exc:
        raise SigningFailure(
            exc.code,
            exc.detail,
        ) from exc

    if not isinstance(value, dict):
        raise SigningFailure(
            "INVALID_CONTEXT",
            "decision context must be an object",
        )

    return value


def create_signed_decision_context(
    context: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    signer_id: str,
    key_id: str,
    signature_id: str,
    signed_at: str,
    schema_dir: Path,
) -> dict[str, Any]:
    try:
        context_canonical = canonical_bytes(context)
    except CanonicalizationError as exc:
        raise SigningFailure(
            "INVALID_CONTEXT",
            f"context canonicalization failed: {exc.code}",
        ) from exc

    digest = hashlib.sha256(context_canonical).hexdigest()

    statement = {
        "object_type": "agp.signature-statement/1",
        "purpose": "decision-context-attestation",
        "context_object_type": "agp.decision-context/1",
        "context_digest": {
            "algorithm": "sha-256",
            "value": digest,
        },
        "signer_id": signer_id,
        "key_id": key_id,
        "algorithm": SUPPORTED_ALGORITHM,
        "signed_at": signed_at,
    }

    try:
        statement_canonical = canonical_bytes(statement)
    except CanonicalizationError as exc:
        raise SigningFailure(
            "INVALID_SIGNATURE_STATEMENT",
            exc.code,
        ) from exc

    signature = private_key.sign(statement_canonical)

    result = {
        "object_type": "agp.signed-decision-context/1",
        "context": context,
        "context_digest": {
            "algorithm": "sha-256",
            "value": digest,
        },
        "signatures": [
            {
                "signature_id": signature_id,
                "statement": statement,
                "signature": b64url_unpadded(signature),
            }
        ],
    }

    try:
        structural_validate(result, schema_dir)
    except ValidationFailure as exc:
        raise SigningFailure(
            exc.code,
            exc.detail,
        ) from exc

    return result


def write_output(path: Path, value: dict[str, Any]) -> None:
    try:
        encoded = canonical_bytes(value) + b"\n"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(encoded)
    except (OSError, CanonicalizationError) as exc:
        raise SigningFailure(
            "OUTPUT_WRITE_FAILED",
            str(exc),
        ) from exc


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Create an AGP Signed Decision Context 1.0 "
            "using an Ed25519 private key."
        )
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--signer-id", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--signature-id", required=True)
    parser.add_argument("--signed-at", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path("registry/schemas"),
    )
    args = parser.parse_args()

    try:
        context = load_context(args.input)
        private_key = load_private_key(args.private_key)

        result = create_signed_decision_context(
            context,
            private_key,
            signer_id=args.signer_id,
            key_id=args.key_id,
            signature_id=args.signature_id,
            signed_at=args.signed_at,
            schema_dir=args.schema_dir,
        )

        write_output(args.output, result)

    except SigningFailure as exc:
        print(
            json.dumps(
                {
                    "status": "error",
                    "error_code": exc.code,
                    "detail": exc.detail,
                },
                separators=(",", ":"),
            )
        )
        return 1

    print(
        json.dumps(
            {
                "status": "signed",
                "output": str(args.output),
                "signature_id": args.signature_id,
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
