#!/usr/bin/env python3
"""Stage 2 cryptographic verification for Signed Decision Context 1."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path
from typing import Any

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PublicKey,
    )
except ImportError as exc:
    raise SystemExit(
        "cryptography is required: pip install 'cryptography>=42.0'"
    ) from exc


ROOT = Path(__file__).resolve().parents[2]

VALIDATOR_PYTHON = ROOT / "signed_decision_context" / "python"
if str(VALIDATOR_PYTHON) not in sys.path:
    sys.path.insert(0, str(VALIDATOR_PYTHON))

CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

from canonicalize import CanonicalizationError, canonical_bytes
from validate_signed_decision_context import (
    ValidationFailure,
    load_json,
    structural_validate,
)


SUPPORTED_ALGORITHM = "ed25519"


class VerificationFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def decode_base64url_unpadded(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise VerificationFailure(
            "INVALID_PUBLIC_KEY_ENCODING",
            f"{field} must be a non-empty base64url string",
        )

    allowed = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_"
    )

    if "=" in value or any(character not in allowed for character in value):
        raise VerificationFailure(
            "INVALID_PUBLIC_KEY_ENCODING",
            f"{field} must use unpadded base64url",
        )

    padding = "=" * ((4 - len(value) % 4) % 4)

    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise VerificationFailure(
            "INVALID_PUBLIC_KEY_ENCODING",
            f"{field} is not valid base64url",
        ) from exc

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise VerificationFailure(
            "INVALID_PUBLIC_KEY_ENCODING",
            f"{field} is not canonical base64url",
        )

    return decoded


def decode_signature(value: str, index: int) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)

    try:
        decoded = base64.urlsafe_b64decode(value + padding)
    except (ValueError, binascii.Error) as exc:
        raise VerificationFailure(
            "INVALID_SIGNATURE_ENCODING",
            f"signature[{index}] is not valid base64url",
        ) from exc

    canonical = base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=")
    if canonical != value:
        raise VerificationFailure(
            "INVALID_SIGNATURE_ENCODING",
            f"signature[{index}] is not canonical base64url",
        )

    return decoded


def load_keyring(path: Path) -> list[dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise VerificationFailure(
            "INVALID_KEYRING",
            str(exc),
        ) from exc

    if not isinstance(value, dict):
        raise VerificationFailure(
            "INVALID_KEYRING",
            "keyring top level must be an object",
        )

    if set(value) != {"keys"} or not isinstance(value["keys"], list):
        raise VerificationFailure(
            "INVALID_KEYRING",
            "keyring must contain exactly one keys array",
        )

    keys: list[dict[str, Any]] = []

    for index, entry in enumerate(value["keys"]):
        if not isinstance(entry, dict):
            raise VerificationFailure(
                "INVALID_KEYRING",
                f"keys[{index}] must be an object",
            )

        required = {
            "signer_id",
            "key_id",
            "algorithm",
            "public_key",
        }

        if set(entry) != required:
            raise VerificationFailure(
                "INVALID_KEYRING",
                f"keys[{index}] has missing or unknown members",
            )

        if not all(isinstance(entry[name], str) for name in required):
            raise VerificationFailure(
                "INVALID_KEYRING",
                f"keys[{index}] members must be strings",
            )

        keys.append(entry)

    return keys


def resolve_key(
    keyring: list[dict[str, Any]],
    signer_id: str,
    key_id: str,
    algorithm: str,
) -> dict[str, Any]:
    matches = [
        entry
        for entry in keyring
        if entry["signer_id"] == signer_id
        and entry["key_id"] == key_id
        and entry["algorithm"] == algorithm
    ]

    if not matches:
        raise VerificationFailure(
            "UNKNOWN_VERIFICATION_KEY",
            (
                f"no key for signer_id={signer_id} "
                f"key_id={key_id} algorithm={algorithm}"
            ),
        )

    if len(matches) > 1:
        raise VerificationFailure(
            "AMBIGUOUS_VERIFICATION_KEY",
            (
                f"multiple keys for signer_id={signer_id} "
                f"key_id={key_id} algorithm={algorithm}"
            ),
        )

    return matches[0]


def verify_signatures(
    value: dict[str, Any],
    schema_dir: Path,
    keyring: list[dict[str, Any]],
) -> dict[str, Any]:
    structural_result = structural_validate(value, schema_dir)

    verified_ids: list[str] = []

    for index, entry in enumerate(value["signatures"]):
        statement = entry["statement"]
        algorithm = statement["algorithm"]

        if algorithm != SUPPORTED_ALGORITHM:
            raise VerificationFailure(
                "UNSUPPORTED_SIGNATURE_ALGORITHM",
                f"signature[{index}] algorithm={algorithm}",
            )

        key_entry = resolve_key(
            keyring,
            statement["signer_id"],
            statement["key_id"],
            algorithm,
        )

        public_key_bytes = decode_base64url_unpadded(
            key_entry["public_key"],
            f"keyring public key for signature[{index}]",
        )

        if len(public_key_bytes) != 32:
            raise VerificationFailure(
                "INVALID_PUBLIC_KEY_LENGTH",
                (
                    f"signature[{index}] public key has "
                    f"{len(public_key_bytes)} bytes; expected 32"
                ),
            )

        signature_bytes = decode_signature(
            entry["signature"],
            index,
        )

        if len(signature_bytes) != 64:
            raise VerificationFailure(
                "INVALID_SIGNATURE_LENGTH",
                (
                    f"signature[{index}] has "
                    f"{len(signature_bytes)} bytes; expected 64"
                ),
            )

        try:
            message = canonical_bytes(statement)
        except CanonicalizationError as exc:
            raise VerificationFailure(
                "INVALID_SIGNATURE_STATEMENT",
                f"signature[{index}]: {exc.code}",
            ) from exc

        try:
            public_key = Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )
            public_key.verify(signature_bytes, message)
        except InvalidSignature as exc:
            raise VerificationFailure(
                "SIGNATURE_VERIFICATION_FAILED",
                f"signature[{index}] is invalid",
            ) from exc
        except ValueError as exc:
            raise VerificationFailure(
                "INVALID_PUBLIC_KEY_ENCODING",
                f"signature[{index}]: {exc}",
            ) from exc

        verified_ids.append(entry["signature_id"])

    return {
        **structural_result,
        "status": "verified",
        "verified_signature_count": len(verified_ids),
        "verified_signature_ids": verified_ids,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--keyring", required=True, type=Path)
    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=Path("registry/schemas"),
    )
    args = parser.parse_args()

    try:
        value = load_json(args.input)
        keyring = load_keyring(args.keyring)
        result = verify_signatures(
            value,
            args.schema_dir,
            keyring,
        )
    except ValidationFailure as exc:
        print(json.dumps({
            "status": "invalid",
            "error_code": exc.code,
            "detail": exc.detail,
        }, separators=(",", ":")))
        return 1
    except VerificationFailure as exc:
        print(json.dumps({
            "status": "unverified",
            "error_code": exc.code,
            "detail": exc.detail,
        }, separators=(",", ":")))
        return 1

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
