#!/usr/bin/env python3
"""Ephemeral Stage 2 Ed25519 conformance runner."""

from __future__ import annotations

import base64
import hashlib
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


ROOT = Path(__file__).resolve().parents[2]

VERIFIER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "verify_signed_decision_context.py"
)

SCHEMA_DIR = ROOT / "registry" / "schemas"
CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"

if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

from canonicalize import canonical_bytes


PRIVATE_SEED = bytes(range(1, 33))
OTHER_PRIVATE_SEED = bytes(range(33, 65))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return b64url(raw)


def base_context() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/1",
        "context_id": "ctx:example:001",
        "created_at": "2026-07-22T20:00:00Z",
        "expires_at": None,
        "policy": {
            "id": "policy:example:approval",
            "version": 1,
            "digest": "1" * 64,
        },
        "proposal": {
            "type": "proposal:example:change",
            "payload": {"enabled": True},
        },
        "participants": [
            {
                "id": "authority:legal",
                "role": "approver",
                "weight": 1,
            }
        ],
        "evidence": [],
        "constraints": [],
    }


def signed_object(
    signing_key: Ed25519PrivateKey,
) -> dict[str, Any]:
    context = base_context()
    digest = hashlib.sha256(canonical_bytes(context)).hexdigest()

    statement = {
        "object_type": "agp.signature-statement/1",
        "purpose": "decision-context-attestation",
        "context_object_type": "agp.decision-context/1",
        "context_digest": {
            "algorithm": "sha-256",
            "value": digest,
        },
        "signer_id": "authority:legal",
        "key_id": "key:authority-legal:2026-q3",
        "algorithm": "ed25519",
        "signed_at": "2026-07-22T20:00:00Z",
    }

    signature = signing_key.sign(canonical_bytes(statement))

    return {
        "object_type": "agp.signed-decision-context/1",
        "context": context,
        "context_digest": {
            "algorithm": "sha-256",
            "value": digest,
        },
        "signatures": [{
            "signature_id": "sig:authority-legal:0001",
            "statement": statement,
            "signature": b64url(signature),
        }],
    }


def keyring(public_key: str) -> dict[str, Any]:
    return {
        "keys": [{
            "signer_id": "authority:legal",
            "key_id": "key:authority-legal:2026-q3",
            "algorithm": "ed25519",
            "public_key": public_key,
        }]
    }


def run_case(
    name: str,
    obj: dict[str, Any],
    keys: dict[str, Any],
    expected_code: str | None,
) -> bool:
    with tempfile.TemporaryDirectory() as directory:
        directory_path = Path(directory)
        object_path = directory_path / "object.json"
        keyring_path = directory_path / "keyring.json"

        object_path.write_text(
            json.dumps(
                obj,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

        keyring_path.write_text(
            json.dumps(
                keys,
                ensure_ascii=False,
                separators=(",", ":"),
            ),
            encoding="utf-8",
        )

        process = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                str(object_path),
                "--keyring",
                str(keyring_path),
                "--schema-dir",
                str(SCHEMA_DIR),
            ],
            text=True,
            capture_output=True,
        )

    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        print(
            f"FAIL {name}: invalid verifier output: "
            f"{process.stdout!r}"
        )
        if process.stderr:
            print(f"  stderr={process.stderr!r}")
        return False

    actual = (
        None
        if result.get("status") == "verified"
        else result.get("error_code")
    )

    passed = actual == expected_code

    print(
        f"{'PASS' if passed else 'FAIL'} {name}: "
        f"expected={expected_code} actual={actual}"
    )

    if not passed and result.get("detail"):
        print(f"  detail={result['detail']}")

    return passed


def main() -> int:
    primary = private_key(PRIVATE_SEED)
    other = private_key(OTHER_PRIVATE_SEED)

    valid = signed_object(primary)
    valid_keyring = keyring(public_key_text(primary))

    cases: list[
        tuple[
            str,
            dict[str, Any],
            dict[str, Any],
            str | None,
        ]
    ] = [
        (
            "valid_ed25519_signature",
            valid,
            valid_keyring,
            None,
        ),
    ]

    x = deepcopy(valid)
    signature = x["signatures"][0]["signature"]
    replacement = "A" if signature[-1] != "A" else "B"
    x["signatures"][0]["signature"] = signature[:-1] + replacement
    cases.append((
        "tampered_signature",
        x,
        valid_keyring,
        "SIGNATURE_VERIFICATION_FAILED",
    ))

    cases.append((
        "wrong_public_key",
        valid,
        keyring(public_key_text(other)),
        "SIGNATURE_VERIFICATION_FAILED",
    ))

    x = deepcopy(valid_keyring)
    x["keys"] = []
    cases.append((
        "unknown_key",
        valid,
        x,
        "UNKNOWN_VERIFICATION_KEY",
    ))

    x = deepcopy(valid)
    x["signatures"][0]["statement"]["algorithm"] = "rsa-pss"
    cases.append((
        "unsupported_algorithm",
        x,
        keyring(public_key_text(primary)),
        "UNSUPPORTED_SIGNATURE_ALGORITHM",
    ))

    x = deepcopy(valid_keyring)
    x["keys"][0]["public_key"] = "AA"
    cases.append((
        "invalid_public_key_length",
        valid,
        x,
        "INVALID_PUBLIC_KEY_LENGTH",
    ))

    x = deepcopy(valid)
    x["signatures"][0]["signature"] = "AA"
    cases.append((
        "invalid_signature_length",
        x,
        valid_keyring,
        "INVALID_SIGNATURE_LENGTH",
    ))

    x = deepcopy(valid_keyring)
    x["keys"][0]["public_key"] += "="
    cases.append((
        "padded_public_key",
        valid,
        x,
        "INVALID_PUBLIC_KEY_ENCODING",
    ))

    passed = all(run_case(*case) for case in cases)
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
