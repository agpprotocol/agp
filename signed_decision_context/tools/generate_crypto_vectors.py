#!/usr/bin/env python3
"""Generate persistent Stage 2 Ed25519 conformance vectors."""

from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
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
VECTORS = ROOT / "signed_decision_context" / "vectors"

CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

from canonicalize import canonical_bytes


PRIMARY_PRIVATE_SEED = bytes(range(1, 33))
OTHER_PRIVATE_SEED = bytes(range(33, 65))


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(value: str) -> bytes:
    padding = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + padding)


def private_key(seed: bytes) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_key_text(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
    return b64url(raw)


def encoded(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    )


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
            "payload": {
                "enabled": True,
            },
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
    digest = hashlib.sha256(
        canonical_bytes(context)
    ).hexdigest()

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

    signature = signing_key.sign(
        canonical_bytes(statement)
    )

    return {
        "object_type": "agp.signed-decision-context/1",
        "context": context,
        "context_digest": {
            "algorithm": "sha-256",
            "value": digest,
        },
        "signatures": [
            {
                "signature_id": "sig:authority-legal:0001",
                "statement": statement,
                "signature": b64url(signature),
            }
        ],
    }


def keyring(public_key: str) -> dict[str, Any]:
    return {
        "keys": [
            {
                "signer_id": "authority:legal",
                "key_id": "key:authority-legal:2026-q3",
                "algorithm": "ed25519",
                "public_key": public_key,
            }
        ]
    }


cases: list[dict[str, Any]] = []


def add(
    name: str,
    input_value: dict[str, Any],
    keyring_value: dict[str, Any],
    verified: bool,
    error_code: str | None = None,
) -> None:
    cases.append(
        {
            "name": name,
            "input": input_value,
            "keyring": keyring_value,
            "verified": verified,
            "error_code": error_code,
        }
    )


primary = private_key(PRIMARY_PRIVATE_SEED)
other = private_key(OTHER_PRIVATE_SEED)

valid = signed_object(primary)
valid_keyring = keyring(public_key_text(primary))

add(
    "valid_ed25519_signature",
    valid,
    valid_keyring,
    True,
)

x = deepcopy(valid)
signature_bytes = bytearray(
    b64url_decode(x["signatures"][0]["signature"])
)
signature_bytes[0] ^= 1
x["signatures"][0]["signature"] = b64url(
    bytes(signature_bytes)
)
add(
    "tampered_signature",
    x,
    valid_keyring,
    False,
    "SIGNATURE_VERIFICATION_FAILED",
)

add(
    "wrong_public_key",
    valid,
    keyring(public_key_text(other)),
    False,
    "SIGNATURE_VERIFICATION_FAILED",
)

x = deepcopy(valid_keyring)
x["keys"] = []
add(
    "unknown_key",
    valid,
    x,
    False,
    "UNKNOWN_VERIFICATION_KEY",
)

x = deepcopy(valid)
x["signatures"][0]["statement"]["algorithm"] = "rsa-pss"
add(
    "unsupported_algorithm",
    x,
    valid_keyring,
    False,
    "UNSUPPORTED_SIGNATURE_ALGORITHM",
)

x = deepcopy(valid_keyring)
x["keys"][0]["public_key"] = "AA"
add(
    "invalid_public_key_length",
    valid,
    x,
    False,
    "INVALID_PUBLIC_KEY_LENGTH",
)

x = deepcopy(valid)
x["signatures"][0]["signature"] = "AA"
add(
    "invalid_signature_length",
    x,
    valid_keyring,
    False,
    "INVALID_SIGNATURE_LENGTH",
)

x = deepcopy(valid_keyring)
x["keys"][0]["public_key"] += "="
add(
    "padded_public_key",
    valid,
    x,
    False,
    "INVALID_PUBLIC_KEY_ENCODING",
)


if VECTORS.exists():
    shutil.rmtree(VECTORS)

VECTORS.mkdir(parents=True)

manifest: dict[str, Any] = {
    "profile": "AGP-SIGNED-DECISION-CONTEXT-1.0-CRYPTO",
    "vectors": [],
}

for index, case in enumerate(cases, start=1):
    stem = f"{index:03d}_{case['name']}"

    input_name = f"{stem}.input.json"
    keyring_name = f"{stem}.keyring.json"
    meta_name = f"{stem}.meta.json"

    (VECTORS / input_name).write_bytes(
        encoded(case["input"])
    )

    (VECTORS / keyring_name).write_bytes(
        encoded(case["keyring"])
    )

    (VECTORS / meta_name).write_text(
        json.dumps(
            {
                "vector": case["name"],
                "verified": case["verified"],
                "error_code": case["error_code"],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    manifest["vectors"].append(
        {
            "name": case["name"],
            "input": input_name,
            "keyring": keyring_name,
            "meta": meta_name,
        }
    )

(VECTORS / "manifest.json").write_text(
    json.dumps(manifest, indent=2) + "\n",
    encoding="utf-8",
)

print(
    f"Generated {len(cases)} "
    "Signed Decision Context crypto vectors"
)
