from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "decision" / "signed" / "vectors"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(
        canonical_bytes(value)
    ).hexdigest()


def normalize_authority_set(authority_set: dict) -> dict:
    members = [
        {
            "member_id": member["member_id"],
            "roles": sorted(member.get("roles", [])),
            "weight": int(member.get("weight", 1)),
        }
        for member in authority_set["members"]
    ]

    return {
        "authority_set_id": authority_set["authority_set_id"],
        "members": sorted(
            members,
            key=lambda member: member["member_id"],
        ),
    }


def sign_envelope(envelope: dict) -> dict:
    unsigned = {
        key: value
        for key, value in envelope.items()
        if key != "signature"
    }

    signed = copy.deepcopy(unsigned)
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(unsigned))
    ).decode("ascii")

    return signed


def write_vector(
    number: int,
    name: str,
    envelope: dict,
    *,
    expected: bool,
    expected_errors: list[str],
    expected_execution_domain: str = "production",
    verification_time: str = "2026-07-22T15:00:00Z",
) -> None:
    vector = {
        "envelope": envelope,
        "expected": expected,
        "expected_errors": expected_errors,
        "expected_execution_domain": expected_execution_domain,
        "keyring": [
            {
                "algorithm": "Ed25519",
                "issuer": "agent:deployment-governance",
                "key_id": "decision-key-1",
                "public_key": public_key,
                "revoked_at": None,
                "valid_from": "2026-01-01T00:00:00Z",
                "valid_until": "2027-01-01T00:00:00Z",
            }
        ],
        "name": name,
        "seen_nonces": [],
        "verification_time": verification_time,
    }

    path = OUTPUT / f"{number:03d}_{name}.json"
    path.write_text(
        json.dumps(
            vector,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
        )
        + "\n",
        encoding="utf-8",
    )


private_key = Ed25519PrivateKey.from_private_bytes(
    bytes([7]) * 32
)

public_key = base64.b64encode(
    private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )
).decode("ascii")


proposal = {
    "action": "deploy",
    "artifact": "payments-api",
    "proposal_id": (
        "urn:agp:proposal:deploy-payments-api-2.4.0"
    ),
    "version": "2.4.0",
}

policy = {
    "policy_id": "urn:agp:policy:production-deployment",
    "policy_version": "1",
    "rule": {
        "abstention_counts_toward_quorum": True,
        "formal_objection_effect": "escalate",
        "quorum_minimum": 3,
        "tie_resolution": "human_escalation",
        "veto_roles": ["legal", "security"],
    },
}

authority_set = {
    "authority_set_id": "urn:agp:authority-set:deployment:v1",
    "members": [
        {
            "member_id": "agent:finance",
            "roles": ["finance"],
            "weight": 1,
        },
        {
            "member_id": "agent:security",
            "roles": ["security"],
            "weight": 1,
        },
        {
            "member_id": "agent:legal",
            "roles": ["legal"],
            "weight": 1,
        },
        {
            "member_id": "agent:ops",
            "roles": ["operations"],
            "weight": 1,
        },
    ],
}

decision_context = {
    "agp_profile": "AGP-0.6",
    "authority_set_digest": digest(
        normalize_authority_set(authority_set)
    ),
    "authority_set_id": authority_set["authority_set_id"],
    "context_type": "agp-decision-context",
    "decision_nonce": "signed-decision-001",
    "execution_domain": "production",
    "policy_digest": digest(policy),
    "policy_id": policy["policy_id"],
    "policy_version": policy["policy_version"],
    "proposal_root": digest(proposal),
    "valid_from": "2026-07-22T14:00:00Z",
    "valid_until": "2026-07-22T16:00:00Z",
}

payload = {
    "authority_set": authority_set,
    "decision_context": decision_context,
    "policy": policy,
    "proposal": proposal,
}

base_envelope = {
    "envelope_id": (
        "urn:agp:envelope:signed-decision:001"
    ),
    "expires_at": "2026-07-22T18:00:00Z",
    "issued_at": "2026-07-22T14:00:00Z",
    "issuer": "agent:deployment-governance",
    "key_id": "decision-key-1",
    "nonce": "signed-decision-envelope-001",
    "object_type": "decision_context",
    "payload": payload,
}


OUTPUT.mkdir(parents=True, exist_ok=True)

for old_vector in OUTPUT.glob("*.json"):
    old_vector.unlink()


# 001: Todo coincide.
write_vector(
    1,
    "signed_decision_valid",
    sign_envelope(base_envelope),
    expected=True,
    expected_errors=[],
)


# 002: El payload cambia después de la firma.
# Debe fallar criptográficamente antes de evaluar el contexto.
tampered = sign_envelope(base_envelope)
tampered["payload"]["proposal"]["version"] = "9.9.9"

write_vector(
    2,
    "tampered_payload",
    tampered,
    expected=False,
    expected_errors=["INVALID_SIGNATURE"],
)


# 003: La política cambia y el atacante vuelve a firmar.
# La firma es válida, pero el digest del contexto quedó obsoleto.
policy_changed = copy.deepcopy(base_envelope)
policy_changed["envelope_id"] = (
    "urn:agp:envelope:signed-decision:003"
)
policy_changed["nonce"] = "signed-decision-envelope-003"
policy_changed["payload"]["policy"]["rule"][
    "quorum_minimum"
] = 2

write_vector(
    3,
    "resigned_policy_mismatch",
    sign_envelope(policy_changed),
    expected=False,
    expected_errors=["POLICY_DIGEST_MISMATCH"],
)


# 004: El dominio firmado es production, pero el ejecutor
# local está configurado para staging.
write_vector(
    4,
    "execution_domain_mismatch",
    sign_envelope(
        {
            **copy.deepcopy(base_envelope),
            "envelope_id": (
                "urn:agp:envelope:signed-decision:004"
            ),
            "nonce": "signed-decision-envelope-004",
        }
    ),
    expected=False,
    expected_errors=["EXECUTION_DOMAIN_MISMATCH"],
    expected_execution_domain="staging",
)


# 005: El contexto está vencido, aunque el sobre criptográfico
# permanece vigente hasta las 18:00.
context_expired = copy.deepcopy(base_envelope)
context_expired["envelope_id"] = (
    "urn:agp:envelope:signed-decision:005"
)
context_expired["nonce"] = "signed-decision-envelope-005"
context_expired["payload"]["decision_context"][
    "valid_until"
] = "2026-07-22T14:30:00Z"

write_vector(
    5,
    "decision_context_expired",
    sign_envelope(context_expired),
    expected=False,
    expected_errors=["DECISION_EXPIRED"],
)


# 006: Firma válida, payload válido, tipo de objeto incorrecto.
wrong_type = copy.deepcopy(base_envelope)
wrong_type["envelope_id"] = (
    "urn:agp:envelope:signed-decision:006"
)
wrong_type["nonce"] = "signed-decision-envelope-006"
wrong_type["object_type"] = "ballot"

write_vector(
    6,
    "wrong_object_type",
    sign_envelope(wrong_type),
    expected=False,
    expected_errors=["WRONG_OBJECT_TYPE"],
)


# 007: Se sustituye un miembro y el sobre se vuelve a firmar.
# La firma es válida, pero el authority_set_digest no coincide.
authority_changed = copy.deepcopy(base_envelope)
authority_changed["envelope_id"] = (
    "urn:agp:envelope:signed-decision:007"
)
authority_changed["nonce"] = "signed-decision-envelope-007"
authority_changed["payload"]["authority_set"]["members"][0][
    "member_id"
] = "agent:attacker"

write_vector(
    7,
    "resigned_authority_mismatch",
    sign_envelope(authority_changed),
    expected=False,
    expected_errors=["AUTHORITY_SET_MISMATCH"],
)


print("Generated 7 signed decision-context vectors")
