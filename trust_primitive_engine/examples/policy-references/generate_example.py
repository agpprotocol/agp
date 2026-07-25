#!/usr/bin/env python3
"""Generate deterministic files for the TPE 2.3 policy-reference example."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
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
EXAMPLE_DIR = Path(__file__).resolve().parent
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_policy_reference_example",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load TPE evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def write_json(name: str, value: Any) -> None:
    (EXAMPLE_DIR / name).write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def key_material(
    *,
    seed: bytes,
    signer_id: str,
    key_id: str,
) -> tuple[dict[str, str], dict[str, str]]:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    return (
        {
            "algorithm": "ed25519",
            "private_key": b64url(seed),
        },
        {
            "signer_id": signer_id,
            "key_id": key_id,
            "algorithm": "ed25519",
            "public_key": b64url(public_key),
        },
    )


def main() -> int:
    evaluator = load_evaluator()

    referenced_policy = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:security-review",
        "version": 1,
        "eligible_roles": ["reviewer"],
        "requirements": [
            {
                "requirement_id": "requirement:security-reviewer",
                "type": "required_signer",
                "signer_id": "authority:security",
            }
        ],
    }
    referenced_policy = evaluator.validate_policy(referenced_policy)
    referenced_digest = evaluator.policy_digest(referenced_policy)

    root_policy = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:production-change",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:operations-approval",
                "type": "required_signer",
                "signer_id": "authority:operations",
            },
            {
                "requirement_id": "requirement:security-policy",
                "type": "policy_reference",
                "policy_id": referenced_policy["policy_id"],
                "policy_version": referenced_policy["version"],
                "policy_digest": referenced_digest,
            },
        ],
    }
    root_policy = evaluator.validate_policy(root_policy)
    root_digest = evaluator.policy_digest(root_policy)

    decision_context = {
        "object_type": "agp.decision-context/2",
        "context_id": "ctx:example:policy-reference:001",
        "created_at": "2026-07-24T20:00:00Z",
        "expires_at": None,
        "evaluation_time": 1784923200,
        "policy": {
            "id": root_policy["policy_id"],
            "version": root_policy["version"],
            "digest": root_digest,
        },
        "proposal": {
            "type": "proposal:production-change",
            "payload": {
                "service": "payments-api",
                "version": "3.0.0",
            },
        },
        "participants": [
            {
                "id": "authority:operations",
                "role": "approver",
                "weight": 1,
            },
            {
                "id": "authority:security",
                "role": "reviewer",
                "weight": 1,
            },
        ],
        "evidence": [],
        "constraints": [],
    }

    operations_private, operations_public = key_material(
        seed=bytes(range(1, 33)),
        signer_id="authority:operations",
        key_id="key:operations:example",
    )
    security_private, security_public = key_material(
        seed=bytes(range(33, 65)),
        signer_id="authority:security",
        key_id="key:security:example",
    )

    write_json("referenced-policy.json", referenced_policy)
    write_json("root-policy.json", root_policy)
    write_json("policy-set.json", [referenced_policy])
    write_json("decision-context.json", decision_context)
    write_json("operations-private-key.json", operations_private)
    write_json("security-private-key.json", security_private)
    write_json(
        "keyring.json",
        {"keys": [operations_public, security_public]},
    )

    for generated in ("signed-context.json", "evaluation-result.json"):
        path = EXAMPLE_DIR / generated
        if path.exists():
            path.unlink()

    print("GENERATED  referenced-policy.json")
    print("GENERATED  root-policy.json")
    print("GENERATED  policy-set.json")
    print("GENERATED  decision-context.json")
    print("GENERATED  deterministic demonstration keys")
    print(f"ROOT DIGEST        {root_digest}")
    print(f"REFERENCED DIGEST  {referenced_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
