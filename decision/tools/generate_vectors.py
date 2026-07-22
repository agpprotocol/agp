from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
VECTOR_DIR = ROOT / "vectors"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def normalized_authority_set(authority_set: dict) -> dict:
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
        "members": sorted(members, key=lambda member: member["member_id"]),
    }


def base_vector() -> dict:
    proposal = {
        "proposal_id": "urn:agp:proposal:deploy-payments-api-2.4.0",
        "action": "deploy",
        "artifact": "payments-api",
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

    context = {
        "agp_profile": "AGP-0.6",
        "context_type": "agp-decision-context",
        "proposal_root": digest(proposal),
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "policy_digest": digest(policy),
        "authority_set_id": authority_set["authority_set_id"],
        "authority_set_digest": digest(
            normalized_authority_set(authority_set)
        ),
        "execution_domain": "production",
        "valid_from": "2026-07-22T14:00:00Z",
        "valid_until": "2026-07-22T16:00:00Z",
        "decision_nonce": "decision-001",
    }

    return {
        "proposal": proposal,
        "policy": policy,
        "authority_set": authority_set,
        "expected_execution_domain": "production",
        "verification_time": "2026-07-22T15:00:00Z",
        "decision_context": context,
    }


def write_vector(filename: str, vector: dict) -> None:
    path = VECTOR_DIR / filename
    path.write_text(
        json.dumps(vector, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def generate() -> None:
    VECTOR_DIR.mkdir(parents=True, exist_ok=True)

    for old_file in VECTOR_DIR.glob("*.json"):
        old_file.unlink()

    valid = base_vector()
    write_vector("001_valid.json", valid)

    changed_proposal = copy.deepcopy(valid)
    changed_proposal["proposal"]["version"] = "2.4.1"
    write_vector("002_proposal_changed.json", changed_proposal)

    changed_policy = copy.deepcopy(valid)
    changed_policy["policy"]["rule"]["quorum_minimum"] = 2
    write_vector("003_policy_changed.json", changed_policy)

    changed_policy_version = copy.deepcopy(valid)
    changed_policy_version["policy"]["policy_version"] = "2"
    write_vector(
        "004_policy_version_changed.json",
        changed_policy_version,
    )

    changed_authority = copy.deepcopy(valid)
    changed_authority["authority_set"]["members"][0]["weight"] = 2
    write_vector("005_authority_changed.json", changed_authority)

    changed_domain = copy.deepcopy(valid)
    changed_domain["expected_execution_domain"] = "staging"
    write_vector("006_execution_domain_changed.json", changed_domain)

    not_yet_valid = copy.deepcopy(valid)
    not_yet_valid["verification_time"] = "2026-07-22T13:59:59Z"
    write_vector("007_not_yet_valid.json", not_yet_valid)

    expired = copy.deepcopy(valid)
    expired["verification_time"] = "2026-07-22T16:00:00Z"
    write_vector("008_expired.json", expired)

    unsupported_profile = copy.deepcopy(valid)
    unsupported_profile["decision_context"]["agp_profile"] = "AGP-9.9"
    write_vector("009_unsupported_profile.json", unsupported_profile)

    invalid_context_type = copy.deepcopy(valid)
    invalid_context_type["decision_context"]["context_type"] = "other"
    write_vector("010_invalid_context_type.json", invalid_context_type)

    reordered_authorities = copy.deepcopy(valid)
    reordered_authorities["authority_set"]["members"].reverse()
    for member in reordered_authorities["authority_set"]["members"]:
        member["roles"].reverse()
    write_vector(
        "011_authority_reordered_valid.json",
        reordered_authorities,
    )

    multiple_failures = copy.deepcopy(valid)
    multiple_failures["proposal"]["version"] = "9.0.0"
    multiple_failures["policy"]["rule"]["quorum_minimum"] = 1
    multiple_failures["expected_execution_domain"] = "staging"
    multiple_failures["verification_time"] = "2026-07-22T17:00:00Z"
    write_vector("012_multiple_failures.json", multiple_failures)

    print("Generated 12 decision-context vectors")


if __name__ == "__main__":
    generate()
