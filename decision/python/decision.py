from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROFILE = "AGP-0.6"
CONTEXT_TYPE = "agp-decision-context"

ERROR_ORDER = [
    "INVALID_DECISION_CONTEXT",
    "UNSUPPORTED_PROFILE",
    "PROPOSAL_ROOT_MISMATCH",
    "POLICY_VERSION_MISMATCH",
    "POLICY_DIGEST_MISMATCH",
    "AUTHORITY_SET_MISMATCH",
    "EXECUTION_DOMAIN_MISMATCH",
    "DECISION_NOT_YET_VALID",
    "DECISION_EXPIRED",
]


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    parsed = datetime.fromisoformat(value)

    if parsed.tzinfo is None:
        raise ValueError("timestamp must contain timezone")

    return parsed.astimezone(timezone.utc)


def normalize_members(members: list[dict]) -> list[dict]:
    normalized: list[dict] = []

    for member in members:
        normalized.append(
            {
                "member_id": member["member_id"],
                "roles": sorted(member.get("roles", [])),
                "weight": int(member.get("weight", 1)),
            }
        )

    return sorted(normalized, key=lambda item: item["member_id"])


def normalize_authority_set(authority_set: dict) -> dict:
    return {
        "authority_set_id": authority_set["authority_set_id"],
        "members": normalize_members(authority_set["members"]),
    }


def normalize_policy(policy: dict) -> dict:
    return {
        "policy_id": policy["policy_id"],
        "policy_version": policy["policy_version"],
        "rule": policy["rule"],
    }


def normalize_proposal(proposal: dict) -> dict:
    return proposal


def normalize_decision_context(context: dict) -> dict:
    fields = [
        "agp_profile",
        "context_type",
        "proposal_root",
        "policy_id",
        "policy_version",
        "policy_digest",
        "authority_set_id",
        "authority_set_digest",
        "execution_domain",
        "valid_from",
        "valid_until",
        "decision_nonce",
    ]

    return {field: context[field] for field in fields}


def validate_input(data: dict) -> tuple[dict | None, list[str]]:
    errors: list[str] = []

    try:
        proposal = normalize_proposal(data["proposal"])
        policy = normalize_policy(data["policy"])
        authority_set = normalize_authority_set(data["authority_set"])
        context = normalize_decision_context(data["decision_context"])
        verification_time = parse_time(data["verification_time"])
        expected_execution_domain = data["expected_execution_domain"]

        valid_from = parse_time(context["valid_from"])
        valid_until = parse_time(context["valid_until"])

        if valid_until <= valid_from:
            raise ValueError("valid_until must be after valid_from")

    except (KeyError, TypeError, ValueError):
        return None, ["INVALID_DECISION_CONTEXT"]

    proposal_root = sha256_digest(proposal)
    policy_digest = sha256_digest(policy)
    authority_set_digest = sha256_digest(authority_set)
    decision_root = sha256_digest(context)

    if context["agp_profile"] != PROFILE:
        errors.append("UNSUPPORTED_PROFILE")

    if context["context_type"] != CONTEXT_TYPE:
        errors.append("INVALID_DECISION_CONTEXT")

    if context["proposal_root"] != proposal_root:
        errors.append("PROPOSAL_ROOT_MISMATCH")

    if context["policy_id"] != policy["policy_id"]:
        errors.append("POLICY_DIGEST_MISMATCH")

    if context["policy_version"] != policy["policy_version"]:
        errors.append("POLICY_VERSION_MISMATCH")

    if context["policy_digest"] != policy_digest:
        errors.append("POLICY_DIGEST_MISMATCH")

    if (
        context["authority_set_id"] != authority_set["authority_set_id"]
        or context["authority_set_digest"] != authority_set_digest
    ):
        errors.append("AUTHORITY_SET_MISMATCH")

    if context["execution_domain"] != expected_execution_domain:
        errors.append("EXECUTION_DOMAIN_MISMATCH")

    if verification_time < valid_from:
        errors.append("DECISION_NOT_YET_VALID")

    if verification_time >= valid_until:
        errors.append("DECISION_EXPIRED")

    unique_errors = sorted(
        set(errors),
        key=lambda code: ERROR_ORDER.index(code),
    )

    receipt = {
        "accepted": len(unique_errors) == 0,
        "authority_set_digest": authority_set_digest,
        "decision_root": decision_root,
        "error_codes": unique_errors,
        "execution_domain": context["execution_domain"],
        "policy_digest": policy_digest,
        "proposal_root": proposal_root,
    }

    return receipt, unique_errors


def verify(data: dict) -> dict:
    receipt, errors = validate_input(data)

    if receipt is not None:
        return receipt

    return {
        "accepted": False,
        "authority_set_digest": None,
        "decision_root": None,
        "error_codes": errors,
        "execution_domain": None,
        "policy_digest": None,
        "proposal_root": None,
    }


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit(
            "usage: decision.py INPUT.json|INPUT_DIR OUTPUT.json|OUTPUT_DIR"
        )

    source, target = map(Path, sys.argv[1:])

    if source.is_dir():
        target.mkdir(parents=True, exist_ok=True)

        for item in sorted(source.glob("*.json")):
            result = verify(json.loads(item.read_text(encoding="utf-8")))
            (target / item.name).write_bytes(canonical_bytes(result) + b"\n")

        return

    result = verify(json.loads(source.read_text(encoding="utf-8")))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(canonical_bytes(result) + b"\n")


if __name__ == "__main__":
    main()
