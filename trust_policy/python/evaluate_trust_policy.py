#!/usr/bin/env python3
"""Evaluate AGP Trust Policy 1.0 over a Signed Decision Context."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"
if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

SIGNED_CONTEXT_PYTHON = ROOT / "signed_decision_context" / "python"
if str(SIGNED_CONTEXT_PYTHON) not in sys.path:
    sys.path.insert(0, str(SIGNED_CONTEXT_PYTHON))

from canonicalize import CanonicalizationError, canonical_bytes
from validate_signed_decision_context import ValidationFailure
from verify_signed_decision_context import (
    VerificationFailure,
    load_keyring,
    verify_signatures,
)


POLICY_OBJECT_TYPE = "agp.trust-policy/1"

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)

ALLOWED_ROLES = {
    "proposer",
    "voter",
    "reviewer",
    "approver",
    "observer",
}

MAX_SAFE_INTEGER = 9007199254740991

POLICY_MEMBERS = {
    "object_type",
    "policy_id",
    "version",
    "eligible_roles",
    "required_signers",
    "any_of_signers",
    "minimum_signatures",
    "minimum_weight",
}


class EvaluationFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def load_json(path: Path, error_code: str) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise EvaluationFailure(error_code, str(exc)) from exc

    if raw.startswith(b"\xef\xbb\xbf"):
        raise EvaluationFailure(
            error_code,
            "UTF-8 BOM is not permitted",
        )

    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder(
            parse_float=lambda _: (_ for _ in ()).throw(
                ValueError("decimal numbers are not permitted")
            ),
            parse_constant=lambda _: (_ for _ in ()).throw(
                ValueError("non-finite numbers are not permitted")
            ),
            object_pairs_hook=reject_duplicate_members,
        )
        value, end = decoder.raw_decode(text)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
    ) as exc:
        raise EvaluationFailure(error_code, str(exc)) from exc

    if text[end:].strip():
        raise EvaluationFailure(
            error_code,
            "trailing data is not permitted",
        )

    return value


def reject_duplicate_members(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value

    return result


def validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} is not a valid identifier",
        )

    return value


def validate_safe_positive_integer(
    value: Any,
    field: str,
    *,
    allow_zero: bool = False,
) -> int:
    minimum = 0 if allow_zero else 1

    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            (
                f"{field} must be an integer from "
                f"{minimum} to {MAX_SAFE_INTEGER}"
            ),
        )

    return value


def validate_sorted_unique_identifiers(
    value: Any,
    field: str,
    *,
    allow_empty: bool,
) -> list[str]:
    if not isinstance(value, list):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} must be an array",
        )

    if not allow_empty and not value:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} must not be empty",
        )

    identifiers = [
        validate_identifier(item, f"{field}[]")
        for item in value
    ]

    if identifiers != sorted(identifiers):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} must be lexicographically sorted",
        )

    if len(identifiers) != len(set(identifiers)):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} must not contain duplicates",
        )

    return identifiers


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "trust policy must be an object",
        )

    unknown = sorted(set(value) - POLICY_MEMBERS)
    missing = sorted(POLICY_MEMBERS - set(value))

    if unknown:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"unknown policy members: {unknown}",
        )

    if missing:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"missing policy members: {missing}",
        )

    if value["object_type"] != POLICY_OBJECT_TYPE:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"object_type must be {POLICY_OBJECT_TYPE}",
        )

    policy_id = validate_identifier(
        value["policy_id"],
        "policy_id",
    )

    version = validate_safe_positive_integer(
        value["version"],
        "version",
    )

    eligible_roles = value["eligible_roles"]

    if not isinstance(eligible_roles, list) or not eligible_roles:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "eligible_roles must be a non-empty array",
        )

    if any(
        not isinstance(role, str) or role not in ALLOWED_ROLES
        for role in eligible_roles
    ):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "eligible_roles contains an unsupported role",
        )

    if eligible_roles != sorted(eligible_roles):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "eligible_roles must be lexicographically sorted",
        )

    if len(eligible_roles) != len(set(eligible_roles)):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "eligible_roles must not contain duplicates",
        )

    required_signers = validate_sorted_unique_identifiers(
        value["required_signers"],
        "required_signers",
        allow_empty=True,
    )

    any_of_signers = validate_sorted_unique_identifiers(
        value["any_of_signers"],
        "any_of_signers",
        allow_empty=True,
    )

    minimum_signatures = validate_safe_positive_integer(
        value["minimum_signatures"],
        "minimum_signatures",
        allow_zero=True,
    )

    minimum_weight = validate_safe_positive_integer(
        value["minimum_weight"],
        "minimum_weight",
        allow_zero=True,
    )

    if (
        not required_signers
        and not any_of_signers
        and minimum_signatures == 0
        and minimum_weight == 0
    ):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "policy must declare at least one trust condition",
        )

    return {
        "object_type": POLICY_OBJECT_TYPE,
        "policy_id": policy_id,
        "version": version,
        "eligible_roles": eligible_roles,
        "required_signers": required_signers,
        "any_of_signers": any_of_signers,
        "minimum_signatures": minimum_signatures,
        "minimum_weight": minimum_weight,
    }


def policy_digest(policy: dict[str, Any]) -> str:
    try:
        encoded = canonical_bytes(policy)
    except CanonicalizationError as exc:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"canonicalization failed: {exc.code}",
        ) from exc

    return hashlib.sha256(encoded).hexdigest()


def evaluate_verified_object(
    signed_context: dict[str, Any],
    policy: dict[str, Any],
    verified_signature_ids: list[str],
) -> dict[str, Any]:
    context = signed_context["context"]
    context_policy = context["policy"]

    digest = policy_digest(policy)

    if context_policy["id"] != policy["policy_id"]:
        raise EvaluationFailure(
            "POLICY_ID_MISMATCH",
            (
                f"context={context_policy['id']} "
                f"provided={policy['policy_id']}"
            ),
        )

    if context_policy["version"] != policy["version"]:
        raise EvaluationFailure(
            "POLICY_VERSION_MISMATCH",
            (
                f"context={context_policy['version']} "
                f"provided={policy['version']}"
            ),
        )

    if context_policy["digest"] != digest:
        raise EvaluationFailure(
            "POLICY_DIGEST_MISMATCH",
            (
                f"context={context_policy['digest']} "
                f"computed={digest}"
            ),
        )

    verified_ids = set(verified_signature_ids)

    verified_entries = [
        entry
        for entry in signed_context["signatures"]
        if entry["signature_id"] in verified_ids
    ]

    verified_signers = sorted(
        {
            entry["statement"]["signer_id"]
            for entry in verified_entries
        }
    )

    participants = {
        participant["id"]: participant
        for participant in context["participants"]
    }

    eligible_roles = set(policy["eligible_roles"])

    matched_signers: list[str] = []
    unauthorized_signers: list[str] = []
    ineligible_role_signers: list[str] = []

    for signer_id in verified_signers:
        participant = participants.get(signer_id)

        if participant is None:
            unauthorized_signers.append(signer_id)
            continue

        if participant["role"] not in eligible_roles:
            ineligible_role_signers.append(signer_id)
            continue

        matched_signers.append(signer_id)

    matched_signers.sort()
    unauthorized_signers.sort()
    ineligible_role_signers.sort()

    matched_set = set(matched_signers)

    missing_required_signers = sorted(
        set(policy["required_signers"]) - matched_set
    )

    any_of_satisfied = (
        not policy["any_of_signers"]
        or bool(matched_set.intersection(policy["any_of_signers"]))
    )

    matching_any_of_signers = sorted(
        matched_set.intersection(policy["any_of_signers"])
    )

    signature_count = len(matched_signers)

    total_weight = sum(
        int(participants[signer_id]["weight"])
        for signer_id in matched_signers
    )

    failures: list[str] = []

    if missing_required_signers:
        failures.append("REQUIRED_SIGNER_MISSING")

    if not any_of_satisfied:
        failures.append("ANY_OF_SIGNERS_NOT_SATISFIED")

    if signature_count < policy["minimum_signatures"]:
        failures.append("MINIMUM_SIGNATURES_NOT_REACHED")

    if total_weight < policy["minimum_weight"]:
        failures.append("MINIMUM_WEIGHT_NOT_REACHED")

    satisfied = not failures

    return {
        "object_type": "agp.trust-policy-evaluation/1",
        "status": "satisfied" if satisfied else "unsatisfied",
        "policy_id": policy["policy_id"],
        "policy_version": policy["version"],
        "policy_digest": digest,
        "context_id": context["context_id"],
        "context_digest": signed_context["context_digest"],
        "verified_signature_ids": sorted(verified_ids),
        "verified_signers": verified_signers,
        "matched_signers": matched_signers,
        "unauthorized_signers": unauthorized_signers,
        "ineligible_role_signers": ineligible_role_signers,
        "missing_required_signers": missing_required_signers,
        "matching_any_of_signers": matching_any_of_signers,
        "signature_count": signature_count,
        "minimum_signatures": policy["minimum_signatures"],
        "weight": total_weight,
        "minimum_weight": policy["minimum_weight"],
        "failure_codes": failures,
    }


def evaluate(
    signed_context: dict[str, Any],
    policy: dict[str, Any],
    keyring: list[dict[str, Any]],
    schema_dir: Path,
) -> dict[str, Any]:
    verified_policy = validate_policy(policy)

    try:
        verification = verify_signatures(
            signed_context,
            schema_dir,
            keyring,
        )
    except ValidationFailure as exc:
        raise EvaluationFailure(
            exc.code,
            exc.detail,
        ) from exc
    except VerificationFailure as exc:
        raise EvaluationFailure(
            exc.code,
            exc.detail,
        ) from exc

    return evaluate_verified_object(
        signed_context,
        verified_policy,
        verification["verified_signature_ids"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a Signed Decision Context and evaluate "
            "an AGP Trust Policy 1.0."
        )
    )

    parser.add_argument("input", type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--keyring", required=True, type=Path)

    parser.add_argument(
        "--schema-dir",
        type=Path,
        default=ROOT / "registry" / "schemas",
    )

    args = parser.parse_args()

    try:
        signed_context = load_json(
            args.input,
            "INVALID_SIGNED_DECISION_CONTEXT",
        )
        policy = load_json(
            args.policy,
            "INVALID_TRUST_POLICY",
        )
        try:
            keyring = load_keyring(args.keyring)
        except VerificationFailure as exc:
            raise EvaluationFailure(
                exc.code,
                exc.detail,
            ) from exc

        result = evaluate(
            signed_context,
            policy,
            keyring,
            args.schema_dir,
        )

    except EvaluationFailure as exc:
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
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )

    return 0 if result["status"] == "satisfied" else 2


if __name__ == "__main__":
    raise SystemExit(main())
