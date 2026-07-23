#!/usr/bin/env python3
"""Evaluate AGP Trust Policy 2.0 with the Trust Primitive Engine (TPE)."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Callable


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


from engine import EvaluationState, PrimitiveRegistry
from primitives.global_signature_threshold import (
    GlobalSignatureThresholdPrimitive,
)
from primitives.global_weight_threshold import (
    GlobalWeightThresholdPrimitive,
)
from primitives.required_signer import RequiredSignerPrimitive
from primitives.role_threshold import RoleThresholdPrimitive
from primitives.signer_threshold import SignerThresholdPrimitive


POLICY_OBJECT_TYPE = "agp.trust-policy/2"
EVALUATION_OBJECT_TYPE = "agp.trust-policy-evaluation/2"

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$")
MAX_SAFE_INTEGER = 9007199254740991

POLICY_MEMBERS = {
    "object_type",
    "policy_id",
    "version",
    "eligible_roles",
    "requirements",
}

COMMON_REQUIREMENT_MEMBERS = {
    "requirement_id",
    "type",
}

ALLOWED_ROLES = {
    "proposer",
    "voter",
    "reviewer",
    "approver",
    "observer",
}

SUPPORTED_PRIMITIVES = {
    "required_signer",
    "signer_threshold",
    "global_signature_threshold",
    "global_weight_threshold",
    "role_threshold",
}


PRIMITIVE_REGISTRY = PrimitiveRegistry(
    [
        GlobalSignatureThresholdPrimitive(),
        GlobalWeightThresholdPrimitive(),
        RequiredSignerPrimitive(),
        RoleThresholdPrimitive(),
        SignerThresholdPrimitive(),
    ]
)


class EvaluationFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def reject_duplicate_members(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}

    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON member: {key}")
        result[key] = value

    return result


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


def validate_identifier(value: Any, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} is not a valid identifier",
        )
    return value


def validate_safe_integer(
    value: Any,
    field: str,
    *,
    minimum: int = 0,
) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < minimum
        or value > MAX_SAFE_INTEGER
    ):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{field} must be an integer from {minimum} to {MAX_SAFE_INTEGER}",
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


def validate_exact_members(
    value: dict[str, Any],
    expected: set[str],
    primitive_type: str,
) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))

    if unknown:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{primitive_type} unknown members: {unknown}",
        )

    if missing:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"{primitive_type} missing members: {missing}",
        )


def validate_requirement(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirements[] must be an object",
        )

    primitive_type = value.get("type")

    if primitive_type not in SUPPORTED_PRIMITIVES:
        raise EvaluationFailure(
            "UNSUPPORTED_TRUST_PRIMITIVE",
            f"unsupported primitive type: {primitive_type!r}",
        )

    try:
        return PRIMITIVE_REGISTRY.resolve(
            primitive_type
        ).validate(value)
    except KeyError as exc:
        raise EvaluationFailure(
            "UNSUPPORTED_TRUST_PRIMITIVE",
            f"primitive is not registered: {primitive_type!r}",
        ) from exc
    except ValueError as exc:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            str(exc),
        ) from exc


def validate_policy(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "trust policy must be an object",
        )

    validate_exact_members(value, POLICY_MEMBERS, "trust_policy")

    if value["object_type"] != POLICY_OBJECT_TYPE:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"object_type must be {POLICY_OBJECT_TYPE}",
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

    raw_requirements = value["requirements"]
    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirements must be a non-empty array",
        )

    requirements = [
        validate_requirement(requirement)
        for requirement in raw_requirements
    ]

    requirement_ids = [
        requirement["requirement_id"]
        for requirement in requirements
    ]

    if requirement_ids != sorted(requirement_ids):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirements must be sorted by requirement_id",
        )

    if len(requirement_ids) != len(set(requirement_ids)):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirement_id values must be unique",
        )

    return {
        "object_type": POLICY_OBJECT_TYPE,
        "policy_id": validate_identifier(
            value["policy_id"],
            "policy_id",
        ),
        "version": validate_safe_integer(
            value["version"],
            "version",
            minimum=1,
        ),
        "eligible_roles": eligible_roles,
        "requirements": requirements,
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


def result(
    requirement: dict[str, Any],
    *,
    satisfied: bool,
    matched_signers: list[str],
    observed: dict[str, Any],
    expected: dict[str, Any],
    failure_code: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement["requirement_id"],
        "type": requirement["type"],
        "status": "satisfied" if satisfied else "unsatisfied",
        "matched_signers": sorted(matched_signers),
        "observed": observed,
        "expected": expected,
        "failure_code": None if satisfied else failure_code,
    }


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
            f"context={context_policy['id']} provided={policy['policy_id']}",
        )

    if context_policy["version"] != policy["version"]:
        raise EvaluationFailure(
            "POLICY_VERSION_MISMATCH",
            f"context={context_policy['version']} provided={policy['version']}",
        )

    if context_policy["digest"] != digest:
        raise EvaluationFailure(
            "POLICY_DIGEST_MISMATCH",
            f"context={context_policy['digest']} computed={digest}",
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
        elif participant["role"] not in eligible_roles:
            ineligible_role_signers.append(signer_id)
        else:
            matched_signers.append(signer_id)

    matched_signers.sort()
    unauthorized_signers.sort()
    ineligible_role_signers.sort()

    total_weight = sum(
        int(participants[signer_id]["weight"])
        for signer_id in matched_signers
    )

    engine_state = EvaluationState.create(
        matched_signers=matched_signers,
        participants=participants,
        weight=total_weight,
    )

    requirement_results: list[dict[str, Any]] = []

    for requirement in policy["requirements"]:
        primitive_type = requirement["type"]

        try:
            primitive = PRIMITIVE_REGISTRY.resolve(
                primitive_type
            )
        except KeyError as exc:
            raise EvaluationFailure(
                "UNSUPPORTED_TRUST_PRIMITIVE",
                f"primitive is not registered: {primitive_type!r}",
            ) from exc

        requirement_results.append(
            primitive.evaluate(
                requirement,
                engine_state,
            ).to_dict()
        )

    failures = [
        item["failure_code"]
        for item in requirement_results
        if item["failure_code"] is not None
    ]
    satisfied = not failures

    return {
        "object_type": EVALUATION_OBJECT_TYPE,
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
        "signature_count": len(matched_signers),
        "weight": total_weight,
        "requirement_results": requirement_results,
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
        raise EvaluationFailure(exc.code, exc.detail) from exc
    except VerificationFailure as exc:
        raise EvaluationFailure(exc.code, exc.detail) from exc

    return evaluate_verified_object(
        signed_context,
        verified_policy,
        verification["verified_signature_ids"],
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a Signed Decision Context and evaluate "
            "an AGP Trust Policy 2.0 with TPE."
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
            raise EvaluationFailure(exc.code, exc.detail) from exc

        evaluation = evaluate(
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
            evaluation,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0 if evaluation["status"] == "satisfied" else 2


if __name__ == "__main__":
    raise SystemExit(main())
