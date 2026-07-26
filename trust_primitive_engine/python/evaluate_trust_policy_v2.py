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


from engine import (
    EvaluationState,
    PolicyEvaluationContext,
    PolicyReferenceIdentity,
    PolicySetIndex,
    PrimitiveRegistry,
    build_policy_set_index,
    UnsupportedPrimitiveError,
    evaluate_policy_document,
    evaluate_requirement,
    project_failure_codes,
    validate_requirement_tree,
)
from primitives.context_values import (
    ContextIntegerAtLeastPrimitive,
    ContextIntegerAtMostPrimitive,
    ContextPathEqualsPrimitive,
    ContextValueEqualsPrimitive,
    ContextValueInPrimitive,
    ContextValuePresentPrimitive,
)
from primitives.evidence_count import EvidenceCountAtLeastPrimitive
from primitives.evidence_present import EvidencePresentPrimitive
from primitives.exactly_n_signers import ExactlyNSignersPrimitive
from primitives.at_least_n_signers import AtLeastNSignersPrimitive
from primitives.at_most_n_signers import AtMostNSignersPrimitive
from primitives.exactly_one_of_signers import ExactlyOneOfSignersPrimitive
from primitives.all_of_signers import AllOfSignersPrimitive
from primitives.any_of_signers import AnyOfSignersPrimitive
from primitives.global_signature_threshold import (
    GlobalSignatureThresholdPrimitive,
)
from primitives.global_weight_threshold import (
    GlobalWeightThresholdPrimitive,
)
from primitives.mutual_exclusion import MutualExclusionPrimitive
from primitives.prohibited_signer import ProhibitedSignerPrimitive
from primitives.required_signer import RequiredSignerPrimitive
from primitives.role_threshold import RoleThresholdPrimitive
from primitives.role_weight_threshold import (
    RoleWeightThresholdPrimitive,
)
from primitives.separation_of_duties import (
    SeparationOfDutiesPrimitive,
)
from primitives.signer_threshold import SignerThresholdPrimitive
from primitives.time_window import TimeWindowPrimitive


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

POLICY_REFERENCE_TYPE = "policy_reference"

POLICY_REFERENCE_MEMBERS = {
    "requirement_id",
    "type",
    "policy_id",
    "policy_version",
    "policy_digest",
}

MAX_POLICY_REFERENCE_DEPTH = 8
MAX_REFERENCED_POLICIES = 32
MAX_EXPANDED_REQUIREMENT_NODES = 2048

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
    "evidence_count_at_least",
    "evidence_present",
    "context_integer_at_least",
    "context_integer_at_most",
    "context_path_equals",
    "context_value_equals",
    "context_value_in",
    "context_value_present",
    "exactly_n_signers",
    "at_least_n_signers",
    "at_most_n_signers",
    "exactly_one_of_signers",
    "all_of_signers",
    "any_of_signers",
    "required_signer",
    "signer_threshold",
    "global_signature_threshold",
    "global_weight_threshold",
    "mutual_exclusion",
    "prohibited_signer",
    "role_threshold",
    "role_weight_threshold",
    "separation_of_duties",
    "time_window",
}


PRIMITIVE_REGISTRY = PrimitiveRegistry(
    [
        EvidenceCountAtLeastPrimitive(),
        EvidencePresentPrimitive(),
        ContextIntegerAtLeastPrimitive(),
        ContextIntegerAtMostPrimitive(),
        ContextPathEqualsPrimitive(),
        ContextValueEqualsPrimitive(),
        ContextValueInPrimitive(),
        ContextValuePresentPrimitive(),
        ExactlyNSignersPrimitive(),
        AtLeastNSignersPrimitive(),
        AtMostNSignersPrimitive(),
        ExactlyOneOfSignersPrimitive(),
        AllOfSignersPrimitive(),
        AnyOfSignersPrimitive(),
        GlobalSignatureThresholdPrimitive(),
        GlobalWeightThresholdPrimitive(),
        MutualExclusionPrimitive(),
        ProhibitedSignerPrimitive(),
        RequiredSignerPrimitive(),
        RoleThresholdPrimitive(),
        RoleWeightThresholdPrimitive(),
        SeparationOfDutiesPrimitive(),
        SignerThresholdPrimitive(),
        TimeWindowPrimitive(),
    ]
)


class EvaluationFailure(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code
        self.detail = detail


def load_policy_set_index(
    path: Path,
) -> PolicySetIndex:
    """Load and deterministically index one explicit policy set."""

    raw_policy_set = load_json(
        path,
        "INVALID_TRUST_POLICY_SET",
    )

    try:
        return build_policy_set_index(
            raw_policy_set,
            validate_policy=validate_policy,
            compute_digest=policy_digest,
        )
    except ValueError as exc:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY_SET",
            str(exc),
        ) from exc


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


def validate_policy_reference(
    value: dict[str, Any],
) -> dict[str, Any]:
    validate_exact_members(
        value,
        POLICY_REFERENCE_MEMBERS,
        POLICY_REFERENCE_TYPE,
    )

    if value["type"] != POLICY_REFERENCE_TYPE:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            f"type must be {POLICY_REFERENCE_TYPE}",
        )

    digest = value["policy_digest"]

    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(
            character not in "0123456789abcdef"
            for character in digest
        )
    ):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "policy_digest must be exactly 64 lowercase "
            "hexadecimal characters",
        )

    return {
        "requirement_id": validate_identifier(
            value["requirement_id"],
            "requirement_id",
        ),
        "type": POLICY_REFERENCE_TYPE,
        "policy_id": validate_identifier(
            value["policy_id"],
            "policy_id",
        ),
        "policy_version": validate_safe_integer(
            value["policy_version"],
            "policy_version",
            minimum=1,
        ),
        "policy_digest": digest,
    }


def resolve_policy_reference(
    requirement: dict[str, Any],
    policy_set_index: PolicySetIndex,
) -> dict[str, Any]:
    """Resolve one validated policy_reference deterministically."""

    if requirement.get("type") != POLICY_REFERENCE_TYPE:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirement must be a validated policy_reference",
        )

    policy_id = requirement["policy_id"]
    policy_version = requirement["policy_version"]
    expected_digest = requirement["policy_digest"]

    entry = policy_set_index.resolve(
        policy_id,
        policy_version,
    )

    if entry is None:
        raise EvaluationFailure(
            "POLICY_REFERENCE_NOT_FOUND",
            (
                f"policy_id={policy_id} "
                f"policy_version={policy_version}"
            ),
        )

    identity = entry.identity

    if identity.policy_id != policy_id:
        raise EvaluationFailure(
            "POLICY_REFERENCE_ID_MISMATCH",
            (
                f"reference={policy_id} "
                f"resolved={identity.policy_id}"
            ),
        )

    if identity.policy_version != policy_version:
        raise EvaluationFailure(
            "POLICY_REFERENCE_VERSION_MISMATCH",
            (
                f"reference={policy_version} "
                f"resolved={identity.policy_version}"
            ),
        )

    if identity.policy_digest != expected_digest:
        raise EvaluationFailure(
            "POLICY_REFERENCE_DIGEST_MISMATCH",
            (
                f"reference={expected_digest} "
                f"computed={identity.policy_digest}"
            ),
        )

    return entry.to_policy()


def iter_requirement_nodes(
    requirements: list[dict[str, Any]],
):
    """Yield every validated requirement node deterministically."""

    for requirement in requirements:
        yield requirement

        requirement_type = requirement["type"]

        if requirement_type in {"all_of", "any_of"}:
            yield from iter_requirement_nodes(
                requirement["requirements"]
            )
        elif requirement_type == "not":
            yield from iter_requirement_nodes(
                [requirement["requirement"]]
            )


def validate_policy_reference_graph(
    root_policy: dict[str, Any],
    policy_set_index: PolicySetIndex,
    *,
    max_reference_depth: int = MAX_POLICY_REFERENCE_DEPTH,
    max_referenced_policies: int = MAX_REFERENCED_POLICIES,
    max_expanded_nodes: int = MAX_EXPANDED_REQUIREMENT_NODES,
) -> dict[str, Any]:
    """Validate the complete reachable policy-reference graph."""

    if (
        not isinstance(max_reference_depth, int)
        or isinstance(max_reference_depth, bool)
        or max_reference_depth < 1
        or max_reference_depth > MAX_POLICY_REFERENCE_DEPTH
    ):
        raise ValueError(
            "max_reference_depth must be an integer from "
            f"1 to {MAX_POLICY_REFERENCE_DEPTH}"
        )

    if (
        not isinstance(max_referenced_policies, int)
        or isinstance(max_referenced_policies, bool)
        or max_referenced_policies < 1
        or max_referenced_policies > MAX_REFERENCED_POLICIES
    ):
        raise ValueError(
            "max_referenced_policies must be an integer from "
            f"1 to {MAX_REFERENCED_POLICIES}"
        )

    if (
        not isinstance(max_expanded_nodes, int)
        or isinstance(max_expanded_nodes, bool)
        or max_expanded_nodes < MAX_EXPANDED_REQUIREMENT_NODES
    ):
        raise ValueError(
            "max_expanded_nodes must be an integer greater than "
            f"or equal to {MAX_EXPANDED_REQUIREMENT_NODES}"
        )

    normalized_root = validate_policy(root_policy)

    root_identity = PolicyReferenceIdentity(
        policy_id=normalized_root["policy_id"],
        policy_version=normalized_root["version"],
        policy_digest=policy_digest(normalized_root),
    )

    active_path: set[PolicyReferenceIdentity] = set()
    completed: set[PolicyReferenceIdentity] = set()
    reachable: dict[
        PolicyReferenceIdentity,
        dict[str, Any],
    ] = {}
    resolution_order: list[PolicyReferenceIdentity] = []

    expanded_node_count = sum(
        1
        for _ in iter_requirement_nodes(
            normalized_root["requirements"]
        )
    )

    if expanded_node_count > max_expanded_nodes:
        raise EvaluationFailure(
            "POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
            (
                f"expanded_requirement_count="
                f"{expanded_node_count} "
                f"limit={max_expanded_nodes}"
            ),
        )

    def visit_policy(
        policy: dict[str, Any],
        identity: PolicyReferenceIdentity,
        *,
        reference_depth: int,
    ) -> None:
        nonlocal expanded_node_count

        active_path.add(identity)

        try:
            for requirement in iter_requirement_nodes(
                policy["requirements"]
            ):
                if requirement["type"] != POLICY_REFERENCE_TYPE:
                    continue

                resolved_policy = resolve_policy_reference(
                    requirement,
                    policy_set_index,
                )

                entry = policy_set_index.resolve(
                    requirement["policy_id"],
                    requirement["policy_version"],
                )

                if entry is None:
                    raise EvaluationFailure(
                        "POLICY_REFERENCE_NOT_FOUND",
                        (
                            f"policy_id="
                            f"{requirement['policy_id']} "
                            f"policy_version="
                            f"{requirement['policy_version']}"
                        ),
                    )

                referenced_identity = entry.identity

                if referenced_identity in active_path:
                    raise EvaluationFailure(
                        "POLICY_REFERENCE_CYCLE",
                        (
                            f"policy_id="
                            f"{referenced_identity.policy_id} "
                            f"policy_version="
                            f"{referenced_identity.policy_version} "
                            f"policy_digest="
                            f"{referenced_identity.policy_digest}"
                        ),
                    )

                if referenced_identity in completed:
                    continue

                next_depth = reference_depth + 1

                if next_depth > max_reference_depth:
                    raise EvaluationFailure(
                        "POLICY_REFERENCE_DEPTH_EXCEEDED",
                        (
                            f"reference_depth={next_depth} "
                            f"limit={max_reference_depth}"
                        ),
                    )

                if referenced_identity not in reachable:
                    if (
                        len(reachable) + 1
                        > max_referenced_policies
                    ):
                        raise EvaluationFailure(
                            "POLICY_REFERENCE_COUNT_EXCEEDED",
                            (
                                f"referenced_policy_count="
                                f"{len(reachable) + 1} "
                                f"limit="
                                f"{max_referenced_policies}"
                            ),
                        )

                    referenced_node_count = sum(
                        1
                        for _ in iter_requirement_nodes(
                            resolved_policy["requirements"]
                        )
                    )

                    expanded_node_count += referenced_node_count

                    if expanded_node_count > max_expanded_nodes:
                        raise EvaluationFailure(
                            "POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
                            (
                                f"expanded_requirement_count="
                                f"{expanded_node_count} "
                                f"limit={max_expanded_nodes}"
                            ),
                        )

                    reachable[referenced_identity] = (
                        resolved_policy
                    )
                    resolution_order.append(
                        referenced_identity
                    )

                visit_policy(
                    resolved_policy,
                    referenced_identity,
                    reference_depth=next_depth,
                )
        finally:
            active_path.remove(identity)

        completed.add(identity)

    visit_policy(
        normalized_root,
        root_identity,
        reference_depth=0,
    )

    return {
        "root_policy": normalized_root,
        "root_identity": root_identity,
        "reachable_policies": tuple(
            (
                identity,
                reachable[identity],
            )
            for identity in sorted(reachable)
        ),
        "resolution_order": tuple(resolution_order),
        "referenced_policy_count": len(reachable),
        "expanded_requirement_count": expanded_node_count,
    }


def validate_requirement(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "requirements[] must be an object",
        )

    primitive_type = value.get("type")

    if not isinstance(primitive_type, str):
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            "primitive type must be a string",
        )

    if primitive_type == POLICY_REFERENCE_TYPE:
        return validate_policy_reference(value)

    if primitive_type not in SUPPORTED_PRIMITIVES:
        raise UnsupportedPrimitiveError(
            f"unsupported primitive type: {primitive_type!r}"
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

    try:
        requirements = validate_requirement_tree(
            value["requirements"],
            validate_leaf=validate_requirement,
            validate_identifier=validate_identifier,
        )
    except UnsupportedPrimitiveError as exc:
        raise EvaluationFailure(
            "UNSUPPORTED_TRUST_PRIMITIVE",
            str(exc),
        ) from exc
    except ValueError as exc:
        raise EvaluationFailure(
            "INVALID_TRUST_POLICY",
            str(exc),
        ) from exc

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
    *,
    policy_set_index: PolicySetIndex | None = None,
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

    evaluation_time = (
        context.get("evaluation_time")
        if context.get("object_type") == "agp.decision-context/2"
        else None
    )

    engine_state = EvaluationState.create(
        matched_signers=matched_signers,
        participants=participants,
        weight=total_weight,
        evaluation_time=evaluation_time,
        decision_context=context,
    )

    has_policy_references = any(
        requirement["type"] == POLICY_REFERENCE_TYPE
        for requirement in iter_requirement_nodes(
            policy["requirements"]
        )
    )

    if has_policy_references:
        if policy_set_index is None:
            raise EvaluationFailure(
                "POLICY_REFERENCE_SET_REQUIRED",
                "policy contains policy_reference requirements "
                "but no PolicySetIndex was provided",
            )

        validate_policy_reference_graph(
            policy,
            policy_set_index,
        )

        recursive_context = PolicyEvaluationContext(
            verified_signers=tuple(verified_signers),
            participants=participants,
            evaluation_time=evaluation_time,
            decision_context=context,
            policy_set=policy_set_index,
            registry=PRIMITIVE_REGISTRY,
        )

        recursive_result = evaluate_policy_document(
            policy,
            policy_id=policy["policy_id"],
            policy_version=policy["version"],
            policy_digest=digest,
            context=recursive_context,
        )

        result_objects = recursive_result.requirement_results
        requirement_results = [
            result.to_dict()
            for result in result_objects
        ]
        failures = list(recursive_result.failure_codes)
        satisfied = recursive_result.satisfied
    else:
        try:
            result_objects = tuple(
                evaluate_requirement(
                    requirement,
                    engine_state,
                    PRIMITIVE_REGISTRY,
                )
                for requirement in policy["requirements"]
            )
        except KeyError as exc:
            raise EvaluationFailure(
                "UNSUPPORTED_TRUST_PRIMITIVE",
                str(exc),
            ) from exc

        requirement_results = [
            result.to_dict()
            for result in result_objects
        ]
        failures = project_failure_codes(result_objects)
        satisfied = all(
            result.satisfied
            for result in result_objects
        )

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
    *,
    policy_set_index: PolicySetIndex | None = None,
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
        policy_set_index=policy_set_index,
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
    parser.add_argument(
        "--policy-set",
        type=Path,
        help=(
            "optional JSON array of referenced Trust Policy "
            "objects"
        ),
    )
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

        policy_set_index = (
            load_policy_set_index(args.policy_set)
            if args.policy_set is not None
            else None
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
            policy_set_index=policy_set_index,
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
