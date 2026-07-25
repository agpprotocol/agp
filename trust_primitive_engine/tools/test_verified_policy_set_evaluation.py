#!/usr/bin/env python3
"""Verified-object integration checks for TPE 2.3 policy sets."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_policy_set_integration",
        EVALUATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(
    policy_id: str,
    *,
    roles: list[str],
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": 1,
        "eligible_roles": roles,
        "requirements": requirements,
    }


def required_signer(
    requirement_id: str,
    signer_id: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "required_signer",
        "signer_id": signer_id,
    }


def reference(
    evaluator: Any,
    target: dict[str, Any],
    requirement_id: str,
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(target)

    return {
        "requirement_id": requirement_id,
        "type": "policy_reference",
        "policy_id": normalized["policy_id"],
        "policy_version": normalized["version"],
        "policy_digest": evaluator.policy_digest(normalized),
    }


def signed_context_for(
    evaluator: Any,
    root_policy: dict[str, Any],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(root_policy)

    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": "context-digest:test",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": "context:test",
            "evaluation_time": 1234567890,
            "policy": {
                "id": normalized["policy_id"],
                "version": normalized["version"],
                "digest": evaluator.policy_digest(normalized),
            },
            "proposal": {
                "type": "proposal:test",
                "payload": {
                    "environment": "production",
                    "coverage": 9000,
                },
            },
            "participants": [
                {
                    "id": "authority:alpha",
                    "role": "approver",
                    "weight": 2,
                },
                {
                    "id": "authority:beta",
                    "role": "reviewer",
                    "weight": 3,
                },
            ],
            "evidence": [
                {
                    "id": "evidence.security-report",
                    "digest": "a" * 64,
                    "media_type": "application/json",
                }
            ],
            "constraints": [],
        },
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {
                    "signer_id": "authority:alpha",
                },
            },
            {
                "signature_id": "signature:beta",
                "statement": {
                    "signer_id": "authority:beta",
                },
            },
        ],
    }


def build_index(
    evaluator: Any,
    policies: list[dict[str, Any]],
):
    return build_policy_set_index(
        policies,
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    referenced = policy(
        "policy:reviewer",
        roles=["reviewer"],
        requirements=[
            required_signer(
                "requirement:beta",
                "authority:beta",
            )
        ],
    )

    root = policy(
        "policy:root",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                referenced,
                "requirement:reviewer-policy",
            )
        ],
    )

    normalized_root = evaluator.validate_policy(root)
    context = signed_context_for(evaluator, normalized_root)
    index = build_index(evaluator, [referenced])

    result = evaluator.evaluate_verified_object(
        context,
        normalized_root,
        [
            "signature:alpha",
            "signature:beta",
        ],
        policy_set_index=index,
    )

    if result["status"] != "satisfied":
        raise TestFailure(
            "direct_reference: root was not satisfied"
        )

    if result["matched_signers"] != [
        "authority:alpha"
    ]:
        raise TestFailure(
            "direct_reference: root eligible_roles changed"
        )

    reference_result = result["requirement_results"][0]

    if reference_result["matched_signers"] != [
        "authority:beta"
    ]:
        raise TestFailure(
            "direct_reference: referenced roles not independent"
        )

    if (
        reference_result["referenced_policy"]["status"]
        != "satisfied"
    ):
        raise TestFailure(
            "direct_reference: referenced policy not satisfied"
        )

    print("PASS  verified_direct_reference")
    passed += 1

    print("PASS  root_and_referenced_roles_independent")
    passed += 1

    failed = policy(
        "policy:failed",
        roles=["reviewer"],
        requirements=[
            required_signer(
                "requirement:missing-alpha",
                "authority:alpha",
            )
        ],
    )

    failed_root = policy(
        "policy:failed-root",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                failed,
                "requirement:failed-policy",
            )
        ],
    )

    normalized_failed_root = evaluator.validate_policy(
        failed_root
    )

    failed_result = evaluator.evaluate_verified_object(
        signed_context_for(
            evaluator,
            normalized_failed_root,
        ),
        normalized_failed_root,
        [
            "signature:alpha",
            "signature:beta",
        ],
        policy_set_index=build_index(
            evaluator,
            [failed],
        ),
    )

    if failed_result["status"] != "unsatisfied":
        raise TestFailure(
            "recursive_failure: root unexpectedly satisfied"
        )

    if failed_result["failure_codes"] != [
        "POLICY_REFERENCE_NOT_SATISFIED",
        "REQUIRED_SIGNER_MISSING",
    ]:
        raise TestFailure(
            "recursive_failure: wrong failure projection "
            f"{failed_result['failure_codes']!r}"
        )

    inner = (
        failed_result["requirement_results"][0]
        ["referenced_policy"]
    )

    if inner["failure_codes"] != [
        "REQUIRED_SIGNER_MISSING"
    ]:
        raise TestFailure(
            "recursive_failure: inner failures missing"
        )

    print("PASS  verified_recursive_failure_projection")
    passed += 1

    try:
        evaluator.evaluate_verified_object(
            signed_context_for(
                evaluator,
                normalized_root,
            ),
            normalized_root,
            [
                "signature:alpha",
                "signature:beta",
            ],
        )
    except evaluator.EvaluationFailure as exc:
        if exc.code != "POLICY_REFERENCE_SET_REQUIRED":
            raise TestFailure(
                "missing_policy_set: wrong error "
                f"{exc.code}"
            ) from exc
    else:
        raise TestFailure(
            "missing_policy_set: unexpectedly accepted"
        )

    print("PASS  missing_policy_set_rejected")
    passed += 1

    legacy = policy(
        "policy:legacy",
        roles=["approver"],
        requirements=[
            required_signer(
                "requirement:alpha",
                "authority:alpha",
            )
        ],
    )

    normalized_legacy = evaluator.validate_policy(legacy)
    legacy_context = signed_context_for(
        evaluator,
        normalized_legacy,
    )

    without_index = evaluator.evaluate_verified_object(
        legacy_context,
        normalized_legacy,
        [
            "signature:alpha",
            "signature:beta",
        ],
    )

    with_empty_index = evaluator.evaluate_verified_object(
        legacy_context,
        normalized_legacy,
        [
            "signature:alpha",
            "signature:beta",
        ],
        policy_set_index=build_index(
            evaluator,
            [],
        ),
    )

    if without_index != with_empty_index:
        raise TestFailure(
            "legacy_path: output changed when index provided"
        )

    print("PASS  legacy_policy_output_unchanged")
    passed += 1

    first = evaluator.evaluate_verified_object(
        context,
        normalized_root,
        [
            "signature:alpha",
            "signature:beta",
        ],
        policy_set_index=index,
    )

    second = evaluator.evaluate_verified_object(
        context,
        normalized_root,
        [
            "signature:alpha",
            "signature:beta",
        ],
        policy_set_index=index,
    )

    if first != second:
        raise TestFailure(
            "deterministic_replay: outputs differ"
        )

    print("PASS  deterministic_replay")
    passed += 1

    context_referenced = policy(
        "policy:tpe24-verified-context",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:coverage",
                "type": "context_integer_at_least",
                "path": "/proposal/payload/coverage",
                "minimum": 9000,
            },
            {
                "requirement_id": "requirement:environment",
                "type": "context_value_equals",
                "path": "/proposal/payload/environment",
                "value": "production",
            },
        ],
    )
    context_root = policy(
        "policy:tpe24-verified-root",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                context_referenced,
                "requirement:tpe24-context-policy",
            )
        ],
    )
    normalized_context_root = evaluator.validate_policy(context_root)
    context_result = evaluator.evaluate_verified_object(
        signed_context_for(evaluator, normalized_context_root),
        normalized_context_root,
        ["signature:alpha", "signature:beta"],
        policy_set_index=build_index(evaluator, [context_referenced]),
    )
    if context_result["status"] != "satisfied":
        raise TestFailure("verified tpe24 context reference failed")
    print("PASS  verified_tpe24_context_reference")
    passed += 1

    evidence_referenced = policy(
        "policy:tpe24-verified-evidence",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:evidence",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "digest": "a" * 64,
                "media_type": "application/json",
            }
        ],
    )
    evidence_root = policy(
        "policy:tpe24-verified-evidence-root",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                evidence_referenced,
                "requirement:tpe24-evidence-policy",
            )
        ],
    )
    normalized_evidence_root = evaluator.validate_policy(evidence_root)
    evidence_result = evaluator.evaluate_verified_object(
        signed_context_for(evaluator, normalized_evidence_root),
        normalized_evidence_root,
        ["signature:alpha", "signature:beta"],
        policy_set_index=build_index(evaluator, [evidence_referenced]),
    )
    if evidence_result["status"] != "satisfied":
        raise TestFailure("verified tpe24 evidence reference failed")
    print("PASS  verified_tpe24_evidence_reference")
    passed += 1

    failing_referenced = policy(
        "policy:tpe24-verified-failing",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:environment",
                "type": "context_value_equals",
                "path": "/proposal/payload/environment",
                "value": "staging",
            }
        ],
    )
    failing_root = policy(
        "policy:tpe24-verified-failing-root",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                failing_referenced,
                "requirement:tpe24-failing-policy",
            )
        ],
    )
    normalized_failing_root = evaluator.validate_policy(failing_root)
    failure_result = evaluator.evaluate_verified_object(
        signed_context_for(evaluator, normalized_failing_root),
        normalized_failing_root,
        ["signature:alpha", "signature:beta"],
        policy_set_index=build_index(evaluator, [failing_referenced]),
    )
    if failure_result["failure_codes"] != [
        "POLICY_REFERENCE_NOT_SATISFIED",
        "CONTEXT_VALUE_NOT_EQUAL",
    ]:
        raise TestFailure(
            "verified tpe24 failure projection changed: "
            f"{failure_result['failure_codes']!r}"
        )
    print("PASS  verified_tpe24_failure_projection")
    passed += 1

    expected = 9

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        "TPE 2.4 verified policy-set integration: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
