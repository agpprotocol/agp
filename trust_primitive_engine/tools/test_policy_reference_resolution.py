#!/usr/bin/env python3
"""Focused deterministic resolution checks for TPE 2.3 references."""

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
        "agp_evaluate_trust_policy_v2_reference_resolution",
        EVALUATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def primitive_policy(
    policy_id: str,
    version: int,
    signer_id: str,
) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": version,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:required-signer",
                "type": "required_signer",
                "signer_id": signer_id,
            }
        ],
    }


def reference(
    *,
    policy_id: str,
    policy_version: int,
    policy_digest: str,
) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:reference",
        "type": "policy_reference",
        "policy_id": policy_id,
        "policy_version": policy_version,
        "policy_digest": policy_digest,
    }


def expect_error(
    evaluator: Any,
    name: str,
    callback: Any,
    expected_code: str,
) -> None:
    try:
        callback()
    except evaluator.EvaluationFailure as exc:
        if exc.code != expected_code:
            raise TestFailure(
                f"{name}: code={exc.code}, expected={expected_code}"
            ) from exc

        print(
            f"PASS  {name:<38} "
            f"error={expected_code}"
        )
        return
    except Exception as exc:
        raise TestFailure(
            f"{name}: wrong exception "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    raise TestFailure(f"{name}: unexpectedly accepted")


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    alpha = primitive_policy(
        "policy:alpha",
        1,
        "authority:alpha",
    )

    beta = primitive_policy(
        "policy:beta",
        2,
        "authority:beta",
    )

    alpha_normalized = evaluator.validate_policy(alpha)
    beta_normalized = evaluator.validate_policy(beta)

    alpha_digest = evaluator.policy_digest(alpha_normalized)
    beta_digest = evaluator.policy_digest(beta_normalized)

    forward_index = build_policy_set_index(
        [alpha, beta],
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )

    reverse_index = build_policy_set_index(
        [beta, alpha],
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )

    alpha_reference = evaluator.validate_policy_reference(
        reference(
            policy_id="policy:alpha",
            policy_version=1,
            policy_digest=alpha_digest,
        )
    )

    resolved = evaluator.resolve_policy_reference(
        alpha_reference,
        forward_index,
    )

    if resolved != alpha_normalized:
        raise TestFailure(
            "valid_resolution: resolved policy differs"
        )

    print("PASS  valid_resolution                       identical")
    passed += 1

    resolved_forward = evaluator.resolve_policy_reference(
        alpha_reference,
        forward_index,
    )

    resolved_reverse = evaluator.resolve_policy_reference(
        alpha_reference,
        reverse_index,
    )

    if resolved_forward != resolved_reverse:
        raise TestFailure(
            "insertion_order_independent: results differ"
        )

    print("PASS  insertion_order_independent            identical")
    passed += 1

    detached = evaluator.resolve_policy_reference(
        alpha_reference,
        forward_index,
    )

    detached["policy_id"] = "policy:mutated"
    detached["requirements"][0]["signer_id"] = (
        "authority:mutated"
    )

    preserved = evaluator.resolve_policy_reference(
        alpha_reference,
        forward_index,
    )

    if preserved["policy_id"] != "policy:alpha":
        raise TestFailure(
            "resolved_copy_is_detached: policy_id mutated"
        )

    if (
        preserved["requirements"][0]["signer_id"]
        != "authority:alpha"
    ):
        raise TestFailure(
            "resolved_copy_is_detached: nested data mutated"
        )

    print("PASS  resolved_copy_is_detached               preserved")
    passed += 1

    missing_reference = evaluator.validate_policy_reference(
        reference(
            policy_id="policy:missing",
            policy_version=1,
            policy_digest="0" * 64,
        )
    )

    expect_error(
        evaluator,
        "missing_reference",
        lambda: evaluator.resolve_policy_reference(
            missing_reference,
            forward_index,
        ),
        "POLICY_REFERENCE_NOT_FOUND",
    )
    passed += 1

    wrong_version_reference = (
        evaluator.validate_policy_reference(
            reference(
                policy_id="policy:alpha",
                policy_version=2,
                policy_digest=alpha_digest,
            )
        )
    )

    expect_error(
        evaluator,
        "missing_policy_version",
        lambda: evaluator.resolve_policy_reference(
            wrong_version_reference,
            forward_index,
        ),
        "POLICY_REFERENCE_NOT_FOUND",
    )
    passed += 1

    wrong_digest_reference = (
        evaluator.validate_policy_reference(
            reference(
                policy_id="policy:alpha",
                policy_version=1,
                policy_digest=beta_digest,
            )
        )
    )

    expect_error(
        evaluator,
        "digest_mismatch",
        lambda: evaluator.resolve_policy_reference(
            wrong_digest_reference,
            forward_index,
        ),
        "POLICY_REFERENCE_DIGEST_MISMATCH",
    )
    passed += 1

    try:
        evaluator.resolve_policy_reference(
            {
                "requirement_id": "requirement:not-reference",
                "type": "required_signer",
                "signer_id": "authority:alpha",
            },
            forward_index,
        )
    except evaluator.EvaluationFailure as exc:
        if exc.code != "INVALID_TRUST_POLICY":
            raise TestFailure(
                "non_reference_rejected: wrong error code"
            ) from exc
    else:
        raise TestFailure(
            "non_reference_rejected: unexpectedly accepted"
        )

    print(
        "PASS  non_reference_rejected"
        "                 error=INVALID_TRUST_POLICY"
    )
    passed += 1

    # Resolving does not evaluate or recursively traverse the returned policy.
    nested_reference_policy = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:nested",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:nested-reference",
                "type": "policy_reference",
                "policy_id": "policy:missing-transitive",
                "policy_version": 1,
                "policy_digest": "1" * 64,
            }
        ],
    }

    nested_normalized = evaluator.validate_policy(
        nested_reference_policy
    )

    nested_digest = evaluator.policy_digest(
        nested_normalized
    )

    nested_index = build_policy_set_index(
        [nested_reference_policy],
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )

    nested_root_reference = evaluator.validate_policy_reference(
        reference(
            policy_id="policy:nested",
            policy_version=1,
            policy_digest=nested_digest,
        )
    )

    nested_resolved = evaluator.resolve_policy_reference(
        nested_root_reference,
        nested_index,
    )

    if nested_resolved != nested_normalized:
        raise TestFailure(
            "no_recursive_resolution: policy changed"
        )

    print("PASS  no_recursive_resolution                 preserved")
    passed += 1

    expected = 8

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        f"TPE 2.3 policy-reference resolution: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
