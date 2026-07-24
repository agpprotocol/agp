#!/usr/bin/env python3
"""Focused validation checks for TPE 2.3 policy references."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_reference_validation",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def reference() -> dict[str, Any]:
    return {
        "requirement_id": "requirement:security-baseline",
        "type": "policy_reference",
        "policy_id": "policy:security-baseline",
        "policy_version": 3,
        "policy_digest": (
            "0123456789abcdef"
            "0123456789abcdef"
            "0123456789abcdef"
            "0123456789abcdef"
        ),
    }


def policy(requirement: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:root",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [requirement],
    }


def expect_accept(
    evaluator: Any,
    name: str,
    raw: dict[str, Any],
) -> dict[str, Any]:
    try:
        normalized = evaluator.validate_policy(raw)
    except Exception as exc:
        raise TestFailure(
            f"{name}: unexpectedly rejected: {exc}"
        ) from exc

    print(f"PASS  {name:<42} accepted")
    return normalized


def expect_reject(
    evaluator: Any,
    name: str,
    raw: dict[str, Any],
    *,
    expected_code: str = "INVALID_TRUST_POLICY",
) -> None:
    try:
        evaluator.validate_policy(raw)
    except evaluator.EvaluationFailure as exc:
        if exc.code != expected_code:
            raise TestFailure(
                f"{name}: code={exc.code}, "
                f"expected={expected_code}"
            ) from exc
        print(
            f"PASS  {name:<42} "
            f"error={expected_code}"
        )
        return
    except Exception as exc:
        raise TestFailure(
            f"{name}: wrong exception: {type(exc).__name__}: {exc}"
        ) from exc

    raise TestFailure(f"{name}: unexpectedly accepted")


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    raw_reference = reference()
    normalized = expect_accept(
        evaluator,
        "valid_policy_reference",
        policy(raw_reference),
    )
    passed += 1

    normalized_reference = normalized["requirements"][0]

    if normalized_reference != raw_reference:
        raise TestFailure(
            "normalized_reference: value changed"
        )
    if list(normalized_reference) != [
        "requirement_id",
        "type",
        "policy_id",
        "policy_version",
        "policy_digest",
    ]:
        raise TestFailure(
            "normalized_reference: unexpected member order"
        )

    print(
        "PASS  deterministic_normalization"
        "                preserved"
    )
    passed += 1

    missing = reference()
    del missing["policy_digest"]
    expect_reject(
        evaluator,
        "missing_policy_digest",
        policy(missing),
    )
    passed += 1

    unknown = reference()
    unknown["fallback"] = True
    expect_reject(
        evaluator,
        "unknown_reference_member",
        policy(unknown),
    )
    passed += 1

    invalid_id = reference()
    invalid_id["policy_id"] = "not valid"
    expect_reject(
        evaluator,
        "invalid_policy_id",
        policy(invalid_id),
    )
    passed += 1

    boolean_version = reference()
    boolean_version["policy_version"] = True
    expect_reject(
        evaluator,
        "boolean_policy_version",
        policy(boolean_version),
    )
    passed += 1

    zero_version = reference()
    zero_version["policy_version"] = 0
    expect_reject(
        evaluator,
        "zero_policy_version",
        policy(zero_version),
    )
    passed += 1

    excessive_version = reference()
    excessive_version["policy_version"] = 9007199254740992
    expect_reject(
        evaluator,
        "excessive_policy_version",
        policy(excessive_version),
    )
    passed += 1

    uppercase_digest = reference()
    uppercase_digest["policy_digest"] = (
        uppercase_digest["policy_digest"][:-1] + "F"
    )
    expect_reject(
        evaluator,
        "uppercase_policy_digest",
        policy(uppercase_digest),
    )
    passed += 1

    short_digest = reference()
    short_digest["policy_digest"] = "0" * 63
    expect_reject(
        evaluator,
        "short_policy_digest",
        policy(short_digest),
    )
    passed += 1

    prefixed_digest = reference()
    prefixed_digest["policy_digest"] = (
        "sha256:" + prefixed_digest["policy_digest"]
    )
    expect_reject(
        evaluator,
        "prefixed_policy_digest",
        policy(prefixed_digest),
    )
    passed += 1

    non_hex_digest = reference()
    non_hex_digest["policy_digest"] = "g" * 64
    expect_reject(
        evaluator,
        "non_hex_policy_digest",
        policy(non_hex_digest),
    )
    passed += 1

    unsupported = reference()
    unsupported["type"] = "policy_import"
    expect_reject(
        evaluator,
        "unknown_structural_type",
        policy(unsupported),
        expected_code="UNSUPPORTED_TRUST_PRIMITIVE",
    )
    passed += 1

    duplicate = reference()
    duplicate_policy = policy(duplicate)
    duplicate_policy["requirements"] = [
        duplicate,
        deepcopy(duplicate),
    ]

    expect_reject(
        evaluator,
        "duplicate_reference_requirement_id",
        duplicate_policy,
    )
    passed += 1

    first = reference()
    first["requirement_id"] = "requirement:a"

    second = reference()
    second["requirement_id"] = "requirement:b"
    second["policy_id"] = "policy:other"

    unsorted_policy = policy(first)
    unsorted_policy["requirements"] = [second, first]

    expect_reject(
        evaluator,
        "unsorted_reference_requirements",
        unsorted_policy,
    )
    passed += 1

    expected = 15

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: {passed} != {expected}"
        )

    print(
        f"TPE 2.3 policy-reference validation: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
