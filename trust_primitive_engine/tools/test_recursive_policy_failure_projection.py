#!/usr/bin/env python3
"""Focused recursive policy-reference failure projection checks."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import (
    PolicyEvaluationResult,
    PrimitiveResult,
    project_recursive_failure_codes,
)


class TestFailure(Exception):
    pass


def satisfied_leaf(
    requirement_id: str,
) -> PrimitiveResult:
    return PrimitiveResult.satisfied_result(
        requirement_id=requirement_id,
        primitive_type="stub",
        matched_signers=[],
        observed={"satisfied": True},
        expected={"satisfied": True},
    )


def failed_leaf(
    requirement_id: str,
    failure_code: str,
) -> PrimitiveResult:
    return PrimitiveResult.unsatisfied_result(
        requirement_id=requirement_id,
        primitive_type="stub",
        matched_signers=[],
        observed={"satisfied": False},
        expected={"satisfied": True},
        failure_code=failure_code,
    )


def policy_result(
    policy_id: str,
    results: Iterable[PrimitiveResult],
) -> PolicyEvaluationResult:
    normalized_results = tuple(results)
    satisfied = all(
        result.satisfied
        for result in normalized_results
    )
    failure_codes = project_recursive_failure_codes(
        normalized_results
    )

    return PolicyEvaluationResult(
        policy_id=policy_id,
        policy_version=1,
        policy_digest="0" * 64,
        satisfied=satisfied,
        requirement_results=normalized_results,
        matched_signers=(),
        failure_codes=failure_codes,
    )


def reference_result(
    requirement_id: str,
    referenced_policy: PolicyEvaluationResult,
) -> PrimitiveResult:
    observed = {
        "policy_id": referenced_policy.policy_id,
        "policy_version": referenced_policy.policy_version,
        "policy_digest": referenced_policy.policy_digest,
        "policy_status": (
            "satisfied"
            if referenced_policy.satisfied
            else "unsatisfied"
        ),
    }
    expected = {
        "policy_status": "satisfied",
    }

    if referenced_policy.satisfied:
        return PrimitiveResult.satisfied_result(
            requirement_id=requirement_id,
            primitive_type="policy_reference",
            matched_signers=[],
            observed=observed,
            expected=expected,
            referenced_policy=referenced_policy,
        )

    return PrimitiveResult.unsatisfied_result(
        requirement_id=requirement_id,
        primitive_type="policy_reference",
        matched_signers=[],
        observed=observed,
        expected=expected,
        failure_code="POLICY_REFERENCE_NOT_SATISFIED",
        referenced_policy=referenced_policy,
    )


def all_of(
    requirement_id: str,
    children: Iterable[PrimitiveResult],
) -> PrimitiveResult:
    normalized_children = tuple(children)
    satisfied = all(
        child.satisfied
        for child in normalized_children
    )

    kwargs = {
        "requirement_id": requirement_id,
        "primitive_type": "all_of",
        "matched_signers": [],
        "observed": {
            "satisfied_children": sum(
                1
                for child in normalized_children
                if child.satisfied
            ),
            "total_children": len(normalized_children),
        },
        "expected": {
            "required_satisfied_children": (
                len(normalized_children)
            ),
        },
        "children": normalized_children,
    }

    if satisfied:
        return PrimitiveResult.satisfied_result(**kwargs)

    return PrimitiveResult.unsatisfied_result(
        **kwargs,
        failure_code="ALL_OF_NOT_SATISFIED",
    )


def any_of(
    requirement_id: str,
    children: Iterable[PrimitiveResult],
) -> PrimitiveResult:
    normalized_children = tuple(children)
    satisfied = any(
        child.satisfied
        for child in normalized_children
    )

    kwargs = {
        "requirement_id": requirement_id,
        "primitive_type": "any_of",
        "matched_signers": [],
        "observed": {
            "satisfied_children": sum(
                1
                for child in normalized_children
                if child.satisfied
            ),
            "total_children": len(normalized_children),
        },
        "expected": {
            "minimum_satisfied_children": 1,
        },
        "children": normalized_children,
    }

    if satisfied:
        return PrimitiveResult.satisfied_result(**kwargs)

    return PrimitiveResult.unsatisfied_result(
        **kwargs,
        failure_code="ANY_OF_NOT_SATISFIED",
    )


def not_result(
    requirement_id: str,
    child: PrimitiveResult,
) -> PrimitiveResult:
    satisfied = not child.satisfied

    kwargs = {
        "requirement_id": requirement_id,
        "primitive_type": "not",
        "matched_signers": [],
        "observed": {
            "child_status": (
                "satisfied"
                if child.satisfied
                else "unsatisfied"
            ),
        },
        "expected": {
            "child_status": "unsatisfied",
        },
        "children": (child,),
    }

    if satisfied:
        return PrimitiveResult.satisfied_result(**kwargs)

    return PrimitiveResult.unsatisfied_result(
        **kwargs,
        failure_code="NOT_NOT_SATISFIED",
    )


def assert_projection(
    name: str,
    results: tuple[PrimitiveResult, ...],
    expected: tuple[str, ...],
) -> None:
    actual = project_recursive_failure_codes(results)

    if actual != expected:
        raise TestFailure(
            f"{name}: actual={actual!r}, expected={expected!r}"
        )

    print(f"PASS  {name:<44} correct")


def main() -> int:
    passed = 0

    inner_failed = policy_result(
        "policy:inner-failed",
        [
            failed_leaf(
                "requirement:inner-leaf",
                "INNER_FAILURE",
            )
        ],
    )
    direct_reference = reference_result(
        "requirement:reference",
        inner_failed,
    )

    assert_projection(
        "direct_reference_failure",
        (direct_reference,),
        (
            "POLICY_REFERENCE_NOT_SATISFIED",
            "INNER_FAILURE",
        ),
    )
    passed += 1

    inner_any = any_of(
        "requirement:inner-any",
        [
            satisfied_leaf("requirement:inner-a"),
            failed_leaf(
                "requirement:inner-b",
                "SUPPRESSED_INNER_FAILURE",
            ),
        ],
    )
    inner_satisfied = policy_result(
        "policy:inner-satisfied",
        [inner_any],
    )
    satisfied_reference = reference_result(
        "requirement:reference",
        inner_satisfied,
    )

    assert_projection(
        "satisfied_reference_suppresses_inner",
        (satisfied_reference,),
        (),
    )
    passed += 1

    all_tree = all_of(
        "requirement:root-all",
        [
            reference_result(
                "requirement:a-reference",
                inner_failed,
            ),
            failed_leaf(
                "requirement:z-leaf",
                "OUTER_FAILURE",
            ),
        ],
    )

    assert_projection(
        "all_of_reference_projection",
        (all_tree,),
        (
            "POLICY_REFERENCE_NOT_SATISFIED",
            "INNER_FAILURE",
            "ALL_OF_NOT_SATISFIED",
            "OUTER_FAILURE",
        ),
    )
    passed += 1

    any_tree = any_of(
        "requirement:root-any",
        [
            satisfied_leaf("requirement:a-success"),
            reference_result(
                "requirement:b-reference",
                inner_failed,
            ),
        ],
    )

    assert_projection(
        "satisfied_any_of_suppresses_reference",
        (any_tree,),
        (),
    )
    passed += 1

    negated_reference = not_result(
        "requirement:not",
        reference_result(
            "requirement:reference",
            inner_failed,
        ),
    )

    assert_projection(
        "satisfied_not_suppresses_reference",
        (negated_reference,),
        (),
    )
    passed += 1

    deepest = policy_result(
        "policy:deepest",
        [
            failed_leaf(
                "requirement:deep-leaf",
                "DEEP_FAILURE",
            )
        ],
    )
    middle = policy_result(
        "policy:middle",
        [
            reference_result(
                "requirement:middle-reference",
                deepest,
            )
        ],
    )
    outer = reference_result(
        "requirement:outer-reference",
        middle,
    )

    assert_projection(
        "nested_reference_projection",
        (outer,),
        (
            "POLICY_REFERENCE_NOT_SATISFIED",
            "POLICY_REFERENCE_NOT_SATISFIED",
            "DEEP_FAILURE",
        ),
    )
    passed += 1

    shared_left = reference_result(
        "requirement:left-reference",
        inner_failed,
    )
    shared_right = reference_result(
        "requirement:right-reference",
        inner_failed,
    )
    shared_root = all_of(
        "requirement:shared-root",
        [
            shared_left,
            shared_right,
        ],
    )

    assert_projection(
        "shared_reference_failure_multiplicity",
        (shared_root,),
        (
            "POLICY_REFERENCE_NOT_SATISFIED",
            "INNER_FAILURE",
            "POLICY_REFERENCE_NOT_SATISFIED",
            "INNER_FAILURE",
            "ALL_OF_NOT_SATISFIED",
        ),
    )
    passed += 1

    first = project_recursive_failure_codes(
        (shared_root,)
    )
    second = project_recursive_failure_codes(
        (shared_root,)
    )

    if first != second:
        raise TestFailure(
            "deterministic_replay: projections differ"
        )

    print(
        "PASS  deterministic_replay"
        "                         identical"
    )
    passed += 1

    serialized = inner_failed.to_dict()

    if serialized["failure_codes"] != [
        "INNER_FAILURE"
    ]:
        raise TestFailure(
            "referenced_policy_serialization: "
            "failure_codes missing"
        )

    print(
        "PASS  referenced_policy_serialization"
        "              preserved"
    )
    passed += 1

    context_failed = policy_result(
        "policy:tpe24-context-failed",
        [
            failed_leaf(
                "requirement:environment",
                "CONTEXT_VALUE_NOT_EQUAL",
            )
        ],
    )
    assert_projection(
        "tpe24_context_failure_through_reference",
        (
            reference_result(
                "requirement:context-reference",
                context_failed,
            ),
        ),
        (
            "POLICY_REFERENCE_NOT_SATISFIED",
            "CONTEXT_VALUE_NOT_EQUAL",
        ),
    )
    passed += 1

    evidence_failed = policy_result(
        "policy:tpe24-evidence-failed",
        [
            failed_leaf(
                "requirement:evidence",
                "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED",
            )
        ],
    )
    suppressed_any = any_of(
        "requirement:tpe24-any",
        [
            satisfied_leaf("requirement:success"),
            reference_result(
                "requirement:evidence-reference",
                evidence_failed,
            ),
        ],
    )
    assert_projection(
        "tpe24_any_of_suppresses_evidence_failure",
        (suppressed_any,),
        (),
    )
    passed += 1

    suppressed_not = not_result(
        "requirement:tpe24-not",
        reference_result(
            "requirement:context-reference",
            context_failed,
        ),
    )
    assert_projection(
        "tpe24_not_suppresses_context_failure",
        (suppressed_not,),
        (),
    )
    passed += 1

    expected = 12

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        "TPE 2.4 recursive failure projection: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
