#!/usr/bin/env python3
"""Focused checks for deterministic composition evaluation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import (
    EvaluationState,
    Primitive,
    PrimitiveRegistry,
    PrimitiveResult,
    evaluate_requirement,
    project_failure_codes,
)


class TestFailure(Exception):
    pass


class StubPrimitive(Primitive):
    TYPE = "stub"

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        return dict(value)

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        del state
        self.calls.append(requirement["requirement_id"])

        matched_signers = list(
            requirement.get("matched_signers", [])
        )

        if requirement["satisfied"]:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=matched_signers,
                observed={"stub": "satisfied"},
                expected={"stub": "satisfied"},
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=matched_signers,
            observed={"stub": "unsatisfied"},
            expected={"stub": "satisfied"},
            failure_code=requirement["failure_code"],
        )


def leaf(
    requirement_id: str,
    *,
    satisfied: bool,
    failure_code: str = "STUB_NOT_SATISFIED",
    matched_signers: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "stub",
        "satisfied": satisfied,
        "failure_code": failure_code,
        "matched_signers": matched_signers or [],
    }


def main() -> int:
    calls: list[str] = []
    registry = PrimitiveRegistry([StubPrimitive(calls)])
    state = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
    )
    passed = 0

    all_satisfied = {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            leaf(
                "requirement:a",
                satisfied=True,
                matched_signers=["authority:legal"],
            ),
            leaf(
                "requirement:b",
                satisfied=True,
                matched_signers=["authority:security"],
            ),
        ],
    }
    result = evaluate_requirement(all_satisfied, state, registry)
    if not result.satisfied:
        raise TestFailure("all_of_all_satisfied failed")
    print("PASS  all_of_all_satisfied")
    passed += 1

    if result.matched_signers != (
        "authority:legal",
        "authority:security",
    ):
        raise TestFailure("all_of signer aggregation failed")
    print("PASS  all_of_signer_aggregation")
    passed += 1

    calls.clear()
    all_failed = {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            leaf(
                "requirement:a",
                satisfied=False,
                failure_code="FAIL_A",
            ),
            leaf("requirement:b", satisfied=True),
        ],
    }
    result = evaluate_requirement(all_failed, state, registry)
    if result.satisfied or result.failure_code != (
        "ALL_OF_NOT_SATISFIED"
    ):
        raise TestFailure("all_of unsatisfied semantics failed")
    print("PASS  all_of_unsatisfied")
    passed += 1

    if calls != ["requirement:a", "requirement:b"]:
        raise TestFailure("all_of short-circuited")
    print("PASS  all_of_no_short_circuit")
    passed += 1

    calls.clear()
    any_satisfied = {
        "requirement_id": "requirement:root",
        "type": "any_of",
        "requirements": [
            leaf("requirement:a", satisfied=True),
            leaf(
                "requirement:b",
                satisfied=False,
                failure_code="FAIL_B",
            ),
        ],
    }
    result = evaluate_requirement(any_satisfied, state, registry)
    if not result.satisfied:
        raise TestFailure("any_of satisfaction failed")
    print("PASS  any_of_one_satisfied")
    passed += 1

    if calls != ["requirement:a", "requirement:b"]:
        raise TestFailure("any_of short-circuited")
    print("PASS  any_of_no_short_circuit")
    passed += 1

    if project_failure_codes((result,)) != []:
        raise TestFailure(
            "satisfied any_of projected child failure"
        )
    print("PASS  satisfied_any_of_suppresses_failures")
    passed += 1

    any_failed = {
        "requirement_id": "requirement:root",
        "type": "any_of",
        "requirements": [
            leaf(
                "requirement:a",
                satisfied=False,
                failure_code="FAIL_A",
            ),
            leaf(
                "requirement:b",
                satisfied=False,
                failure_code="FAIL_B",
            ),
        ],
    }
    result = evaluate_requirement(any_failed, state, registry)
    if result.satisfied:
        raise TestFailure("any_of all-unsatisfied failed")
    print("PASS  any_of_all_unsatisfied")
    passed += 1

    if project_failure_codes((result,)) != [
        "FAIL_A",
        "FAIL_B",
        "ANY_OF_NOT_SATISFIED",
    ]:
        raise TestFailure("any_of projection failed")
    print("PASS  any_of_recursive_projection")
    passed += 1

    not_satisfied = {
        "requirement_id": "requirement:not-root",
        "type": "not",
        "requirement": leaf(
            "requirement:a",
            satisfied=False,
            failure_code="FAIL_A",
            matched_signers=["authority:legal"],
        ),
    }
    result = evaluate_requirement(not_satisfied, state, registry)
    if not result.satisfied:
        raise TestFailure("not unsatisfied-child semantics failed")
    print("PASS  not_unsatisfied_child_satisfies")
    passed += 1

    if result.matched_signers != ():
        raise TestFailure("not aggregated child signer")
    print("PASS  not_matched_signers_empty")
    passed += 1

    child_dict = result.to_dict()["children"][0]
    if child_dict["failure_code"] != "FAIL_A":
        raise TestFailure("not lost child evidence")
    print("PASS  not_preserves_child_evidence")
    passed += 1

    if project_failure_codes((result,)) != []:
        raise TestFailure("satisfied not projected child failure")
    print("PASS  satisfied_not_suppresses_child_failure")
    passed += 1

    not_failed = {
        "requirement_id": "requirement:not-root",
        "type": "not",
        "requirement": leaf(
            "requirement:a",
            satisfied=True,
        ),
    }
    result = evaluate_requirement(not_failed, state, registry)
    if result.satisfied or result.failure_code != (
        "NOT_NOT_SATISFIED"
    ):
        raise TestFailure("not satisfied-child semantics failed")
    print("PASS  not_satisfied_child_fails")
    passed += 1

    if project_failure_codes((result,)) != [
        "NOT_NOT_SATISFIED"
    ]:
        raise TestFailure("not projection failed")
    print("PASS  not_projects_parent_only")
    passed += 1

    nested = {
        "requirement_id": "requirement:z-root",
        "type": "all_of",
        "requirements": [
            {
                "requirement_id": "requirement:a-any",
                "type": "any_of",
                "requirements": [
                    leaf(
                        "requirement:b-leaf",
                        satisfied=False,
                        failure_code="FAIL_B",
                    ),
                    leaf(
                        "requirement:c-leaf",
                        satisfied=False,
                        failure_code="FAIL_C",
                    ),
                ],
            },
            leaf(
                "requirement:y-leaf",
                satisfied=False,
                failure_code="FAIL_Y",
            ),
        ],
    }
    first = evaluate_requirement(nested, state, registry)
    second = evaluate_requirement(nested, state, registry)

    expected_projection = [
        "ANY_OF_NOT_SATISFIED",
        "FAIL_B",
        "FAIL_C",
        "FAIL_Y",
        "ALL_OF_NOT_SATISFIED",
    ]
    if project_failure_codes((first,)) != expected_projection:
        raise TestFailure("nested projection ordering failed")
    print("PASS  nested_projection_order")
    passed += 1

    if first.to_dict() != second.to_dict():
        raise TestFailure("composition replay was not deterministic")
    print("PASS  deterministic_replay")
    passed += 1

    expected = 17
    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: {passed} != {expected}"
        )

    print(
        "AGP TPE 2.2 composition evaluation: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
