#!/usr/bin/env python3
"""Focused checks for structural requirement dispatch."""

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
    evaluate_composition,
    evaluate_requirement,
)


class RecordingPrimitive(Primitive):
    TYPE = "recording"

    def __init__(self) -> None:
        self.evaluated: list[str] = []

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
        self.evaluated.append(requirement["requirement_id"])

        satisfied = requirement.get("satisfied", True)

        if satisfied:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=list(state.matched_signers),
                observed={"evaluated": True},
                expected={"evaluated": True},
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed={"evaluated": True},
            expected={"satisfied": True},
            failure_code="RECORDING_NOT_SATISFIED",
        )


def leaf(
    requirement_id: str,
    *,
    satisfied: bool = True,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "recording",
        "satisfied": satisfied,
    }


def main() -> int:
    passed = 0

    state = EvaluationState.create(
        matched_signers=["authority:alpha"],
        participants={
            "authority:alpha": {
                "id": "authority:alpha",
                "role": "approver",
                "weight": 1,
            }
        },
        weight=1,
    )

    primitive = RecordingPrimitive()
    registry = PrimitiveRegistry([primitive])

    direct = evaluate_requirement(
        leaf("requirement:direct"),
        state,
        registry,
    )

    if not direct.satisfied:
        raise AssertionError(
            "primitive_dispatch: primitive was not satisfied"
        )

    if primitive.evaluated != ["requirement:direct"]:
        raise AssertionError(
            "primitive_dispatch: wrong primitive calls"
        )

    print("PASS  primitive_dispatch                    correct")
    passed += 1

    primitive.evaluated.clear()

    all_of = {
        "requirement_id": "requirement:all",
        "type": "all_of",
        "requirements": [
            leaf("requirement:a"),
            leaf("requirement:b"),
        ],
    }

    all_result = evaluate_requirement(
        all_of,
        state,
        registry,
    )

    if not all_result.satisfied:
        raise AssertionError(
            "composition_dispatch: all_of was not satisfied"
        )

    if primitive.evaluated != [
        "requirement:a",
        "requirement:b",
    ]:
        raise AssertionError(
            "composition_dispatch: children not dispatched"
        )

    if len(all_result.children) != 2:
        raise AssertionError(
            "composition_dispatch: children not preserved"
        )

    print("PASS  composition_dispatch                  correct")
    passed += 1

    primitive.evaluated.clear()

    any_of = {
        "requirement_id": "requirement:any",
        "type": "any_of",
        "requirements": [
            leaf("requirement:a", satisfied=True),
            leaf("requirement:b", satisfied=False),
        ],
    }

    any_result = evaluate_requirement(
        any_of,
        state,
        registry,
    )

    if not any_result.satisfied:
        raise AssertionError(
            "complete_tree_evaluation: any_of not satisfied"
        )

    if primitive.evaluated != [
        "requirement:a",
        "requirement:b",
    ]:
        raise AssertionError(
            "complete_tree_evaluation: short-circuited"
        )

    print("PASS  complete_tree_evaluation              preserved")
    passed += 1

    primitive.evaluated.clear()

    nested = {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            {
                "requirement_id": "requirement:any",
                "type": "any_of",
                "requirements": [
                    leaf("requirement:a"),
                    leaf("requirement:b", satisfied=False),
                ],
            },
            {
                "requirement_id": "requirement:not",
                "type": "not",
                "requirement": leaf(
                    "requirement:c",
                    satisfied=False,
                ),
            },
        ],
    }

    nested_result = evaluate_requirement(
        nested,
        state,
        registry,
    )

    if not nested_result.satisfied:
        raise AssertionError(
            "recursive_dispatch: nested result not satisfied"
        )

    if primitive.evaluated != [
        "requirement:a",
        "requirement:b",
        "requirement:c",
    ]:
        raise AssertionError(
            "recursive_dispatch: wrong traversal order"
        )

    print("PASS  recursive_dispatch                    correct")
    passed += 1

    try:
        evaluate_composition(
            leaf("requirement:not-composition"),
            state,
            registry,
            evaluate_child=evaluate_requirement,
        )
    except ValueError:
        pass
    else:
        raise AssertionError(
            "composition_boundary: primitive was accepted"
        )

    print("PASS  composition_boundary                  enforced")
    passed += 1

    try:
        evaluate_requirement(
            {
                "requirement_id": "requirement:reference",
                "type": "policy_reference",
                "policy_id": "policy:target",
                "policy_version": 1,
                "policy_digest": "0" * 64,
            },
            state,
            registry,
        )
    except KeyError:
        pass
    else:
        raise AssertionError(
            "reference_not_enabled: reference was evaluated"
        )

    print("PASS  reference_not_enabled                 preserved")
    passed += 1

    expected = 6

    if passed != expected:
        raise AssertionError(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        "TPE structural dispatcher: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
