#!/usr/bin/env python3
"""Small deterministic checks for the TPE engine core contracts."""

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
)


class ExamplePrimitive(Primitive):
    TYPE = "example"

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
        return PrimitiveResult.satisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=list(state.matched_signers),
            observed={"signature_count": state.signature_count},
            expected={"minimum_signatures": 1},
        )


def main() -> int:
    state = EvaluationState.create(
        matched_signers=[
            "authority:legal",
            "authority:finance",
        ],
        participants={
            "authority:finance": {
                "id": "authority:finance",
                "role": "approver",
                "weight": 1,
            },
            "authority:legal": {
                "id": "authority:legal",
                "role": "approver",
                "weight": 2,
            },
        },
        weight=3,
    )

    if state.matched_signers != (
        "authority:finance",
        "authority:legal",
    ):
        raise AssertionError("state signer normalization failed")

    if state.evaluation_time is not None:
        raise AssertionError(
            "legacy state must default evaluation_time to None"
        )

    temporal_state = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        evaluation_time=1784894400,
    )

    if temporal_state.evaluation_time != 1784894400:
        raise AssertionError(
            "evaluation_time was not preserved"
        )

    boundary_state = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        evaluation_time=9007199254740991,
    )

    if boundary_state.evaluation_time != 9007199254740991:
        raise AssertionError(
            "maximum safe evaluation_time was not accepted"
        )

    invalid_evaluation_times = [
        True,
        False,
        -1,
        9007199254740992,
        "1784894400",
    ]

    for invalid_value in invalid_evaluation_times:
        try:
            EvaluationState.create(
                matched_signers=[],
                participants={},
                weight=0,
                evaluation_time=invalid_value,
            )
        except ValueError:
            pass
        else:
            raise AssertionError(
                "invalid evaluation_time was accepted: "
                f"{invalid_value!r}"
            )

    registry = PrimitiveRegistry([ExamplePrimitive()])

    if registry.types() != ("example",):
        raise AssertionError("registry type ordering failed")

    primitive = registry.resolve("example")
    result = primitive.evaluate(
        {
            "requirement_id": "requirement:example",
            "type": "example",
        },
        state,
    )

    expected = {
        "requirement_id": "requirement:example",
        "type": "example",
        "status": "satisfied",
        "matched_signers": [
            "authority:finance",
            "authority:legal",
        ],
        "observed": {"signature_count": 2},
        "expected": {"minimum_signatures": 1},
        "failure_code": None,
    }

    if result.to_dict() != expected:
        raise AssertionError(
            f"unexpected primitive result: {result.to_dict()!r}"
        )

    if result.children != ():
        raise AssertionError(
            "leaf result must default children to an empty tuple"
        )

    if "children" in result.to_dict():
        raise AssertionError(
            "leaf serialization must not contain children"
        )

    unsatisfied_child = PrimitiveResult.unsatisfied_result(
        requirement_id="requirement:child-b",
        primitive_type="example",
        matched_signers=[],
        observed={"matched": False},
        expected={"matched": True},
        failure_code="EXAMPLE_NOT_SATISFIED",
    )

    satisfied_child = PrimitiveResult.satisfied_result(
        requirement_id="requirement:child-a",
        primitive_type="example",
        matched_signers=["authority:legal"],
        observed={"matched": True},
        expected={"matched": True},
    )

    supplied_children = [
        satisfied_child,
        unsatisfied_child,
    ]

    parent = PrimitiveResult.unsatisfied_result(
        requirement_id="requirement:parent",
        primitive_type="all_of",
        matched_signers=["authority:legal"],
        observed={
            "satisfied_children": 1,
            "total_children": 2,
        },
        expected={
            "required_satisfied_children": 2,
        },
        failure_code="ALL_OF_NOT_SATISFIED",
        children=supplied_children,
    )

    supplied_children.clear()

    if parent.children != (
        satisfied_child,
        unsatisfied_child,
    ):
        raise AssertionError(
            "children were not normalized to an immutable tuple"
        )

    expected_parent = {
        "requirement_id": "requirement:parent",
        "type": "all_of",
        "status": "unsatisfied",
        "matched_signers": ["authority:legal"],
        "observed": {
            "satisfied_children": 1,
            "total_children": 2,
        },
        "expected": {
            "required_satisfied_children": 2,
        },
        "failure_code": "ALL_OF_NOT_SATISFIED",
        "children": [
            {
                "requirement_id": "requirement:child-a",
                "type": "example",
                "status": "satisfied",
                "matched_signers": ["authority:legal"],
                "observed": {"matched": True},
                "expected": {"matched": True},
                "failure_code": None,
            },
            {
                "requirement_id": "requirement:child-b",
                "type": "example",
                "status": "unsatisfied",
                "matched_signers": [],
                "observed": {"matched": False},
                "expected": {"matched": True},
                "failure_code": "EXAMPLE_NOT_SATISFIED",
            },
        ],
    }

    if parent.to_dict() != expected_parent:
        raise AssertionError(
            f"unexpected recursive result: {parent.to_dict()!r}"
        )

    exported_parent = parent.to_dict()
    exported_parent["children"][0]["observed"]["matched"] = False
    exported_parent["observed"]["satisfied_children"] = 999

    if parent.to_dict() != expected_parent:
        raise AssertionError(
            "mutating serialized output changed the result"
        )

    try:
        PrimitiveResult.satisfied_result(
            requirement_id="requirement:invalid-child",
            primitive_type="all_of",
            matched_signers=[],
            observed={},
            expected={},
            children=[object()],
        )
    except TypeError:
        pass
    else:
        raise AssertionError(
            "non-PrimitiveResult child was accepted"
        )

    try:
        parent.children = ()
    except Exception:
        pass
    else:
        raise AssertionError(
            "frozen PrimitiveResult allowed children mutation"
        )

    nested_parent = PrimitiveResult.satisfied_result(
        requirement_id="requirement:nested-parent",
        primitive_type="not",
        matched_signers=[],
        observed={"child_status": "unsatisfied"},
        expected={"child_status": "unsatisfied"},
        children=(unsatisfied_child,),
    )

    if (
        nested_parent.to_dict()["children"][0]["failure_code"]
        != "EXAMPLE_NOT_SATISFIED"
    ):
        raise AssertionError(
            "nested child evidence was not preserved"
        )

    try:
        registry.register(ExamplePrimitive())
    except ValueError:
        pass
    else:
        raise AssertionError(
            "duplicate primitive registration was accepted"
        )

    print("TPE engine core checks: 16/16 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
