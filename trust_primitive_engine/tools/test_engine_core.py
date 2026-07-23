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

    try:
        registry.register(ExamplePrimitive())
    except ValueError:
        pass
    else:
        raise AssertionError(
            "duplicate primitive registration was accepted"
        )

    print("TPE engine core checks: 5/5 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
