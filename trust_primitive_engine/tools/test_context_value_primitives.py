#!/usr/bin/env python3
"""Focused checks for TPE 2.4 proposal-payload primitives."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
SCHEMA_PATH = ROOT / "registry/schemas/agp.trust-policy-2.schema.json"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import EvaluationState, PrimitiveRegistry
from primitives.context_values import (
    ContextIntegerAtLeastPrimitive,
    ContextIntegerAtMostPrimitive,
    ContextValueEqualsPrimitive,
    ContextValuePresentPrimitive,
)

PRIMITIVES = [
    ContextIntegerAtLeastPrimitive(),
    ContextIntegerAtMostPrimitive(),
    ContextValueEqualsPrimitive(),
    ContextValuePresentPrimitive(),
]
REGISTRY = PrimitiveRegistry(PRIMITIVES)


class TestFailure(Exception):
    pass


def requirement(primitive_type: str, path: str, **extra: Any) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:" + primitive_type.replace("_", "-"),
        "type": primitive_type,
        "path": path,
        **extra,
    }


def evaluate(state: EvaluationState, primitive_type: str, path: str, **extra: Any):
    primitive = REGISTRY.resolve(primitive_type)
    normalized = primitive.validate(requirement(primitive_type, path, **extra))
    return primitive.evaluate(normalized, state)


def expect_reject(name: str, primitive: Any, value: dict[str, Any]) -> None:
    try:
        primitive.validate(value)
    except ValueError:
        print(f"PASS  {name:<46} rejected")
        return
    raise TestFailure(f"{name}: invalid requirement was accepted")


def policy_with(req: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe-2.4-context-values",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [req],
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
        decision_context={
            "proposal": {
                "payload": {
                    "environment": "production",
                    "nullable": None,
                    "enabled": True,
                    "coverage": 9000,
                    "rollout": 2500,
                    "object": {"name": "service"},
                    "long": "x" * 4097,
                }
            },
            "evidence": [],
        },
    )

    cases = [
        ("present_scalar", "context_value_present", "/proposal/payload/environment", {}, True, None),
        ("present_null", "context_value_present", "/proposal/payload/nullable", {}, True, None),
        ("present_object", "context_value_present", "/proposal/payload/object", {}, True, None),
        ("present_missing", "context_value_present", "/proposal/payload/missing", {}, False, "CONTEXT_VALUE_NOT_PRESENT"),
        ("present_type_mismatch", "context_value_present", "/proposal/payload/environment/name", {}, False, "CONTEXT_VALUE_NOT_PRESENT"),
        ("equals_string_match", "context_value_equals", "/proposal/payload/environment", {"value": "production"}, True, None),
        ("equals_string_mismatch", "context_value_equals", "/proposal/payload/environment", {"value": "staging"}, False, "CONTEXT_VALUE_NOT_EQUAL"),
        ("equals_bool_int_strict", "context_value_equals", "/proposal/payload/enabled", {"value": 1}, False, "CONTEXT_VALUE_NOT_EQUAL"),
        ("equals_null_match", "context_value_equals", "/proposal/payload/nullable", {"value": None}, True, None),
        ("equals_container_unsatisfied", "context_value_equals", "/proposal/payload/object", {"value": "service"}, False, "CONTEXT_VALUE_NOT_EQUAL"),
        ("minimum_boundary", "context_integer_at_least", "/proposal/payload/coverage", {"minimum": 9000}, True, None),
        ("minimum_above", "context_integer_at_least", "/proposal/payload/coverage", {"minimum": 8999}, True, None),
        ("minimum_below", "context_integer_at_least", "/proposal/payload/coverage", {"minimum": 9001}, False, "CONTEXT_INTEGER_MINIMUM_NOT_REACHED"),
        ("minimum_boolean_observed", "context_integer_at_least", "/proposal/payload/enabled", {"minimum": 1}, False, "CONTEXT_INTEGER_MINIMUM_NOT_REACHED"),
        ("maximum_boundary", "context_integer_at_most", "/proposal/payload/rollout", {"maximum": 2500}, True, None),
        ("maximum_below", "context_integer_at_most", "/proposal/payload/rollout", {"maximum": 2501}, True, None),
        ("maximum_above", "context_integer_at_most", "/proposal/payload/rollout", {"maximum": 2499}, False, "CONTEXT_INTEGER_MAXIMUM_EXCEEDED"),
        ("maximum_string_observed", "context_integer_at_most", "/proposal/payload/environment", {"maximum": 2500}, False, "CONTEXT_INTEGER_MAXIMUM_EXCEEDED"),
    ]

    for name, primitive_type, path, extra, satisfied, failure in cases:
        result = evaluate(state, primitive_type, path, **extra)
        if result.satisfied is not satisfied:
            raise TestFailure(f"{name}: wrong satisfaction")
        actual_failure = None if result.satisfied else result.failure_code
        if actual_failure != failure:
            raise TestFailure(f"{name}: wrong failure code")
        if result.matched_signers != ():
            raise TestFailure(f"{name}: matched_signers must be empty")
        print(f"PASS  {name:<46} correct")
        passed += 1

    no_context = EvaluationState.create(matched_signers=[], participants={}, weight=0)
    missing = evaluate(
        no_context,
        "context_value_present",
        "/proposal/payload/environment",
    )
    if missing.observed["resolution"] != "missing":
        raise TestFailure("missing context was not missing")
    print("PASS  missing_context                                missing")
    passed += 1

    long_result = evaluate(
        state,
        "context_value_present",
        "/proposal/payload/long",
    )
    if long_result.observed["value"] is not None:
        raise TestFailure("long string was copied to result")
    print("PASS  long_observed_string_bounded                   omitted")
    passed += 1

    first = evaluate(
        state,
        "context_value_equals",
        "/proposal/payload/environment",
        value="production",
    ).to_dict()
    second = evaluate(
        state,
        "context_value_equals",
        "/proposal/payload/environment",
        value="production",
    ).to_dict()
    if first != second:
        raise TestFailure("deterministic replay changed")
    print("PASS  deterministic_replay                          identical")
    passed += 1

    present = ContextValuePresentPrimitive()
    equals = ContextValueEqualsPrimitive()
    minimum = ContextIntegerAtLeastPrimitive()
    maximum = ContextIntegerAtMostPrimitive()

    invalid = [
        ("present_unknown_member", present, {**requirement("context_value_present", "/proposal/payload/environment"), "extra": True}),
        ("present_missing_path", present, {"requirement_id": "requirement:present", "type": "context_value_present"}),
        ("present_invalid_path", present, requirement("context_value_present", "/participants/0/id")),
        ("equals_container_expected", equals, requirement("context_value_equals", "/proposal/payload/object", value={"name": "service"})),
        ("equals_oversized_string", equals, requirement("context_value_equals", "/proposal/payload/environment", value="x" * 4097)),
        ("equals_unsafe_integer", equals, requirement("context_value_equals", "/proposal/payload/coverage", value=9_007_199_254_740_992)),
        ("minimum_boolean", minimum, requirement("context_integer_at_least", "/proposal/payload/coverage", minimum=True)),
        ("minimum_unsafe", minimum, requirement("context_integer_at_least", "/proposal/payload/coverage", minimum=-9_007_199_254_740_992)),
        ("maximum_decimal", maximum, requirement("context_integer_at_most", "/proposal/payload/rollout", maximum=2500.5)),
    ]

    for name, primitive, value in invalid:
        expect_reject(name, primitive, value)
        passed += 1

    if REGISTRY.types() != (
        "context_integer_at_least",
        "context_integer_at_most",
        "context_value_equals",
        "context_value_present",
    ):
        raise TestFailure("registry types are incorrect")
    print("PASS  registry_contains_four_types                  correct")
    passed += 1

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    valid_requirements = [
        requirement("context_value_present", "/proposal/payload/environment"),
        requirement("context_value_equals", "/proposal/payload/environment", value="production"),
        requirement("context_integer_at_least", "/proposal/payload/coverage", minimum=-9_007_199_254_740_991),
        requirement("context_integer_at_most", "/proposal/payload/rollout", maximum=9_007_199_254_740_991),
    ]

    for index, req in enumerate(valid_requirements, 1):
        errors = list(validator.iter_errors(policy_with(req)))
        if errors:
            raise TestFailure(f"schema valid {index}: {errors[0].message}")
        print(f"PASS  schema_accepts_context_type_{index:<18} accepted")
        passed += 1

    invalid_schema = policy_with(
        requirement(
            "context_value_equals",
            "/proposal/payload/object",
            value={"name": "service"},
        )
    )
    if not list(validator.iter_errors(invalid_schema)):
        raise TestFailure("schema accepted container expected value")
    print("PASS  schema_rejects_container_expected             rejected")
    passed += 1

    if passed != 36:
        raise TestFailure(f"expected 36 checks, observed {passed}")

    print(f"TPE 2.4 context value primitives: {passed}/{passed} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
