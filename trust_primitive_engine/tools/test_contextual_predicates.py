#!/usr/bin/env python3
"""Focused TPE 2.5 checks for deterministic contextual predicates."""

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
    ContextPathEqualsPrimitive,
    ContextValueInPrimitive,
)

REGISTRY = PrimitiveRegistry([
    ContextPathEqualsPrimitive(),
    ContextValueInPrimitive(),
])


class TestFailure(Exception):
    pass


def value_in(path: str, values: list[Any]) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:value-in",
        "type": "context_value_in",
        "path": path,
        "values": values,
    }


def path_equals(left_path: str, right_path: str) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:path-equals",
        "type": "context_path_equals",
        "left_path": left_path,
        "right_path": right_path,
    }


def policy_with(requirement: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe-2.5-contextual-predicates",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [requirement],
    }


def evaluate(state: EvaluationState, requirement: dict[str, Any]):
    primitive = REGISTRY.resolve(requirement["type"])
    normalized = primitive.validate(requirement)
    return primitive.evaluate(normalized, state)


def expect_reject(name: str, primitive: Any, requirement: dict[str, Any]) -> None:
    try:
        primitive.validate(requirement)
    except ValueError:
        print(f"PASS  {name:<48} rejected")
        return
    raise TestFailure(f"{name}: invalid requirement was accepted")


def main() -> int:
    passed = 0
    state = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        decision_context={
            "proposal": {
                "payload": {
                    "environment": "production",
                    "enabled": True,
                    "count": 1,
                    "nullable": None,
                    "nullable_copy": None,
                    "requested_version": "3.0.0",
                    "approved_version": "3.0.0",
                    "different_version": "3.0.1",
                    "object": {"name": "service"},
                    "object_copy": {"name": "service"},
                }
            },
            "evidence": [],
        },
    )

    cases = [
        ("value_in_string_match", value_in("/proposal/payload/environment", ["canary", "production"]), True, None),
        ("value_in_string_mismatch", value_in("/proposal/payload/environment", ["canary", "staging"]), False, "CONTEXT_VALUE_NOT_IN_SET"),
        ("value_in_boolean_match", value_in("/proposal/payload/enabled", [False, True]), True, None),
        ("value_in_boolean_integer_strict", value_in("/proposal/payload/enabled", [1]), False, "CONTEXT_VALUE_NOT_IN_SET"),
        ("value_in_integer_match", value_in("/proposal/payload/count", [0, 1, 2]), True, None),
        ("value_in_null_match", value_in("/proposal/payload/nullable", [None]), True, None),
        ("value_in_missing", value_in("/proposal/payload/missing", ["production"]), False, "CONTEXT_VALUE_NOT_IN_SET"),
        ("value_in_container", value_in("/proposal/payload/object", ["service"]), False, "CONTEXT_VALUE_NOT_IN_SET"),
        ("path_equals_string", path_equals("/proposal/payload/requested_version", "/proposal/payload/approved_version"), True, None),
        ("path_equals_unequal", path_equals("/proposal/payload/requested_version", "/proposal/payload/different_version"), False, "CONTEXT_PATH_VALUES_NOT_EQUAL"),
        ("path_equals_boolean_integer_strict", path_equals("/proposal/payload/enabled", "/proposal/payload/count"), False, "CONTEXT_PATH_VALUES_NOT_EQUAL"),
        ("path_equals_null", path_equals("/proposal/payload/nullable", "/proposal/payload/nullable_copy"), True, None),
        ("path_equals_one_missing", path_equals("/proposal/payload/requested_version", "/proposal/payload/missing"), False, "CONTEXT_PATH_VALUES_NOT_EQUAL"),
        ("path_equals_container", path_equals("/proposal/payload/object", "/proposal/payload/object_copy"), False, "CONTEXT_PATH_VALUES_NOT_EQUAL"),
    ]

    for name, requirement, satisfied, failure_code in cases:
        result = evaluate(state, requirement)
        if result.satisfied is not satisfied:
            raise TestFailure(f"{name}: wrong satisfaction")
        observed_failure = None if result.satisfied else result.failure_code
        if observed_failure != failure_code:
            raise TestFailure(f"{name}: wrong failure code")
        if result.matched_signers != ():
            raise TestFailure(f"{name}: matched_signers must be empty")
        print(f"PASS  {name:<48} correct")
        passed += 1

    value_primitive = ContextValueInPrimitive()
    path_primitive = ContextPathEqualsPrimitive()
    invalid = [
        ("value_in_empty", value_primitive, value_in("/proposal/payload/environment", [])),
        ("value_in_over_limit", value_primitive, value_in("/proposal/payload/count", list(range(65)))),
        ("value_in_heterogeneous", value_primitive, value_in("/proposal/payload/environment", [1, "1"])),
        ("value_in_duplicate", value_primitive, value_in("/proposal/payload/environment", ["prod", "prod"])),
        ("value_in_unordered_strings", value_primitive, value_in("/proposal/payload/environment", ["production", "canary"])),
        ("value_in_unordered_booleans", value_primitive, value_in("/proposal/payload/enabled", [True, False])),
        ("value_in_unsafe_integer", value_primitive, value_in("/proposal/payload/count", [9_007_199_254_740_992])),
        ("value_in_oversized_string", value_primitive, value_in("/proposal/payload/environment", ["x" * 4097])),
        ("value_in_unknown_member", value_primitive, {**value_in("/proposal/payload/environment", ["production"]), "x": 1}),
        ("path_equals_identical", path_primitive, path_equals("/proposal/payload/environment", "/proposal/payload/environment")),
        ("path_equals_invalid_left", path_primitive, path_equals("/participants/0/id", "/proposal/payload/environment")),
        ("path_equals_missing_right_member", path_primitive, {
            "requirement_id": "requirement:path-equals",
            "type": "context_path_equals",
            "left_path": "/proposal/payload/environment",
        }),
    ]

    for name, primitive, requirement in invalid:
        expect_reject(name, primitive, requirement)
        passed += 1

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)

    valid_schema = [
        ("schema_accepts_value_in", value_in("/proposal/payload/environment", ["canary", "production"])),
        ("schema_accepts_path_equals", path_equals("/proposal/payload/requested_version", "/proposal/payload/approved_version")),
    ]
    for name, requirement in valid_schema:
        errors = list(validator.iter_errors(policy_with(requirement)))
        if errors:
            raise TestFailure(f"{name}: {errors[0].message}")
        print(f"PASS  {name:<48} accepted")
        passed += 1

    invalid_schema = [
        ("schema_rejects_empty_values", value_in("/proposal/payload/environment", [])),
        ("schema_rejects_65_values", value_in("/proposal/payload/count", list(range(65)))),
    ]
    for name, requirement in invalid_schema:
        if not list(validator.iter_errors(policy_with(requirement))):
            raise TestFailure(f"{name}: schema accepted invalid requirement")
        print(f"PASS  {name:<48} rejected")
        passed += 1

    if REGISTRY.types() != ("context_path_equals", "context_value_in"):
        raise TestFailure("registry types are incorrect")
    print("PASS  registry_contains_tpe25_context_types          correct")
    passed += 1

    first = evaluate(state, value_in("/proposal/payload/environment", ["canary", "production"])).to_dict()
    second = evaluate(state, value_in("/proposal/payload/environment", ["canary", "production"])).to_dict()
    if first != second:
        raise TestFailure("deterministic replay changed")
    print("PASS  deterministic_replay                           identical")
    passed += 1

    if passed != 32:
        raise TestFailure(f"expected 32 checks, observed {passed}")

    print(f"TPE 2.5 contextual predicates: {passed}/{passed} passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
