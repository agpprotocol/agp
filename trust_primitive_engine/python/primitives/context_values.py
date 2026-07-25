"""Deterministic proposal-payload context trust primitives."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult, resolve_context_path
from engine.context_resolution import ContextResolution, parse_context_path

IDENTIFIER_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$")
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_EXPECTED_STRING_LENGTH = 4096
MAX_RESULT_STRING_LENGTH = 4096


def _validate_exact_members(value: dict[str, Any], expected: set[str], primitive_type: str) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))
    if unknown:
        raise ValueError(f"{primitive_type} unknown members: {unknown}")
    if missing:
        raise ValueError(f"{primitive_type} missing members: {missing}")


def _validate_requirement_id(value: Any) -> str:
    if not isinstance(value, str) or not IDENTIFIER_RE.fullmatch(value):
        raise ValueError("requirements[].requirement_id is not a valid identifier")
    return value


def _validate_path(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("requirements[].path must be a string")
    parse_context_path(value)
    return value


def _scalar_type(value: Any) -> str | None:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, str):
        return "string"
    return None


def _validate_scalar(value: Any) -> Any:
    value_type = _scalar_type(value)
    if value_type is None:
        raise ValueError("requirements[].value must be a JSON scalar")
    if value_type == "integer" and not (-MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER):
        raise ValueError("requirements[].value integer exceeds the AGP safe-integer range")
    if value_type == "string" and len(value) > MAX_EXPECTED_STRING_LENGTH:
        raise ValueError("requirements[].value string exceeds 4096 Unicode scalar values")
    return value


def _validate_integer_bound(value: Any, field: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < -MAX_SAFE_INTEGER
        or value > MAX_SAFE_INTEGER
    ):
        raise ValueError(
            f"requirements[].{field} must be an integer from "
            f"{-MAX_SAFE_INTEGER} to {MAX_SAFE_INTEGER}"
        )
    return value


def _observation(path: str, resolution: ContextResolution) -> dict[str, Any]:
    observed_value: Any = None
    if resolution.status == "found":
        if resolution.value_type in {"null", "boolean", "integer"}:
            observed_value = resolution.value
        elif resolution.value_type == "string" and len(resolution.value) <= MAX_RESULT_STRING_LENGTH:
            observed_value = resolution.value
    return {
        "path": path,
        "resolution": resolution.status,
        "value_type": resolution.value_type,
        "value": observed_value,
    }


def _strict_scalar_equal(observed: Any, expected: Any) -> bool:
    observed_type = _scalar_type(observed)
    expected_type = _scalar_type(expected)
    return observed_type is not None and observed_type == expected_type and observed == expected


class ContextValuePresentPrimitive(Primitive):
    TYPE = "context_value_present"
    EXPECTED_MEMBERS = {"requirement_id", "type", "path"}

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        _validate_exact_members(value, self.EXPECTED_MEMBERS, self.TYPE)
        requirement_id = _validate_requirement_id(value["requirement_id"])
        path = _validate_path(value["path"])
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        return {"requirement_id": requirement_id, "type": self.TYPE, "path": path}

    def evaluate(self, requirement: dict[str, Any], state: EvaluationState) -> PrimitiveResult:
        path = requirement["path"]
        resolution = resolve_context_path(state.decision_context, path)
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observation(path, resolution),
            expected={"resolution": "found"},
        )
        if resolution.status == "found":
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs,
            failure_code="CONTEXT_VALUE_NOT_PRESENT",
        )


class ContextValueEqualsPrimitive(Primitive):
    TYPE = "context_value_equals"
    EXPECTED_MEMBERS = {"requirement_id", "type", "path", "value"}

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        _validate_exact_members(value, self.EXPECTED_MEMBERS, self.TYPE)
        requirement_id = _validate_requirement_id(value["requirement_id"])
        path = _validate_path(value["path"])
        expected_value = _validate_scalar(value["value"])
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "path": path,
            "value": expected_value,
        }

    def evaluate(self, requirement: dict[str, Any], state: EvaluationState) -> PrimitiveResult:
        path = requirement["path"]
        expected_value = requirement["value"]
        resolution = resolve_context_path(state.decision_context, path)
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observation(path, resolution),
            expected={"value": expected_value},
        )
        if resolution.status == "found" and _strict_scalar_equal(resolution.value, expected_value):
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs,
            failure_code="CONTEXT_VALUE_NOT_EQUAL",
        )


class ContextIntegerAtLeastPrimitive(Primitive):
    TYPE = "context_integer_at_least"
    EXPECTED_MEMBERS = {"requirement_id", "type", "path", "minimum"}

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        _validate_exact_members(value, self.EXPECTED_MEMBERS, self.TYPE)
        requirement_id = _validate_requirement_id(value["requirement_id"])
        path = _validate_path(value["path"])
        minimum = _validate_integer_bound(value["minimum"], "minimum")
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "path": path,
            "minimum": minimum,
        }

    def evaluate(self, requirement: dict[str, Any], state: EvaluationState) -> PrimitiveResult:
        path = requirement["path"]
        minimum = requirement["minimum"]
        resolution = resolve_context_path(state.decision_context, path)
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observation(path, resolution),
            expected={"minimum": minimum},
        )
        if (
            resolution.status == "found"
            and resolution.value_type == "integer"
            and resolution.value >= minimum
        ):
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs,
            failure_code="CONTEXT_INTEGER_MINIMUM_NOT_REACHED",
        )


class ContextIntegerAtMostPrimitive(Primitive):
    TYPE = "context_integer_at_most"
    EXPECTED_MEMBERS = {"requirement_id", "type", "path", "maximum"}

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        _validate_exact_members(value, self.EXPECTED_MEMBERS, self.TYPE)
        requirement_id = _validate_requirement_id(value["requirement_id"])
        path = _validate_path(value["path"])
        maximum = _validate_integer_bound(value["maximum"], "maximum")
        if value["type"] != self.TYPE:
            raise ValueError(f"type must be {self.TYPE}")
        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "path": path,
            "maximum": maximum,
        }

    def evaluate(self, requirement: dict[str, Any], state: EvaluationState) -> PrimitiveResult:
        path = requirement["path"]
        maximum = requirement["maximum"]
        resolution = resolve_context_path(state.decision_context, path)
        kwargs = dict(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=_observation(path, resolution),
            expected={"maximum": maximum},
        )
        if (
            resolution.status == "found"
            and resolution.value_type == "integer"
            and resolution.value <= maximum
        ):
            return PrimitiveResult.satisfied_result(**kwargs)
        return PrimitiveResult.unsatisfied_result(
            **kwargs,
            failure_code="CONTEXT_INTEGER_MAXIMUM_EXCEEDED",
        )
