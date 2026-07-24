"""Deterministic inclusive time-window trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "not_before",
    "not_after",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)

MAX_SAFE_INTEGER = 9_007_199_254_740_991


class TimeWindowPrimitive(Primitive):
    """Require evaluation_time to fall inside an inclusive interval."""

    TYPE = "time_window"

    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(f"time_window unknown members: {unknown}")
        if missing:
            raise ValueError(f"time_window missing members: {missing}")

        requirement_id = value["requirement_id"]
        not_before = value["not_before"]
        not_after = value["not_after"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id is not a valid identifier"
            )

        for field, bound in (
            ("not_before", not_before),
            ("not_after", not_after),
        ):
            if (
                not isinstance(bound, int)
                or isinstance(bound, bool)
                or bound < 0
                or bound > MAX_SAFE_INTEGER
            ):
                raise ValueError(
                    f"requirements[].{field} must be an integer from "
                    f"0 to {MAX_SAFE_INTEGER}"
                )

        if not_before > not_after:
            raise ValueError(
                "time_window.not_before must be less than or equal to "
                "time_window.not_after"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "not_before": not_before,
            "not_after": not_after,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        not_before = requirement["not_before"]
        not_after = requirement["not_after"]
        evaluation_time = state.evaluation_time

        if evaluation_time is None:
            position = "missing"
        elif evaluation_time < not_before:
            position = "before"
        elif evaluation_time > not_after:
            position = "after"
        else:
            position = "inside"

        observed = {
            "evaluation_time": evaluation_time,
            "position": position,
        }
        expected = {
            "not_before": not_before,
            "not_after": not_after,
        }

        if position == "inside":
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=[],
                observed=observed,
                expected=expected,
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed=observed,
            expected=expected,
            failure_code="TIME_WINDOW_NOT_SATISFIED",
        )
