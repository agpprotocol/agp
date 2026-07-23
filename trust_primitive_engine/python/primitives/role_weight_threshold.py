"""Role weight threshold trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "role",
    "minimum_weight",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)

ALLOWED_ROLES = {
    "approver",
    "observer",
    "proposer",
    "reviewer",
    "voter",
}

MAX_SAFE_INTEGER = 9_007_199_254_740_991


class RoleWeightThresholdPrimitive(Primitive):
    """Require a minimum matched signer weight for one role."""

    TYPE = "role_weight_threshold"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"role_weight_threshold unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"role_weight_threshold missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        role = value["role"]
        minimum = value["minimum_weight"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if role not in ALLOWED_ROLES:
            raise ValueError(
                "role_weight_threshold.role must be one of: "
                + ", ".join(sorted(ALLOWED_ROLES))
            )

        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or minimum < 1
            or minimum > MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "requirements[].minimum_weight must be "
                f"an integer from 1 to {MAX_SAFE_INTEGER}"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "role": role,
            "minimum_weight": minimum,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        role = requirement["role"]
        minimum = requirement["minimum_weight"]

        matched = sorted(
            signer_id
            for signer_id in state.matched_signers
            if state.participants[signer_id]["role"] == role
        )
        observed_weight = sum(
            state.participants[signer_id]["weight"]
            for signer_id in matched
        )

        observed = {
            "role": role,
            "weight": observed_weight,
        }
        expected = {
            "role": role,
            "minimum_weight": minimum,
        }

        if observed_weight >= minimum:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=matched,
                observed=observed,
                expected=expected,
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=matched,
            observed=observed,
            expected=expected,
            failure_code="ROLE_WEIGHT_THRESHOLD_NOT_REACHED",
        )
