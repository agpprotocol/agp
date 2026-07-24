"""Role threshold trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "role",
    "minimum_signatures",
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


class RoleThresholdPrimitive(Primitive):
    """Require a minimum number of matched identities with one role."""

    TYPE = "role_threshold"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"role_threshold unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"role_threshold missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        role = value["role"]
        minimum = value["minimum_signatures"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if not isinstance(role, str):
            raise ValueError(
                "role_threshold.role must be a string"
            )

        if role not in ALLOWED_ROLES:
            raise ValueError(
                "role_threshold.role must be one of: "
                + ", ".join(sorted(ALLOWED_ROLES))
            )

        if (
            not isinstance(minimum, int)
            or isinstance(minimum, bool)
            or minimum < 1
            or minimum > MAX_SAFE_INTEGER
        ):
            raise ValueError(
                "requirements[].minimum_signatures must be "
                f"an integer from 1 to {MAX_SAFE_INTEGER}"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "role": role,
            "minimum_signatures": minimum,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        role = requirement["role"]
        minimum = requirement["minimum_signatures"]

        matched = sorted(
            signer_id
            for signer_id in state.matched_signers
            if state.participants[signer_id]["role"] == role
        )

        observed = {
            "role": role,
            "signature_count": len(matched),
        }
        expected = {
            "role": role,
            "minimum_signatures": minimum,
        }

        if len(matched) >= minimum:
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
            failure_code="ROLE_THRESHOLD_NOT_REACHED",
        )
