"""Global signature threshold trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "minimum_signatures",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)

MAX_SAFE_INTEGER = 9_007_199_254_740_991


class GlobalSignatureThresholdPrimitive(Primitive):
    """Require a minimum number of eligible signer identities."""

    TYPE = "global_signature_threshold"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                "global_signature_threshold unknown members: "
                f"{unknown}"
            )

        if missing:
            raise ValueError(
                "global_signature_threshold missing members: "
                f"{missing}"
            )

        requirement_id = value["requirement_id"]
        minimum = value["minimum_signatures"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
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
            "minimum_signatures": minimum,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        minimum = requirement["minimum_signatures"]
        observed = {
            "signature_count": state.signature_count,
        }
        expected = {
            "minimum_signatures": minimum,
        }

        if state.signature_count >= minimum:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=list(state.matched_signers),
                observed=observed,
                expected=expected,
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=list(state.matched_signers),
            observed=observed,
            expected=expected,
            failure_code=(
                "GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"
            ),
        )
