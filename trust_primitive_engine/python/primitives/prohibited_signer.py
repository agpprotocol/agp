"""Prohibited signer trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "signer_id",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)


class ProhibitedSignerPrimitive(Primitive):
    """Reject one specific identity from the matched signer set."""

    TYPE = "prohibited_signer"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"prohibited_signer unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"prohibited_signer missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        signer_id = value["signer_id"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if (
            not isinstance(signer_id, str)
            or not IDENTIFIER_RE.fullmatch(signer_id)
        ):
            raise ValueError(
                "requirements[].signer_id "
                "is not a valid identifier"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "signer_id": signer_id,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        signer_id = requirement["signer_id"]
        present = signer_id in state.matched_set
        matched = [signer_id] if present else []

        if not present:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=[],
                observed={"present": False},
                expected={"signer_id": signer_id},
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=matched,
            observed={"present": True},
            expected={"signer_id": signer_id},
            failure_code="PROHIBITED_SIGNER_PRESENT",
        )
