"""Required signer trust primitive."""

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


class RequiredSignerPrimitive(Primitive):
    """Require one specific eligible, authorized signer identity."""

    TYPE = "required_signer"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"required_signer unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"required_signer missing members: {missing}"
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
        matched = (
            [signer_id]
            if signer_id in state.matched_set
            else []
        )

        if matched:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=matched,
                observed={"present": True},
                expected={"signer_id": signer_id},
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed={"present": False},
            expected={"signer_id": signer_id},
            failure_code="REQUIRED_SIGNER_MISSING",
        )
