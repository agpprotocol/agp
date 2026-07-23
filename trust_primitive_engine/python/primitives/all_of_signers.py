"""All-of signers trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "signer_ids",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)


class AllOfSignersPrimitive(Primitive):
    """Require every signer in a configured identity set."""

    TYPE = "all_of_signers"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"all_of_signers unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"all_of_signers missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        signer_ids = value["signer_ids"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if (
            not isinstance(signer_ids, list)
            or len(signer_ids) < 2
            or any(
                not isinstance(signer_id, str)
                for signer_id in signer_ids
            )
        ):
            raise ValueError(
                "all_of_signers.signer_ids must contain "
                "at least two signer identifier strings"
            )

        if any(
            not IDENTIFIER_RE.fullmatch(signer_id)
            for signer_id in signer_ids
        ):
            raise ValueError(
                "all_of_signers.signer_ids entries "
                "must be valid identifiers"
            )

        if len(set(signer_ids)) != len(signer_ids):
            raise ValueError(
                "all_of_signers.signer_ids must contain "
                "distinct identities"
            )

        if signer_ids != sorted(signer_ids):
            raise ValueError(
                "all_of_signers.signer_ids must be "
                "lexicographically sorted"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "signer_ids": list(signer_ids),
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        signer_ids = requirement["signer_ids"]
        matched = [
            signer_id
            for signer_id in signer_ids
            if signer_id in state.matched_set
        ]
        missing = [
            signer_id
            for signer_id in signer_ids
            if signer_id not in state.matched_set
        ]

        observed = {
            "matched_count": len(matched),
            "missing_signer_ids": missing,
        }
        expected = {
            "required_count": len(signer_ids),
            "signer_ids": list(signer_ids),
        }

        if not missing:
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
            failure_code="ALL_OF_SIGNERS_NOT_SATISFIED",
        )
