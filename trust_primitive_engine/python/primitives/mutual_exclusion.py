"""Mutual exclusion trust primitive."""

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


class MutualExclusionPrimitive(Primitive):
    """Reject simultaneous presence of two specified signer identities."""

    TYPE = "mutual_exclusion"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"mutual_exclusion unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"mutual_exclusion missing members: {missing}"
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
            or len(signer_ids) != 2
            or any(
                not isinstance(signer_id, str)
                for signer_id in signer_ids
            )
        ):
            raise ValueError(
                "mutual_exclusion.signer_ids must contain "
                "exactly two signer identifier strings"
            )

        if any(
            not IDENTIFIER_RE.fullmatch(signer_id)
            for signer_id in signer_ids
        ):
            raise ValueError(
                "mutual_exclusion.signer_ids entries "
                "must be valid identifiers"
            )

        if len(set(signer_ids)) != 2:
            raise ValueError(
                "mutual_exclusion.signer_ids must contain "
                "two distinct identities"
            )

        if signer_ids != sorted(signer_ids):
            raise ValueError(
                "mutual_exclusion.signer_ids must be "
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
        present = [
            signer_id
            for signer_id in signer_ids
            if signer_id in state.matched_set
        ]

        observed = {
            "present_signer_ids": present,
        }
        expected = {
            "maximum_simultaneous": 1,
            "signer_ids": list(signer_ids),
        }

        if len(present) <= 1:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=present,
                observed=observed,
                expected=expected,
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=present,
            observed=observed,
            expected=expected,
            failure_code="MUTUAL_EXCLUSION_VIOLATED",
        )
