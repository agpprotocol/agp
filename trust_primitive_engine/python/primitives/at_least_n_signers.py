"""At-least-N signers trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "signer_ids",
    "minimum_matches",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)


class AtLeastNSignersPrimitive(Primitive):
    """Require a minimum number of configured signer identities."""

    TYPE = "at_least_n_signers"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"at_least_n_signers unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"at_least_n_signers missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        signer_ids = value["signer_ids"]
        minimum_matches = value["minimum_matches"]

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
                "at_least_n_signers.signer_ids must contain "
                "at least two signer identifier strings"
            )

        if any(
            not IDENTIFIER_RE.fullmatch(signer_id)
            for signer_id in signer_ids
        ):
            raise ValueError(
                "at_least_n_signers.signer_ids entries "
                "must be valid identifiers"
            )

        if len(set(signer_ids)) != len(signer_ids):
            raise ValueError(
                "at_least_n_signers.signer_ids must contain "
                "distinct identities"
            )

        if signer_ids != sorted(signer_ids):
            raise ValueError(
                "at_least_n_signers.signer_ids must be "
                "lexicographically sorted"
            )

        if (
            not isinstance(minimum_matches, int)
            or isinstance(minimum_matches, bool)
            or minimum_matches < 1
            or minimum_matches > len(signer_ids)
        ):
            raise ValueError(
                "at_least_n_signers.minimum_matches must be an integer "
                "from one through len(signer_ids)"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "signer_ids": list(signer_ids),
            "minimum_matches": minimum_matches,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        signer_ids = requirement["signer_ids"]
        minimum_matches = requirement["minimum_matches"]

        matched = [
            signer_id
            for signer_id in signer_ids
            if signer_id in state.matched_set
        ]

        observed = {
            "matched_count": len(matched),
        }
        expected = {
            "minimum_matches": minimum_matches,
            "signer_ids": list(signer_ids),
        }

        if len(matched) >= minimum_matches:
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
            failure_code="AT_LEAST_N_SIGNERS_NOT_REACHED",
        )
