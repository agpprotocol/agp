"""Signer threshold trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "signer_ids",
    "minimum_signatures",
}

IDENTIFIER_RE = re.compile(
    r"^[a-z0-9][a-z0-9._:/-]{1,127}[a-z0-9]$"
)


class SignerThresholdPrimitive(Primitive):
    """Require a minimum number of identities from a signer group."""

    TYPE = "signer_threshold"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"signer_threshold unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"signer_threshold missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        signer_ids = value["signer_ids"]
        minimum_signatures = value["minimum_signatures"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if not isinstance(signer_ids, list) or not signer_ids:
            raise ValueError(
                "signer_threshold.signer_ids "
                "must be a non-empty array"
            )

        if any(
            not isinstance(signer_id, str)
            or not IDENTIFIER_RE.fullmatch(signer_id)
            for signer_id in signer_ids
        ):
            raise ValueError(
                "signer_threshold.signer_ids "
                "contains an invalid identifier"
            )

        if signer_ids != sorted(signer_ids):
            raise ValueError(
                "signer_threshold.signer_ids "
                "must be lexicographically sorted"
            )

        if len(signer_ids) != len(set(signer_ids)):
            raise ValueError(
                "signer_threshold.signer_ids "
                "must not contain duplicates"
            )

        if (
            isinstance(minimum_signatures, bool)
            or not isinstance(minimum_signatures, int)
            or minimum_signatures < 1
        ):
            raise ValueError(
                "signer_threshold.minimum_signatures "
                "must be a positive integer"
            )

        if minimum_signatures > len(signer_ids):
            raise ValueError(
                "signer_threshold.minimum_signatures "
                "must not exceed signer_ids length"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "signer_ids": list(signer_ids),
            "minimum_signatures": minimum_signatures,
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        allowed = set(requirement["signer_ids"])
        matched = sorted(state.matched_set & allowed)
        observed_count = len(matched)
        minimum = requirement["minimum_signatures"]

        observed = {
            "signature_count": observed_count,
        }
        expected = {
            "minimum_signatures": minimum,
            "signer_ids": requirement["signer_ids"],
        }

        if observed_count >= minimum:
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
            failure_code="SIGNER_THRESHOLD_NOT_REACHED",
        )
