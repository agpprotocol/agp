"""Separation of duties trust primitive."""

from __future__ import annotations

import re
from typing import Any

from engine import EvaluationState, Primitive, PrimitiveResult


EXPECTED_MEMBERS = {
    "requirement_id",
    "type",
    "roles",
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


class SeparationOfDutiesPrimitive(Primitive):
    """Require two distinct participant roles among matched signers."""

    TYPE = "separation_of_duties"

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        unknown = sorted(set(value) - EXPECTED_MEMBERS)
        missing = sorted(EXPECTED_MEMBERS - set(value))

        if unknown:
            raise ValueError(
                f"separation_of_duties unknown members: {unknown}"
            )

        if missing:
            raise ValueError(
                f"separation_of_duties missing members: {missing}"
            )

        requirement_id = value["requirement_id"]
        roles = value["roles"]

        if (
            not isinstance(requirement_id, str)
            or not IDENTIFIER_RE.fullmatch(requirement_id)
        ):
            raise ValueError(
                "requirements[].requirement_id "
                "is not a valid identifier"
            )

        if (
            not isinstance(roles, list)
            or len(roles) != 2
            or any(not isinstance(role, str) for role in roles)
        ):
            raise ValueError(
                "separation_of_duties.roles must contain "
                "exactly two role strings"
            )

        if any(role not in ALLOWED_ROLES for role in roles):
            raise ValueError(
                "separation_of_duties.roles entries must be one of: "
                + ", ".join(sorted(ALLOWED_ROLES))
            )

        if len(set(roles)) != 2:
            raise ValueError(
                "separation_of_duties.roles must contain "
                "two distinct roles"
            )

        if roles != sorted(roles):
            raise ValueError(
                "separation_of_duties.roles must be "
                "lexicographically sorted"
            )

        return {
            "requirement_id": requirement_id,
            "type": self.TYPE,
            "roles": list(roles),
        }

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        roles = requirement["roles"]

        matched_by_role = {
            role: sorted(
                signer_id
                for signer_id in state.matched_signers
                if state.participants[signer_id]["role"] == role
            )
            for role in roles
        }

        matched = sorted(
            signer_id
            for role in roles
            for signer_id in matched_by_role[role]
        )
        present_roles = [
            role
            for role in roles
            if matched_by_role[role]
        ]
        missing_roles = [
            role
            for role in roles
            if not matched_by_role[role]
        ]

        observed = {
            "present_roles": present_roles,
            "missing_roles": missing_roles,
        }
        expected = {
            "roles": list(roles),
            "distinct_identities": 2,
        }

        if not missing_roles:
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
            failure_code="SEPARATION_OF_DUTIES_NOT_SATISFIED",
        )
