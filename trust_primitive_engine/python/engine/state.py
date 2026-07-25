"""Normalized immutable evaluation state."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Iterable, Mapping

from .context_resolution import create_context_projection


@dataclass(frozen=True)
class EvaluationState:
    """Identity-normalized state shared by all primitive plugins."""

    matched_signers: tuple[str, ...]
    participants: Mapping[str, Mapping[str, Any]]
    signature_count: int
    weight: int
    evaluation_time: int | None = None
    decision_context: Mapping[str, Any] | None = None

    def __post_init__(self) -> None:
        if tuple(sorted(self.matched_signers)) != self.matched_signers:
            raise ValueError(
                "matched_signers must be lexicographically sorted"
            )

        if len(self.matched_signers) != len(
            set(self.matched_signers)
        ):
            raise ValueError(
                "matched_signers must not contain duplicates"
            )

        if self.signature_count != len(self.matched_signers):
            raise ValueError(
                "signature_count must equal matched signer count"
            )

        if self.signature_count < 0:
            raise ValueError(
                "signature_count must not be negative"
            )

        if self.weight < 0:
            raise ValueError("weight must not be negative")

        if self.evaluation_time is not None:
            if (
                isinstance(self.evaluation_time, bool)
                or not isinstance(self.evaluation_time, int)
            ):
                raise ValueError(
                    "evaluation_time must be an integer or None"
                )

            if self.evaluation_time < 0:
                raise ValueError(
                    "evaluation_time must not be negative"
                )

            if self.evaluation_time > 9007199254740991:
                raise ValueError(
                    "evaluation_time exceeds maximum safe integer"
                )

    @property
    def matched_set(self) -> frozenset[str]:
        return frozenset(self.matched_signers)

    @classmethod
    def create(
        cls,
        *,
        matched_signers: list[str],
        participants: dict[str, dict[str, Any]],
        weight: int,
        evaluation_time: int | None = None,
        decision_context: Mapping[str, Any] | None = None,
    ) -> "EvaluationState":
        normalized_signers = tuple(sorted(matched_signers))
        immutable_participants = MappingProxyType(
            {
                signer_id: MappingProxyType(dict(participant))
                for signer_id, participant in participants.items()
            }
        )

        return cls(
            matched_signers=normalized_signers,
            participants=immutable_participants,
            signature_count=len(normalized_signers),
            weight=weight,
            evaluation_time=evaluation_time,
            decision_context=create_context_projection(
                decision_context
            ),
        )


def create_policy_evaluation_state(
    *,
    verified_signers: Iterable[str],
    participants: Mapping[str, Mapping[str, Any]],
    eligible_roles: Iterable[str],
    evaluation_time: int | None = None,
    decision_context: Mapping[str, Any] | None = None,
) -> EvaluationState:
    """Create the policy-local state for one Trust Policy.

    Verified signer identity, normalized participants, and evaluation
    time are shared across the complete policy-reference evaluation.

    Signer eligibility, signature count, and weight are recalculated
    independently for each policy from that policy's eligible_roles.
    """

    normalized_verified_signers = tuple(
        sorted(set(verified_signers))
    )
    eligible_role_set = frozenset(eligible_roles)

    matched_signers = [
        signer_id
        for signer_id in normalized_verified_signers
        if (
            signer_id in participants
            and participants[signer_id]["role"]
            in eligible_role_set
        )
    ]

    weight = sum(
        int(participants[signer_id]["weight"])
        for signer_id in matched_signers
    )

    return EvaluationState.create(
        matched_signers=matched_signers,
        participants={
            signer_id: dict(participant)
            for signer_id, participant in participants.items()
        },
        weight=weight,
        evaluation_time=evaluation_time,
        decision_context=decision_context,
    )
