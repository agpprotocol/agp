"""Normalized immutable evaluation state."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class EvaluationState:
    """Identity-normalized state shared by all primitive plugins."""

    matched_signers: tuple[str, ...]
    participants: Mapping[str, Mapping[str, Any]]
    signature_count: int
    weight: int

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
        )
