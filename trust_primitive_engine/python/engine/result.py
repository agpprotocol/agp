"""Deterministic primitive evaluation result."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PrimitiveResult:
    """Result produced by one trust primitive."""

    requirement_id: str
    primitive_type: str
    satisfied: bool
    matched_signers: tuple[str, ...]
    observed: dict[str, Any]
    expected: dict[str, Any]
    failure_code: str

    def __post_init__(self) -> None:
        if tuple(sorted(self.matched_signers)) != self.matched_signers:
            raise ValueError(
                "matched_signers must be lexicographically sorted"
            )

        if self.satisfied and self.failure_code:
            raise ValueError(
                "satisfied result must not contain failure_code"
            )

        if not self.satisfied and not self.failure_code:
            raise ValueError(
                "unsatisfied result must contain failure_code"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "type": self.primitive_type,
            "status": (
                "satisfied"
                if self.satisfied
                else "unsatisfied"
            ),
            "matched_signers": list(self.matched_signers),
            "observed": self.observed,
            "expected": self.expected,
            "failure_code": (
                None
                if self.satisfied
                else self.failure_code
            ),
        }

    @classmethod
    def satisfied_result(
        cls,
        *,
        requirement_id: str,
        primitive_type: str,
        matched_signers: list[str],
        observed: dict[str, Any],
        expected: dict[str, Any],
    ) -> "PrimitiveResult":
        return cls(
            requirement_id=requirement_id,
            primitive_type=primitive_type,
            satisfied=True,
            matched_signers=tuple(sorted(matched_signers)),
            observed=observed,
            expected=expected,
            failure_code="",
        )

    @classmethod
    def unsatisfied_result(
        cls,
        *,
        requirement_id: str,
        primitive_type: str,
        matched_signers: list[str],
        observed: dict[str, Any],
        expected: dict[str, Any],
        failure_code: str,
    ) -> "PrimitiveResult":
        return cls(
            requirement_id=requirement_id,
            primitive_type=primitive_type,
            satisfied=False,
            matched_signers=tuple(sorted(matched_signers)),
            observed=observed,
            expected=expected,
            failure_code=failure_code,
        )
