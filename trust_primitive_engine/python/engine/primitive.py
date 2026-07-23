"""Base contract for Trust Primitive Engine plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .result import PrimitiveResult
from .state import EvaluationState


class Primitive(ABC):
    """Validation and evaluation contract for one primitive type."""

    TYPE: str = ""

    @abstractmethod
    def validate(self, value: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize a primitive definition."""

    @abstractmethod
    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        """Evaluate a validated primitive against normalized state."""
