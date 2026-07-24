"""Structural dispatch for validated Trust Policy requirements."""

from __future__ import annotations

from typing import Any

from .composition import evaluate_composition
from .policy_tree import COMPOSITION_TYPES
from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import EvaluationState


def evaluate_requirement(
    requirement: dict[str, Any],
    state: EvaluationState,
    registry: PrimitiveRegistry,
) -> PrimitiveResult:
    """Dispatch one validated requirement by structural category.

    Composition operators are evaluated by the composition engine.
    All other currently supported requirement types are resolved as
    executable primitives through the primitive registry.

    Policy references are not enabled here yet. A later TPE 2.3 change
    will add a dedicated structural branch without modifying primitive
    or composition implementations.
    """

    requirement_type = requirement["type"]

    if requirement_type in COMPOSITION_TYPES:
        return evaluate_composition(
            requirement,
            state,
            registry,
            evaluate_child=evaluate_requirement,
        )

    primitive = registry.resolve(requirement_type)
    return primitive.evaluate(requirement, state)
