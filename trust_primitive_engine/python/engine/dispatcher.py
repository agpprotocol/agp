"""Structural dispatch for validated Trust Policy requirements."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .composition import evaluate_composition
from .policy_tree import COMPOSITION_TYPES
from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import EvaluationState



PolicyReferenceEvaluator = Callable[
    [dict[str, Any]],
    PrimitiveResult,
]


@dataclass(frozen=True)
class RequirementEvaluationContext:
    """Structural callbacks available during requirement evaluation."""

    evaluate_policy_reference: (
        PolicyReferenceEvaluator | None
    ) = None


def evaluate_requirement(
    requirement: dict[str, Any],
    state: EvaluationState,
    registry: PrimitiveRegistry,
    *,
    context: RequirementEvaluationContext | None = None,
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
        def evaluate_child(
            child: dict[str, Any],
            child_state: EvaluationState,
            child_registry: PrimitiveRegistry,
        ) -> PrimitiveResult:
            return evaluate_requirement(
                child,
                child_state,
                child_registry,
                context=context,
            )

        return evaluate_composition(
            requirement,
            state,
            registry,
            evaluate_child=evaluate_child,
        )

    if (
        requirement_type == "policy_reference"
        and context is not None
        and context.evaluate_policy_reference is not None
    ):
        return context.evaluate_policy_reference(requirement)

    primitive = registry.resolve(requirement_type)
    return primitive.evaluate(requirement, state)
