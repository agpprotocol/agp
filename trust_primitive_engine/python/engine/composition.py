"""Deterministic evaluation for recursive policy composition."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import EvaluationState


RequirementEvaluator = Callable[
    [dict[str, Any], EvaluationState, PrimitiveRegistry],
    PrimitiveResult,
]


def _aggregate_matched_signers(
    children: tuple[PrimitiveResult, ...],
) -> list[str]:
    return sorted({
        signer_id
        for child in children
        for signer_id in child.matched_signers
    })


def evaluate_composition(
    requirement: dict[str, Any],
    state: EvaluationState,
    registry: PrimitiveRegistry,
    *,
    evaluate_child: RequirementEvaluator,
) -> PrimitiveResult:
    """Evaluate one validated composition requirement.

    Structural dispatch is intentionally handled outside this module.
    Recursive child evaluation is supplied by the dispatcher so that
    additional structural requirement types can be introduced without
    coupling them to composition logic.
    """

    requirement_type = requirement["type"]

    if requirement_type in {"all_of", "any_of"}:
        children = tuple(
            evaluate_child(child, state, registry)
            for child in requirement["requirements"]
        )

        satisfied_children = sum(
            1 for child in children if child.satisfied
        )
        total_children = len(children)
        matched_signers = _aggregate_matched_signers(children)

        if requirement_type == "all_of":
            satisfied = satisfied_children == total_children
            observed = {
                "satisfied_children": satisfied_children,
                "total_children": total_children,
            }
            expected = {
                "required_satisfied_children": total_children,
            }
            failure_code = "ALL_OF_NOT_SATISFIED"
        else:
            satisfied = satisfied_children >= 1
            observed = {
                "satisfied_children": satisfied_children,
                "total_children": total_children,
            }
            expected = {
                "minimum_satisfied_children": 1,
            }
            failure_code = "ANY_OF_NOT_SATISFIED"

        factory = (
            PrimitiveResult.satisfied_result
            if satisfied
            else PrimitiveResult.unsatisfied_result
        )

        kwargs: dict[str, Any] = {
            "requirement_id": requirement["requirement_id"],
            "primitive_type": requirement_type,
            "matched_signers": matched_signers,
            "observed": observed,
            "expected": expected,
            "children": children,
        }

        if not satisfied:
            kwargs["failure_code"] = failure_code

        return factory(**kwargs)

    if requirement_type == "not":
        child = evaluate_child(
            requirement["requirement"],
            state,
            registry,
        )
        satisfied = not child.satisfied

        factory = (
            PrimitiveResult.satisfied_result
            if satisfied
            else PrimitiveResult.unsatisfied_result
        )

        kwargs = {
            "requirement_id": requirement["requirement_id"],
            "primitive_type": "not",
            "matched_signers": [],
            "observed": {
                "child_status": (
                    "satisfied"
                    if child.satisfied
                    else "unsatisfied"
                ),
            },
            "expected": {
                "child_status": "unsatisfied",
            },
            "children": (child,),
        }

        if not satisfied:
            kwargs["failure_code"] = "NOT_NOT_SATISFIED"

        return factory(**kwargs)

    raise ValueError(
        "evaluate_composition received non-composition "
        f"requirement type: {requirement_type!r}"
    )


def project_failure_codes(
    top_level_results: tuple[PrimitiveResult, ...],
) -> list[str]:
    """Project policy-level failures according to TPE 2.2 rules."""

    projected: list[tuple[str, str]] = []

    def visit(result: PrimitiveResult) -> None:
        if result.satisfied:
            return

        projected.append(
            (result.requirement_id, result.failure_code)
        )

        if result.primitive_type == "all_of":
            for child in result.children:
                if not child.satisfied:
                    visit(child)
            return

        if result.primitive_type == "any_of":
            for child in result.children:
                visit(child)
            return

        if result.primitive_type == "not":
            return

    for result in top_level_results:
        visit(result)

    projected.sort(key=lambda item: item[0])
    return [failure_code for _, failure_code in projected]
