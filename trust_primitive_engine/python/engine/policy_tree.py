"""Deterministic validation for recursive Trust Policy requirement trees."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


MAX_REQUIREMENT_DEPTH = 8
MAX_REQUIREMENT_NODES = 256

COMPOSITION_TYPES = frozenset({"all_of", "any_of", "not"})

_NARY_MEMBERS = frozenset({"requirement_id", "type", "requirements"})
_NOT_MEMBERS = frozenset({"requirement_id", "type", "requirement"})


class UnsupportedPrimitiveError(ValueError):
    """Raised when a leaf requirement type is not supported."""


def _validate_exact_members(
    value: dict[str, Any],
    expected: frozenset[str],
    operator_type: str,
) -> None:
    unknown = sorted(set(value) - expected)
    missing = sorted(expected - set(value))

    if unknown:
        raise ValueError(f"{operator_type} unknown members: {unknown}")

    if missing:
        raise ValueError(f"{operator_type} missing members: {missing}")


def validate_requirement_tree(
    raw_requirements: Any,
    *,
    validate_leaf: Callable[[Any], dict[str, Any]],
    validate_identifier: Callable[[Any, str], str],
    max_depth: int = MAX_REQUIREMENT_DEPTH,
    max_nodes: int = MAX_REQUIREMENT_NODES,
) -> list[dict[str, Any]]:
    """Validate and normalize a complete recursive requirement tree."""

    if (
        not isinstance(max_depth, int)
        or isinstance(max_depth, bool)
        or max_depth < 1
    ):
        raise ValueError("max_depth must be a positive integer")

    if (
        not isinstance(max_nodes, int)
        or isinstance(max_nodes, bool)
        or max_nodes < 1
    ):
        raise ValueError("max_nodes must be a positive integer")

    if not isinstance(raw_requirements, list) or not raw_requirements:
        raise ValueError("requirements must be a non-empty array")

    seen_ids: set[str] = set()
    node_count = 0

    def validate_node(value: Any, *, depth: int) -> dict[str, Any]:
        nonlocal node_count

        if depth > max_depth:
            raise ValueError(
                f"requirement tree depth exceeds {max_depth}"
            )

        node_count += 1
        if node_count > max_nodes:
            raise ValueError(
                f"requirement tree node count exceeds {max_nodes}"
            )

        if not isinstance(value, dict):
            raise ValueError("requirement tree node must be an object")

        requirement_id = validate_identifier(
            value.get("requirement_id"),
            "requirement_id",
        )

        if requirement_id in seen_ids:
            raise ValueError(
                "requirement_id values must be globally unique"
            )
        seen_ids.add(requirement_id)

        operator_type = value.get("type")
        if not isinstance(operator_type, str):
            raise ValueError("primitive type must be a string")

        if operator_type in {"all_of", "any_of"}:
            _validate_exact_members(value, _NARY_MEMBERS, operator_type)

            raw_children = value["requirements"]
            if (
                not isinstance(raw_children, list)
                or len(raw_children) < 2
            ):
                raise ValueError(
                    f"{operator_type} requirements must contain "
                    "at least 2 children"
                )

            child_ids: list[str] = []
            for child in raw_children:
                if not isinstance(child, dict):
                    raise ValueError(
                        f"{operator_type} child must be an object"
                    )
                child_ids.append(
                    validate_identifier(
                        child.get("requirement_id"),
                        "requirement_id",
                    )
                )

            if child_ids != sorted(child_ids):
                raise ValueError(
                    f"{operator_type} requirements must be sorted "
                    "by requirement_id"
                )

            children = [
                validate_node(child, depth=depth + 1)
                for child in raw_children
            ]

            return {
                "requirement_id": requirement_id,
                "type": operator_type,
                "requirements": children,
            }

        if operator_type == "not":
            _validate_exact_members(value, _NOT_MEMBERS, operator_type)

            child = value["requirement"]
            if not isinstance(child, dict):
                raise ValueError("not requirement must be an object")

            return {
                "requirement_id": requirement_id,
                "type": operator_type,
                "requirement": validate_node(
                    child,
                    depth=depth + 1,
                ),
            }

        return validate_leaf(value)

    top_level_ids: list[str] = []
    for requirement in raw_requirements:
        if not isinstance(requirement, dict):
            raise ValueError("requirements[] must be an object")
        top_level_ids.append(
            validate_identifier(
                requirement.get("requirement_id"),
                "requirement_id",
            )
        )

    if top_level_ids != sorted(top_level_ids):
        raise ValueError(
            "requirements must be sorted by requirement_id"
        )

    return [
        validate_node(requirement, depth=1)
        for requirement in raw_requirements
    ]
