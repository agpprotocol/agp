"""Core types for the AGP Trust Primitive Engine."""

from .primitive import Primitive
from .composition import (
    evaluate_requirement,
    project_failure_codes,
)
from .policy_tree import (
    COMPOSITION_TYPES,
    MAX_REQUIREMENT_DEPTH,
    MAX_REQUIREMENT_NODES,
    UnsupportedPrimitiveError,
    validate_requirement_tree,
)
from .policy_set import (
    PolicyReferenceIdentity,
    PolicySetEntry,
    PolicySetIndex,
    build_policy_set_index,
)
from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import EvaluationState

__all__ = [
    "PolicyReferenceIdentity",
    "PolicySetEntry",
    "PolicySetIndex",
    "build_policy_set_index",
    "project_failure_codes",
    "evaluate_requirement",
    "validate_requirement_tree",
    "UnsupportedPrimitiveError",
    "MAX_REQUIREMENT_NODES",
    "MAX_REQUIREMENT_DEPTH",
    "COMPOSITION_TYPES",
    "EvaluationState",
    "Primitive",
    "PrimitiveRegistry",
    "PrimitiveResult",
]
