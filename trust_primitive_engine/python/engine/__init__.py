"""Core types for the AGP Trust Primitive Engine."""

from .context_resolution import (
    ContextPathError,
    ContextResolution,
    create_context_projection,
    parse_context_path,
    resolve_context_path,
)
from .primitive import Primitive
from .composition import (
    evaluate_composition,
    project_failure_codes,
)
from .dispatcher import (
    RequirementEvaluationContext,
    evaluate_requirement,
)
from .policy_tree import (
    COMPOSITION_TYPES,
    MAX_REQUIREMENT_DEPTH,
    MAX_REQUIREMENT_NODES,
    UnsupportedPrimitiveError,
    validate_requirement_tree,
)
from .policy_evaluation import (
    PolicyEvaluationContext,
    PolicyEvaluationResult,
    evaluate_indexed_policy,
    evaluate_policy_document,
    evaluate_policy_reference_requirement,
    project_recursive_failure_codes,
)
from .policy_set import (
    PolicyReferenceIdentity,
    PolicySetEntry,
    PolicySetIndex,
    build_policy_set_index,
)
from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import (
    EvaluationState,
    create_policy_evaluation_state,
)

__all__ = [
    "ContextPathError",
    "ContextResolution",
    "create_context_projection",
    "parse_context_path",
    "resolve_context_path",
    "PolicyEvaluationContext",
    "PolicyEvaluationResult",
    "RequirementEvaluationContext",
    "evaluate_indexed_policy",
    "evaluate_policy_document",
    "evaluate_policy_reference_requirement",
    "project_recursive_failure_codes",
    "create_policy_evaluation_state",
    "PolicyReferenceIdentity",
    "PolicySetEntry",
    "PolicySetIndex",
    "build_policy_set_index",
    "project_failure_codes",
    "evaluate_composition",
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
