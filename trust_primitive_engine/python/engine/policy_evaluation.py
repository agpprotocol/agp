"""Recursive deterministic evaluation of referenced policies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from .dispatcher import (
    RequirementEvaluationContext,
    evaluate_requirement,
)
from .policy_set import PolicySetEntry, PolicySetIndex
from .registry import PrimitiveRegistry
from .result import PrimitiveResult
from .state import create_policy_evaluation_state


@dataclass(frozen=True)
class PolicyEvaluationContext:
    """Immutable data shared by one recursive policy evaluation."""

    verified_signers: tuple[str, ...]
    participants: Mapping[str, Mapping[str, Any]]
    evaluation_time: int | None
    policy_set: PolicySetIndex
    registry: PrimitiveRegistry

    def __post_init__(self) -> None:
        normalized_signers = tuple(
            sorted(self.verified_signers)
        )

        if normalized_signers != self.verified_signers:
            raise ValueError(
                "verified_signers must be lexicographically sorted"
            )

        if len(normalized_signers) != len(
            set(normalized_signers)
        ):
            raise ValueError(
                "verified_signers must not contain duplicates"
            )


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Internal recursive result for one evaluated Trust Policy."""

    policy_id: str
    policy_version: int
    policy_digest: str
    satisfied: bool
    requirement_results: tuple[PrimitiveResult, ...]
    matched_signers: tuple[str, ...]
    failure_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        normalized_results = tuple(self.requirement_results)
        normalized_signers = tuple(self.matched_signers)
        normalized_failure_codes = tuple(self.failure_codes)

        if not all(
            isinstance(result, PrimitiveResult)
            for result in normalized_results
        ):
            raise TypeError(
                "requirement_results must contain "
                "only PrimitiveResult values"
            )

        if tuple(sorted(normalized_signers)) != normalized_signers:
            raise ValueError(
                "matched_signers must be lexicographically sorted"
            )

        if len(normalized_signers) != len(
            set(normalized_signers)
        ):
            raise ValueError(
                "matched_signers must not contain duplicates"
            )

        if not all(
            isinstance(code, str) and code
            for code in normalized_failure_codes
        ):
            raise ValueError(
                "failure_codes must contain non-empty strings"
            )

        if self.satisfied and normalized_failure_codes:
            raise ValueError(
                "satisfied policy must not contain failure_codes"
            )

        if not self.satisfied and not normalized_failure_codes:
            raise ValueError(
                "unsatisfied policy must contain failure_codes"
            )

        object.__setattr__(
            self,
            "requirement_results",
            normalized_results,
        )
        object.__setattr__(
            self,
            "failure_codes",
            normalized_failure_codes,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "policy_digest": self.policy_digest,
            "status": (
                "satisfied"
                if self.satisfied
                else "unsatisfied"
            ),
            "requirement_results": [
                result.to_dict()
                for result in self.requirement_results
            ],
            "failure_codes": list(self.failure_codes),
        }


def _aggregate_top_level_matched_signers(
    results: tuple[PrimitiveResult, ...],
) -> tuple[str, ...]:
    return tuple(sorted({
        signer_id
        for result in results
        for signer_id in result.matched_signers
    }))


def project_recursive_failure_codes(
    top_level_results: tuple[PrimitiveResult, ...],
) -> tuple[str, ...]:
    """Project failures across policy-reference boundaries.

    For trees without policy references this preserves the TPE 2.2
    ordering rule based on emitting requirement_id.

    Failures inside a referenced policy are ordered beneath the
    requirement path of the visible policy_reference boundary.
    Repeated failure-code strings remain present once per emitting node.
    """

    projected: list[
        tuple[tuple[str, ...], int, str]
    ] = []
    emission_index = 0

    def emit(
        path: tuple[str, ...],
        failure_code: str,
    ) -> None:
        nonlocal emission_index

        projected.append(
            (
                path,
                emission_index,
                failure_code,
            )
        )
        emission_index += 1

    def visit(
        result: PrimitiveResult,
        *,
        path_prefix: tuple[str, ...],
    ) -> None:
        if result.satisfied:
            return

        result_path = (
            path_prefix
            + (result.requirement_id,)
        )

        emit(
            result_path,
            result.failure_code,
        )

        if result.primitive_type == "all_of":
            for child in result.children:
                if not child.satisfied:
                    visit(
                        child,
                        path_prefix=path_prefix,
                    )
            return

        if result.primitive_type == "any_of":
            for child in result.children:
                visit(
                    child,
                    path_prefix=path_prefix,
                )
            return

        if result.primitive_type == "not":
            return

        if result.primitive_type == "policy_reference":
            referenced_policy = result.referenced_policy

            if referenced_policy is None:
                raise ValueError(
                    "policy_reference result is missing "
                    "referenced_policy evidence"
                )

            for nested_result in (
                referenced_policy.requirement_results
            ):
                visit(
                    nested_result,
                    path_prefix=result_path,
                )

    for result in top_level_results:
        visit(
            result,
            path_prefix=(),
        )

    projected.sort(
        key=lambda item: (
            item[0],
            item[1],
        )
    )

    return tuple(
        failure_code
        for _, _, failure_code in projected
    )


def evaluate_policy_reference_requirement(
    requirement: dict[str, Any],
    context: PolicyEvaluationContext,
) -> PrimitiveResult:
    """Evaluate one prevalidated policy_reference boundary."""

    entry = context.policy_set.resolve(
        requirement["policy_id"],
        requirement["policy_version"],
    )

    if entry is None:
        raise ValueError(
            "validated policy reference could not be resolved: "
            f"policy_id={requirement['policy_id']} "
            f"policy_version={requirement['policy_version']}"
        )

    identity = entry.identity

    if identity.policy_id != requirement["policy_id"]:
        raise ValueError(
            "resolved policy reference identity changed"
        )

    if identity.policy_version != requirement["policy_version"]:
        raise ValueError(
            "resolved policy reference version changed"
        )

    if identity.policy_digest != requirement["policy_digest"]:
        raise ValueError(
            "resolved policy reference digest changed"
        )

    referenced_policy = evaluate_indexed_policy(
        entry,
        context,
    )

    policy_status = (
        "satisfied"
        if referenced_policy.satisfied
        else "unsatisfied"
    )

    common_kwargs: dict[str, Any] = {
        "requirement_id": requirement["requirement_id"],
        "primitive_type": "policy_reference",
        "matched_signers": list(
            referenced_policy.matched_signers
        ),
        "observed": {
            "policy_id": referenced_policy.policy_id,
            "policy_version": (
                referenced_policy.policy_version
            ),
            "policy_digest": (
                referenced_policy.policy_digest
            ),
            "policy_status": policy_status,
        },
        "expected": {
            "policy_status": "satisfied",
        },
        "referenced_policy": referenced_policy,
    }

    if referenced_policy.satisfied:
        return PrimitiveResult.satisfied_result(
            **common_kwargs,
        )

    return PrimitiveResult.unsatisfied_result(
        **common_kwargs,
        failure_code="POLICY_REFERENCE_NOT_SATISFIED",
    )


def evaluate_indexed_policy(
    entry: PolicySetEntry,
    context: PolicyEvaluationContext,
) -> PolicyEvaluationResult:
    """Evaluate one indexed policy recursively.

    The complete reachable graph must be validated before this function
    is called. Resolution defects remain fatal and are never converted
    into unsatisfied requirement results.
    """

    policy = entry.to_policy()

    state = create_policy_evaluation_state(
        verified_signers=context.verified_signers,
        participants=context.participants,
        eligible_roles=policy["eligible_roles"],
        evaluation_time=context.evaluation_time,
    )

    requirement_context = RequirementEvaluationContext(
        evaluate_policy_reference=lambda requirement: (
            evaluate_policy_reference_requirement(
                requirement,
                context,
            )
        ),
    )

    requirement_results = tuple(
        evaluate_requirement(
            requirement,
            state,
            context.registry,
            context=requirement_context,
        )
        for requirement in policy["requirements"]
    )

    satisfied = all(
        result.satisfied
        for result in requirement_results
    )

    failure_codes = project_recursive_failure_codes(
        requirement_results
    )

    return PolicyEvaluationResult(
        policy_id=entry.identity.policy_id,
        policy_version=entry.identity.policy_version,
        policy_digest=entry.identity.policy_digest,
        satisfied=satisfied,
        requirement_results=requirement_results,
        matched_signers=(
            _aggregate_top_level_matched_signers(
                requirement_results
            )
        ),
        failure_codes=failure_codes,
    )
