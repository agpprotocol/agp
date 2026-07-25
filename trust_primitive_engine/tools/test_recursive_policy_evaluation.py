#!/usr/bin/env python3
"""Focused recursive policy-reference evaluation checks."""

from __future__ import annotations

import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import (
    EvaluationState,
    PolicyEvaluationContext,
    Primitive,
    PrimitiveRegistry,
    PrimitiveResult,
    build_policy_set_index,
    evaluate_indexed_policy,
)
from primitives.context_values import (
    ContextIntegerAtLeastPrimitive,
    ContextValueEqualsPrimitive,
)
from primitives.evidence_present import EvidencePresentPrimitive


class TestFailure(Exception):
    pass


class StateSignerPrimitive(Primitive):
    TYPE = "state_signer"

    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def validate(
        self,
        value: dict[str, Any],
    ) -> dict[str, Any]:
        return deepcopy(value)

    def evaluate(
        self,
        requirement: dict[str, Any],
        state: EvaluationState,
    ) -> PrimitiveResult:
        self.calls.append(requirement["requirement_id"])
        signer_id = requirement["signer_id"]
        satisfied = signer_id in state.matched_set

        if satisfied:
            return PrimitiveResult.satisfied_result(
                requirement_id=requirement["requirement_id"],
                primitive_type=self.TYPE,
                matched_signers=[signer_id],
                observed={"signer_present": True},
                expected={"signer_present": True},
            )

        return PrimitiveResult.unsatisfied_result(
            requirement_id=requirement["requirement_id"],
            primitive_type=self.TYPE,
            matched_signers=[],
            observed={"signer_present": False},
            expected={"signer_present": True},
            failure_code="STATE_SIGNER_NOT_SATISFIED",
        )


def digest(policy: dict[str, Any]) -> str:
    encoded = json.dumps(
        policy,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_policy(policy: Any) -> dict[str, Any]:
    if not isinstance(policy, dict):
        raise ValueError("policy must be an object")
    return deepcopy(policy)


def leaf(
    requirement_id: str,
    signer_id: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "state_signer",
        "signer_id": signer_id,
    }


def policy(
    policy_id: str,
    *,
    roles: list[str],
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": 1,
        "eligible_roles": roles,
        "requirements": requirements,
    }


def reference(
    target: dict[str, Any],
    requirement_id: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "policy_reference",
        "policy_id": target["policy_id"],
        "policy_version": target["version"],
        "policy_digest": digest(target),
    }


def evaluate(
    target: dict[str, Any],
    policies: list[dict[str, Any]],
    calls: list[str],
    *,
    decision_context: dict[str, Any] | None = None,
):
    index = build_policy_set_index(
        policies,
        validate_policy=validate_policy,
        compute_digest=digest,
    )

    entry = index.resolve(
        target["policy_id"],
        target["version"],
    )

    if entry is None:
        raise TestFailure("target policy missing from index")

    context = PolicyEvaluationContext(
        verified_signers=(
            "authority:alpha",
            "authority:beta",
        ),
        participants={
            "authority:alpha": {
                "id": "authority:alpha",
                "role": "approver",
                "weight": 2,
            },
            "authority:beta": {
                "id": "authority:beta",
                "role": "reviewer",
                "weight": 3,
            },
        },
        evaluation_time=1234567890,
        policy_set=index,
        registry=PrimitiveRegistry([
            ContextIntegerAtLeastPrimitive(),
            ContextValueEqualsPrimitive(),
            EvidencePresentPrimitive(),
            StateSignerPrimitive(calls),
        ]),
        decision_context=decision_context,
    )

    return evaluate_indexed_policy(entry, context)


def main() -> int:
    passed = 0
    calls: list[str] = []

    satisfied_target = policy(
        "policy:satisfied-target",
        roles=["reviewer"],
        requirements=[
            leaf("requirement:beta", "authority:beta"),
        ],
    )
    direct_root = policy(
        "policy:direct-root",
        roles=["approver"],
        requirements=[
            reference(
                satisfied_target,
                "requirement:target",
            ),
        ],
    )

    result = evaluate(
        direct_root,
        [direct_root, satisfied_target],
        calls,
    )

    reference_result = result.requirement_results[0]

    if not result.satisfied or not reference_result.satisfied:
        raise TestFailure("direct_reference_satisfied failed")

    if reference_result.matched_signers != (
        "authority:beta",
    ):
        raise TestFailure(
            "referenced eligible_roles were not independent"
        )

    if reference_result.referenced_policy is None:
        raise TestFailure("referenced policy evidence missing")

    print("PASS  direct_reference_satisfied")
    passed += 1

    print("PASS  referenced_eligible_roles_independent")
    passed += 1

    unsatisfied_target = policy(
        "policy:unsatisfied-target",
        roles=["reviewer"],
        requirements=[
            leaf("requirement:alpha", "authority:alpha"),
        ],
    )
    unsatisfied_root = policy(
        "policy:unsatisfied-root",
        roles=["approver"],
        requirements=[
            reference(
                unsatisfied_target,
                "requirement:target",
            ),
        ],
    )

    result = evaluate(
        unsatisfied_root,
        [unsatisfied_root, unsatisfied_target],
        calls,
    )
    reference_result = result.requirement_results[0]

    if result.satisfied:
        raise TestFailure("direct_reference_unsatisfied passed")

    if reference_result.failure_code != (
        "POLICY_REFERENCE_NOT_SATISFIED"
    ):
        raise TestFailure("wrong reference failure code")

    print("PASS  direct_reference_unsatisfied")
    passed += 1

    nested_leaf = policy(
        "policy:nested-leaf",
        roles=["reviewer"],
        requirements=[
            leaf("requirement:nested-beta", "authority:beta"),
        ],
    )
    nested_middle = policy(
        "policy:nested-middle",
        roles=["approver"],
        requirements=[
            reference(
                nested_leaf,
                "requirement:nested-leaf-reference",
            ),
        ],
    )
    nested_root = policy(
        "policy:nested-root",
        roles=["reviewer"],
        requirements=[
            reference(
                nested_middle,
                "requirement:nested-middle-reference",
            ),
        ],
    )

    result = evaluate(
        nested_root,
        [nested_root, nested_middle, nested_leaf],
        calls,
    )

    if not result.satisfied:
        raise TestFailure("nested references failed")

    nested_boundary = (
        result.requirement_results[0]
        .referenced_policy
        .requirement_results[0]
    )

    if nested_boundary.referenced_policy is None:
        raise TestFailure("nested result tree missing")

    print("PASS  nested_references")
    passed += 1

    shared = policy(
        "policy:shared",
        roles=["reviewer"],
        requirements=[
            leaf("requirement:shared-beta", "authority:beta"),
        ],
    )
    shared_root = policy(
        "policy:shared-root",
        roles=["approver"],
        requirements=[
            {
                "requirement_id": "requirement:shared-all",
                "type": "all_of",
                "requirements": [
                    reference(shared, "requirement:left"),
                    reference(shared, "requirement:right"),
                ],
            }
        ],
    )

    calls.clear()
    result = evaluate(
        shared_root,
        [shared_root, shared],
        calls,
    )

    if not result.satisfied:
        raise TestFailure("shared reference failed")

    if calls != [
        "requirement:shared-beta",
        "requirement:shared-beta",
    ]:
        raise TestFailure(
            "shared reference multiplicity changed"
        )

    print("PASS  shared_reference_multiplicity")
    passed += 1

    all_root = policy(
        "policy:all-root",
        roles=["approver"],
        requirements=[
            {
                "requirement_id": "requirement:all",
                "type": "all_of",
                "requirements": [
                    reference(
                        satisfied_target,
                        "requirement:reference",
                    ),
                    leaf(
                        "requirement:alpha",
                        "authority:alpha",
                    ),
                ],
            }
        ],
    )

    result = evaluate(
        all_root,
        [all_root, satisfied_target],
        calls,
    )

    if not result.satisfied:
        raise TestFailure("reference inside all_of failed")

    print("PASS  reference_inside_all_of")
    passed += 1

    calls.clear()
    any_root = policy(
        "policy:any-root",
        roles=["approver"],
        requirements=[
            {
                "requirement_id": "requirement:any",
                "type": "any_of",
                "requirements": [
                    leaf(
                        "requirement:alpha",
                        "authority:alpha",
                    ),
                    reference(
                        satisfied_target,
                        "requirement:reference",
                    ),
                ],
            }
        ],
    )

    result = evaluate(
        any_root,
        [any_root, satisfied_target],
        calls,
    )

    if not result.satisfied:
        raise TestFailure("reference inside any_of failed")

    if calls != [
        "requirement:alpha",
        "requirement:beta",
    ]:
        raise TestFailure("any_of short-circuited")

    print("PASS  reference_inside_any_of_no_short_circuit")
    passed += 1

    not_root = policy(
        "policy:not-root",
        roles=["approver"],
        requirements=[
            {
                "requirement_id": "requirement:not",
                "type": "not",
                "requirement": reference(
                    unsatisfied_target,
                    "requirement:reference",
                ),
            }
        ],
    )

    first = evaluate(
        not_root,
        [not_root, unsatisfied_target],
        calls,
    )
    second = evaluate(
        not_root,
        [not_root, unsatisfied_target],
        calls,
    )

    if not first.satisfied:
        raise TestFailure("reference inside not failed")

    if first.to_dict() != second.to_dict():
        raise TestFailure("deterministic replay failed")

    print("PASS  reference_inside_not")
    passed += 1

    print("PASS  deterministic_replay")
    passed += 1

    tpe24_context = {
        "object_type": "agp.decision-context/2",
        "proposal": {
            "payload": {
                "environment": "production",
                "coverage": 9000,
            }
        },
        "evidence": [
            {
                "id": "evidence.security-report",
                "digest": "a" * 64,
                "media_type": "application/json",
            }
        ],
    }

    context_target = policy(
        "policy:tpe24-context-target",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:environment",
                "type": "context_value_equals",
                "path": "/proposal/payload/environment",
                "value": "production",
            }
        ],
    )
    context_root = policy(
        "policy:tpe24-context-root",
        roles=["approver"],
        requirements=[
            reference(context_target, "requirement:context-reference")
        ],
    )
    result = evaluate(
        context_root,
        [context_root, context_target],
        calls,
        decision_context=tpe24_context,
    )
    if not result.satisfied:
        raise TestFailure("tpe24 direct context reference failed")
    inner = (
        result.requirement_results[0]
        .referenced_policy
        .requirement_results[0]
    )
    if inner.primitive_type != "context_value_equals":
        raise TestFailure("tpe24 direct context primitive missing")
    print("PASS  tpe24_direct_context_reference")
    passed += 1

    nested_leaf_policy = policy(
        "policy:tpe24-nested-leaf",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:coverage",
                "type": "context_integer_at_least",
                "path": "/proposal/payload/coverage",
                "minimum": 9000,
            }
        ],
    )
    nested_middle_policy = policy(
        "policy:tpe24-nested-middle",
        roles=["approver"],
        requirements=[
            reference(nested_leaf_policy, "requirement:nested-leaf")
        ],
    )
    nested_root_policy = policy(
        "policy:tpe24-nested-root",
        roles=["reviewer"],
        requirements=[
            reference(nested_middle_policy, "requirement:nested-middle")
        ],
    )
    result = evaluate(
        nested_root_policy,
        [nested_root_policy, nested_middle_policy, nested_leaf_policy],
        calls,
        decision_context=tpe24_context,
    )
    if not result.satisfied:
        raise TestFailure("tpe24 nested context reference failed")
    print("PASS  tpe24_nested_context_reference")
    passed += 1

    evidence_target = policy(
        "policy:tpe24-evidence-target",
        roles=["reviewer"],
        requirements=[
            {
                "requirement_id": "requirement:evidence-all",
                "type": "all_of",
                "requirements": [
                    {
                        "requirement_id": "requirement:evidence-present",
                        "type": "evidence_present",
                        "evidence_id": "evidence.security-report",
                    },
                    {
                        "requirement_id": "requirement:evidence-bound",
                        "type": "evidence_present",
                        "evidence_id": "evidence.security-report",
                        "digest": "a" * 64,
                        "media_type": "application/json",
                    },
                ],
            }
        ],
    )
    evidence_root = policy(
        "policy:tpe24-evidence-root",
        roles=["approver"],
        requirements=[
            reference(evidence_target, "requirement:evidence-reference")
        ],
    )
    first = evaluate(
        evidence_root,
        [evidence_root, evidence_target],
        calls,
        decision_context=tpe24_context,
    )
    second = evaluate(
        evidence_root,
        [evidence_root, evidence_target],
        calls,
        decision_context=tpe24_context,
    )
    if not first.satisfied:
        raise TestFailure("tpe24 referenced evidence composition failed")
    print("PASS  tpe24_referenced_evidence_composition")
    passed += 1

    if first.to_dict() != second.to_dict():
        raise TestFailure("tpe24 referenced replay changed")
    print("PASS  tpe24_referenced_replay")
    passed += 1

    expected = 13

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        "TPE 2.4 recursive policy evaluation: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
