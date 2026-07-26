#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_tpe25_integration",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(policy_id, requirements, roles=None):
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": 1,
        "eligible_roles": roles or ["approver"],
        "requirements": requirements,
    }


def reference(evaluator, target, requirement_id):
    normalized = evaluator.validate_policy(target)
    return {
        "requirement_id": requirement_id,
        "type": "policy_reference",
        "policy_id": normalized["policy_id"],
        "policy_version": normalized["version"],
        "policy_digest": evaluator.policy_digest(normalized),
    }


def signed_context(
    evaluator,
    root,
    *,
    environment="production",
    requested_version="3.0.0",
    approved_version="3.0.0",
    evidence_count=2,
):
    normalized = evaluator.validate_policy(root)
    evidence = [
        {
            "id": f"evidence.report-{index}",
            "digest": f"{index:x}" * 64,
            "media_type": "application/json",
        }
        for index in range(1, evidence_count + 1)
    ]
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": "context-digest:tpe25-integration",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": "context:tpe25:integration",
            "evaluation_time": 1700000000,
            "policy": {
                "id": normalized["policy_id"],
                "version": normalized["version"],
                "digest": evaluator.policy_digest(normalized),
            },
            "proposal": {
                "type": "proposal:tpe25:integration",
                "payload": {
                    "approved_version": approved_version,
                    "environment": environment,
                    "requested_version": requested_version,
                },
            },
            "participants": [
                {
                    "id": "authority:alpha",
                    "role": "approver",
                    "weight": 1,
                }
            ],
            "evidence": evidence,
            "constraints": [],
        },
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {"signer_id": "authority:alpha"},
            }
        ],
    }


def evaluate(evaluator, root, *, policy_set=None, **context_overrides):
    normalized = evaluator.validate_policy(root)
    policies = policy_set or []
    index = build_policy_set_index(
        policies,
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )
    evaluator.validate_policy_reference_graph(normalized, index)
    return evaluator.evaluate_verified_object(
        signed_context(evaluator, normalized, **context_overrides),
        normalized,
        ["signature:alpha"],
        policy_set_index=index,
    )


def tpe25_requirements():
    return [
        {
            "requirement_id": "requirement:01-environment",
            "type": "context_value_in",
            "path": "/proposal/payload/environment",
            "values": ["canary", "production"],
        },
        {
            "requirement_id": "requirement:02-version-match",
            "type": "context_path_equals",
            "left_path": "/proposal/payload/requested_version",
            "right_path": "/proposal/payload/approved_version",
        },
        {
            "requirement_id": "requirement:03-evidence-count",
            "type": "evidence_count_at_least",
            "minimum": 2,
            "media_type": "application/json",
        },
    ]


def assert_failures(result, expected, name):
    if result["failure_codes"] != expected:
        raise TestFailure(
            f"{name}: {result['failure_codes']!r} != {expected!r}"
        )


def main():
    evaluator = load_evaluator()
    passed = 0

    direct = evaluator.validate_policy(
        policy(
            "policy:tpe25:direct",
            [{
                "requirement_id": "requirement:all-tpe25",
                "type": "all_of",
                "requirements": tpe25_requirements(),
            }],
        )
    )
    direct_result = evaluate(evaluator, direct)
    if direct_result["status"] != "satisfied":
        raise TestFailure("direct composition was not satisfied")
    print("PASS  tpe25_composition_satisfied")
    passed += 1

    children = direct_result["requirement_results"][0]["children"]
    if [item["type"] for item in children] != [
        "context_value_in",
        "context_path_equals",
        "evidence_count_at_least",
    ]:
        raise TestFailure("composition child types changed")
    print("PASS  tpe25_composition_children_preserved")
    passed += 1

    if children[2]["observed"]["evidence_ids"] != [
        "evidence.report-1",
        "evidence.report-2",
    ]:
        raise TestFailure("evidence ids were not canonical")
    print("PASS  tpe25_evidence_ids_canonical")
    passed += 1

    referenced = evaluator.validate_policy(
        policy(
            "policy:tpe25:referenced",
            tpe25_requirements(),
            roles=["reviewer"],
        )
    )
    root = evaluator.validate_policy(
        policy(
            "policy:tpe25:root",
            [reference(evaluator, referenced, "requirement:reference")],
        )
    )
    referenced_result = evaluate(
        evaluator, root, policy_set=[referenced]
    )
    if referenced_result["status"] != "satisfied":
        raise TestFailure("direct reference was not satisfied")
    print("PASS  tpe25_direct_reference")
    passed += 1

    middle = evaluator.validate_policy(
        policy(
            "policy:tpe25:middle",
            [reference(evaluator, referenced, "requirement:leaf")],
        )
    )
    nested_root = evaluator.validate_policy(
        policy(
            "policy:tpe25:nested-root",
            [reference(evaluator, middle, "requirement:middle")],
        )
    )
    nested_result = evaluate(
        evaluator,
        nested_root,
        policy_set=[middle, referenced],
    )
    if nested_result["status"] != "satisfied":
        raise TestFailure("nested reference was not satisfied")
    print("PASS  tpe25_nested_reference")
    passed += 1

    value_failure = evaluate(
        evaluator,
        root,
        policy_set=[referenced],
        environment="staging",
    )
    assert_failures(
        value_failure,
        [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "CONTEXT_VALUE_NOT_IN_SET",
        ],
        "value failure",
    )
    print("PASS  tpe25_value_in_failure_projection")
    passed += 1

    path_failure = evaluate(
        evaluator,
        root,
        policy_set=[referenced],
        approved_version="3.1.0",
    )
    assert_failures(
        path_failure,
        [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "CONTEXT_PATH_VALUES_NOT_EQUAL",
        ],
        "path failure",
    )
    print("PASS  tpe25_path_equals_failure_projection")
    passed += 1

    count_failure = evaluate(
        evaluator,
        root,
        policy_set=[referenced],
        evidence_count=1,
    )
    assert_failures(
        count_failure,
        [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "EVIDENCE_COUNT_NOT_REACHED",
        ],
        "count failure",
    )
    print("PASS  tpe25_evidence_count_failure_projection")
    passed += 1

    any_root = evaluator.validate_policy(
        policy(
            "policy:tpe25:any-root",
            [{
                "requirement_id": "requirement:any",
                "type": "any_of",
                "requirements": [
                    {
                        "requirement_id": "requirement:a-success",
                        "type": "required_signer",
                        "signer_id": "authority:alpha",
                    },
                    reference(
                        evaluator,
                        referenced,
                        "requirement:z-reference",
                    ),
                ],
            }],
        )
    )
    suppressed_any = evaluate(
        evaluator,
        any_root,
        policy_set=[referenced],
        environment="staging",
    )
    if (
        suppressed_any["status"] != "satisfied"
        or suppressed_any["failure_codes"] != []
    ):
        raise TestFailure("any_of did not suppress TPE 2.5 failure")
    print("PASS  tpe25_any_of_suppression")
    passed += 1

    not_root = evaluator.validate_policy(
        policy(
            "policy:tpe25:not-root",
            [{
                "requirement_id": "requirement:not",
                "type": "not",
                "requirement": reference(
                    evaluator,
                    referenced,
                    "requirement:reference",
                ),
            }],
        )
    )
    suppressed_not = evaluate(
        evaluator,
        not_root,
        policy_set=[referenced],
        environment="staging",
    )
    if (
        suppressed_not["status"] != "satisfied"
        or suppressed_not["failure_codes"] != []
    ):
        raise TestFailure("not did not suppress TPE 2.5 failure")
    print("PASS  tpe25_not_suppression")
    passed += 1

    first = evaluate(evaluator, root, policy_set=[referenced])
    second = evaluate(evaluator, root, policy_set=[referenced])
    if first != second:
        raise TestFailure("deterministic replay changed")
    print("PASS  tpe25_deterministic_replay")
    passed += 1

    inner = first["requirement_results"][0]["referenced_policy"]
    if [item["type"] for item in inner["requirement_results"]] != [
        "context_value_in",
        "context_path_equals",
        "evidence_count_at_least",
    ]:
        raise TestFailure("referenced serialization changed")
    print("PASS  tpe25_referenced_serialization")
    passed += 1

    expected = 12
    if passed != expected:
        raise TestFailure(f"expected {expected}, observed {passed}")
    print(f"TPE 2.5 formal integration: {passed}/{expected} passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
