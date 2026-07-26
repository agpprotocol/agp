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
    spec = importlib.util.spec_from_file_location("agp_tpe26_integration", EVALUATOR_PATH)
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


def evidence_manifest():
    return [
        {
            "id": "evidence.assessment-a",
            "digest": "a" * 64,
            "media_type": "application/json",
            "evidence_type": "security:assessment/1",
            "issuer_id": "authority:lab-a",
        },
        {
            "id": "evidence.assessment-b",
            "digest": "b" * 64,
            "media_type": "application/json",
            "evidence_type": "security:assessment/1",
            "issuer_id": "authority:lab-b",
        },
        {
            "id": "evidence.penetration-test",
            "digest": "c" * 64,
            "media_type": "application/json",
            "evidence_type": "security:penetration-test/1",
            "issuer_id": "authority:lab-a",
        },
    ]


def signed_context(evaluator, root, *, evidence=None, generation=3):
    normalized = evaluator.validate_policy(root)
    context = {
        "object_type": f"agp.decision-context/{generation}",
        "context_id": f"context:tpe26:integration:{generation}",
        "policy": {
            "id": normalized["policy_id"],
            "version": normalized["version"],
            "digest": evaluator.policy_digest(normalized),
        },
        "proposal": {
            "type": "proposal:tpe26:integration",
            "payload": {"environment": "production"},
        },
        "participants": [
            {"id": "authority:alpha", "role": "approver", "weight": 1}
        ],
        "evidence": evidence_manifest() if evidence is None else evidence,
        "constraints": [],
    }
    if generation >= 2:
        context["evaluation_time"] = 1700000000
    return {
        "object_type": f"agp.signed-decision-context/{generation}",
        "context_digest": "context-digest:tpe26-integration",
        "context": context,
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {"signer_id": "authority:alpha"},
            }
        ],
    }


def evaluate(evaluator, root, *, policy_set=None, evidence=None, generation=3):
    normalized = evaluator.validate_policy(root)
    policies = policy_set or []
    index = build_policy_set_index(
        policies,
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )
    evaluator.validate_policy_reference_graph(normalized, index)
    return evaluator.evaluate_verified_object(
        signed_context(evaluator, normalized, evidence=evidence, generation=generation),
        normalized,
        ["signature:alpha"],
        policy_set_index=index,
    )


def requirements():
    return [
        {
            "requirement_id": "requirement:01-approved-issuer",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a", "authority:lab-b"],
            "evidence_types": ["security:assessment/1"],
        },
        {
            "requirement_id": "requirement:02-approved-type",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
            "issuer_ids": ["authority:lab-a", "authority:lab-b"],
        },
        {
            "requirement_id": "requirement:03-distinct-issuers",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 2,
            "evidence_types": ["security:assessment/1"],
        },
    ]


def main():
    evaluator = load_evaluator()
    passed = 0

    direct = evaluator.validate_policy(policy(
        "policy:tpe26:direct",
        [{
            "requirement_id": "requirement:all-tpe26",
            "type": "all_of",
            "requirements": requirements(),
        }],
    ))
    result = evaluate(evaluator, direct)
    assert result["status"] == "satisfied", result
    print("PASS  tpe26_composition_satisfied"); passed += 1

    children = result["requirement_results"][0]["children"]
    assert [x["type"] for x in children] == [
        "evidence_issuer_in",
        "evidence_type_in",
        "evidence_distinct_issuers_at_least",
    ], children
    print("PASS  tpe26_composition_children_preserved"); passed += 1

    assert children[2]["observed"]["issuer_ids"] == [
        "authority:lab-a",
        "authority:lab-b",
    ], children[2]
    print("PASS  tpe26_observed_ids_canonical"); passed += 1

    referenced = evaluator.validate_policy(
        policy("policy:tpe26:referenced", requirements(), roles=["reviewer"])
    )
    root = evaluator.validate_policy(policy(
        "policy:tpe26:root",
        [reference(evaluator, referenced, "requirement:reference")],
    ))
    assert evaluate(evaluator, root, policy_set=[referenced])["status"] == "satisfied"
    print("PASS  tpe26_direct_reference"); passed += 1

    middle = evaluator.validate_policy(policy(
        "policy:tpe26:middle",
        [reference(evaluator, referenced, "requirement:leaf")],
    ))
    nested = evaluator.validate_policy(policy(
        "policy:tpe26:nested",
        [reference(evaluator, middle, "requirement:middle")],
    ))
    assert evaluate(
        evaluator, nested, policy_set=[middle, referenced]
    )["status"] == "satisfied"
    print("PASS  tpe26_nested_reference"); passed += 1

    bad_issuer = [{**x, "issuer_id": "authority:unapproved"} for x in evidence_manifest()]
    failure = evaluate(
        evaluator, root, policy_set=[referenced], evidence=bad_issuer
    )
    assert failure["failure_codes"] == [
        "POLICY_REFERENCE_NOT_SATISFIED",
        "EVIDENCE_ISSUER_NOT_ALLOWED",
        "EVIDENCE_TYPE_NOT_ALLOWED",
        "EVIDENCE_DISTINCT_ISSUER_MINIMUM_NOT_REACHED",
    ], failure
    print("PASS  tpe26_failure_projection"); passed += 1

    any_root = evaluator.validate_policy(policy(
        "policy:tpe26:any",
        [{
            "requirement_id": "requirement:any",
            "type": "any_of",
            "requirements": [
                {
                    "requirement_id": "requirement:a-success",
                    "type": "required_signer",
                    "signer_id": "authority:alpha",
                },
                reference(evaluator, referenced, "requirement:z-reference"),
            ],
        }],
    ))
    suppressed = evaluate(
        evaluator, any_root, policy_set=[referenced], evidence=bad_issuer
    )
    assert suppressed["status"] == "satisfied" and suppressed["failure_codes"] == []
    print("PASS  tpe26_any_of_suppression"); passed += 1

    not_root = evaluator.validate_policy(policy(
        "policy:tpe26:not",
        [{
            "requirement_id": "requirement:not",
            "type": "not",
            "requirement": reference(
                evaluator, referenced, "requirement:reference"
            ),
        }],
    ))
    suppressed = evaluate(
        evaluator, not_root, policy_set=[referenced], evidence=bad_issuer
    )
    assert suppressed["status"] == "satisfied" and suppressed["failure_codes"] == []
    print("PASS  tpe26_not_suppression"); passed += 1

    cross_entry = [
        {
            "id": "evidence.approved-issuer",
            "digest": "a" * 64,
            "media_type": "application/json",
            "evidence_type": "security:penetration-test/1",
            "issuer_id": "authority:lab-a",
        },
        {
            "id": "evidence.approved-type",
            "digest": "b" * 64,
            "media_type": "application/json",
            "evidence_type": "security:assessment/1",
            "issuer_id": "authority:unapproved",
        },
    ]
    cross_policy = evaluator.validate_policy(policy(
        "policy:tpe26:cross-entry",
        [{
            "requirement_id": "requirement:cross-entry",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
            "evidence_types": ["security:assessment/1"],
        }],
    ))
    assert evaluate(
        evaluator, cross_policy, evidence=cross_entry
    )["status"] == "unsatisfied"
    print("PASS  tpe26_same_entry_binding"); passed += 1

    legacy = evaluate(evaluator, direct, generation=2, evidence=[])
    assert legacy["status"] == "unsatisfied"
    assert (
        legacy["requirement_results"][0]["children"][0]["observed"]["provenance_status"]
        == "unavailable"
    )
    print("PASS  tpe26_dc2_provenance_unavailable"); passed += 1

    empty = evaluate(evaluator, direct, evidence=[])
    assert empty["status"] == "unsatisfied"
    assert (
        empty["requirement_results"][0]["children"][0]["observed"]["provenance_status"]
        == "available"
    )
    print("PASS  tpe26_empty_dc3_available"); passed += 1

    first = evaluate(evaluator, root, policy_set=[referenced])
    second = evaluate(evaluator, root, policy_set=[referenced])
    assert first == second
    print("PASS  tpe26_deterministic_replay"); passed += 1

    inner = first["requirement_results"][0]["referenced_policy"]
    assert [x["type"] for x in inner["requirement_results"]] == [
        "evidence_issuer_in",
        "evidence_type_in",
        "evidence_distinct_issuers_at_least",
    ]
    print("PASS  tpe26_referenced_serialization"); passed += 1

    time_policy = evaluator.validate_policy(policy(
        "policy:tpe26:time-inheritance",
        [{
            "requirement_id": "requirement:time",
            "type": "time_window",
            "not_before": 1699999999,
            "not_after": 1700000001,
        }],
    ))
    assert evaluate(evaluator, time_policy)["status"] == "satisfied"
    print("PASS  tpe26_inherits_evaluation_time"); passed += 1

    assert passed == 14, passed
    print("TPE 2.6 formal integration: 14/14 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
