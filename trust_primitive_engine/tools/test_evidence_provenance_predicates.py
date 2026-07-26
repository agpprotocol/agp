#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[2]
TPE = ROOT / "trust_primitive_engine/python"
sys.path.insert(0, str(TPE))

from engine import EvaluationState
from primitives.evidence_provenance import (
    EvidenceDistinctIssuersAtLeastPrimitive,
    EvidenceIssuerInPrimitive,
    EvidenceTypeInPrimitive,
)


class TestFailure(Exception):
    pass


def load_evaluator():
    path = ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_focused_evaluator",
        path,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def ev(evidence_id, issuer_id, evidence_type):
    return {
        "id": evidence_id,
        "digest": "a" * 64,
        "media_type": "application/json",
        "issuer_id": issuer_id,
        "evidence_type": evidence_type,
    }


def state(object_type, evidence):
    return EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        decision_context={
            "object_type": object_type,
            "proposal": {"payload": {}},
            "evidence": evidence,
        },
    )


def policy(requirement):
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe-2.6-focused",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [requirement],
    }


def main():
    checks = 0
    dc3 = state("agp.decision-context/3", [
        ev("evidence.assessment-a", "authority:lab-a", "security:assessment/1"),
        ev("evidence.assessment-b", "authority:lab-b", "security:assessment/1"),
        ev("evidence.test-a", "authority:lab-a", "security:penetration-test/1"),
    ])

    issuer = EvidenceIssuerInPrimitive()
    req = issuer.validate({
        "requirement_id": "requirement:issuer",
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:lab-a"],
    })
    if not issuer.evaluate(req, dc3).satisfied:
        raise TestFailure("issuer membership")
    checks += 1
    print("PASS  issuer_membership")

    req = issuer.validate({
        "requirement_id": "requirement:cross",
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:lab-b"],
        "evidence_types": ["security:penetration-test/1"],
    })
    if issuer.evaluate(req, dc3).satisfied:
        raise TestFailure("cross-entry false positive")
    checks += 1
    print("PASS  same_entry_cross_filter")

    type_primitive = EvidenceTypeInPrimitive()
    req = type_primitive.validate({
        "requirement_id": "requirement:type",
        "type": "evidence_type_in",
        "evidence_types": ["security:assessment/1"],
        "issuer_ids": ["authority:lab-b"],
    })
    if not type_primitive.evaluate(req, dc3).satisfied:
        raise TestFailure("type membership")
    checks += 1
    print("PASS  evidence_type_membership")

    count = EvidenceDistinctIssuersAtLeastPrimitive()
    req = count.validate({
        "requirement_id": "requirement:distinct",
        "type": "evidence_distinct_issuers_at_least",
        "minimum": 2,
        "evidence_types": ["security:assessment/1"],
    })
    result = count.evaluate(req, dc3)
    if not result.satisfied or result.observed["count"] != 2:
        raise TestFailure("distinct issuer count")
    checks += 1
    print("PASS  distinct_issuer_count")

    empty = state("agp.decision-context/3", [])
    req = issuer.validate({
        "requirement_id": "requirement:empty",
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:lab-a"],
    })
    if issuer.evaluate(req, empty).satisfied:
        raise TestFailure("empty DC3")
    checks += 1
    print("PASS  empty_dc3_unsatisfied")

    dc2 = state("agp.decision-context/2", [])
    result = issuer.evaluate(req, dc2)
    if result.observed["provenance_status"] != "unavailable":
        raise TestFailure("DC2 status")
    checks += 1
    print("PASS  dc2_provenance_unavailable")

    invalid = [
        (
            issuer,
            {
                "requirement_id": "requirement:unordered",
                "type": "evidence_issuer_in",
                "issuer_ids": ["authority:z", "authority:a"],
            },
        ),
        (
            type_primitive,
            {
                "requirement_id": "requirement:duplicate",
                "type": "evidence_type_in",
                "evidence_types": [
                    "security:assessment/1",
                    "security:assessment/1",
                ],
            },
        ),
        (
            count,
            {
                "requirement_id": "requirement:boolean",
                "type": "evidence_distinct_issuers_at_least",
                "minimum": True,
            },
        ),
    ]
    for primitive, value in invalid:
        try:
            primitive.validate(value)
        except ValueError:
            pass
        else:
            raise TestFailure("invalid runtime policy accepted")
    checks += 1
    print("PASS  runtime_validation_rejections")

    evaluator = load_evaluator()
    public_valid_forms = [
        {
            "requirement_id": "requirement:public-issuer",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
        },
        {
            "requirement_id": "requirement:public-type",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
        },
        {
            "requirement_id": "requirement:public-count",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 2,
        },
    ]
    for value in public_valid_forms:
        normalized = evaluator.validate_policy(policy(value))
        if normalized["requirements"][0]["type"] != value["type"]:
            raise TestFailure(f"public evaluator changed {value['type']}")
    checks += 1
    print("PASS  public_evaluator_accepts_tpe26_forms")

    schema = json.loads(
        (ROOT / "registry/schemas/agp.trust-policy-2.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    valid_forms = [
        {
            "requirement_id": "requirement:schema-issuer",
            "type": "evidence_issuer_in",
            "issuer_ids": ["authority:lab-a"],
        },
        {
            "requirement_id": "requirement:schema-type",
            "type": "evidence_type_in",
            "evidence_types": ["security:assessment/1"],
        },
        {
            "requirement_id": "requirement:schema-count",
            "type": "evidence_distinct_issuers_at_least",
            "minimum": 2,
        },
    ]
    for value in valid_forms:
        if any(validator.iter_errors(policy(value))):
            raise TestFailure(f"schema rejected {value['type']}")
    checks += 1
    print("PASS  schema_accepts_tpe26_forms")

    if checks != 9:
        raise TestFailure(f"expected 9, got {checks}")
    print("TPE 2.6 evidence provenance predicates: 9/9 passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
