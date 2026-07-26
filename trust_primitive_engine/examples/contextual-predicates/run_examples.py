#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
TPE = ROOT / "trust_primitive_engine/python"
EVAL = TPE / "evaluate_trust_policy_v2.py"

if str(TPE) not in sys.path:
    sys.path.insert(0, str(TPE))

from engine import build_policy_set_index


def evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("tpe25_example", EVAL)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run(ev: Any, environment: str, approved_version: str, count: int):
    leaf = ev.validate_policy({
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:tpe25:leaf",
        "version": 1,
        "eligible_roles": ["reviewer"],
        "requirements": [
            {
                "requirement_id": "requirement:01-environment",
                "type": "context_value_in",
                "path": "/proposal/payload/environment",
                "values": ["canary", "production"],
            },
            {
                "requirement_id": "requirement:02-version",
                "type": "context_path_equals",
                "left_path": "/proposal/payload/requested_version",
                "right_path": "/proposal/payload/approved_version",
            },
            {
                "requirement_id": "requirement:03-evidence",
                "type": "evidence_count_at_least",
                "minimum": 2,
                "media_type": "application/json",
            },
        ],
    })
    root = ev.validate_policy({
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:tpe25:root",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [{
            "requirement_id": "requirement:reference",
            "type": "policy_reference",
            "policy_id": leaf["policy_id"],
            "policy_version": leaf["version"],
            "policy_digest": ev.policy_digest(leaf),
        }],
    })
    evidence = [
        {
            "id": f"evidence.report-{index}",
            "digest": f"{index:x}" * 64,
            "media_type": "application/json",
        }
        for index in range(1, count + 1)
    ]
    signed = {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": "context-digest:tpe25-example",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": "context:tpe25:example",
            "evaluation_time": 1700000000,
            "policy": {
                "id": root["policy_id"],
                "version": 1,
                "digest": ev.policy_digest(root),
            },
            "proposal": {
                "type": "proposal:tpe25",
                "payload": {
                    "environment": environment,
                    "requested_version": "3.0.0",
                    "approved_version": approved_version,
                },
            },
            "participants": [
                {"id": "authority:alpha", "role": "approver", "weight": 1}
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
    index = build_policy_set_index(
        [leaf],
        validate_policy=ev.validate_policy,
        compute_digest=ev.policy_digest,
    )
    return ev.evaluate_verified_object(
        signed,
        root,
        ["signature:alpha"],
        policy_set_index=index,
    )


def main() -> int:
    ev = evaluator()
    cases = [
        ("satisfied", "production", "3.0.0", 2, "satisfied", []),
        (
            "value-not-in-set",
            "staging",
            "3.0.0",
            2,
            "unsatisfied",
            ["POLICY_REFERENCE_NOT_SATISFIED", "CONTEXT_VALUE_NOT_IN_SET"],
        ),
        (
            "path-not-equal",
            "production",
            "3.1.0",
            2,
            "unsatisfied",
            ["POLICY_REFERENCE_NOT_SATISFIED", "CONTEXT_PATH_VALUES_NOT_EQUAL"],
        ),
        (
            "evidence-count-low",
            "production",
            "3.0.0",
            1,
            "unsatisfied",
            ["POLICY_REFERENCE_NOT_SATISFIED", "EVIDENCE_COUNT_NOT_REACHED"],
        ),
    ]
    for name, environment, version, count, status, failures in cases:
        result = run(ev, environment, version, count)
        assert result["status"] == status, result
        assert result["failure_codes"] == failures, result
        print(
            f"PASS  {name:<20} status={status} failures={len(failures)}"
        )
    print("TPE_2_5_CONTEXTUAL_PREDICATES_EXAMPLES_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
