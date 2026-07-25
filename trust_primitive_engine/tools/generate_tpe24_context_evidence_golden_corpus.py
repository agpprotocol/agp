#!/usr/bin/env python3
"""Generate the deterministic TPE 2.4 context/evidence golden corpus."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"
CORPUS_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2.4"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index

EVIDENCE_DIGEST = "a" * 64
OTHER_DIGEST = "b" * 64


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_generate_tpe24_golden",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def base_context(
    *,
    policy: dict[str, Any],
    policy_digest: str,
    name: str,
    payload: dict[str, Any] | None = None,
    evidence: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:tpe-2.4:{name}",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": f"context:tpe-2.4:{name}",
            "evaluation_time": 1700000000,
            "policy": {
                "id": policy["policy_id"],
                "version": policy["version"],
                "digest": policy_digest,
            },
            "proposal": {
                "type": "proposal:tpe-2.4:golden",
                "payload": payload or {},
            },
            "participants": [
                {"id": "authority:alpha", "role": "approver", "weight": 2},
                {"id": "authority:beta", "role": "reviewer", "weight": 3},
            ],
            "evidence": evidence or [],
        },
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {"signer_id": "authority:alpha"},
            },
            {
                "signature_id": "signature:beta",
                "statement": {"signer_id": "authority:beta"},
            },
        ],
    }


def direct_policy(
    evaluator: Any,
    *,
    name: str,
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return evaluator.validate_policy(
        {
            "object_type": "agp.trust-policy/2",
            "policy_id": f"policy:golden:tpe24:{name}",
            "version": 1,
            "eligible_roles": ["approver"],
            "requirements": requirements,
        }
    )


def evaluate(
    evaluator: Any,
    *,
    root_policy: dict[str, Any],
    policy_set: list[dict[str, Any]],
    evaluation_input: dict[str, Any],
) -> dict[str, Any]:
    index = build_policy_set_index(
        policy_set,
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )
    evaluator.validate_policy_reference_graph(root_policy, index)
    signature_ids = sorted(
        item["signature_id"]
        for item in evaluation_input["signatures"]
    )
    return evaluator.evaluate_verified_object(
        evaluation_input,
        root_policy,
        signature_ids,
        policy_set_index=index,
    )


def add_case(
    evaluator: Any,
    manifest_cases: list[dict[str, str]],
    *,
    name: str,
    root_policy: dict[str, Any],
    policy_set: list[dict[str, Any]],
    payload: dict[str, Any],
    evidence: list[dict[str, str]],
    expected_status: str,
) -> None:
    root_digest = evaluator.policy_digest(root_policy)
    evaluation_input = base_context(
        policy=root_policy,
        policy_digest=root_digest,
        name=name,
        payload=payload,
        evidence=evidence,
    )
    result = evaluate(
        evaluator,
        root_policy=root_policy,
        policy_set=policy_set,
        evaluation_input=evaluation_input,
    )
    if result["status"] != expected_status:
        raise RuntimeError(
            f"{name}: expected {expected_status}, got {result['status']}"
        )

    case_dir = CORPUS_DIR / name
    case_dir.mkdir(parents=True, exist_ok=True)
    write_json(case_dir / "root-policy.json", root_policy)
    write_json(case_dir / "policy-set.json", policy_set)
    write_json(case_dir / "evaluation-input.json", evaluation_input)
    write_json(case_dir / "expected-evaluation.json", result)

    digest = hashlib.sha256(compact_json(result)).hexdigest()
    (case_dir / "expected-evaluation.sha256").write_text(
        digest + "\n",
        encoding="ascii",
    )

    manifest_cases.append(
        {
            "name": name,
            "directory": name,
            "expected_status": expected_status,
            "expected_sha256": digest,
        }
    )


def main() -> int:
    evaluator = load_evaluator()

    if CORPUS_DIR.exists():
        for path in CORPUS_DIR.iterdir():
            if path.is_dir():
                shutil.rmtree(path)
            elif path.name != "README.md":
                path.unlink()

    cases: list[dict[str, str]] = []

    satisfied = direct_policy(
        evaluator,
        name="satisfied-all",
        requirements=[
            {
                "requirement_id": "requirement:01-present",
                "type": "context_value_present",
                "path": "/proposal/payload/version",
            },
            {
                "requirement_id": "requirement:02-equals",
                "type": "context_value_equals",
                "path": "/proposal/payload/environment",
                "value": "production",
            },
            {
                "requirement_id": "requirement:03-minimum",
                "type": "context_integer_at_least",
                "path": "/proposal/payload/coverage",
                "minimum": 9000,
            },
            {
                "requirement_id": "requirement:04-maximum",
                "type": "context_integer_at_most",
                "path": "/proposal/payload/rollout",
                "maximum": 2500,
            },
            {
                "requirement_id": "requirement:05-evidence",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "digest": EVIDENCE_DIGEST,
                "media_type": "application/json",
            },
        ],
    )
    add_case(
        evaluator,
        cases,
        name="satisfied-all",
        root_policy=satisfied,
        policy_set=[],
        payload={
            "coverage": 9500,
            "environment": "production",
            "rollout": 2000,
            "version": "3.0.0",
        },
        evidence=[
            {
                "id": "evidence.security-report",
                "digest": EVIDENCE_DIGEST,
                "media_type": "application/json",
            }
        ],
        expected_status="satisfied",
    )

    direct_cases = [
        (
            "context-value-not-equal",
            {
                "requirement_id": "requirement:context-value-not-equal",
                "type": "context_value_equals",
                "path": "/proposal/payload/environment",
                "value": "production",
            },
            {"environment": "staging"},
            [],
        ),
        (
            "context-value-not-present",
            {
                "requirement_id": "requirement:context-value-not-present",
                "type": "context_value_present",
                "path": "/proposal/payload/version",
            },
            {"environment": "production"},
            [],
        ),
        (
            "integer-minimum-not-reached",
            {
                "requirement_id": "requirement:integer-minimum",
                "type": "context_integer_at_least",
                "path": "/proposal/payload/coverage",
                "minimum": 9000,
            },
            {"coverage": 8999},
            [],
        ),
        (
            "integer-maximum-exceeded",
            {
                "requirement_id": "requirement:integer-maximum",
                "type": "context_integer_at_most",
                "path": "/proposal/payload/rollout",
                "maximum": 2500,
            },
            {"rollout": 2501},
            [],
        ),
        (
            "evidence-absent",
            {
                "requirement_id": "requirement:evidence-absent",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
            },
            {},
            [],
        ),
        (
            "evidence-digest-mismatch",
            {
                "requirement_id": "requirement:evidence-digest",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "digest": EVIDENCE_DIGEST,
            },
            {},
            [
                {
                    "id": "evidence.security-report",
                    "digest": OTHER_DIGEST,
                    "media_type": "application/json",
                }
            ],
        ),
        (
            "evidence-media-type-mismatch",
            {
                "requirement_id": "requirement:evidence-media-type",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "media_type": "application/json",
            },
            {},
            [
                {
                    "id": "evidence.security-report",
                    "digest": EVIDENCE_DIGEST,
                    "media_type": "application/pdf",
                }
            ],
        ),
        (
            "evidence-both-mismatch",
            {
                "requirement_id": "requirement:evidence-both",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "digest": EVIDENCE_DIGEST,
                "media_type": "application/json",
            },
            {},
            [
                {
                    "id": "evidence.security-report",
                    "digest": OTHER_DIGEST,
                    "media_type": "application/pdf",
                }
            ],
        ),
    ]

    for name, requirement, payload, evidence in direct_cases:
        policy = direct_policy(
            evaluator,
            name=name,
            requirements=[requirement],
        )
        add_case(
            evaluator,
            cases,
            name=name,
            root_policy=policy,
            policy_set=[],
            payload=payload,
            evidence=evidence,
            expected_status="unsatisfied",
        )

    referenced = evaluator.validate_policy(
        {
            "object_type": "agp.trust-policy/2",
            "policy_id": "policy:golden:tpe24:recursive-leaf",
            "version": 1,
            "eligible_roles": ["reviewer"],
            "requirements": [
                {
                    "requirement_id": "requirement:recursive-environment",
                    "type": "context_value_equals",
                    "path": "/proposal/payload/environment",
                    "value": "production",
                }
            ],
        }
    )
    root = evaluator.validate_policy(
        {
            "object_type": "agp.trust-policy/2",
            "policy_id": "policy:golden:tpe24:recursive-root",
            "version": 1,
            "eligible_roles": ["approver"],
            "requirements": [
                {
                    "requirement_id": "requirement:recursive-reference",
                    "type": "policy_reference",
                    "policy_id": referenced["policy_id"],
                    "policy_version": referenced["version"],
                    "policy_digest": evaluator.policy_digest(referenced),
                }
            ],
        }
    )
    add_case(
        evaluator,
        cases,
        name="recursive-reference-projection",
        root_policy=root,
        policy_set=[referenced],
        payload={"environment": "staging"},
        evidence=[],
        expected_status="unsatisfied",
    )

    write_json(
        CORPUS_DIR / "manifest.json",
        {
            "corpus": "agp.tpe-context-evidence-conformance/2.4",
            "hash_serialization": "json-sort-keys-compact-utf8",
            "hash_algorithm": "sha-256",
            "cases": cases,
        },
    )

    print(f"GENERATED TPE 2.4 golden corpus: {len(cases)} cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
