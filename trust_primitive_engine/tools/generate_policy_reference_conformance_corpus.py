#!/usr/bin/env python3
"""Generate deterministic TPE 2.3 policy-reference corpus fixtures."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"
CORPUS_DIR = ROOT / "trust_primitive_engine/fixtures/golden/v2.3"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_generate_tpe23_conformance",
        EVALUATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )


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


def required_signer(
    requirement_id: str,
    signer_id: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "required_signer",
        "signer_id": signer_id,
    }


def reference(
    evaluator: Any,
    target: dict[str, Any],
    requirement_id: str,
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(target)

    return {
        "requirement_id": requirement_id,
        "type": "policy_reference",
        "policy_id": normalized["policy_id"],
        "policy_version": normalized["version"],
        "policy_digest": evaluator.policy_digest(normalized),
    }


def all_of(
    requirement_id: str,
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "all_of",
        "requirements": sorted(
            requirements,
            key=lambda item: item["requirement_id"],
        ),
    }


def any_of(
    requirement_id: str,
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "any_of",
        "requirements": sorted(
            requirements,
            key=lambda item: item["requirement_id"],
        ),
    }


def negation(
    requirement_id: str,
    requirement: dict[str, Any],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "not",
        "requirement": requirement,
    }


def signed_context(
    evaluator: Any,
    root_policy: dict[str, Any],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(root_policy)

    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": "context-digest:tpe-2.3-golden",
        "context": {
            "object_type": "agp.decision-context/2",
            "context_id": "context:tpe-2.3-golden",
            "evaluation_time": 1700000000,
            "policy": {
                "id": normalized["policy_id"],
                "version": normalized["version"],
                "digest": evaluator.policy_digest(normalized),
            },
            "participants": [
                {
                    "id": "authority:alpha",
                    "role": "approver",
                    "weight": 2,
                },
                {
                    "id": "authority:beta",
                    "role": "reviewer",
                    "weight": 3,
                },
                {
                    "id": "authority:gamma",
                    "role": "voter",
                    "weight": 5,
                },
            ],
        },
        "signatures": [
            {
                "signature_id": "signature:alpha",
                "statement": {
                    "signer_id": "authority:alpha",
                },
            },
            {
                "signature_id": "signature:beta",
                "statement": {
                    "signer_id": "authority:beta",
                },
            },
            {
                "signature_id": "signature:gamma",
                "statement": {
                    "signer_id": "authority:gamma",
                },
            },
        ],
    }


def build_cases(evaluator: Any):
    reviewer_satisfied = policy(
        "policy:golden:reviewer-satisfied",
        roles=["reviewer"],
        requirements=[
            required_signer(
                "requirement:beta",
                "authority:beta",
            )
        ],
    )

    reviewer_failed = policy(
        "policy:golden:reviewer-failed",
        roles=["reviewer"],
        requirements=[
            required_signer(
                "requirement:alpha-required",
                "authority:alpha",
            )
        ],
    )

    direct_satisfied = policy(
        "policy:golden:direct-satisfied",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                reviewer_satisfied,
                "requirement:reviewer-reference",
            )
        ],
    )

    direct_unsatisfied = policy(
        "policy:golden:direct-unsatisfied",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                reviewer_failed,
                "requirement:reviewer-reference",
            )
        ],
    )

    nested_middle = policy(
        "policy:golden:nested-middle",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                reviewer_satisfied,
                "requirement:nested-leaf-reference",
            )
        ],
    )

    nested_root = policy(
        "policy:golden:nested-root",
        roles=["voter"],
        requirements=[
            reference(
                evaluator,
                nested_middle,
                "requirement:nested-middle-reference",
            )
        ],
    )

    shared_root = policy(
        "policy:golden:shared-unsatisfied",
        roles=["approver"],
        requirements=[
            all_of(
                "requirement:shared-all",
                [
                    reference(
                        evaluator,
                        reviewer_failed,
                        "requirement:left-reference",
                    ),
                    reference(
                        evaluator,
                        reviewer_failed,
                        "requirement:right-reference",
                    ),
                ],
            )
        ],
    )

    eligible_root = policy(
        "policy:golden:eligible-independent",
        roles=["approver"],
        requirements=[
            reference(
                evaluator,
                reviewer_satisfied,
                "requirement:reviewer-reference",
            )
        ],
    )

    all_root = policy(
        "policy:golden:reference-all-of",
        roles=["approver"],
        requirements=[
            all_of(
                "requirement:outer-all",
                [
                    required_signer(
                        "requirement:alpha",
                        "authority:alpha",
                    ),
                    reference(
                        evaluator,
                        reviewer_satisfied,
                        "requirement:reviewer-reference",
                    ),
                ],
            )
        ],
    )

    any_root = policy(
        "policy:golden:reference-any-of",
        roles=["approver"],
        requirements=[
            any_of(
                "requirement:outer-any",
                [
                    required_signer(
                        "requirement:alpha",
                        "authority:alpha",
                    ),
                    reference(
                        evaluator,
                        reviewer_failed,
                        "requirement:failed-reference",
                    ),
                ],
            )
        ],
    )

    not_root = policy(
        "policy:golden:reference-not",
        roles=["approver"],
        requirements=[
            negation(
                "requirement:outer-not",
                reference(
                    evaluator,
                    reviewer_failed,
                    "requirement:failed-reference",
                ),
            )
        ],
    )

    return {
        "direct-satisfied": (
            direct_satisfied,
            [reviewer_satisfied],
        ),
        "direct-unsatisfied": (
            direct_unsatisfied,
            [reviewer_failed],
        ),
        "nested-satisfied": (
            nested_root,
            [
                nested_middle,
                reviewer_satisfied,
            ],
        ),
        "shared-unsatisfied": (
            shared_root,
            [reviewer_failed],
        ),
        "eligible-roles-independent": (
            eligible_root,
            [reviewer_satisfied],
        ),
        "reference-inside-all-of": (
            all_root,
            [reviewer_satisfied],
        ),
        "reference-inside-any-of": (
            any_root,
            [reviewer_failed],
        ),
        "reference-inside-not": (
            not_root,
            [reviewer_failed],
        ),
    }


def main() -> int:
    evaluator = load_evaluator()
    cases = build_cases(evaluator)

    for name, (root_policy, policy_set) in cases.items():
        case_dir = CORPUS_DIR / name
        case_dir.mkdir(parents=True, exist_ok=True)

        normalized_root = evaluator.validate_policy(root_policy)

        index = build_policy_set_index(
            policy_set,
            validate_policy=evaluator.validate_policy,
            compute_digest=evaluator.policy_digest,
        )

        context = signed_context(
            evaluator,
            normalized_root,
        )

        evaluation = evaluator.evaluate_verified_object(
            context,
            normalized_root,
            [
                "signature:alpha",
                "signature:beta",
                "signature:gamma",
            ],
            policy_set_index=index,
        )

        write_json(
            case_dir / "root-policy.json",
            normalized_root,
        )
        write_json(
            case_dir / "policy-set.json",
            policy_set,
        )
        write_json(
            case_dir / "evaluation-input.json",
            context,
        )
        write_json(
            case_dir / "expected-evaluation.json",
            evaluation,
        )

        print(
            f"GENERATED  {name:<32} "
            f"status={evaluation['status']}"
        )

    print(
        f"TPE 2.3 corpus generation: "
        f"{len(cases)}/{len(cases)} generated"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
