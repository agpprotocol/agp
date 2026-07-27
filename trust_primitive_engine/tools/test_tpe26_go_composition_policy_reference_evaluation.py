#!/usr/bin/env python3
"""Python/Go parity for compositions containing policy references."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "trust_primitive_engine/go"
EVALUATOR_PATH = (
    ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)


@dataclass(frozen=True)
class Vector:
    name: str
    root: dict[str, Any]
    policy_set: list[dict[str, Any]]
    evidence: list[dict[str, Any]]


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_go_composition_policy_reference",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def issuer(
    requirement_id: str,
    issuer_id: str = "authority:lab-a",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_issuer_in",
        "issuer_ids": [issuer_id],
    }


def evidence_type(
    requirement_id: str,
    value: str = "security:assessment/1",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_type_in",
        "evidence_types": [value],
    }


def distinct(
    requirement_id: str,
    minimum: int = 1,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_distinct_issuers_at_least",
        "minimum": minimum,
    }


def all_of(
    requirement_id: str,
    children: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "all_of",
        "requirements": sorted(
            children,
            key=lambda item: item["requirement_id"],
        ),
    }


def any_of(
    requirement_id: str,
    children: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "any_of",
        "requirements": sorted(
            children,
            key=lambda item: item["requirement_id"],
        ),
    }


def negate(
    requirement_id: str,
    child: dict[str, Any],
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "not",
        "requirement": child,
    }


def policy(
    policy_id: str,
    requirements: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": sorted(
            requirements,
            key=lambda item: item["requirement_id"],
        ),
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


def evidence(
    evidence_id: str,
    issuer_id: str,
    evidence_type_value: str,
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "issuer_id": issuer_id,
        "evidence_type": evidence_type_value,
    }


BASE_EVIDENCE = [
    evidence(
        "evidence:a",
        "authority:lab-a",
        "security:assessment/1",
    ),
]


def build_vectors(evaluator: Any) -> list[Vector]:
    satisfied_leaf = policy(
        "policy:ref:satisfied",
        [issuer("requirement:issuer")],
    )
    failed_leaf = policy(
        "policy:ref:failed",
        [
            issuer(
                "requirement:issuer",
                "authority:missing",
            )
        ],
    )
    failed_composed = policy(
        "policy:ref:failed-composed",
        [
            any_of(
                "requirement:any",
                [
                    issuer(
                        "requirement:a-issuer",
                        "authority:missing-a",
                    ),
                    evidence_type(
                        "requirement:b-type",
                        "security:missing/1",
                    ),
                ],
            )
        ],
    )
    transitive_middle = policy(
        "policy:ref:middle",
        [
            reference(
                evaluator,
                failed_composed,
                "requirement:to-leaf",
            )
        ],
    )

    return [
        Vector(
            "reference_inside_all_satisfied",
            policy(
                "policy:root:all-satisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            issuer("requirement:a-direct"),
                            reference(
                                evaluator,
                                satisfied_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [satisfied_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "reference_inside_all_unsatisfied",
            policy(
                "policy:root:all-unsatisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            issuer("requirement:a-direct"),
                            reference(
                                evaluator,
                                failed_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [failed_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "reference_inside_any_suppressed",
            policy(
                "policy:root:any-suppressed",
                [
                    any_of(
                        "requirement:root",
                        [
                            issuer("requirement:a-direct"),
                            reference(
                                evaluator,
                                failed_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [failed_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "reference_inside_any_all_failed",
            policy(
                "policy:root:any-failed",
                [
                    any_of(
                        "requirement:root",
                        [
                            issuer(
                                "requirement:a-direct",
                                "authority:missing",
                            ),
                            reference(
                                evaluator,
                                failed_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [failed_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "reference_inside_not_satisfied",
            policy(
                "policy:root:not-satisfied",
                [
                    negate(
                        "requirement:root",
                        reference(
                            evaluator,
                            failed_leaf,
                            "requirement:reference",
                        ),
                    )
                ],
            ),
            [failed_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "reference_inside_not_failed",
            policy(
                "policy:root:not-failed",
                [
                    negate(
                        "requirement:root",
                        reference(
                            evaluator,
                            satisfied_leaf,
                            "requirement:reference",
                        ),
                    )
                ],
            ),
            [satisfied_leaf],
            BASE_EVIDENCE,
        ),
        Vector(
            "transitive_reference_in_composition",
            policy(
                "policy:root:transitive",
                [
                    all_of(
                        "requirement:root",
                        [
                            issuer("requirement:a-direct"),
                            reference(
                                evaluator,
                                transitive_middle,
                                "requirement:b-middle",
                            ),
                        ],
                    )
                ],
            ),
            [transitive_middle, failed_composed],
            BASE_EVIDENCE,
        ),
        Vector(
            "shared_failed_reference_paths",
            policy(
                "policy:root:shared",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                failed_composed,
                                "requirement:a-reference",
                            ),
                            reference(
                                evaluator,
                                failed_composed,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [failed_composed],
            BASE_EVIDENCE,
        ),
    ]


def evaluation_input(
    evaluator: Any,
    root_policy: dict[str, Any],
    evidence_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(root_policy)
    digest = evaluator.policy_digest(normalized)
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:{root_policy['policy_id']}",
        "context": {
            "object_type": "agp.decision-context/3",
            "context_id": f"context:{root_policy['policy_id']}",
            "evaluation_time": 1700000000,
            "proposal": {
                "type": "proposal:tpe-2.6:reference-parity",
                "payload": {
                    "scenario": root_policy["policy_id"],
                },
            },
            "policy": {
                "id": normalized["policy_id"],
                "version": normalized["version"],
                "digest": digest,
            },
            "participants": [],
            "evidence": evidence_entries,
        },
        "signatures": [],
    }


def compact(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def main() -> int:
    evaluator = load_evaluator()
    cases = build_vectors(evaluator)
    if len(cases) != 8:
        raise AssertionError(f"expected 8 vectors, got {len(cases)}")

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-composition-reference-"
    ) as raw:
        temp = Path(raw)
        binary = temp / "agp-tpe26-reproduce"

        subprocess.run(
            [
                "go",
                "build",
                "-trimpath",
                "-o",
                str(binary),
                "./cmd/agp-tpe26-reproduce",
            ],
            cwd=GO_DIR,
            check=True,
        )

        passed = 0
        for index, vector in enumerate(cases):
            normalized_root = evaluator.validate_policy(vector.root)
            normalized_set = [
                evaluator.validate_policy(item)
                for item in vector.policy_set
            ]
            policy_set_index = evaluator.build_policy_set_index(
                normalized_set,
                validate_policy=evaluator.validate_policy,
                compute_digest=evaluator.policy_digest,
            )
            signed_context = evaluation_input(
                evaluator,
                normalized_root,
                vector.evidence,
            )
            expected = evaluator.evaluate_verified_object(
                signed_context,
                normalized_root,
                [],
                policy_set_index=policy_set_index,
            )

            case_dir = temp / f"{index:02d}-{vector.name}"
            case_dir.mkdir()
            input_path = case_dir / "evaluation-input.json"
            root_path = case_dir / "root-policy.json"
            set_path = case_dir / "policy-set.json"

            input_path.write_text(
                compact(signed_context),
                encoding="utf-8",
            )
            root_path.write_text(
                compact(normalized_root),
                encoding="utf-8",
            )
            set_path.write_text(
                compact(normalized_set),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    str(binary),
                    str(input_path),
                    str(root_path),
                    str(set_path),
                ],
                cwd=case_dir,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"{vector.name}: Go command failed: "
                    f"{completed.stderr}"
                )

            observed = json.loads(completed.stdout)
            if observed != expected:
                raise AssertionError(
                    f"{vector.name}: Python/Go evaluation differs\n"
                    f"expected={compact(expected)}\n"
                    f"observed={compact(observed)}"
                )

            print(
                f"PASS  {vector.name:<38} "
                f"status={observed['status']} full_object=True"
            )
            passed += 1

        print(
            "TPE 2.6 Python/Go composition + policy-reference "
            f"evaluation parity: {passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
