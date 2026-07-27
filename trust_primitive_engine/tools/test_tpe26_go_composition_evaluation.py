#!/usr/bin/env python3
"""Full Python/Go evaluation parity for bounded TPE 2.6 compositions."""

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
    requirements: list[dict[str, Any]]
    evidence: list[dict[str, Any]]


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_go_composition_evaluation",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def issuer(requirement_id: str, issuer_id: str = "authority:lab-a") -> dict[str, Any]:
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


def distinct(requirement_id: str, minimum: int = 1) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_distinct_issuers_at_least",
        "minimum": minimum,
    }


def all_of(requirement_id: str, children: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "all_of",
        "requirements": sorted(
            children,
            key=lambda item: item["requirement_id"],
        ),
    }


def any_of(requirement_id: str, children: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "any_of",
        "requirements": sorted(
            children,
            key=lambda item: item["requirement_id"],
        ),
    }


def negate(requirement_id: str, child: dict[str, Any]) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "not",
        "requirement": child,
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


def vectors() -> list[Vector]:
    return [
        Vector(
            "all_of_all_satisfied",
            [all_of("requirement:root", [
                issuer("requirement:a"),
                evidence_type("requirement:b"),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "all_of_one_unsatisfied",
            [all_of("requirement:root", [
                issuer("requirement:a"),
                evidence_type("requirement:b", "security:missing/1"),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "any_of_one_satisfied",
            [any_of("requirement:root", [
                issuer("requirement:a"),
                evidence_type("requirement:b", "security:missing/1"),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "any_of_all_unsatisfied",
            [any_of("requirement:root", [
                issuer("requirement:a", "authority:missing"),
                evidence_type("requirement:b", "security:missing/1"),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "not_unsatisfied_child_satisfies",
            [negate(
                "requirement:not",
                issuer("requirement:a", "authority:missing"),
            )],
            BASE_EVIDENCE,
        ),
        Vector(
            "not_satisfied_child_fails",
            [negate("requirement:not", issuer("requirement:a"))],
            BASE_EVIDENCE,
        ),
        Vector(
            "nested_failure_projection",
            [all_of("requirement:z-root", [
                any_of("requirement:a-any", [
                    issuer("requirement:b-leaf", "authority:missing-b"),
                    evidence_type(
                        "requirement:c-leaf",
                        "security:missing/1",
                    ),
                ]),
                distinct("requirement:y-leaf", minimum=2),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "nested_all_satisfied",
            [all_of("requirement:root", [
                any_of("requirement:a-any", [
                    issuer("requirement:a-issuer"),
                    evidence_type(
                        "requirement:b-missing",
                        "security:missing/1",
                    ),
                ]),
                negate(
                    "requirement:c-not",
                    distinct("requirement:c-distinct", minimum=2),
                ),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "all_of_evaluates_every_branch",
            [all_of("requirement:root", [
                issuer("requirement:a-failed", "authority:missing"),
                evidence_type(
                    "requirement:b-failed",
                    "security:missing/1",
                ),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "any_of_preserves_failed_child",
            [any_of("requirement:root", [
                issuer("requirement:a-satisfied"),
                evidence_type(
                    "requirement:b-failed",
                    "security:missing/1",
                ),
            ])],
            BASE_EVIDENCE,
        ),
        Vector(
            "not_preserves_failed_child",
            [negate(
                "requirement:not",
                evidence_type(
                    "requirement:failed-child",
                    "security:missing/1",
                ),
            )],
            BASE_EVIDENCE,
        ),
        Vector(
            "top_level_failure_order",
            [
                distinct("requirement:a-distinct", minimum=2),
                issuer("requirement:z-issuer", "authority:missing"),
            ],
            BASE_EVIDENCE,
        ),
    ]


def policy_for(vector: Vector) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": f"policy:{vector.name}",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": vector.requirements,
    }


def input_for(
    evaluator: Any,
    policy: dict[str, Any],
    evidence_entries: list[dict[str, Any]],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(policy)
    digest = evaluator.policy_digest(normalized)
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:{policy['policy_id']}",
        "context": {
            "object_type": "agp.decision-context/3",
            "context_id": f"context:{policy['policy_id']}",
            "evaluation_time": 1700000000,
            "proposal": {
                "type": "proposal:tpe-2.6:composition-parity",
                "payload": {
                    "scenario": policy["policy_id"],
                },
            },
            "policy": {
                "id": policy["policy_id"],
                "version": policy["version"],
                "digest": digest,
            },
            "participants": [],
            "evidence": evidence_entries,
        },
        "signatures": [],
    }


def main() -> int:
    cases = vectors()
    if len(cases) != 12:
        raise AssertionError(f"expected 12 vectors, got {len(cases)}")

    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-composition-evaluation-"
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
            policy = policy_for(vector)
            normalized = evaluator.validate_policy(policy)
            evaluation_input = input_for(
                evaluator,
                normalized,
                vector.evidence,
            )
            expected = evaluator.evaluate_verified_object(
                evaluation_input,
                normalized,
                [],
            )

            case_dir = temp / f"{index:02d}-{vector.name}"
            case_dir.mkdir()
            input_path = case_dir / "evaluation-input.json"
            policy_path = case_dir / "root-policy.json"
            policy_set_path = case_dir / "policy-set.json"

            input_path.write_text(
                json.dumps(
                    evaluation_input,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            policy_path.write_text(
                json.dumps(
                    normalized,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            policy_set_path.write_text("[]", encoding="utf-8")

            completed = subprocess.run(
                [
                    str(binary),
                    str(input_path),
                    str(policy_path),
                    str(policy_set_path),
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
                    f"expected={json.dumps(expected, sort_keys=True)}\n"
                    f"observed={json.dumps(observed, sort_keys=True)}"
                )

            print(
                f"PASS  {vector.name:<34} "
                f"status={observed['status']} byte_model=True"
            )
            passed += 1

        print(
            "TPE 2.6 Python/Go composition evaluation parity: "
            f"{passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
