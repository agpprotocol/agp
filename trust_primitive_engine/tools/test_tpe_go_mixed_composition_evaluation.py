#!/usr/bin/env python3
"""Byte-identical Python/Go parity for mixed leaf compositions."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
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
    expected_status: str
    signer_ids: tuple[str, ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[dict[str, Any], ...] = ()
    evaluation_time: int = 150


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe_go_mixed_composition_evaluation",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


A = "authority:approver-a"
B = "authority:approver-b"
R = "authority:reviewer"
O = "authority:observer"


PARTICIPANTS = (
    {"id": A, "role": "approver", "weight": 2},
    {"id": B, "role": "approver", "weight": 3},
    {"id": R, "role": "reviewer", "weight": 4},
    {"id": O, "role": "observer", "weight": 5},
)


def required(
    requirement_id: str,
    signer_id: str = A,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "required_signer",
        "signer_id": signer_id,
    }


def context_equals(
    requirement_id: str,
    path: str,
    value: Any,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "context_value_equals",
        "path": path,
        "value": value,
    }


def context_present(
    requirement_id: str,
    path: str,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "context_value_present",
        "path": path,
    }


def time_window(
    requirement_id: str,
    not_before: int = 100,
    not_after: int = 200,
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "time_window",
        "not_before": not_before,
        "not_after": not_after,
    }


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
    payload = {
        "environment": "production",
        "service": "payments-api",
        "version": "3.0.0",
    }

    return [
        Vector(
            "all_of_signer_context_satisfied",
            [
                all_of("requirement:root", [
                    required("requirement:a-signer"),
                    context_equals(
                        "requirement:b-context",
                        "/proposal/payload/environment",
                        "production",
                    ),
                ]),
            ],
            "satisfied",
            signer_ids=(A,),
            payload=payload,
        ),
        Vector(
            "all_of_signer_context_unsatisfied",
            [
                all_of("requirement:root", [
                    required("requirement:a-signer"),
                    context_equals(
                        "requirement:b-context",
                        "/proposal/payload/environment",
                        "staging",
                    ),
                ]),
            ],
            "unsatisfied",
            signer_ids=(A,),
            payload=payload,
        ),
        Vector(
            "any_of_evidence_time_satisfied",
            [
                any_of("requirement:root", [
                    issuer(
                        "requirement:a-evidence",
                        "authority:missing",
                    ),
                    time_window("requirement:b-time"),
                ]),
            ],
            "satisfied",
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
            evaluation_time=150,
        ),
        Vector(
            "any_of_evidence_time_unsatisfied",
            [
                any_of("requirement:root", [
                    issuer(
                        "requirement:a-evidence",
                        "authority:missing",
                    ),
                    time_window("requirement:b-time"),
                ]),
            ],
            "unsatisfied",
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
            evaluation_time=201,
        ),
        Vector(
            "not_required_signer_satisfied",
            [
                negate(
                    "requirement:not",
                    required("requirement:child"),
                ),
            ],
            "satisfied",
            payload=payload,
        ),
        Vector(
            "not_context_equals_unsatisfied",
            [
                negate(
                    "requirement:not",
                    context_equals(
                        "requirement:child",
                        "/proposal/payload/environment",
                        "production",
                    ),
                ),
            ],
            "unsatisfied",
            payload=payload,
        ),
        Vector(
            "nested_all_any_mixed_satisfied",
            [
                all_of("requirement:z-root", [
                    any_of("requirement:a-choice", [
                        issuer(
                            "requirement:a-evidence",
                            "authority:missing",
                        ),
                        required("requirement:b-signer"),
                    ]),
                    context_present(
                        "requirement:y-context",
                        "/proposal/payload/service",
                    ),
                ]),
            ],
            "satisfied",
            signer_ids=(A,),
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
        ),
        Vector(
            "nested_all_any_mixed_unsatisfied",
            [
                all_of("requirement:z-root", [
                    any_of("requirement:a-choice", [
                        issuer(
                            "requirement:a-evidence",
                            "authority:missing",
                        ),
                        required("requirement:b-signer"),
                    ]),
                    context_present(
                        "requirement:y-context",
                        "/proposal/payload/missing",
                    ),
                ]),
            ],
            "unsatisfied",
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
        ),
        Vector(
            "all_of_multiple_mixed_failures",
            [
                all_of("requirement:root", [
                    required("requirement:a-signer"),
                    context_equals(
                        "requirement:b-context",
                        "/proposal/payload/environment",
                        "staging",
                    ),
                    time_window("requirement:c-time"),
                ]),
            ],
            "unsatisfied",
            payload=payload,
            evaluation_time=201,
        ),
        Vector(
            "any_of_suppresses_mixed_failures",
            [
                any_of("requirement:root", [
                    required("requirement:a-signer"),
                    context_equals(
                        "requirement:b-context",
                        "/proposal/payload/environment",
                        "staging",
                    ),
                    issuer("requirement:c-evidence"),
                ]),
            ],
            "satisfied",
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
        ),
        Vector(
            "not_suppresses_child_failure",
            [
                negate(
                    "requirement:not",
                    all_of("requirement:child-all", [
                        required("requirement:a-signer"),
                        context_present(
                            "requirement:b-context",
                            "/proposal/payload/missing",
                        ),
                    ]),
                ),
            ],
            "satisfied",
            payload=payload,
        ),
        Vector(
            "mixed_top_level_failure_order",
            [
                context_equals(
                    "requirement:a-context",
                    "/proposal/payload/environment",
                    "staging",
                ),
                required("requirement:m-signer"),
                time_window("requirement:z-time"),
            ],
            "unsatisfied",
            payload=payload,
            evaluation_time=201,
        ),
    ]

def policy_for(vector: Vector) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": f"policy:{vector.name}",
        "version": 1,
        "eligible_roles": [
            "approver",
            "observer",
            "reviewer",
        ],
        "requirements": vector.requirements,
    }


def input_for(
    evaluator: Any,
    vector: Vector,
    policy: dict[str, Any],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(policy)
    digest = evaluator.policy_digest(normalized)

    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:{vector.name}",
        "context": {
            "object_type": "agp.decision-context/3",
            "context_id": f"context:{vector.name}",
            "evaluation_time": vector.evaluation_time,
            "proposal": {
                "type": "proposal:mixed-composition-parity",
                "payload": vector.payload,
            },
            "policy": {
                "id": normalized["policy_id"],
                "version": normalized["version"],
                "digest": digest,
            },
            "participants": sorted(
                [dict(item) for item in PARTICIPANTS],
                key=lambda item: item["id"],
            ),
            "evidence": sorted(
                [dict(item) for item in vector.evidence],
                key=lambda item: item["id"],
            ),
        },
        "signatures": [
            {
                "signature_id": (
                    f"signature:{index:02d}:{signer_id}"
                ),
                "statement": {
                    "signer_id": signer_id,
                },
            }
            for index, signer_id in enumerate(
                sorted(vector.signer_ids)
            )
        ],
    }

def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def main() -> int:
    cases = vectors()
    if len(cases) != 12:
        raise AssertionError(f"expected 12 vectors, got {len(cases)}")

    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-go-mixed-composition-evaluation-"
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
                vector,
                normalized,
            )
            verified_signature_ids = [
                entry["signature_id"]
                for entry in evaluation_input["signatures"]
            ]
            expected = evaluator.evaluate_verified_object(
                evaluation_input,
                normalized,
                verified_signature_ids,
            )

            if expected["status"] != vector.expected_status:
                raise AssertionError(
                    f"{vector.name}: Python status "
                    f"{expected['status']!r}, expected "
                    f"{vector.expected_status!r}"
                )

            case_dir = temp / f"{index:02d}-{vector.name}"
            case_dir.mkdir()
            input_path = case_dir / "evaluation-input.json"
            policy_path = case_dir / "root-policy.json"
            policy_set_path = case_dir / "policy-set.json"

            input_path.write_bytes(
                compact_json(evaluation_input)
            )
            policy_path.write_bytes(
                compact_json(normalized)
            )
            policy_set_path.write_text("[]", encoding="utf-8")

            expected_bytes = compact_json(expected)

            completed = subprocess.run(
                [
                    str(binary),
                    str(input_path),
                    str(policy_path),
                    str(policy_set_path),
                ],
                cwd=case_dir,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"{vector.name}: Go command failed: "
                    f"{completed.stderr.decode(errors='replace')}"
                )

            if completed.stdout != expected_bytes:
                raise AssertionError(
                    f"{vector.name}: Python/Go canonical bytes differ\n"
                    f"expected={expected_bytes.decode()}\n"
                    f"observed="
                    f"{completed.stdout.decode(errors='replace')}"
                )

            observed = json.loads(completed.stdout)
            if observed["status"] != vector.expected_status:
                raise AssertionError(
                    f"{vector.name}: Go status "
                    f"{observed['status']!r}, expected "
                    f"{vector.expected_status!r}"
                )

            print(
                f"PASS  {vector.name:<44} "
                f"status={observed['status']} bytes=identical"
            )
            passed += 1

        print(
            "TPE Python/Go mixed composition evaluation parity: "
            f"{passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
