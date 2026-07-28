#!/usr/bin/env python3
"""Byte-identical Python/Go parity for mixed policy-reference compositions."""

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
    root: dict[str, Any]
    policy_set: list[dict[str, Any]]
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
        "agp_tpe_go_mixed_policy_reference",
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
    payload = {
        "environment": "production",
        "service": "payments-api",
    }

    signer_leaf = policy(
        "policy:ref:signer",
        [required("requirement:signer")],
    )
    context_leaf = policy(
        "policy:ref:context",
        [
            context_equals(
                "requirement:context",
                "/proposal/payload/environment",
                "production",
            )
        ],
    )
    time_leaf = policy(
        "policy:ref:time",
        [time_window("requirement:time")],
    )
    evidence_leaf = policy(
        "policy:ref:evidence",
        [issuer("requirement:evidence")],
    )
    transitive_leaf = policy(
        "policy:ref:transitive-leaf",
        [required("requirement:signer")],
    )
    transitive_middle = policy(
        "policy:ref:transitive-middle",
        [
            all_of(
                "requirement:middle",
                [
                    reference(
                        evaluator,
                        transitive_leaf,
                        "requirement:a-leaf",
                    ),
                    context_present(
                        "requirement:b-context",
                        "/proposal/payload/service",
                    ),
                ],
            )
        ],
    )
    shared_leaf = policy(
        "policy:ref:shared",
        [
            context_present(
                "requirement:shared-context",
                "/proposal/payload/service",
            )
        ],
    )

    return [
        Vector(
            "reference_signer_all_satisfied",
            policy(
                "policy:root:signer-all-satisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                signer_leaf,
                                "requirement:a-reference",
                            ),
                            context_present(
                                "requirement:b-context",
                                "/proposal/payload/service",
                            ),
                        ],
                    )
                ],
            ),
            [signer_leaf],
            "satisfied",
            signer_ids=(A,),
            payload=payload,
        ),
        Vector(
            "reference_signer_all_unsatisfied",
            policy(
                "policy:root:signer-all-unsatisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                signer_leaf,
                                "requirement:a-reference",
                            ),
                            context_present(
                                "requirement:b-context",
                                "/proposal/payload/service",
                            ),
                        ],
                    )
                ],
            ),
            [signer_leaf],
            "unsatisfied",
            payload=payload,
        ),
        Vector(
            "reference_context_any_satisfied",
            policy(
                "policy:root:context-any-satisfied",
                [
                    any_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                context_leaf,
                                "requirement:a-reference",
                            ),
                            required(
                                "requirement:b-signer",
                                B,
                            ),
                        ],
                    )
                ],
            ),
            [context_leaf],
            "satisfied",
            payload=payload,
        ),
        Vector(
            "reference_context_any_unsatisfied",
            policy(
                "policy:root:context-any-unsatisfied",
                [
                    any_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                context_leaf,
                                "requirement:a-reference",
                            ),
                            required(
                                "requirement:b-signer",
                                B,
                            ),
                        ],
                    )
                ],
            ),
            [context_leaf],
            "unsatisfied",
            payload={
                "environment": "staging",
            },
        ),
        Vector(
            "reference_time_not_satisfied",
            policy(
                "policy:root:time-not-satisfied",
                [
                    negate(
                        "requirement:root",
                        reference(
                            evaluator,
                            time_leaf,
                            "requirement:reference",
                        ),
                    )
                ],
            ),
            [time_leaf],
            "satisfied",
            payload=payload,
            evaluation_time=201,
        ),
        Vector(
            "reference_time_not_unsatisfied",
            policy(
                "policy:root:time-not-unsatisfied",
                [
                    negate(
                        "requirement:root",
                        reference(
                            evaluator,
                            time_leaf,
                            "requirement:reference",
                        ),
                    )
                ],
            ),
            [time_leaf],
            "unsatisfied",
            payload=payload,
            evaluation_time=150,
        ),
        Vector(
            "reference_evidence_all_satisfied",
            policy(
                "policy:root:evidence-all-satisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                evidence_leaf,
                                "requirement:a-reference",
                            ),
                            required(
                                "requirement:b-signer",
                            ),
                        ],
                    )
                ],
            ),
            [evidence_leaf],
            "satisfied",
            signer_ids=(A,),
            payload=payload,
            evidence=tuple(BASE_EVIDENCE),
        ),
        Vector(
            "reference_evidence_all_unsatisfied",
            policy(
                "policy:root:evidence-all-unsatisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                evidence_leaf,
                                "requirement:a-reference",
                            ),
                            required(
                                "requirement:b-signer",
                            ),
                        ],
                    )
                ],
            ),
            [evidence_leaf],
            "unsatisfied",
            signer_ids=(A,),
            payload=payload,
        ),
        Vector(
            "transitive_reference_mixed_satisfied",
            policy(
                "policy:root:transitive-satisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                transitive_middle,
                                "requirement:a-middle",
                            ),
                            time_window(
                                "requirement:b-time",
                            ),
                        ],
                    )
                ],
            ),
            [transitive_middle, transitive_leaf],
            "satisfied",
            signer_ids=(A,),
            payload=payload,
            evaluation_time=150,
        ),
        Vector(
            "transitive_reference_mixed_unsatisfied",
            policy(
                "policy:root:transitive-unsatisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                transitive_middle,
                                "requirement:a-middle",
                            ),
                            time_window(
                                "requirement:b-time",
                            ),
                        ],
                    )
                ],
            ),
            [transitive_middle, transitive_leaf],
            "unsatisfied",
            signer_ids=(A,),
            payload={
                "environment": "production",
            },
            evaluation_time=150,
        ),
        Vector(
            "shared_reference_paths_satisfied",
            policy(
                "policy:root:shared-satisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                shared_leaf,
                                "requirement:a-reference",
                            ),
                            reference(
                                evaluator,
                                shared_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [shared_leaf],
            "satisfied",
            payload=payload,
        ),
        Vector(
            "shared_reference_paths_unsatisfied",
            policy(
                "policy:root:shared-unsatisfied",
                [
                    all_of(
                        "requirement:root",
                        [
                            reference(
                                evaluator,
                                shared_leaf,
                                "requirement:a-reference",
                            ),
                            reference(
                                evaluator,
                                shared_leaf,
                                "requirement:b-reference",
                            ),
                        ],
                    )
                ],
            ),
            [shared_leaf],
            "unsatisfied",
            payload={
                "environment": "production",
            },
        ),
    ]

def evaluation_input(
    evaluator: Any,
    vector: Vector,
    root_policy: dict[str, Any],
) -> dict[str, Any]:
    normalized = evaluator.validate_policy(root_policy)
    digest = evaluator.policy_digest(normalized)

    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": f"context-digest:{vector.name}",
        "context": {
            "object_type": "agp.decision-context/3",
            "context_id": f"context:{vector.name}",
            "evaluation_time": vector.evaluation_time,
            "proposal": {
                "type": "proposal:mixed-reference-parity",
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
    if len(cases) != 12:
        raise AssertionError(f"expected 12 vectors, got {len(cases)}")

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-go-mixed-policy-reference-"
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
                vector,
                normalized_root,
            )
            verified_signature_ids = [
                entry["signature_id"]
                for entry in signed_context["signatures"]
            ]
            expected = evaluator.evaluate_verified_object(
                signed_context,
                normalized_root,
                verified_signature_ids,
                policy_set_index=policy_set_index,
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

            expected_bytes = compact(expected).encode("utf-8")

            completed = subprocess.run(
                [
                    str(binary),
                    str(input_path),
                    str(root_path),
                    str(set_path),
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
                    f"{vector.name}: canonical bytes differ\n"
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
                f"PASS  {vector.name:<46} "
                f"status={observed['status']} bytes=identical"
            )
            passed += 1

        print(
            "TPE Python/Go mixed policy-reference evaluation parity: "
            f"{passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
