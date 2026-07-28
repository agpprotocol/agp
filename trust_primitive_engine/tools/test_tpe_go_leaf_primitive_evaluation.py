#!/usr/bin/env python3
"""Byte-identical Python/Go evaluation parity for all leaf primitives."""

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
TPE = ROOT / "trust_primitive_engine"
GO_DIR = TPE / "go"
EVALUATOR_PATH = TPE / "python/evaluate_trust_policy_v2.py"

A = "authority:approver-a"
B = "authority:approver-b"
R = "authority:reviewer"
O = "authority:observer"

DIGEST_A = "a" * 64
DIGEST_B = "b" * 64


class TestFailure(Exception):
    pass


@dataclass(frozen=True)
class Vector:
    name: str
    requirement: dict[str, Any]
    expected_status: str
    signer_ids: tuple[str, ...] = ()
    participants: tuple[dict[str, Any], ...] = ()
    payload: dict[str, Any] = field(default_factory=dict)
    evidence: tuple[dict[str, Any], ...] = ()
    evaluation_time: int = 150


def load_evaluator() -> Any:
    python_dir = str(EVALUATOR_PATH.parent)
    if python_dir not in sys.path:
        sys.path.insert(0, python_dir)

    spec = importlib.util.spec_from_file_location(
        "evaluate_trust_policy_v2",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("unable to load Python evaluator")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def requirement(
    primitive_type: str,
    **members: Any,
) -> dict[str, Any]:
    return {
        "requirement_id": f"requirement:{primitive_type}",
        "type": primitive_type,
        **members,
    }


def participant(
    signer_id: str,
    role: str,
    weight: int,
) -> dict[str, Any]:
    return {
        "id": signer_id,
        "role": role,
        "weight": weight,
    }


PARTICIPANTS = (
    participant(A, "approver", 2),
    participant(B, "approver", 3),
    participant(R, "reviewer", 4),
    participant(O, "observer", 5),
)


def evidence(
    evidence_id: str,
    *,
    digest: str = DIGEST_A,
    media_type: str = "application/json",
    evidence_type: str = "security:report/1",
    issuer_id: str = "authority:issuer-a",
) -> dict[str, Any]:
    return {
        "id": evidence_id,
        "digest": digest,
        "media_type": media_type,
        "evidence_type": evidence_type,
        "issuer_id": issuer_id,
    }


EVIDENCE_A = evidence("evidence:a")
EVIDENCE_B = evidence(
    "evidence:b",
    digest=DIGEST_B,
    evidence_type="audit:report/1",
    issuer_id="authority:issuer-b",
)


def vector(
    primitive_type: str,
    outcome: str,
    requirement_value: dict[str, Any],
    *,
    signer_ids: tuple[str, ...] = (),
    participants: tuple[dict[str, Any], ...] = PARTICIPANTS,
    payload: dict[str, Any] | None = None,
    evidence_entries: tuple[dict[str, Any], ...] = (),
    evaluation_time: int = 150,
) -> Vector:
    return Vector(
        name=f"{primitive_type}-{outcome}",
        requirement=requirement_value,
        expected_status=outcome,
        signer_ids=signer_ids,
        participants=participants,
        payload={} if payload is None else payload,
        evidence=evidence_entries,
        evaluation_time=evaluation_time,
    )


def vectors() -> list[Vector]:
    cases: list[Vector] = []

    cases.extend([
        vector(
            "required_signer",
            "satisfied",
            requirement("required_signer", signer_id=A),
            signer_ids=(A,),
        ),
        vector(
            "required_signer",
            "unsatisfied",
            requirement("required_signer", signer_id=A),
        ),
        vector(
            "prohibited_signer",
            "satisfied",
            requirement("prohibited_signer", signer_id=A),
        ),
        vector(
            "prohibited_signer",
            "unsatisfied",
            requirement("prohibited_signer", signer_id=A),
            signer_ids=(A,),
        ),
        vector(
            "signer_threshold",
            "satisfied",
            requirement(
                "signer_threshold",
                signer_ids=[A, B],
                minimum_signatures=2,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "signer_threshold",
            "unsatisfied",
            requirement(
                "signer_threshold",
                signer_ids=[A, B],
                minimum_signatures=2,
            ),
            signer_ids=(A,),
        ),
        vector(
            "global_signature_threshold",
            "satisfied",
            requirement(
                "global_signature_threshold",
                minimum_signatures=2,
            ),
            signer_ids=(A, R),
        ),
        vector(
            "global_signature_threshold",
            "unsatisfied",
            requirement(
                "global_signature_threshold",
                minimum_signatures=2,
            ),
            signer_ids=(A,),
        ),
        vector(
            "global_weight_threshold",
            "satisfied",
            requirement(
                "global_weight_threshold",
                minimum_weight=6,
            ),
            signer_ids=(A, R),
        ),
        vector(
            "global_weight_threshold",
            "unsatisfied",
            requirement(
                "global_weight_threshold",
                minimum_weight=7,
            ),
            signer_ids=(A, R),
        ),
        vector(
            "role_threshold",
            "satisfied",
            requirement(
                "role_threshold",
                role="approver",
                minimum_signatures=2,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "role_threshold",
            "unsatisfied",
            requirement(
                "role_threshold",
                role="approver",
                minimum_signatures=2,
            ),
            signer_ids=(A, R),
        ),
        vector(
            "role_weight_threshold",
            "satisfied",
            requirement(
                "role_weight_threshold",
                role="approver",
                minimum_weight=5,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "role_weight_threshold",
            "unsatisfied",
            requirement(
                "role_weight_threshold",
                role="approver",
                minimum_weight=5,
            ),
            signer_ids=(A, R),
        ),
        vector(
            "separation_of_duties",
            "satisfied",
            requirement(
                "separation_of_duties",
                roles=["approver", "reviewer"],
            ),
            signer_ids=(A, R),
        ),
        vector(
            "separation_of_duties",
            "unsatisfied",
            requirement(
                "separation_of_duties",
                roles=["approver", "reviewer"],
            ),
            signer_ids=(A, B),
        ),
        vector(
            "mutual_exclusion",
            "satisfied",
            requirement(
                "mutual_exclusion",
                signer_ids=[A, B],
            ),
            signer_ids=(A,),
        ),
        vector(
            "mutual_exclusion",
            "unsatisfied",
            requirement(
                "mutual_exclusion",
                signer_ids=[A, B],
            ),
            signer_ids=(A, B),
        ),
        vector(
            "any_of_signers",
            "satisfied",
            requirement(
                "any_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(B,),
        ),
        vector(
            "any_of_signers",
            "unsatisfied",
            requirement(
                "any_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(R,),
        ),
        vector(
            "all_of_signers",
            "satisfied",
            requirement(
                "all_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(A, B),
        ),
        vector(
            "all_of_signers",
            "unsatisfied",
            requirement(
                "all_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(A,),
        ),
        vector(
            "exactly_one_of_signers",
            "satisfied",
            requirement(
                "exactly_one_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(A,),
        ),
        vector(
            "exactly_one_of_signers",
            "unsatisfied",
            requirement(
                "exactly_one_of_signers",
                signer_ids=[A, B],
            ),
            signer_ids=(A, B),
        ),
        vector(
            "at_most_n_signers",
            "satisfied",
            requirement(
                "at_most_n_signers",
                signer_ids=[A, B, R],
                maximum_matches=1,
            ),
            signer_ids=(A,),
        ),
        vector(
            "at_most_n_signers",
            "unsatisfied",
            requirement(
                "at_most_n_signers",
                signer_ids=[A, B, R],
                maximum_matches=1,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "at_least_n_signers",
            "satisfied",
            requirement(
                "at_least_n_signers",
                signer_ids=[A, B, R],
                minimum_matches=2,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "at_least_n_signers",
            "unsatisfied",
            requirement(
                "at_least_n_signers",
                signer_ids=[A, B, R],
                minimum_matches=2,
            ),
            signer_ids=(A,),
        ),
        vector(
            "exactly_n_signers",
            "satisfied",
            requirement(
                "exactly_n_signers",
                signer_ids=[A, B, R],
                exact_matches=2,
            ),
            signer_ids=(A, B),
        ),
        vector(
            "exactly_n_signers",
            "unsatisfied",
            requirement(
                "exactly_n_signers",
                signer_ids=[A, B, R],
                exact_matches=2,
            ),
            signer_ids=(A,),
        ),
    ])

    context_payload = {
        "service": "payments-api",
        "environment": "production",
        "coverage": 90,
        "rollout": 25,
        "version": "3.0.0",
        "target_version": "3.0.0",
    }

    cases.extend([
        vector(
            "context_value_present",
            "satisfied",
            requirement(
                "context_value_present",
                path="/proposal/payload/service",
            ),
            payload=context_payload,
        ),
        vector(
            "context_value_present",
            "unsatisfied",
            requirement(
                "context_value_present",
                path="/proposal/payload/missing",
            ),
            payload=context_payload,
        ),
        vector(
            "context_value_equals",
            "satisfied",
            requirement(
                "context_value_equals",
                path="/proposal/payload/environment",
                value="production",
            ),
            payload=context_payload,
        ),
        vector(
            "context_value_equals",
            "unsatisfied",
            requirement(
                "context_value_equals",
                path="/proposal/payload/environment",
                value="staging",
            ),
            payload=context_payload,
        ),
        vector(
            "context_value_in",
            "satisfied",
            requirement(
                "context_value_in",
                path="/proposal/payload/environment",
                values=["production", "staging"],
            ),
            payload=context_payload,
        ),
        vector(
            "context_value_in",
            "unsatisfied",
            requirement(
                "context_value_in",
                path="/proposal/payload/environment",
                values=["development", "staging"],
            ),
            payload=context_payload,
        ),
        vector(
            "context_path_equals",
            "satisfied",
            requirement(
                "context_path_equals",
                left_path="/proposal/payload/version",
                right_path="/proposal/payload/target_version",
            ),
            payload=context_payload,
        ),
        vector(
            "context_path_equals",
            "unsatisfied",
            requirement(
                "context_path_equals",
                left_path="/proposal/payload/version",
                right_path="/proposal/payload/environment",
            ),
            payload=context_payload,
        ),
        vector(
            "context_integer_at_least",
            "satisfied",
            requirement(
                "context_integer_at_least",
                path="/proposal/payload/coverage",
                minimum=90,
            ),
            payload=context_payload,
        ),
        vector(
            "context_integer_at_least",
            "unsatisfied",
            requirement(
                "context_integer_at_least",
                path="/proposal/payload/coverage",
                minimum=91,
            ),
            payload=context_payload,
        ),
        vector(
            "context_integer_at_most",
            "satisfied",
            requirement(
                "context_integer_at_most",
                path="/proposal/payload/rollout",
                maximum=25,
            ),
            payload=context_payload,
        ),
        vector(
            "context_integer_at_most",
            "unsatisfied",
            requirement(
                "context_integer_at_most",
                path="/proposal/payload/rollout",
                maximum=24,
            ),
            payload=context_payload,
        ),
    ])

    cases.extend([
        vector(
            "evidence_present",
            "satisfied",
            requirement(
                "evidence_present",
                evidence_id="evidence:a",
                digest=DIGEST_A,
                media_type="application/json",
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_present",
            "unsatisfied",
            requirement(
                "evidence_present",
                evidence_id="evidence:a",
                digest=DIGEST_B,
                media_type="application/json",
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_count_at_least",
            "satisfied",
            requirement(
                "evidence_count_at_least",
                minimum=2,
            ),
            evidence_entries=(EVIDENCE_A, EVIDENCE_B),
        ),
        vector(
            "evidence_count_at_least",
            "unsatisfied",
            requirement(
                "evidence_count_at_least",
                minimum=3,
            ),
            evidence_entries=(EVIDENCE_A, EVIDENCE_B),
        ),
        vector(
            "evidence_issuer_in",
            "satisfied",
            requirement(
                "evidence_issuer_in",
                issuer_ids=["authority:issuer-a"],
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_issuer_in",
            "unsatisfied",
            requirement(
                "evidence_issuer_in",
                issuer_ids=["authority:issuer-c"],
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_type_in",
            "satisfied",
            requirement(
                "evidence_type_in",
                evidence_types=["security:report/1"],
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_type_in",
            "unsatisfied",
            requirement(
                "evidence_type_in",
                evidence_types=["legal:opinion/1"],
            ),
            evidence_entries=(EVIDENCE_A,),
        ),
        vector(
            "evidence_distinct_issuers_at_least",
            "satisfied",
            requirement(
                "evidence_distinct_issuers_at_least",
                minimum=2,
            ),
            evidence_entries=(EVIDENCE_A, EVIDENCE_B),
        ),
        vector(
            "evidence_distinct_issuers_at_least",
            "unsatisfied",
            requirement(
                "evidence_distinct_issuers_at_least",
                minimum=3,
            ),
            evidence_entries=(EVIDENCE_A, EVIDENCE_B),
        ),
        vector(
            "time_window",
            "satisfied",
            requirement(
                "time_window",
                not_before=100,
                not_after=200,
            ),
            evaluation_time=150,
        ),
        vector(
            "time_window",
            "unsatisfied",
            requirement(
                "time_window",
                not_before=100,
                not_after=200,
            ),
            evaluation_time=201,
        ),
    ])

    return cases


def policy_for(vector_value: Vector) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": f"policy:{vector_value.name}",
        "version": 1,
        "eligible_roles": [
            "approver",
            "observer",
            "reviewer",
        ],
        "requirements": [vector_value.requirement],
    }


def input_for(
    evaluator: Any,
    vector_value: Vector,
    policy: dict[str, Any],
) -> dict[str, Any]:
    return {
        "object_type": "agp.signed-decision-context/2",
        "context_digest": (
            f"context-digest:{vector_value.name}"
        ),
        "context": {
            "object_type": "agp.decision-context/3",
            "context_id": f"context:{vector_value.name}",
            "evaluation_time": vector_value.evaluation_time,
            "policy": {
                "id": policy["policy_id"],
                "version": policy["version"],
                "digest": evaluator.policy_digest(policy),
            },
            "proposal": {
                "type": "proposal:leaf-parity",
                "payload": vector_value.payload,
            },
            "participants": sorted(
                [dict(item) for item in vector_value.participants],
                key=lambda item: item["id"],
            ),
            "evidence": sorted(
                [dict(item) for item in vector_value.evidence],
                key=lambda item: item["id"],
            ),
        },
        "signatures": [
            {
                "signature_id": f"signature:{index:02d}:{signer_id}",
                "statement": {
                    "signer_id": signer_id,
                },
            }
            for index, signer_id in enumerate(
                sorted(vector_value.signer_ids)
            )
        ],
    }


def main() -> int:
    cases = vectors()

    if len(cases) != 54:
        raise TestFailure(
            f"expected 54 vectors, got {len(cases)}"
        )

    names = [case.name for case in cases]
    if len(names) != len(set(names)):
        raise TestFailure("duplicate vector names")

    primitive_types = [
        case.requirement["type"]
        for case in cases
    ]
    counts = {
        primitive_type: primitive_types.count(primitive_type)
        for primitive_type in set(primitive_types)
    }

    if len(counts) != 27:
        raise TestFailure(
            f"expected 27 primitive types, got {len(counts)}"
        )

    invalid_counts = {
        primitive_type: count
        for primitive_type, count in counts.items()
        if count != 2
    }
    if invalid_counts:
        raise TestFailure(
            f"each primitive requires two vectors: {invalid_counts}"
        )

    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-go-leaf-evaluation-"
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

        for index, case in enumerate(cases):
            raw_policy = policy_for(case)
            policy = evaluator.validate_policy(raw_policy)
            evaluation_input = input_for(
                evaluator,
                case,
                policy,
            )

            verified_signature_ids = [
                entry["signature_id"]
                for entry in evaluation_input["signatures"]
            ]

            expected = evaluator.evaluate_verified_object(
                evaluation_input,
                policy,
                verified_signature_ids,
            )
            expected_bytes = compact_json(expected)

            expected_status = expected["status"]
            if expected_status != case.expected_status:
                raise TestFailure(
                    f"{case.name}: Python status "
                    f"{expected_status!r}, expected "
                    f"{case.expected_status!r}"
                )

            case_dir = temp / f"{index:02d}-{case.name}"
            case_dir.mkdir()

            input_path = case_dir / "evaluation-input.json"
            policy_path = case_dir / "root-policy.json"
            policy_set_path = case_dir / "policy-set.json"

            input_path.write_bytes(
                compact_json(evaluation_input)
            )
            policy_path.write_bytes(compact_json(policy))
            policy_set_path.write_text(
                "[]",
                encoding="utf-8",
            )

            completed = subprocess.run(
                [
                    str(binary),
                    str(input_path),
                    str(policy_path),
                    str(policy_set_path),
                ],
                cwd=GO_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            if completed.returncode != 0:
                raise TestFailure(
                    f"{case.name}: Go exited "
                    f"{completed.returncode}: "
                    f"{completed.stderr.decode(errors='replace')}"
                )

            actual_bytes = completed.stdout

            if actual_bytes != expected_bytes:
                raise TestFailure(
                    f"{case.name}: Python/Go bytes differ\n"
                    f"expected={expected_bytes.decode()}\n"
                    f"actual={actual_bytes.decode(errors='replace')}"
                )

            actual = json.loads(actual_bytes)
            if actual["status"] != case.expected_status:
                raise TestFailure(
                    f"{case.name}: Go status "
                    f"{actual['status']!r}, expected "
                    f"{case.expected_status!r}"
                )

            print(
                f"PASS  {case.name:<55} "
                f"status={case.expected_status} "
                "bytes=identical"
            )
            passed += 1

    print(
        "TPE Python/Go leaf primitive evaluation parity: "
        f"{passed}/{len(cases)} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}")
        raise SystemExit(1)
