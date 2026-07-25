#!/usr/bin/env python3
"""Focused checks for the TPE 2.4 evidence_present primitive."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
SCHEMA_PATH = (
    ROOT / "registry/schemas/agp.trust-policy-2.schema.json"
)

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import EvaluationState, PrimitiveRegistry, evaluate_requirement
from primitives.evidence_present import EvidencePresentPrimitive


DIGEST_A = "a" * 64
DIGEST_B = "b" * 64
FAILURE = "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED"
PRIMITIVE = EvidencePresentPrimitive()
REGISTRY = PrimitiveRegistry([PRIMITIVE])


class TestFailure(Exception):
    pass


def req(**extra: Any) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:evidence-report",
        "type": "evidence_present",
        "evidence_id": "evidence.security-report",
        **extra,
    }


def state(
    *,
    object_type: str = "agp.decision-context/2",
    evidence: list[dict[str, Any]] | None = None,
) -> EvaluationState:
    return EvaluationState.create(
        matched_signers=["authority:security"],
        participants={
            "authority:security": {
                "id": "authority:security",
                "role": "reviewer",
                "weight": 1,
            }
        },
        weight=1,
        decision_context={
            "object_type": object_type,
            "proposal": {
                "payload": {
                    "service": "payments-api",
                }
            },
            "evidence": (
                evidence
                if evidence is not None
                else [
                    {
                        "id": "evidence.security-report",
                        "digest": DIGEST_A,
                        "media_type": "application/json",
                    },
                    {
                        "id": "evidence.test-report",
                        "digest": DIGEST_B,
                        "media_type": "application/pdf",
                    },
                ]
            ),
        },
    )


def evaluate(
    evaluation_state: EvaluationState,
    requirement: dict[str, Any],
):
    return PRIMITIVE.evaluate(
        PRIMITIVE.validate(requirement),
        evaluation_state,
    )


def expect_result(
    name: str,
    result: Any,
    *,
    satisfied: bool,
    status: str,
    present: bool,
) -> None:
    if result.satisfied is not satisfied:
        raise TestFailure(f"{name}: wrong satisfaction")

    if result.observed["match_status"] != status:
        raise TestFailure(f"{name}: wrong match status")

    if result.observed["present"] is not present:
        raise TestFailure(f"{name}: wrong present value")

    expected_failure = None if satisfied else FAILURE
    actual_failure = None if satisfied else result.failure_code

    if actual_failure != expected_failure:
        raise TestFailure(f"{name}: wrong failure code")

    if result.matched_signers != ():
        raise TestFailure(f"{name}: matched_signers must be empty")

    print(f"PASS  {name:<46} {status}")


def expect_reject(
    name: str,
    requirement: dict[str, Any],
) -> None:
    try:
        PRIMITIVE.validate(requirement)
    except ValueError:
        print(f"PASS  {name:<46} rejected")
        return

    raise TestFailure(f"{name}: invalid requirement accepted")


def policy_with(requirement: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe-2.4-evidence",
        "version": 1,
        "eligible_roles": ["reviewer"],
        "requirements": [requirement],
    }


def main() -> int:
    passed = 0
    base_state = state()

    cases = [
        (
            "minimal_match",
            req(),
            True,
            "matched",
            True,
        ),
        (
            "fully_bound_match",
            req(
                digest=DIGEST_A,
                media_type="application/json",
            ),
            True,
            "matched",
            True,
        ),
        (
            "absent",
            {
                **req(),
                "evidence_id": "evidence.missing-report",
            },
            False,
            "absent",
            False,
        ),
        (
            "digest_mismatch",
            req(digest=DIGEST_B),
            False,
            "digest_mismatch",
            True,
        ),
        (
            "media_type_mismatch",
            req(media_type="application/pdf"),
            False,
            "media_type_mismatch",
            True,
        ),
        (
            "combined_mismatch",
            req(
                digest=DIGEST_B,
                media_type="application/pdf",
            ),
            False,
            "digest_and_media_type_mismatch",
            True,
        ),
        (
            "digest_only_match",
            req(digest=DIGEST_A),
            True,
            "matched",
            True,
        ),
        (
            "media_type_only_match",
            req(media_type="application/json"),
            True,
            "matched",
            True,
        ),
    ]

    for name, requirement, satisfied, status, present in cases:
        expect_result(
            name,
            evaluate(base_state, requirement),
            satisfied=satisfied,
            status=status,
            present=present,
        )
        passed += 1

    matched = evaluate(
        base_state,
        req(
            digest=DIGEST_A,
            media_type="application/json",
        ),
    )
    if (
        matched.observed["digest"] != DIGEST_A
        or matched.observed["media_type"] != "application/json"
        or matched.expected != {
            "evidence_id": "evidence.security-report",
            "digest": DIGEST_A,
            "media_type": "application/json",
        }
    ):
        raise TestFailure("observed/expected binding shape changed")
    print("PASS  observed_and_expected_bindings                 correct")
    passed += 1

    absent = evaluate(
        base_state,
        {
            **req(),
            "evidence_id": "evidence.missing-report",
        },
    )
    if (
        absent.observed["digest"] is not None
        or absent.observed["media_type"] is not None
    ):
        raise TestFailure("absent result leaked observed bindings")
    print("PASS  absent_observed_bindings                       null")
    passed += 1

    no_context = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
    )
    expect_result(
        "missing_context",
        evaluate(no_context, req()),
        satisfied=False,
        status="absent",
        present=False,
    )
    passed += 1

    reverse_state = state(
        evidence=[
            {
                "id": "evidence.test-report",
                "digest": DIGEST_B,
                "media_type": "application/pdf",
            },
            {
                "id": "evidence.security-report",
                "digest": DIGEST_A,
                "media_type": "application/json",
            },
        ]
    )
    first = evaluate(
        base_state,
        req(digest=DIGEST_A),
    ).to_dict()
    second = evaluate(
        reverse_state,
        req(digest=DIGEST_A),
    ).to_dict()
    if first != second:
        raise TestFailure("insertion order changed result")
    print("PASS  evidence_insertion_order                       independent")
    passed += 1

    v1 = evaluate(
        state(object_type="agp.decision-context/1"),
        req(digest=DIGEST_A),
    ).to_dict()
    v2 = evaluate(
        state(object_type="agp.decision-context/2"),
        req(digest=DIGEST_A),
    ).to_dict()
    if v1 != v2:
        raise TestFailure("Decision Context versions diverged")
    print("PASS  decision_context_v1_v2                         equivalent")
    passed += 1

    replay_a = evaluate(
        base_state,
        req(
            digest=DIGEST_A,
            media_type="application/json",
        ),
    ).to_dict()
    replay_b = evaluate(
        base_state,
        req(
            digest=DIGEST_A,
            media_type="application/json",
        ),
    ).to_dict()
    if replay_a != replay_b:
        raise TestFailure("deterministic replay changed")
    print("PASS  deterministic_replay                          identical")
    passed += 1

    invalid = [
        (
            "unknown_member",
            {
                **req(),
                "uri": "https://example.invalid/report",
            },
        ),
        (
            "missing_evidence_id",
            {
                "requirement_id": "requirement:evidence-report",
                "type": "evidence_present",
            },
        ),
        (
            "invalid_evidence_id",
            {
                **req(),
                "evidence_id": "Bad ID",
            },
        ),
        (
            "invalid_requirement_id",
            {
                **req(),
                "requirement_id": "Bad ID",
            },
        ),
        (
            "uppercase_digest",
            req(digest="A" * 64),
        ),
        (
            "short_digest",
            req(digest="a" * 63),
        ),
        (
            "invalid_media_type",
            req(media_type="Application/JSON"),
        ),
        (
            "wrong_type",
            {
                **req(),
                "type": "context_value_present",
            },
        ),
    ]

    for name, requirement in invalid:
        expect_reject(name, requirement)
        passed += 1

    if REGISTRY.types() != ("evidence_present",):
        raise TestFailure("registry did not expose evidence_present")
    print("PASS  registry_contains_evidence_present             correct")
    passed += 1

    composed = {
        "requirement_id": "requirement:all-evidence",
        "type": "all_of",
        "requirements": [
            PRIMITIVE.validate(
                {
                    **req(digest=DIGEST_A),
                    "requirement_id": "requirement:evidence-a",
                }
            ),
            PRIMITIVE.validate(
                {
                    **req(media_type="application/json"),
                    "requirement_id": "requirement:evidence-b",
                }
            ),
        ],
    }
    composed_result = evaluate_requirement(
        composed,
        base_state,
        REGISTRY,
    )
    if (
        not composed_result.satisfied
        or len(composed_result.children) != 2
    ):
        raise TestFailure("composition integration failed")
    print("PASS  composition_integration                       satisfied")
    passed += 1

    schema = json.loads(
        SCHEMA_PATH.read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)

    schema_valid = [
        req(),
        req(digest=DIGEST_A),
        req(media_type="application/json"),
        req(
            digest=DIGEST_A,
            media_type="application/json",
        ),
    ]
    for index, requirement in enumerate(schema_valid, 1):
        errors = list(
            validator.iter_errors(policy_with(requirement))
        )
        if errors:
            raise TestFailure(
                f"schema valid {index}: {errors[0].message}"
            )
        print(
            f"PASS  schema_accepts_evidence_form_{index:<17} accepted"
        )
        passed += 1

    schema_invalid = [
        req(digest="A" * 64),
        req(media_type="Application/JSON"),
        {
            **req(),
            "extra": True,
        },
    ]
    for index, requirement in enumerate(schema_invalid, 1):
        if not list(
            validator.iter_errors(policy_with(requirement))
        ):
            raise TestFailure(
                f"schema invalid {index} was accepted"
            )
        print(
            f"PASS  schema_rejects_evidence_form_{index:<17} rejected"
        )
        passed += 1

    duplicate_state = state(
        evidence=[
            {
                "id": "evidence.security-report",
                "digest": DIGEST_A,
                "media_type": "application/json",
            },
            {
                "id": "evidence.security-report",
                "digest": DIGEST_A,
                "media_type": "application/json",
            },
        ]
    )
    expect_result(
        "duplicate_identifier_not_exactly_one",
        evaluate(duplicate_state, req()),
        satisfied=False,
        status="absent",
        present=False,
    )
    passed += 1

    if passed != 32:
        raise TestFailure(
            f"expected 32 checks, observed {passed}"
        )

    print(
        "TPE 2.4 evidence_present primitive: "
        f"{passed}/{passed} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
