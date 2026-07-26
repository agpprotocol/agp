#!/usr/bin/env python3
"""Focused checks for TPE 2.4 context projection and resolution."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import (
    ContextPathError,
    EvaluationState,
    create_context_projection,
    create_policy_evaluation_state,
    parse_context_path,
    resolve_context_path,
)


class TestFailure(Exception):
    pass


def expect_path_error(name: str, path: str) -> None:
    try:
        parse_context_path(path)
    except ContextPathError:
        print(f"PASS  {name:<42} rejected")
        return

    raise TestFailure(f"{name}: invalid path was accepted")


def main() -> int:
    passed = 0

    source = {
        "object_type": "agp.decision-context/2",
        "proposal": {
            "type": "proposal:test",
            "payload": {
                "environment": "production",
                "nested": {
                    "coverage": 9000,
                    "a/b": {
                        "tilde~key": True,
                    },
                },
                "services": [
                    {"name": "payments"},
                    {"name": "billing"},
                ],
                "nullable": None,
            },
        },
        "evidence": [
            {
                "id": "evidence.report",
                "digest": "a" * 64,
                "media_type": "application/json",
            }
        ],
        "participants": [
            {
                "id": "authority:ignored",
                "role": "observer",
                "weight": 1,
            }
        ],
    }

    projection = create_context_projection(source)

    if projection is None:
        raise TestFailure("projection unexpectedly missing")

    if set(projection) != {"object_type", "proposal", "evidence"}:
        raise TestFailure("projection exposed forbidden context members")

    print("PASS  projection_scope                           restricted")
    passed += 1

    source["proposal"]["payload"]["environment"] = "staging"
    source["evidence"][0]["media_type"] = "text/plain"

    observed = resolve_context_path(
        projection,
        "/proposal/payload/environment",
    )

    if (
        observed.status != "found"
        or observed.value != "production"
        or observed.value_type != "string"
    ):
        raise TestFailure("projection was not detached from caller input")

    print("PASS  projection_detached                        preserved")
    passed += 1

    try:
        projection["proposal"] = {}
    except TypeError:
        pass
    else:
        raise TestFailure("top-level projection remained mutable")

    try:
        projection["proposal"]["payload"]["nested"]["coverage"] = 1
    except TypeError:
        pass
    else:
        raise TestFailure("nested projection remained mutable")

    print("PASS  projection_deeply_immutable                enforced")
    passed += 1

    shallow = resolve_context_path(
        projection,
        "/proposal/payload/environment",
    )

    if shallow != observed:
        raise TestFailure("shallow deterministic lookup changed")

    print("PASS  shallow_lookup                             found")
    passed += 1

    nested = resolve_context_path(
        projection,
        "/proposal/payload/nested/coverage",
    )

    if (
        nested.status != "found"
        or nested.value_type != "integer"
        or nested.value != 9000
    ):
        raise TestFailure("nested lookup failed")

    print("PASS  nested_lookup                              found")
    passed += 1

    escaped = resolve_context_path(
        projection,
        "/proposal/payload/nested/a~1b/tilde~0key",
    )

    if (
        escaped.status != "found"
        or escaped.value_type != "boolean"
        or escaped.value is not True
    ):
        raise TestFailure("escaped lookup failed")

    print("PASS  escaped_lookup                             found")
    passed += 1

    array_value = resolve_context_path(
        projection,
        "/proposal/payload/services/1/name",
    )

    if (
        array_value.status != "found"
        or array_value.value != "billing"
    ):
        raise TestFailure("array lookup failed")

    print("PASS  canonical_array_lookup                     found")
    passed += 1

    nullable = resolve_context_path(
        projection,
        "/proposal/payload/nullable",
    )

    if (
        nullable.status != "found"
        or nullable.value_type != "null"
        or nullable.value is not None
    ):
        raise TestFailure("present null was not preserved")

    print("PASS  present_null                               found")
    passed += 1

    missing = resolve_context_path(
        projection,
        "/proposal/payload/missing",
    )

    if missing.status != "missing":
        raise TestFailure("missing member did not resolve as missing")

    print("PASS  missing_member                             missing")
    passed += 1

    missing_index = resolve_context_path(
        projection,
        "/proposal/payload/services/9/name",
    )

    if missing_index.status != "missing":
        raise TestFailure("missing array index was not missing")

    print("PASS  missing_array_index                        missing")
    passed += 1

    mismatch = resolve_context_path(
        projection,
        "/proposal/payload/environment/name",
    )

    if mismatch.status != "type_mismatch":
        raise TestFailure("scalar traversal did not type-mismatch")

    print("PASS  scalar_traversal                           type_mismatch")
    passed += 1

    expect_path_error("forbidden_prefix", "/participants/0/id")
    passed += 1

    expect_path_error("payload_root_forbidden", "/proposal/payload")
    passed += 1

    expect_path_error("empty_segment", "/proposal/payload//name")
    passed += 1

    expect_path_error("malformed_escape", "/proposal/payload/a~2b")
    passed += 1

    expect_path_error(
        "leading_zero_index",
        "/proposal/payload/services/01/name",
    )
    passed += 1

    legacy_projection = create_context_projection(
        {
            "object_type": "agp.decision-context/legacy-test",
            "participants": [],
        }
    )

    if legacy_projection is not None:
        raise TestFailure(
            "legacy context without proposal/evidence was projected"
        )

    print("PASS  legacy_context_without_projection          preserved")
    passed += 1

    state = EvaluationState.create(
        matched_signers=[],
        participants={},
        weight=0,
        decision_context=source,
    )

    source["proposal"]["payload"]["nested"]["coverage"] = 1

    state_value = resolve_context_path(
        state.decision_context,
        "/proposal/payload/nested/coverage",
    )

    if state_value.value != 9000:
        raise TestFailure("EvaluationState did not detach context")

    print("PASS  evaluation_state_projection                preserved")
    passed += 1

    policy_state = create_policy_evaluation_state(
        verified_signers=[],
        participants={},
        eligible_roles=[],
        decision_context=source,
    )

    policy_value = resolve_context_path(
        policy_state.decision_context,
        "/proposal/payload/environment",
    )

    if policy_value.value != "staging":
        raise TestFailure(
            "policy-local state did not receive context projection"
        )

    print("PASS  policy_local_context_propagation           preserved")
    passed += 1

    if projection["object_type"] != "agp.decision-context/2":
        raise TestFailure("projection did not preserve object_type")

    print("PASS  projection_object_type                     preserved")
    passed += 1

    if passed != 20:
        raise TestFailure(f"expected 19 checks, observed {passed}")

    print(
        "TPE context projection and resolution: "
        f"{passed}/{passed} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
