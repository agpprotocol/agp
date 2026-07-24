#!/usr/bin/env python3
"""Focused deterministic checks for recursive policy-tree validation."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
EVALUATOR_PATH = (
    ROOT
    / "trust_primitive_engine"
    / "python"
    / "evaluate_trust_policy_v2.py"
)


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_tree",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def leaf(requirement_id: str) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "required_signer",
        "signer_id": (
            "authority:" + requirement_id.split(":")[-1]
        ),
    }


def policy(requirement: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:composition-validation",
        "version": 2,
        "eligible_roles": ["approver", "reviewer"],
        "requirements": [requirement],
    }


def expect_accept(
    evaluator: Any,
    name: str,
    value: dict[str, Any],
) -> dict[str, Any]:
    try:
        result = evaluator.validate_policy(value)
    except Exception as exc:
        raise TestFailure(
            f"{name}: unexpectedly rejected: "
            f"{getattr(exc, 'code', None)!r} {exc}"
        ) from exc

    print(f"PASS  {name:<44} accepted")
    return result


def expect_reject(
    evaluator: Any,
    name: str,
    value: dict[str, Any],
    code: str,
) -> None:
    try:
        evaluator.validate_policy(value)
    except Exception as exc:
        observed = getattr(exc, "code", None)
        if observed != code:
            raise TestFailure(
                f"{name}: expected {code!r}, got "
                f"{observed!r}: {exc}"
            ) from exc
    else:
        raise TestFailure(f"{name}: unexpectedly accepted")

    print(f"PASS  {name:<44} error={code}")


def not_chain(depth: int) -> dict[str, Any]:
    node = leaf("requirement:z-leaf")
    for level in range(depth - 1, 0, -1):
        node = {
            "requirement_id": f"requirement:not-{level:02d}",
            "type": "not",
            "requirement": node,
        }
    return node


def wide_all_of(leaf_count: int) -> dict[str, Any]:
    return {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            leaf(f"requirement:child-{index:03d}")
            for index in range(leaf_count)
        ],
    }


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    valid_all = {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            leaf("requirement:a"),
            leaf("requirement:b"),
        ],
    }
    expect_accept(evaluator, "all_of_valid", policy(valid_all))
    passed += 1

    valid_any = deepcopy(valid_all)
    valid_any["type"] = "any_of"
    expect_accept(evaluator, "any_of_valid", policy(valid_any))
    passed += 1

    valid_not = {
        "requirement_id": "requirement:not-root",
        "type": "not",
        "requirement": leaf("requirement:a"),
    }
    expect_accept(evaluator, "not_valid", policy(valid_not))
    passed += 1

    nested = {
        "requirement_id": "requirement:root",
        "type": "all_of",
        "requirements": [
            {
                "requirement_id": "requirement:a-branch",
                "type": "any_of",
                "requirements": [
                    leaf("requirement:a-one"),
                    leaf("requirement:a-two"),
                ],
            },
            {
                "requirement_id": "requirement:b-branch",
                "type": "not",
                "requirement": leaf("requirement:b-one"),
            },
        ],
    }
    normalized = expect_accept(
        evaluator,
        "nested_tree_valid",
        policy(nested),
    )
    if normalized["requirements"][0] != nested:
        raise TestFailure("nested_tree_valid: normalization changed tree")
    passed += 1

    unsorted = deepcopy(valid_all)
    unsorted["requirements"].reverse()
    expect_reject(
        evaluator,
        "children_unsorted",
        policy(unsorted),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    duplicate_sibling = deepcopy(valid_all)
    duplicate_sibling["requirements"][1]["requirement_id"] = "requirement:a"
    expect_reject(
        evaluator,
        "duplicate_sibling_id",
        policy(duplicate_sibling),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    duplicate_cross_branch = deepcopy(nested)
    duplicate_cross_branch["requirements"][1]["requirement"][
        "requirement_id"
    ] = "requirement:a-one"
    expect_reject(
        evaluator,
        "duplicate_cross_branch_id",
        policy(duplicate_cross_branch),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    all_too_short = deepcopy(valid_all)
    all_too_short["requirements"] = [leaf("requirement:a")]
    expect_reject(
        evaluator,
        "all_of_requires_two",
        policy(all_too_short),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    any_too_short = deepcopy(valid_any)
    any_too_short["requirements"] = [leaf("requirement:a")]
    expect_reject(
        evaluator,
        "any_of_requires_two",
        policy(any_too_short),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    missing_not_child = {
        "requirement_id": "requirement:not-root",
        "type": "not",
    }
    expect_reject(
        evaluator,
        "not_missing_child",
        policy(missing_not_child),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    array_not_child = deepcopy(valid_not)
    array_not_child["requirement"] = [leaf("requirement:a")]
    expect_reject(
        evaluator,
        "not_array_child",
        policy(array_not_child),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    unknown_all_member = deepcopy(valid_all)
    unknown_all_member["unexpected"] = True
    expect_reject(
        evaluator,
        "all_of_unknown_member",
        policy(unknown_all_member),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    unknown_not_member = deepcopy(valid_not)
    unknown_not_member["unexpected"] = True
    expect_reject(
        evaluator,
        "not_unknown_member",
        policy(unknown_not_member),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    expect_accept(
        evaluator,
        "depth_8_accepted",
        policy(not_chain(8)),
    )
    passed += 1

    expect_reject(
        evaluator,
        "depth_9_rejected",
        policy(not_chain(9)),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    expect_accept(
        evaluator,
        "node_count_256_accepted",
        policy(wide_all_of(255)),
    )
    passed += 1

    expect_reject(
        evaluator,
        "node_count_257_rejected",
        policy(wide_all_of(256)),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    hidden_invalid = deepcopy(valid_any)
    hidden_invalid["requirements"][1] = {
        "requirement_id": "requirement:b",
        "type": "required_signer",
    }
    expect_reject(
        evaluator,
        "hidden_invalid_branch_rejected",
        policy(hidden_invalid),
        "INVALID_TRUST_POLICY",
    )
    passed += 1

    unsupported_nested = deepcopy(valid_any)
    unsupported_nested["requirements"][1] = {
        "requirement_id": "requirement:b",
        "type": "future_primitive",
    }
    expect_reject(
        evaluator,
        "unsupported_nested_leaf",
        policy(unsupported_nested),
        "UNSUPPORTED_TRUST_PRIMITIVE",
    )
    passed += 1

    first = evaluator.validate_policy(policy(nested))
    second = evaluator.validate_policy(policy(nested))
    if first != second:
        raise TestFailure("deterministic_validation: results differ")
    print(
        "PASS  deterministic_validation"
        "                     outputs=identical"
    )
    passed += 1

    expected = 20
    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: {passed} != {expected}"
        )

    print(
        "AGP TPE 2.2 policy-tree validation: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
