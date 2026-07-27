#!/usr/bin/env python3
"""Python/Go parity for bounded policy-reference graph validation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "trust_primitive_engine/go"
EVALUATOR_PATH = (
    ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_go_policy_graph",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def leaf(
    requirement_id: str = "requirement:leaf",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:alpha"],
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
        "requirements": requirements,
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


def make_chain(
    evaluator: Any,
    length: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    current = policy(
        f"policy:chain-{length:02d}",
        [leaf()],
    )
    policies = [current]

    for index in range(length - 1, 0, -1):
        parent = policy(
            f"policy:chain-{index:02d}",
            [
                reference(
                    evaluator,
                    current,
                    "requirement:next",
                )
            ],
        )
        policies.append(parent)
        current = parent

    root = policy(
        "policy:chain-root",
        [
            reference(
                evaluator,
                current,
                "requirement:root-reference",
            )
        ],
    )
    return root, policies


def wide_policy(
    evaluator: Any,
    policy_id: str,
    next_policy: dict[str, Any] | None,
) -> dict[str, Any]:
    children = [
        leaf(f"requirement:leaf-{index:03d}")
        for index in range(254)
    ]
    if next_policy is None:
        children.append(leaf("requirement:leaf-254"))
    else:
        children.append(
            reference(
                evaluator,
                next_policy,
                "requirement:next",
            )
        )
    children.sort(key=lambda item: item["requirement_id"])
    return policy(
        policy_id,
        [
            {
                "requirement_id": "requirement:root",
                "type": "all_of",
                "requirements": children,
            }
        ],
    )


def compact(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def run_receipt(
    binary: Path,
    temp: Path,
    name: str,
    root: dict[str, Any],
    policy_set: list[dict[str, Any]],
    *,
    fixture: bool = False,
) -> dict[str, Any]:
    case_dir = temp / name
    case_dir.mkdir()
    root_path = case_dir / "root-policy.json"
    set_path = case_dir / "policy-set.json"
    root_path.write_text(compact(root), encoding="utf-8")
    set_path.write_text(compact(policy_set), encoding="utf-8")

    mode = (
        "--validate-policy-graph-fixture"
        if fixture
        else "--validate-policy-graph"
    )
    completed = subprocess.run(
        [str(binary), mode, str(root_path), str(set_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise TestFailure(
            f"{name}: command failed: {completed.stderr}"
        )
    return json.loads(completed.stdout)


def expect(
    binary: Path,
    temp: Path,
    name: str,
    root: dict[str, Any],
    policy_set: list[dict[str, Any]],
    accepted: bool,
    error_code: str | None,
    *,
    fixture: bool = False,
) -> None:
    receipt = run_receipt(
        binary,
        temp,
        name,
        root,
        policy_set,
        fixture=fixture,
    )
    expected = {
        "accepted": accepted,
        "error_code": error_code,
    }
    if receipt != expected:
        raise TestFailure(
            f"{name}: receipt differs\n"
            f"expected={compact(expected)}\n"
            f"actual={compact(receipt)}"
        )
    marker = "valid" if accepted else f"error={error_code}"
    print(f"PASS  {name:<40} {marker}")


def main() -> int:
    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-policy-graph-"
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

        leaf_policy = policy("policy:leaf", [leaf()])
        direct_root = policy(
            "policy:direct-root",
            [
                reference(
                    evaluator,
                    leaf_policy,
                    "requirement:leaf-reference",
                )
            ],
        )
        expect(
            binary,
            temp,
            "direct_reference",
            direct_root,
            [leaf_policy],
            True,
            None,
        )
        passed += 1

        middle = policy(
            "policy:middle",
            [
                reference(
                    evaluator,
                    leaf_policy,
                    "requirement:leaf-reference",
                )
            ],
        )
        transitive_root = policy(
            "policy:transitive-root",
            [
                reference(
                    evaluator,
                    middle,
                    "requirement:middle-reference",
                )
            ],
        )
        expect(
            binary,
            temp,
            "transitive_reference",
            transitive_root,
            [middle, leaf_policy],
            True,
            None,
        )
        passed += 1

        shared = policy("policy:shared", [leaf()])
        left = policy(
            "policy:left",
            [reference(evaluator, shared, "requirement:shared")],
        )
        right = policy(
            "policy:right",
            [reference(evaluator, shared, "requirement:shared")],
        )
        shared_root = policy(
            "policy:shared-root",
            [
                {
                    "requirement_id": "requirement:branches",
                    "type": "all_of",
                    "requirements": sorted(
                        [
                            reference(
                                evaluator,
                                left,
                                "requirement:left",
                            ),
                            reference(
                                evaluator,
                                right,
                                "requirement:right",
                            ),
                        ],
                        key=lambda item: item["requirement_id"],
                    ),
                }
            ],
        )
        expect(
            binary,
            temp,
            "shared_policy_reuse",
            shared_root,
            [right, shared, left],
            True,
            None,
        )
        passed += 1

        missing_root = policy(
            "policy:missing-root",
            [
                {
                    "requirement_id": "requirement:missing",
                    "type": "policy_reference",
                    "policy_id": "policy:not-present",
                    "policy_version": 1,
                    "policy_digest": "0" * 64,
                }
            ],
        )
        expect(
            binary,
            temp,
            "missing_reference",
            missing_root,
            [],
            False,
            "POLICY_REFERENCE_NOT_FOUND",
        )
        passed += 1

        digest_root = policy(
            "policy:digest-root",
            [
                {
                    **reference(
                        evaluator,
                        leaf_policy,
                        "requirement:digest",
                    ),
                    "policy_digest": "0" * 64,
                }
            ],
        )
        expect(
            binary,
            temp,
            "digest_mismatch",
            digest_root,
            [leaf_policy],
            False,
            "POLICY_REFERENCE_DIGEST_MISMATCH",
        )
        passed += 1

        self_cycle = policy(
            "policy:self-cycle",
            [
                {
                    "requirement_id": "requirement:self",
                    "type": "policy_reference",
                    "policy_id": "policy:self-cycle",
                    "policy_version": 1,
                    "policy_digest": "a" * 64,
                }
            ],
        )
        self_fixture = [
            {
                "policy": self_cycle,
                "identity_digest": "a" * 64,
            }
        ]
        expect(
            binary,
            temp,
            "self_cycle",
            self_cycle,
            self_fixture,
            False,
            "POLICY_REFERENCE_CYCLE",
            fixture=True,
        )
        passed += 1

        cycle_a = policy(
            "policy:cycle-a",
            [
                {
                    "requirement_id": "requirement:to-b",
                    "type": "policy_reference",
                    "policy_id": "policy:cycle-b",
                    "policy_version": 1,
                    "policy_digest": "b" * 64,
                }
            ],
        )
        cycle_b = policy(
            "policy:cycle-b",
            [
                {
                    "requirement_id": "requirement:to-a",
                    "type": "policy_reference",
                    "policy_id": "policy:cycle-a",
                    "policy_version": 1,
                    "policy_digest": "a" * 64,
                }
            ],
        )
        cycle_root = policy(
            "policy:cycle-root",
            [
                {
                    "requirement_id": "requirement:cycle",
                    "type": "policy_reference",
                    "policy_id": "policy:cycle-a",
                    "policy_version": 1,
                    "policy_digest": "a" * 64,
                }
            ],
        )
        cycle_fixture = [
            {"policy": cycle_a, "identity_digest": "a" * 64},
            {"policy": cycle_b, "identity_digest": "b" * 64},
        ]
        expect(
            binary,
            temp,
            "indirect_cycle",
            cycle_root,
            cycle_fixture,
            False,
            "POLICY_REFERENCE_CYCLE",
            fixture=True,
        )
        passed += 1

        depth_8_root, depth_8_set = make_chain(evaluator, 8)
        expect(
            binary,
            temp,
            "reference_depth_8",
            depth_8_root,
            depth_8_set,
            True,
            None,
        )
        passed += 1

        depth_9_root, depth_9_set = make_chain(evaluator, 9)
        expect(
            binary,
            temp,
            "reference_depth_9",
            depth_9_root,
            depth_9_set,
            False,
            "POLICY_REFERENCE_DEPTH_EXCEEDED",
        )
        passed += 1

        count_policies = [
            policy(f"policy:count-{index:02d}", [leaf()])
            for index in range(33)
        ]
        count_root = policy(
            "policy:count-root",
            [
                {
                    "requirement_id": "requirement:all",
                    "type": "all_of",
                    "requirements": [
                        reference(
                            evaluator,
                            item,
                            f"requirement:target-{index:02d}",
                        )
                        for index, item in enumerate(count_policies)
                    ],
                }
            ],
        )
        expect(
            binary,
            temp,
            "referenced_policy_count_33",
            count_root,
            count_policies,
            False,
            "POLICY_REFERENCE_COUNT_EXCEEDED",
        )
        passed += 1

        terminal = wide_policy(
            evaluator,
            "policy:wide-07",
            None,
        )
        wide_policies = [terminal]
        current = terminal
        for index in range(6, 0, -1):
            current = wide_policy(
                evaluator,
                f"policy:wide-{index:02d}",
                current,
            )
            wide_policies.append(current)
        exact_root = wide_policy(
            evaluator,
            "policy:wide-root",
            current,
        )
        expect(
            binary,
            temp,
            "expanded_nodes_2048",
            exact_root,
            wide_policies,
            True,
            None,
        )
        passed += 1

        overflow_terminal = policy(
            "policy:overflow-terminal",
            [leaf()],
        )
        chain = [overflow_terminal]
        current = overflow_terminal
        for index in range(8, 0, -1):
            current = wide_policy(
                evaluator,
                f"policy:overflow-{index:02d}",
                current,
            )
            chain.append(current)
        overflow_root = policy(
            "policy:overflow-root",
            [
                reference(
                    evaluator,
                    current,
                    "requirement:overflow",
                )
            ],
        )
        expect(
            binary,
            temp,
            "expanded_nodes_over_limit",
            overflow_root,
            chain,
            False,
            "POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
        )
        passed += 1

        forward = run_receipt(
            binary,
            temp,
            "policy_set_order_forward",
            shared_root,
            [left, right, shared],
        )
        reverse = run_receipt(
            binary,
            temp,
            "policy_set_order_reverse",
            shared_root,
            [shared, right, left],
        )
        if forward != reverse or forward != {
            "accepted": True,
            "error_code": None,
        }:
            raise TestFailure("policy_set_order_independent: differs")
        print(
            "PASS  policy_set_order_independent             identical"
        )
        passed += 1

        expected = 13
        if passed != expected:
            raise TestFailure(
                f"internal count mismatch: {passed} != {expected}"
            )

        print(
            "TPE 2.6 Python/Go policy-reference graph "
            f"validation parity: {passed}/{expected} passed"
        )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
