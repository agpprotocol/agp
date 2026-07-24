#!/usr/bin/env python3
"""Focused reachable policy-reference graph checks for TPE 2.3."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine import build_policy_set_index


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_reference_graph",
        EVALUATOR_PATH,
    )

    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def primitive(
    requirement_id: str = "requirement:leaf",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "required_signer",
        "signer_id": "authority:alpha",
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


def build_index(
    evaluator: Any,
    policies: list[dict[str, Any]],
):
    return build_policy_set_index(
        policies,
        validate_policy=evaluator.validate_policy,
        compute_digest=evaluator.policy_digest,
    )


def expect_error(
    evaluator: Any,
    name: str,
    callback: Any,
    expected_code: str,
) -> None:
    try:
        callback()
    except evaluator.EvaluationFailure as exc:
        if exc.code != expected_code:
            raise TestFailure(
                f"{name}: code={exc.code}, "
                f"expected={expected_code}"
            ) from exc

        print(
            f"PASS  {name:<38} "
            f"error={expected_code}"
        )
        return
    except Exception as exc:
        raise TestFailure(
            f"{name}: wrong exception "
            f"{type(exc).__name__}: {exc}"
        ) from exc

    raise TestFailure(f"{name}: unexpectedly accepted")


def make_chain(
    evaluator: Any,
    length: int,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    current = policy(
        f"policy:chain-{length:02d}",
        [primitive()],
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
        primitive(f"requirement:leaf-{index:03d}")
        for index in range(254)
    ]

    if next_policy is None:
        children.append(
            primitive("requirement:leaf-254")
        )
    else:
        children.append(
            reference(
                evaluator,
                next_policy,
                "requirement:next",
            )
        )

    children.sort(
        key=lambda requirement: requirement["requirement_id"]
    )

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


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    leaf_policy = policy(
        "policy:leaf",
        [primitive()],
    )

    root = policy(
        "policy:root",
        [
            reference(
                evaluator,
                leaf_policy,
                "requirement:leaf-reference",
            )
        ],
    )

    index = build_index(evaluator, [leaf_policy])

    graph = evaluator.validate_policy_reference_graph(
        root,
        index,
    )

    if graph["referenced_policy_count"] != 1:
        raise TestFailure("direct_reference: wrong count")

    if graph["expanded_requirement_count"] != 2:
        raise TestFailure("direct_reference: wrong node count")

    print("PASS  direct_reference                       valid")
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

    transitive_index = build_index(
        evaluator,
        [middle, leaf_policy],
    )

    transitive_graph = (
        evaluator.validate_policy_reference_graph(
            transitive_root,
            transitive_index,
        )
    )

    if transitive_graph["referenced_policy_count"] != 2:
        raise TestFailure("transitive_reference: wrong count")

    print("PASS  transitive_reference                   valid")
    passed += 1

    shared = policy(
        "policy:shared",
        [primitive()],
    )

    left = policy(
        "policy:left",
        [
            reference(
                evaluator,
                shared,
                "requirement:shared-reference",
            )
        ],
    )

    right = policy(
        "policy:right",
        [
            reference(
                evaluator,
                shared,
                "requirement:shared-reference",
            )
        ],
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

    shared_graph = evaluator.validate_policy_reference_graph(
        shared_root,
        build_index(
            evaluator,
            [right, shared, left],
        ),
    )

    if shared_graph["referenced_policy_count"] != 3:
        raise TestFailure("shared_policy_reuse: wrong count")

    if shared_graph["expanded_requirement_count"] != 6:
        raise TestFailure(
            "shared_policy_reuse: shared policy counted twice"
        )

    print("PASS  shared_policy_reuse                    valid")
    passed += 1

    # Construct a self-reference whose declared identity matches
    # the final policy by using a controlled PolicySetIndex entry.
    self_cycle = policy(
        "policy:self-cycle",
        [
            {
                "requirement_id": "requirement:self",
                "type": "policy_reference",
                "policy_id": "policy:self-cycle",
                "policy_version": 1,
                "policy_digest": "0" * 64,
            }
        ],
    )

    self_normalized = evaluator.validate_policy(self_cycle)
    self_digest = evaluator.policy_digest(self_normalized)
    self_cycle["requirements"][0]["policy_digest"] = self_digest

    # Recompute once more because the digest field is part of the root
    # canonical representation. A true direct fixed-point digest is not
    # representable, so test root re-entry through an equivalent indexed
    # identity using the root identity declared by the reference.
    from engine import (
        PolicyReferenceIdentity,
        PolicySetEntry,
        PolicySetIndex,
    )
    from types import MappingProxyType

    self_identity = PolicyReferenceIdentity(
        policy_id="policy:self-cycle",
        policy_version=1,
        policy_digest=self_cycle["requirements"][0][
            "policy_digest"
        ],
    )

    self_entry = PolicySetEntry(
        identity=self_identity,
        policy=MappingProxyType(
            evaluator.validate_policy(self_cycle)
        ),
    )

    self_index = PolicySetIndex(
        entries=(self_entry,),
        _by_policy_key=MappingProxyType({
            ("policy:self-cycle", 1): self_entry,
        }),
    )

    expect_error(
        evaluator,
        "self_cycle",
        lambda: evaluator.validate_policy_reference_graph(
            self_cycle,
            self_index,
        ),
        "POLICY_REFERENCE_CYCLE",
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

    cycle_a_identity = PolicyReferenceIdentity(
        "policy:cycle-a",
        1,
        "a" * 64,
    )
    cycle_b_identity = PolicyReferenceIdentity(
        "policy:cycle-b",
        1,
        "b" * 64,
    )

    cycle_a_entry = PolicySetEntry(
        identity=cycle_a_identity,
        policy=MappingProxyType(
            evaluator.validate_policy(cycle_a)
        ),
    )
    cycle_b_entry = PolicySetEntry(
        identity=cycle_b_identity,
        policy=MappingProxyType(
            evaluator.validate_policy(cycle_b)
        ),
    )

    cycle_index = PolicySetIndex(
        entries=tuple(sorted(
            (cycle_a_entry, cycle_b_entry),
            key=lambda entry: entry.identity,
        )),
        _by_policy_key=MappingProxyType({
            ("policy:cycle-a", 1): cycle_a_entry,
            ("policy:cycle-b", 1): cycle_b_entry,
        }),
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

    expect_error(
        evaluator,
        "indirect_cycle",
        lambda: evaluator.validate_policy_reference_graph(
            cycle_root,
            cycle_index,
        ),
        "POLICY_REFERENCE_CYCLE",
    )
    passed += 1

    depth_8_root, depth_8_policies = make_chain(
        evaluator,
        8,
    )

    depth_8_graph = evaluator.validate_policy_reference_graph(
        depth_8_root,
        build_index(evaluator, depth_8_policies),
    )

    if depth_8_graph["referenced_policy_count"] != 8:
        raise TestFailure("reference_depth_8: wrong count")

    print("PASS  reference_depth_8                     accepted")
    passed += 1

    depth_9_root, depth_9_policies = make_chain(
        evaluator,
        9,
    )

    expect_error(
        evaluator,
        "reference_depth_9",
        lambda: evaluator.validate_policy_reference_graph(
            depth_9_root,
            build_index(evaluator, depth_9_policies),
        ),
        "POLICY_REFERENCE_DEPTH_EXCEEDED",
    )
    passed += 1

    count_policies = [
        policy(
            f"policy:count-{index:02d}",
            [primitive()],
        )
        for index in range(33)
    ]

    count_references = [
        reference(
            evaluator,
            target,
            f"requirement:target-{index:02d}",
        )
        for index, target in enumerate(count_policies)
    ]

    count_root = policy(
        "policy:count-root",
        [
            {
                "requirement_id": "requirement:all",
                "type": "all_of",
                "requirements": count_references,
            }
        ],
    )

    expect_error(
        evaluator,
        "referenced_policy_count_33",
        lambda: evaluator.validate_policy_reference_graph(
            count_root,
            build_index(evaluator, count_policies),
        ),
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

    wide_root = wide_policy(
        evaluator,
        "policy:wide-root",
        current,
    )

    exact_graph = evaluator.validate_policy_reference_graph(
        wide_root,
        build_index(evaluator, wide_policies),
    )

    if exact_graph["expanded_requirement_count"] != 2048:
        raise TestFailure(
            "expanded_nodes_2048: wrong node count "
            f"{exact_graph['expanded_requirement_count']}"
        )

    print("PASS  expanded_nodes_2048                    accepted")
    passed += 1

    overflow_terminal = policy(
        "policy:overflow-terminal",
        [primitive()],
    )

    overflow_parent = wide_policy(
        evaluator,
        "policy:overflow-parent",
        overflow_terminal,
    )

    overflow_policies = (
        wide_policies
        + [overflow_parent, overflow_terminal]
    )

    overflow_root = wide_policy(
        evaluator,
        "policy:overflow-root",
        overflow_parent,
    )

    # Rebuild a deterministic 2049-node chain:
    # eight 256-node policies plus one 1-node policy.
    chain: list[dict[str, Any]] = [overflow_terminal]
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

    expect_error(
        evaluator,
        "expanded_nodes_2049",
        lambda: evaluator.validate_policy_reference_graph(
            overflow_root,
            build_index(evaluator, chain),
        ),
        "POLICY_REFERENCE_NODE_LIMIT_EXCEEDED",
    )
    passed += 1

    forward_graph = evaluator.validate_policy_reference_graph(
        shared_root,
        build_index(evaluator, [left, right, shared]),
    )

    reverse_graph = evaluator.validate_policy_reference_graph(
        shared_root,
        build_index(evaluator, [shared, right, left]),
    )

    if (
        forward_graph["resolution_order"]
        != reverse_graph["resolution_order"]
    ):
        raise TestFailure(
            "policy_set_order_independent: order differs"
        )

    if (
        forward_graph["reachable_policies"]
        != reverse_graph["reachable_policies"]
    ):
        raise TestFailure(
            "policy_set_order_independent: graph differs"
        )

    print("PASS  policy_set_order_independent            identical")
    passed += 1

    expected = 11

    if passed != expected:
        raise TestFailure(
            f"internal check count mismatch: "
            f"{passed} != {expected}"
        )

    print(
        f"TPE 2.3 policy-reference graph: "
        f"{passed}/{expected} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
