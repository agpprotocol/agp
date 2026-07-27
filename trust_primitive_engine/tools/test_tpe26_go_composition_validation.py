#!/usr/bin/env python3
# Python/Go structural validation parity for bounded TPE 2.6 compositions.

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
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
    policy: dict[str, Any]
    accepted: bool


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_go_composition_validation",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def issuer(requirement_id: str) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:lab-a"],
    }


def evidence_type(requirement_id: str) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_type_in",
        "evidence_types": ["security:assessment/1"],
    }


def distinct(requirement_id: str) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_distinct_issuers_at_least",
        "minimum": 1,
    }


def policy(requirements: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe26-go-composition-parity",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": requirements,
    }


def nested_not(depth: int) -> dict[str, Any]:
    node: dict[str, Any] = issuer(
        f"requirement:depth-{depth:02d}-leaf"
    )
    for index in range(depth - 1, -1, -1):
        node = {
            "requirement_id": f"requirement:depth-{index:02d}",
            "type": "not",
            "requirement": node,
        }
    return node


def all_of_with_node_count(node_count: int) -> dict[str, Any]:
    children = [
        issuer(f"requirement:node-{index:03d}")
        for index in range(node_count - 1)
    ]
    return {
        "requirement_id": "requirement:node-root",
        "type": "all_of",
        "requirements": children,
    }


def vectors() -> list[Vector]:
    valid_all = {
        "requirement_id": "requirement:all",
        "type": "all_of",
        "requirements": [
            issuer("requirement:all-issuer"),
            evidence_type("requirement:all-type"),
        ],
    }
    valid_any = {
        "requirement_id": "requirement:any",
        "type": "any_of",
        "requirements": [
            distinct("requirement:any-distinct"),
            issuer("requirement:any-issuer"),
        ],
    }
    valid_not = {
        "requirement_id": "requirement:not",
        "type": "not",
        "requirement": issuer("requirement:not-issuer"),
    }
    nested = {
        "requirement_id": "requirement:nested-all",
        "type": "all_of",
        "requirements": [
            {
                "requirement_id": "requirement:nested-any",
                "type": "any_of",
                "requirements": [
                    distinct("requirement:nested-distinct"),
                    issuer("requirement:nested-issuer"),
                ],
            },
            {
                "requirement_id": "requirement:nested-not",
                "type": "not",
                "requirement": evidence_type(
                    "requirement:nested-type"
                ),
            },
        ],
    }

    children_unsorted = deepcopy(valid_all)
    children_unsorted["requirements"].reverse()

    duplicate_sibling = deepcopy(valid_all)
    duplicate_sibling["requirements"][1]["requirement_id"] = (
        duplicate_sibling["requirements"][0]["requirement_id"]
    )

    duplicate_cross_branch = deepcopy(nested)
    duplicate_cross_branch["requirements"][1]["requirement"][
        "requirement_id"
    ] = "requirement:nested-distinct"

    all_one = deepcopy(valid_all)
    all_one["requirements"] = [all_one["requirements"][0]]

    any_one = deepcopy(valid_any)
    any_one["requirements"] = [any_one["requirements"][0]]

    not_missing = deepcopy(valid_not)
    not_missing.pop("requirement")

    not_array = deepcopy(valid_not)
    not_array["requirement"] = [issuer("requirement:bad-array")]

    all_unknown = deepcopy(valid_all)
    all_unknown["unexpected"] = True

    not_unknown = deepcopy(valid_not)
    not_unknown["unexpected"] = True

    hidden_invalid = deepcopy(nested)
    hidden_invalid["requirements"][0]["requirements"][1][
        "issuer_ids"
    ] = []

    unsupported_nested = deepcopy(valid_not)
    unsupported_nested["requirement"] = {
        "requirement_id": "requirement:unsupported",
        "type": "unknown_primitive",
    }

    return [
        Vector("all_of_valid", policy([valid_all]), True),
        Vector("any_of_valid", policy([valid_any]), True),
        Vector("not_valid", policy([valid_not]), True),
        Vector("nested_tree_valid", policy([nested]), True),
        Vector("children_unsorted", policy([children_unsorted]), False),
        Vector("duplicate_sibling_id", policy([duplicate_sibling]), False),
        Vector(
            "duplicate_cross_branch_id",
            policy([duplicate_cross_branch]),
            False,
        ),
        Vector("all_of_requires_two", policy([all_one]), False),
        Vector("any_of_requires_two", policy([any_one]), False),
        Vector("not_missing_child", policy([not_missing]), False),
        Vector("not_array_child", policy([not_array]), False),
        Vector("all_of_unknown_member", policy([all_unknown]), False),
        Vector("not_unknown_member", policy([not_unknown]), False),
        Vector("depth_8_accepted", policy([nested_not(7)]), True),
        Vector("depth_9_rejected", policy([nested_not(8)]), False),
        Vector(
            "node_count_256_accepted",
            policy([all_of_with_node_count(256)]),
            True,
        ),
        Vector(
            "node_count_257_rejected",
            policy([all_of_with_node_count(257)]),
            False,
        ),
        Vector("hidden_invalid_branch", policy([hidden_invalid]), False),
        Vector(
            "unsupported_nested_leaf",
            policy([unsupported_nested]),
            False,
        ),
        Vector(
            "malformed_policy_reference_nested",
            policy([
                {
                    "requirement_id": "requirement:not-reference",
                    "type": "not",
                    "requirement": {
                        "requirement_id": "requirement:reference",
                        "type": "policy_reference",
                        "policy_id": "policy:other",
                        "policy_version": 1,
                    },
                }
            ]),
            False,
        ),
    ]


def python_accepts(evaluator: Any, value: dict[str, Any]) -> bool:
    try:
        evaluator.validate_policy(value)
    except Exception:
        return False
    return True


def main() -> int:
    cases = vectors()
    if len(cases) != 20:
        raise AssertionError(f"expected 20 vectors, got {len(cases)}")

    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-composition-validation-"
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
            input_path = temp / f"{index:02d}-{vector.name}.json"
            input_path.write_text(
                json.dumps(
                    vector.policy,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    sort_keys=True,
                ),
                encoding="utf-8",
            )

            completed = subprocess.run(
                [str(binary), "--validate-policy", str(input_path)],
                cwd=temp,
                text=True,
                capture_output=True,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(
                    f"{vector.name}: Go command failed: "
                    f"{completed.stderr}"
                )

            go_accepted = json.loads(completed.stdout)["accepted"]
            py_accepted = python_accepts(evaluator, vector.policy)

            if py_accepted != vector.accepted:
                raise AssertionError(
                    f"{vector.name}: Python expected={vector.accepted} "
                    f"actual={py_accepted}"
                )
            if go_accepted != vector.accepted:
                raise AssertionError(
                    f"{vector.name}: Go expected={vector.accepted} "
                    f"actual={go_accepted}"
                )
            if py_accepted != go_accepted:
                raise AssertionError(
                    f"{vector.name}: Python/Go acceptance differs"
                )

            print(
                f"PASS  {vector.name:<34} "
                f"accepted={py_accepted} python_go=True"
            )
            passed += 1

        print(
            "TPE 2.6 Python/Go composition validation parity: "
            f"{passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
