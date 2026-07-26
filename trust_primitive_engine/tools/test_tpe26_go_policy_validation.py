#!/usr/bin/env python3
# Python/Go policy-validation parity for the bounded TPE 2.6 leaf profile.

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[2]
GO_DIR = ROOT / "trust_primitive_engine/go"
EVALUATOR_PATH = (
    ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)


@dataclass(frozen=True)
class Vector:
    name: str
    policy: Any
    accepted: bool


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_tpe26_go_policy_validation",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def issuer_requirement(
    requirement_id: str = "requirement:issuer",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_issuer_in",
        "issuer_ids": ["authority:lab-a"],
    }


def type_requirement(
    requirement_id: str = "requirement:type",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_type_in",
        "evidence_types": ["security:assessment/1"],
    }


def distinct_requirement(
    requirement_id: str = "requirement:distinct",
) -> dict[str, Any]:
    return {
        "requirement_id": requirement_id,
        "type": "evidence_distinct_issuers_at_least",
        "minimum": 1,
    }


def base_policy() -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:tpe26-go-policy-parity",
        "version": 1,
        "eligible_roles": ["approver", "reviewer"],
        "requirements": [issuer_requirement()],
    }


def mutate(fn: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    value = deepcopy(base_policy())
    fn(value)
    return value


def vectors() -> list[Vector]:
    mixed = base_policy()
    mixed["requirements"] = [
        distinct_requirement("requirement:01-distinct"),
        issuer_requirement("requirement:02-issuer"),
        type_requirement("requirement:03-type"),
    ]

    return [
        Vector("valid_single_tpe26_leaf", base_policy(), True),
        Vector("valid_mixed_tpe26_leaves", mixed, True),
        Vector("root_not_object", [], False),
        Vector("root_missing_object_type", mutate(lambda p: p.pop("object_type")), False),
        Vector("root_missing_policy_id", mutate(lambda p: p.pop("policy_id")), False),
        Vector("root_unknown_member", mutate(lambda p: p.update({"unexpected": True})), False),
        Vector("wrong_object_type", mutate(lambda p: p.update({"object_type": "agp.trust-policy/1"})), False),
        Vector("invalid_policy_id", mutate(lambda p: p.update({"policy_id": "INVALID ID"})), False),
        Vector("version_boolean", mutate(lambda p: p.update({"version": True})), False),
        Vector("version_zero", mutate(lambda p: p.update({"version": 0})), False),
        Vector("version_decimal", mutate(lambda p: p.update({"version": 1.5})), False),
        Vector("eligible_roles_wrong_type", mutate(lambda p: p.update({"eligible_roles": "approver"})), False),
        Vector("eligible_roles_empty", mutate(lambda p: p.update({"eligible_roles": []})), False),
        Vector("eligible_roles_unsupported", mutate(lambda p: p.update({"eligible_roles": ["administrator"]})), False),
        Vector("eligible_roles_unordered", mutate(lambda p: p.update({"eligible_roles": ["reviewer", "approver"]})), False),
        Vector("eligible_roles_duplicate", mutate(lambda p: p.update({"eligible_roles": ["approver", "approver"]})), False),
        Vector("requirements_wrong_type", mutate(lambda p: p.update({"requirements": {}})), False),
        Vector("requirements_empty", mutate(lambda p: p.update({"requirements": []})), False),
        Vector("requirement_not_object", mutate(lambda p: p.update({"requirements": ["invalid"]})), False),
        Vector(
            "unsupported_primitive",
            mutate(
                lambda p: p.update(
                    {
                        "requirements": [
                            {
                                "requirement_id": "requirement:unsupported",
                                "type": "unknown_primitive",
                            }
                        ]
                    }
                )
            ),
            False,
        ),
        Vector(
            "requirements_unordered",
            mutate(
                lambda p: p.update(
                    {
                        "requirements": [
                            type_requirement("requirement:02-type"),
                            issuer_requirement("requirement:01-issuer"),
                        ]
                    }
                )
            ),
            False,
        ),
        Vector(
            "duplicate_requirement_id",
            mutate(
                lambda p: p.update(
                    {
                        "requirements": [
                            issuer_requirement("requirement:duplicate"),
                            type_requirement("requirement:duplicate"),
                        ]
                    }
                )
            ),
            False,
        ),
    ]


def python_accepts(evaluator: Any, policy: Any) -> bool:
    try:
        evaluator.validate_policy(policy)
    except Exception:
        return False
    return True


def main() -> int:
    cases = vectors()
    if len(cases) != 22:
        raise AssertionError(f"expected 22 vectors, got {len(cases)}")

    evaluator = load_evaluator()

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe26-go-policy-validation-"
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
            "TPE 2.6 Python/Go leaf-policy validation parity: "
            f"{passed}/{len(cases)} passed"
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
