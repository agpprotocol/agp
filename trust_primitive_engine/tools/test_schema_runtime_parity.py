#!/usr/bin/env python3
"""Check AGP Trust Policy 2.0 JSON Schema/runtime validation parity."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Callable

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/agp.trust-policy-2.schema.json"
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
        "agp_evaluate_trust_policy_v2",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def base_policy() -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:parity-test",
        "version": 2,
        "eligible_roles": [
            "approver",
            "reviewer",
        ],
        "requirements": [
            {
                "requirement_id": "requirement:legal",
                "type": "required_signer",
                "signer_id": "authority:legal",
            }
        ],
    }


def schema_accepts(
    validator: Draft202012Validator,
    value: Any,
) -> bool:
    return not any(validator.iter_errors(value))


def runtime_accepts(
    evaluator: Any,
    value: Any,
) -> tuple[bool, str | None]:
    try:
        evaluator.validate_policy(value)
    except Exception as exc:
        return False, getattr(exc, "code", None)
    return True, None


def expect_shared(
    *,
    name: str,
    validator: Draft202012Validator,
    evaluator: Any,
    value: Any,
    expected: bool,
) -> None:
    schema_ok = schema_accepts(validator, value)
    runtime_ok, runtime_code = runtime_accepts(evaluator, value)

    if schema_ok != expected or runtime_ok != expected:
        raise TestFailure(
            f"{name}: expected schema/runtime={expected}; "
            f"schema={schema_ok} runtime={runtime_ok} "
            f"runtime_code={runtime_code!r}"
        )

    detail = "accepted-by-both" if expected else "rejected-by-both"
    print(f"PASS  {name:<48} {detail}")


def expect_runtime_stricter(
    *,
    name: str,
    validator: Draft202012Validator,
    evaluator: Any,
    value: Any,
) -> None:
    schema_ok = schema_accepts(validator, value)
    runtime_ok, runtime_code = runtime_accepts(evaluator, value)

    if not schema_ok or runtime_ok:
        raise TestFailure(
            f"{name}: expected schema accept/runtime reject; "
            f"schema={schema_ok} runtime={runtime_ok} "
            f"runtime_code={runtime_code!r}"
        )

    if runtime_code != "INVALID_TRUST_POLICY":
        raise TestFailure(
            f"{name}: expected INVALID_TRUST_POLICY, "
            f"got {runtime_code!r}"
        )

    print(
        f"PASS  {name:<48} "
        "schema=accept runtime=canonical-reject"
    )


def mutate(
    fn: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    value = deepcopy(base_policy())
    fn(value)
    return value


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    evaluator = load_evaluator()

    checks = 0

    expect_shared(
        name="valid_policy_accepted",
        validator=validator,
        evaluator=evaluator,
        value=base_policy(),
        expected=True,
    )
    checks += 1

    expect_shared(
        name="root_missing_policy_id_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(lambda p: p.pop("policy_id")),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="root_unknown_member_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(lambda p: p.update({"unexpected": True})),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="requirements_wrong_type_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(lambda p: p.update({"requirements": {}})),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="requirement_missing_id_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(
            lambda p: p["requirements"][0].pop("requirement_id")
        ),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="requirement_missing_specific_field_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(lambda p: p["requirements"][0].pop("signer_id")),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="requirement_unknown_member_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(
            lambda p: p["requirements"][0].update({"unexpected": 1})
        ),
        expected=False,
    )
    checks += 1

    expect_shared(
        name="version_boolean_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(lambda p: p.update({"version": True})),
        expected=False,
    )
    checks += 1

    def cardinality_bad_signer_ids(
        policy: dict[str, Any],
    ) -> None:
        policy["requirements"] = [
            {
                "requirement_id": "requirement:min-two",
                "type": "at_least_n_signers",
                "signer_ids": "authority:legal",
                "minimum_matches": 1,
            }
        ]

    expect_shared(
        name="signer_ids_wrong_type_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(cardinality_bad_signer_ids),
        expected=False,
    )
    checks += 1

    def cardinality_boolean_limit(
        policy: dict[str, Any],
    ) -> None:
        policy["requirements"] = [
            {
                "requirement_id": "requirement:min-two",
                "type": "at_least_n_signers",
                "signer_ids": [
                    "authority:legal",
                    "authority:security",
                ],
                "minimum_matches": True,
            }
        ]

    expect_shared(
        name="numeric_boolean_rejected",
        validator=validator,
        evaluator=evaluator,
        value=mutate(cardinality_boolean_limit),
        expected=False,
    )
    checks += 1

    def unsorted_roles(policy: dict[str, Any]) -> None:
        policy["eligible_roles"] = [
            "reviewer",
            "approver",
        ]

    expect_runtime_stricter(
        name="eligible_roles_canonical_order_runtime_only",
        validator=validator,
        evaluator=evaluator,
        value=mutate(unsorted_roles),
    )
    checks += 1

    def unsorted_signer_ids(policy: dict[str, Any]) -> None:
        policy["requirements"] = [
            {
                "requirement_id": "requirement:min-two",
                "type": "at_least_n_signers",
                "signer_ids": [
                    "authority:security",
                    "authority:legal",
                ],
                "minimum_matches": 1,
            }
        ]

    expect_runtime_stricter(
        name="signer_ids_canonical_order_runtime_only",
        validator=validator,
        evaluator=evaluator,
        value=mutate(unsorted_signer_ids),
    )
    checks += 1

    print(
        "AGP Trust Policy 2.0 schema/runtime parity: "
        f"{checks}/{checks} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
