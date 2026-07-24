#!/usr/bin/env python3
"""Declarative schema/runtime validation matrix for all TPE 2.0 primitives."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
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
MAX_SAFE_INTEGER = 9_007_199_254_740_991


class TestFailure(Exception):
    pass


@dataclass(frozen=True)
class PrimitiveCase:
    primitive_type: str
    requirement: dict[str, Any]
    specific_field: str


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_matrix",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy_for(requirement: dict[str, Any]) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:primitive-matrix",
        "version": 2,
        "eligible_roles": [
            "approver",
            "reviewer",
        ],
        "requirements": [deepcopy(requirement)],
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


def check(
    *,
    name: str,
    validator: Draft202012Validator,
    evaluator: Any,
    policy: dict[str, Any],
    schema_expected: bool,
    runtime_expected: bool,
    runtime_code: str | None = None,
) -> None:
    schema_ok = schema_accepts(validator, policy)
    runtime_ok, observed_code = runtime_accepts(evaluator, policy)

    if schema_ok != schema_expected or runtime_ok != runtime_expected:
        raise TestFailure(
            f"{name}: expected schema={schema_expected} "
            f"runtime={runtime_expected}; got schema={schema_ok} "
            f"runtime={runtime_ok} code={observed_code!r}"
        )

    if runtime_code is not None and observed_code != runtime_code:
        raise TestFailure(
            f"{name}: expected runtime code {runtime_code!r}, "
            f"got {observed_code!r}"
        )

    relation = (
        "accepted-by-both"
        if schema_expected and runtime_expected
        else "rejected-by-both"
        if not schema_expected and not runtime_expected
        else "schema=accept runtime=canonical-or-semantic-reject"
    )
    print(f"PASS  {name:<64} {relation}")


def mutated(
    requirement: dict[str, Any],
    fn: Callable[[dict[str, Any]], None],
) -> dict[str, Any]:
    value = deepcopy(requirement)
    fn(value)
    return policy_for(value)


CASES = [
    PrimitiveCase(
        "required_signer",
        {
            "requirement_id": "requirement:required",
            "type": "required_signer",
            "signer_id": "authority:legal",
        },
        "signer_id",
    ),
    PrimitiveCase(
        "signer_threshold",
        {
            "requirement_id": "requirement:signer-threshold",
            "type": "signer_threshold",
            "signer_ids": [
                "authority:legal",
                "authority:security",
            ],
            "minimum_signatures": 1,
        },
        "minimum_signatures",
    ),
    PrimitiveCase(
        "global_signature_threshold",
        {
            "requirement_id": "requirement:global-signature",
            "type": "global_signature_threshold",
            "minimum_signatures": 1,
        },
        "minimum_signatures",
    ),
    PrimitiveCase(
        "global_weight_threshold",
        {
            "requirement_id": "requirement:global-weight",
            "type": "global_weight_threshold",
            "minimum_weight": 1,
        },
        "minimum_weight",
    ),
    PrimitiveCase(
        "role_threshold",
        {
            "requirement_id": "requirement:role-threshold",
            "type": "role_threshold",
            "role": "approver",
            "minimum_signatures": 1,
        },
        "minimum_signatures",
    ),
    PrimitiveCase(
        "role_weight_threshold",
        {
            "requirement_id": "requirement:role-weight",
            "type": "role_weight_threshold",
            "role": "approver",
            "minimum_weight": 1,
        },
        "minimum_weight",
    ),
    PrimitiveCase(
        "prohibited_signer",
        {
            "requirement_id": "requirement:prohibited",
            "type": "prohibited_signer",
            "signer_id": "authority:observer",
        },
        "signer_id",
    ),
    PrimitiveCase(
        "separation_of_duties",
        {
            "requirement_id": "requirement:separation",
            "type": "separation_of_duties",
            "roles": [
                "approver",
                "reviewer",
            ],
        },
        "roles",
    ),
    PrimitiveCase(
        "mutual_exclusion",
        {
            "requirement_id": "requirement:mutual",
            "type": "mutual_exclusion",
            "signer_ids": [
                "authority:legal",
                "authority:security",
            ],
        },
        "signer_ids",
    ),
    PrimitiveCase(
        "any_of_signers",
        {
            "requirement_id": "requirement:any",
            "type": "any_of_signers",
            "signer_ids": [
                "authority:legal",
                "authority:security",
            ],
        },
        "signer_ids",
    ),
    PrimitiveCase(
        "all_of_signers",
        {
            "requirement_id": "requirement:all",
            "type": "all_of_signers",
            "signer_ids": [
                "authority:legal",
                "authority:security",
            ],
        },
        "signer_ids",
    ),
    PrimitiveCase(
        "exactly_one_of_signers",
        {
            "requirement_id": "requirement:exactly-one",
            "type": "exactly_one_of_signers",
            "signer_ids": [
                "authority:legal",
                "authority:security",
            ],
        },
        "signer_ids",
    ),
    PrimitiveCase(
        "at_most_n_signers",
        {
            "requirement_id": "requirement:at-most",
            "type": "at_most_n_signers",
            "signer_ids": [
                "authority:finance",
                "authority:legal",
                "authority:security",
            ],
            "maximum_matches": 1,
        },
        "maximum_matches",
    ),
    PrimitiveCase(
        "at_least_n_signers",
        {
            "requirement_id": "requirement:at-least",
            "type": "at_least_n_signers",
            "signer_ids": [
                "authority:finance",
                "authority:legal",
                "authority:security",
            ],
            "minimum_matches": 2,
        },
        "minimum_matches",
    ),
    PrimitiveCase(
        "exactly_n_signers",
        {
            "requirement_id": "requirement:exactly",
            "type": "exactly_n_signers",
            "signer_ids": [
                "authority:finance",
                "authority:legal",
                "authority:security",
            ],
            "exact_matches": 2,
        },
        "exact_matches",
    ),
]


def shared_reject(
    *,
    name: str,
    requirement: dict[str, Any],
    mutate_fn: Callable[[dict[str, Any]], None],
    validator: Draft202012Validator,
    evaluator: Any,
) -> None:
    check(
        name=name,
        validator=validator,
        evaluator=evaluator,
        policy=mutated(requirement, mutate_fn),
        schema_expected=False,
        runtime_expected=False,
        runtime_code="INVALID_TRUST_POLICY",
    )


def runtime_stricter(
    *,
    name: str,
    requirement: dict[str, Any],
    mutate_fn: Callable[[dict[str, Any]], None],
    validator: Draft202012Validator,
    evaluator: Any,
) -> None:
    check(
        name=name,
        validator=validator,
        evaluator=evaluator,
        policy=mutated(requirement, mutate_fn),
        schema_expected=True,
        runtime_expected=False,
        runtime_code="INVALID_TRUST_POLICY",
    )


def main() -> int:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    evaluator = load_evaluator()
    checks = 0

    # Four common checks for every primitive: 15 * 4 = 60.
    for case in CASES:
        check(
            name=f"{case.primitive_type}.valid",
            validator=validator,
            evaluator=evaluator,
            policy=policy_for(case.requirement),
            schema_expected=True,
            runtime_expected=True,
        )
        checks += 1

        shared_reject(
            name=f"{case.primitive_type}.missing_specific_field",
            requirement=case.requirement,
            mutate_fn=lambda r, field=case.specific_field: r.pop(field),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

        shared_reject(
            name=f"{case.primitive_type}.unknown_member",
            requirement=case.requirement,
            mutate_fn=lambda r: r.update({"unexpected": True}),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

        shared_reject(
            name=f"{case.primitive_type}.invalid_requirement_id",
            requirement=case.requirement,
            mutate_fn=lambda r: r.update({"requirement_id": "INVALID ID"}),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

    by_type = {case.primitive_type: case.requirement for case in CASES}

    for primitive_type in ("required_signer", "prohibited_signer"):
        shared_reject(
            name=f"{primitive_type}.invalid_signer_id",
            requirement=by_type[primitive_type],
            mutate_fn=lambda r: r.update({"signer_id": "INVALID ID"}),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

    # signer_threshold
    req = by_type["signer_threshold"]
    signer_threshold_shared = [
        ("signer_ids_wrong_type", lambda r: r.update({"signer_ids": "x"})),
        (
            "signer_ids_invalid_identifier",
            lambda r: r.update({"signer_ids": ["INVALID ID"]}),
        ),
        (
            "signer_ids_duplicate",
            lambda r: r.update(
                {"signer_ids": ["authority:legal", "authority:legal"]}
            ),
        ),
        ("signer_ids_empty", lambda r: r.update({"signer_ids": []})),
        (
            "minimum_boolean",
            lambda r: r.update({"minimum_signatures": True}),
        ),
        ("minimum_zero", lambda r: r.update({"minimum_signatures": 0})),
    ]
    for suffix, fn in signer_threshold_shared:
        shared_reject(
            name=f"signer_threshold.{suffix}",
            requirement=req,
            mutate_fn=fn,
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

    for suffix, fn in [
        (
            "signer_ids_unsorted",
            lambda r: r.update(
                {
                    "signer_ids": [
                        "authority:security",
                        "authority:legal",
                    ]
                }
            ),
        ),
        (
            "minimum_exceeds_set",
            lambda r: r.update({"minimum_signatures": 3}),
        ),
    ]:
        runtime_stricter(
            name=f"signer_threshold.{suffix}",
            requirement=req,
            mutate_fn=fn,
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

    # Safe integer threshold primitives.
    for primitive_type, field in [
        ("global_signature_threshold", "minimum_signatures"),
        ("global_weight_threshold", "minimum_weight"),
    ]:
        req = by_type[primitive_type]
        for suffix, value in [
            ("boolean", True),
            ("zero", 0),
            ("above_safe_integer", MAX_SAFE_INTEGER + 1),
        ]:
            shared_reject(
                name=f"{primitive_type}.{field}_{suffix}",
                requirement=req,
                mutate_fn=lambda r, f=field, v=value: r.update({f: v}),
                validator=validator,
                evaluator=evaluator,
            )
            checks += 1

    # Role threshold primitives.
    for primitive_type, field in [
        ("role_threshold", "minimum_signatures"),
        ("role_weight_threshold", "minimum_weight"),
    ]:
        req = by_type[primitive_type]
        shared_reject(
            name=f"{primitive_type}.unsupported_role",
            requirement=req,
            mutate_fn=lambda r: r.update({"role": "administrator"}),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1
        for suffix, value in [
            ("boolean", True),
            ("zero", 0),
            ("above_safe_integer", MAX_SAFE_INTEGER + 1),
        ]:
            shared_reject(
                name=f"{primitive_type}.{field}_{suffix}",
                requirement=req,
                mutate_fn=lambda r, f=field, v=value: r.update({f: v}),
                validator=validator,
                evaluator=evaluator,
            )
            checks += 1

    # Two-item role list.
    req = by_type["separation_of_duties"]
    for suffix, fn in [
        ("roles_wrong_type", lambda r: r.update({"roles": "approver"})),
        (
            "roles_unsupported",
            lambda r: r.update({"roles": ["approver", "administrator"]}),
        ),
        (
            "roles_duplicate",
            lambda r: r.update({"roles": ["approver", "approver"]}),
        ),
        ("roles_wrong_length", lambda r: r.update({"roles": ["approver"]})),
    ]:
        shared_reject(
            name=f"separation_of_duties.{suffix}",
            requirement=req,
            mutate_fn=fn,
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1
    runtime_stricter(
        name="separation_of_duties.roles_unsorted",
        requirement=req,
        mutate_fn=lambda r: r.update({"roles": ["reviewer", "approver"]}),
        validator=validator,
        evaluator=evaluator,
    )
    checks += 1

    # Signer-list primitives with shared structural rules.
    signer_list_types = [
        "mutual_exclusion",
        "any_of_signers",
        "all_of_signers",
        "exactly_one_of_signers",
    ]
    for primitive_type in signer_list_types:
        req = by_type[primitive_type]
        for suffix, fn in [
            (
                "signer_ids_wrong_type",
                lambda r: r.update({"signer_ids": "authority:legal"}),
            ),
            (
                "signer_ids_invalid_identifier",
                lambda r: r.update(
                    {"signer_ids": ["INVALID ID", "authority:legal"]}
                ),
            ),
            (
                "signer_ids_duplicate",
                lambda r: r.update(
                    {
                        "signer_ids": [
                            "authority:legal",
                            "authority:legal",
                        ]
                    }
                ),
            ),
            (
                "signer_ids_too_short",
                lambda r: r.update({"signer_ids": ["authority:legal"]}),
            ),
        ]:
            shared_reject(
                name=f"{primitive_type}.{suffix}",
                requirement=req,
                mutate_fn=fn,
                validator=validator,
                evaluator=evaluator,
            )
            checks += 1
        runtime_stricter(
            name=f"{primitive_type}.signer_ids_unsorted",
            requirement=req,
            mutate_fn=lambda r: r.update(
                {
                    "signer_ids": [
                        "authority:security",
                        "authority:legal",
                    ]
                }
            ),
            validator=validator,
            evaluator=evaluator,
        )
        checks += 1

    # Cardinality primitives.
    cardinalities = [
        ("at_most_n_signers", "maximum_matches", -1, 3),
        ("at_least_n_signers", "minimum_matches", 0, 4),
        ("exactly_n_signers", "exact_matches", 0, 4),
    ]
    for primitive_type, field, invalid_low, invalid_high in cardinalities:
        req = by_type[primitive_type]
        for suffix, fn in [
            (
                "signer_ids_wrong_type",
                lambda r: r.update({"signer_ids": "authority:legal"}),
            ),
            (
                "signer_ids_invalid_identifier",
                lambda r: r.update(
                    {
                        "signer_ids": [
                            "INVALID ID",
                            "authority:legal",
                        ]
                    }
                ),
            ),
            (
                "signer_ids_duplicate",
                lambda r: r.update(
                    {
                        "signer_ids": [
                            "authority:legal",
                            "authority:legal",
                        ]
                    }
                ),
            ),
            (
                "signer_ids_too_short",
                lambda r: r.update({"signer_ids": ["authority:legal"]}),
            ),
            (
                f"{field}_boolean",
                lambda r, f=field: r.update({f: True}),
            ),
            (
                f"{field}_invalid_low",
                lambda r, f=field, v=invalid_low: r.update({f: v}),
            ),
        ]:
            shared_reject(
                name=f"{primitive_type}.{suffix}",
                requirement=req,
                mutate_fn=fn,
                validator=validator,
                evaluator=evaluator,
            )
            checks += 1

        for suffix, fn in [
            (
                "signer_ids_unsorted",
                lambda r: r.update(
                    {
                        "signer_ids": [
                            "authority:security",
                            "authority:legal",
                            "authority:finance",
                        ]
                    }
                ),
            ),
            (
                f"{field}_relational_limit",
                lambda r, f=field, v=invalid_high: r.update({f: v}),
            ),
            (
                f"{field}_above_safe_integer",
                lambda r, f=field: r.update(
                    {f: MAX_SAFE_INTEGER + 1}
                ),
            ),
        ]:
            runtime_stricter(
                name=f"{primitive_type}.{suffix}",
                requirement=req,
                mutate_fn=fn,
                validator=validator,
                evaluator=evaluator,
            )
            checks += 1

    expected_checks = 136
    if checks != expected_checks:
        raise TestFailure(
            f"internal matrix count mismatch: {checks} != {expected_checks}"
        )

    print(
        "AGP Trust Policy 2.0 primitive validation matrix: "
        f"{checks}/{checks} passed"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
