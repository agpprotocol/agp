#!/usr/bin/env python3
"""Property-based hardening for AGP Trust Policy 2.0 validation."""

from __future__ import annotations

from copy import deepcopy
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

from hypothesis import HealthCheck, given, settings, strategies as st
from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "registry/schemas/agp.trust-policy-2.schema.json"
EVALUATOR_PATH = (
    ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"
)
MAX_SAFE_INTEGER = 9_007_199_254_740_991
EXAMPLES_PER_PROPERTY = 250
PROPERTY_COUNT = 4
TOTAL_GENERATED_EXAMPLES = EXAMPLES_PER_PROPERTY * PROPERTY_COUNT


class TestFailure(Exception):
    pass


def load_evaluator() -> Any:
    python_dir = EVALUATOR_PATH.parent
    if str(python_dir) not in sys.path:
        sys.path.insert(0, str(python_dir))

    spec = importlib.util.spec_from_file_location(
        "agp_evaluate_trust_policy_v2_property",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
Draft202012Validator.check_schema(SCHEMA)
VALIDATOR = Draft202012Validator(SCHEMA)
EVALUATOR = load_evaluator()


identifier = st.from_regex(
    r"^[a-z0-9][a-z0-9._:/-]{1,30}[a-z0-9]$",
    fullmatch=True,
).filter(lambda value: len(value) >= 3)

role = st.sampled_from(
    ["approver", "observer", "proposer", "reviewer", "voter"]
)


@st.composite
def sorted_unique_identifiers(
    draw: st.DrawFn,
    *,
    minimum_size: int,
    maximum_size: int = 5,
) -> list[str]:
    values = draw(
        st.lists(
            identifier,
            min_size=minimum_size,
            max_size=maximum_size,
            unique=True,
        )
    )
    return sorted(values)


@st.composite
def valid_requirement(draw: st.DrawFn) -> dict[str, Any]:
    primitive_type = draw(
        st.sampled_from(
            [
                "required_signer",
                "signer_threshold",
                "global_signature_threshold",
                "global_weight_threshold",
                "role_threshold",
                "role_weight_threshold",
                "prohibited_signer",
                "separation_of_duties",
                "mutual_exclusion",
                "any_of_signers",
                "all_of_signers",
                "exactly_one_of_signers",
                "at_most_n_signers",
                "at_least_n_signers",
                "exactly_n_signers",
            ]
        )
    )
    requirement_id = draw(identifier)

    if primitive_type in {"required_signer", "prohibited_signer"}:
        return {
            "requirement_id": requirement_id,
            "type": primitive_type,
            "signer_id": draw(identifier),
        }

    if primitive_type in {
        "global_signature_threshold",
        "global_weight_threshold",
    }:
        field = (
            "minimum_signatures"
            if primitive_type == "global_signature_threshold"
            else "minimum_weight"
        )
        return {
            "requirement_id": requirement_id,
            "type": primitive_type,
            field: draw(st.integers(min_value=1, max_value=100_000)),
        }

    if primitive_type in {"role_threshold", "role_weight_threshold"}:
        field = (
            "minimum_signatures"
            if primitive_type == "role_threshold"
            else "minimum_weight"
        )
        return {
            "requirement_id": requirement_id,
            "type": primitive_type,
            "role": draw(role),
            field: draw(st.integers(min_value=1, max_value=100_000)),
        }

    if primitive_type == "separation_of_duties":
        roles = sorted(
            draw(
                st.lists(
                    role,
                    min_size=2,
                    max_size=2,
                    unique=True,
                )
            )
        )
        return {
            "requirement_id": requirement_id,
            "type": primitive_type,
            "roles": roles,
        }

    minimum_size = 1 if primitive_type == "signer_threshold" else 2
    maximum_size = 2 if primitive_type == "mutual_exclusion" else 5
    signer_ids = draw(
        sorted_unique_identifiers(
            minimum_size=minimum_size,
            maximum_size=maximum_size,
        )
    )

    requirement: dict[str, Any] = {
        "requirement_id": requirement_id,
        "type": primitive_type,
        "signer_ids": signer_ids,
    }

    if primitive_type == "signer_threshold":
        requirement["minimum_signatures"] = draw(
            st.integers(min_value=1, max_value=len(signer_ids))
        )
    elif primitive_type == "at_most_n_signers":
        requirement["maximum_matches"] = draw(
            st.integers(min_value=0, max_value=len(signer_ids) - 1)
        )
    elif primitive_type == "at_least_n_signers":
        requirement["minimum_matches"] = draw(
            st.integers(min_value=1, max_value=len(signer_ids))
        )
    elif primitive_type == "exactly_n_signers":
        requirement["exact_matches"] = draw(
            st.integers(min_value=1, max_value=len(signer_ids))
        )

    return requirement


@st.composite
def valid_policy(draw: st.DrawFn) -> dict[str, Any]:
    requirements = draw(
        st.lists(
            valid_requirement(),
            min_size=1,
            max_size=5,
            unique_by=lambda item: item["requirement_id"],
        )
    )
    requirements = sorted(
        requirements,
        key=lambda item: item["requirement_id"],
    )
    eligible_roles = sorted(
        draw(
            st.lists(
                role,
                min_size=1,
                max_size=5,
                unique=True,
            )
        )
    )
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": draw(identifier),
        "version": 2,
        "eligible_roles": eligible_roles,
        "requirements": requirements,
    }


@st.composite
def malformed_policy(draw: st.DrawFn) -> dict[str, Any]:
    policy = deepcopy(draw(valid_policy()))
    mutation = draw(
        st.sampled_from(
            [
                "unknown_root",
                "missing_policy_id",
                "bad_version_bool",
                "requirements_wrong_type",
                "unknown_requirement_member",
                "bad_requirement_id",
                "missing_requirement_type",
            ]
        )
    )

    if mutation == "unknown_root":
        policy["unexpected"] = draw(st.integers())
    elif mutation == "missing_policy_id":
        policy.pop("policy_id")
    elif mutation == "bad_version_bool":
        policy["version"] = draw(st.booleans())
    elif mutation == "requirements_wrong_type":
        policy["requirements"] = {"not": "an array"}
    elif mutation == "unknown_requirement_member":
        policy["requirements"][0]["unexpected"] = draw(st.integers())
    elif mutation == "bad_requirement_id":
        policy["requirements"][0]["requirement_id"] = "INVALID ID"
    elif mutation == "missing_requirement_type":
        policy["requirements"][0].pop("type")

    return policy


@st.composite
def runtime_stricter_policy(draw: st.DrawFn) -> dict[str, Any]:
    policy = deepcopy(draw(valid_policy()))
    mutation = draw(
        st.sampled_from(
            [
                "unsorted_roles",
                "unsorted_requirements",
                "unsorted_signer_ids",
                "semantic_threshold",
            ]
        )
    )

    if mutation == "unsorted_roles":
        policy["eligible_roles"] = ["reviewer", "approver"]
        return policy

    if mutation == "unsorted_requirements":
        first = {
            "requirement_id": "requirement:z",
            "type": "required_signer",
            "signer_id": "authority:z",
        }
        second = {
            "requirement_id": "requirement:a",
            "type": "required_signer",
            "signer_id": "authority:a",
        }
        policy["requirements"] = [first, second]
        return policy

    if mutation == "unsorted_signer_ids":
        policy["requirements"] = [
            {
                "requirement_id": "requirement:unsorted",
                "type": "any_of_signers",
                "signer_ids": [
                    "authority:z",
                    "authority:a",
                ],
            }
        ]
        return policy

    policy["requirements"] = [
        {
            "requirement_id": "requirement:semantic",
            "type": "at_least_n_signers",
            "signer_ids": [
                "authority:a",
                "authority:b",
            ],
            "minimum_matches": 3,
        }
    ]
    return policy


def schema_accepts(value: Any) -> bool:
    return not any(VALIDATOR.iter_errors(value))


def runtime_validate(value: Any) -> dict[str, Any]:
    return EVALUATOR.validate_policy(value)


COMMON_SETTINGS = settings(
    max_examples=EXAMPLES_PER_PROPERTY,
    deadline=None,
    derandomize=True,
    database=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@COMMON_SETTINGS
@given(valid_policy())
def property_valid_policies_are_accepted(policy: dict[str, Any]) -> None:
    assert schema_accepts(policy), (
        "generated valid policy was rejected by schema: "
        f"{policy!r}"
    )
    runtime_validate(deepcopy(policy))


@COMMON_SETTINGS
@given(malformed_policy())
def property_shared_malformed_policies_are_rejected(
    policy: dict[str, Any],
) -> None:
    assert not schema_accepts(policy)
    try:
        runtime_validate(policy)
    except Exception:
        return
    raise AssertionError("runtime accepted a schema-invalid policy")


@COMMON_SETTINGS
@given(valid_policy())
def property_runtime_validation_is_deterministic(
    policy: dict[str, Any],
) -> None:
    original = deepcopy(policy)
    first_input = deepcopy(policy)
    second_input = deepcopy(policy)

    runtime_validate(first_input)
    runtime_validate(second_input)

    assert first_input == original, (
        "first validation mutated the input policy"
    )
    assert second_input == original, (
        "second validation mutated the input policy"
    )
    assert first_input == second_input


@COMMON_SETTINGS
@given(runtime_stricter_policy())
def property_runtime_only_constraints_are_enforced(
    policy: dict[str, Any],
) -> None:
    assert schema_accepts(policy)
    try:
        runtime_validate(policy)
    except Exception as exc:
        assert getattr(exc, "code", None) == "INVALID_TRUST_POLICY"
        return
    raise AssertionError(
        "runtime accepted a non-canonical or semantically invalid policy"
    )


def run_property(name: str, fn: Any) -> None:
    try:
        fn()
    except Exception as exc:
        raise TestFailure(f"{name}: {type(exc).__name__}: {exc}") from exc
    print(
        f"PASS  {name:<52} "
        f"examples={EXAMPLES_PER_PROPERTY}"
    )


def main() -> int:
    properties = [
        (
            "valid_policies_accepted_by_schema_and_runtime",
            property_valid_policies_are_accepted,
        ),
        (
            "shared_malformed_policies_rejected",
            property_shared_malformed_policies_are_rejected,
        ),
        (
            "runtime_validation_deterministic",
            property_runtime_validation_is_deterministic,
        ),
        (
            "runtime_only_constraints_enforced",
            property_runtime_only_constraints_are_enforced,
        ),
    ]

    for name, fn in properties:
        run_property(name, fn)

    print(
        "AGP Trust Policy 2.0 property hardening: "
        f"{PROPERTY_COUNT}/{PROPERTY_COUNT} properties passed; "
        f"{TOTAL_GENERATED_EXAMPLES} generated examples"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
