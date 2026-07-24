#!/usr/bin/env python3
"""Focused deterministic checks for TPE 2.3 policy-set indexing."""

from __future__ import annotations

from copy import deepcopy
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
        "agp_evaluate_trust_policy_v2_policy_set", EVALUATOR_PATH
    )
    if spec is None or spec.loader is None:
        raise TestFailure("could not load evaluator module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def policy(policy_id: str, version: int, signer_id: str) -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": policy_id,
        "version": version,
        "eligible_roles": ["approver"],
        "requirements": [{
            "requirement_id": "requirement:required-signer",
            "type": "required_signer",
            "signer_id": signer_id,
        }],
    }


def expect_reject(name: str, callback: Any) -> None:
    try:
        callback()
    except Exception:
        print(f"PASS  {name:<38} rejected")
        return
    raise TestFailure(f"{name}: unexpectedly accepted")


def main() -> int:
    evaluator = load_evaluator()
    passed = 0

    empty = build_policy_set_index([], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest)
    if len(empty) != 0 or empty.identities != ():
        raise TestFailure("empty_policy_set: unexpected index")
    print("PASS  empty_policy_set                       accepted")
    passed += 1

    expect_reject("invalid_policy_set_type", lambda: build_policy_set_index({}, validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest))
    passed += 1

    invalid = policy("policy:invalid", 1, "authority:invalid")
    del invalid["requirements"][0]["signer_id"]
    expect_reject("invalid_policy", lambda: build_policy_set_index([invalid], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest))
    passed += 1

    first = policy("policy:alpha", 1, "authority:alpha")
    duplicate_identity = policy("policy:alpha", 1, "authority:other")
    expect_reject("duplicate_policy_identity", lambda: build_policy_set_index([first, duplicate_identity], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest))
    passed += 1

    expect_reject("duplicate_canonical_policy", lambda: build_policy_set_index([first, deepcopy(first)], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest))
    passed += 1

    second = policy("policy:beta", 2, "authority:beta")
    forward = build_policy_set_index([first, second], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest)
    reverse = build_policy_set_index([second, first], validate_policy=evaluator.validate_policy, compute_digest=evaluator.policy_digest)
    if forward.identities != reverse.identities:
        raise TestFailure("deterministic_order: identities differ by input order")
    print("PASS  deterministic_order                    identical")
    passed += 1

    first_entry = forward.resolve("policy:alpha", 1)
    if first_entry is None:
        raise TestFailure("digest_matches_runtime: entry not found")
    expected_digest = evaluator.policy_digest(evaluator.validate_policy(first))
    if first_entry.identity.policy_digest != expected_digest:
        raise TestFailure("digest_matches_runtime: digest mismatch")
    print("PASS  digest_matches_runtime                identical")
    passed += 1

    detached = first_entry.to_policy()
    detached["policy_id"] = "policy:mutated"
    detached["requirements"][0]["signer_id"] = "authority:mutated"
    preserved = first_entry.to_policy()
    if preserved["policy_id"] != "policy:alpha":
        raise TestFailure("immutable_index: policy_id was mutated")
    if preserved["requirements"][0]["signer_id"] != "authority:alpha":
        raise TestFailure("immutable_index: nested policy data was mutated")
    try:
        first_entry.policy["policy_id"] = "policy:mutated"
    except TypeError:
        pass
    else:
        raise TestFailure("immutable_index: mapping allowed mutation")
    print("PASS  immutable_index                       preserved")
    passed += 1

    expected = 8
    if passed != expected:
        raise TestFailure(f"internal check count mismatch: {passed} != {expected}")
    print(f"TPE 2.3 policy-set indexing: {passed}/{expected} passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
