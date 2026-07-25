#!/usr/bin/env python3
from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
POSITIVE = ROOT / "trust_primitive_engine/examples/policy-references"
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
EVALUATOR_PATH = TPE_PYTHON / "evaluate_trust_policy_v2.py"
SIGNER = ROOT / "signed_decision_context/python/sign_decision_context.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from engine.policy_set import (  # noqa: E402
    PolicyReferenceIdentity,
    PolicySetEntry,
    PolicySetIndex,
)


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location(
        "agp_negative_policy_reference_examples",
        EVALUATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load TPE evaluator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


E = load_evaluator()


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def run(command: list[str], expected: int | None = 0) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if expected is not None and result.returncode != expected:
        raise AssertionError(
            f"command returned {result.returncode}, expected {expected}\n"
            f"STDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
        )
    return result


def prepare_positive_material() -> None:
    run([sys.executable, str(POSITIVE / "generate_example.py")])

    signed = HERE / "signed-context.json"
    run(
        [
            sys.executable,
            str(SIGNER),
            str(POSITIVE / "decision-context.json"),
            "--private-key",
            str(POSITIVE / "operations-private-key.json"),
            "--signer-id",
            "authority:operations",
            "--key-id",
            "key:operations:example",
            "--signature-id",
            "sig:operations:failure-examples:001",
            "--signed-at",
            "2026-07-24T20:01:00Z",
            "--output",
            str(signed),
        ]
    )
    run(
        [
            sys.executable,
            str(SIGNER),
            str(signed),
            "--append",
            "--private-key",
            str(POSITIVE / "security-private-key.json"),
            "--signer-id",
            "authority:security",
            "--key-id",
            "key:security:example",
            "--signature-id",
            "sig:security:failure-examples:001",
            "--signed-at",
            "2026-07-24T20:02:00Z",
            "--output",
            str(signed),
        ]
    )


def cli_error(
    *,
    name: str,
    policy: Path,
    policy_set: Path,
    expected_code: str,
) -> None:
    result = run(
        [
            sys.executable,
            str(EVALUATOR_PATH),
            str(HERE / "signed-context.json"),
            "--policy",
            str(policy),
            "--policy-set",
            str(policy_set),
            "--keyring",
            str(POSITIVE / "keyring.json"),
        ],
        expected=1,
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "error", payload
    assert payload["error_code"] == expected_code, payload
    print(f"PASS  {name:<20} {expected_code}")


def case_digest_mismatch() -> None:
    root = json.loads((POSITIVE / "root-policy.json").read_text())
    referenced = json.loads((POSITIVE / "referenced-policy.json").read_text())

    referenced["requirements"][0]["signer_id"] = "authority:operations"
    referenced = E.validate_policy(referenced)

    root_path = HERE / "digest-mismatch-root-policy.json"
    set_path = HERE / "digest-mismatch-policy-set.json"
    write_json(root_path, root)
    write_json(set_path, [referenced])

    cli_error(
        name="digest_mismatch",
        policy=root_path,
        policy_set=set_path,
        expected_code="POLICY_REFERENCE_DIGEST_MISMATCH",
    )


def case_missing_policy() -> None:
    root_path = POSITIVE / "root-policy.json"
    set_path = HERE / "missing-policy-set.json"
    write_json(set_path, [])

    cli_error(
        name="missing_policy",
        policy=root_path,
        policy_set=set_path,
        expected_code="POLICY_REFERENCE_NOT_FOUND",
    )


def sign_context_for_policy(
    *,
    context: dict[str, Any],
    output: Path,
) -> None:
    unsigned = HERE / "ineligible-role-decision-context.json"
    write_json(unsigned, context)

    run(
        [
            sys.executable,
            str(SIGNER),
            str(unsigned),
            "--private-key",
            str(POSITIVE / "operations-private-key.json"),
            "--signer-id",
            "authority:operations",
            "--key-id",
            "key:operations:example",
            "--signature-id",
            "sig:operations:ineligible-role:001",
            "--signed-at",
            "2026-07-24T20:01:00Z",
            "--output",
            str(output),
        ]
    )
    run(
        [
            sys.executable,
            str(SIGNER),
            str(output),
            "--append",
            "--private-key",
            str(POSITIVE / "security-private-key.json"),
            "--signer-id",
            "authority:security",
            "--key-id",
            "key:security:example",
            "--signature-id",
            "sig:security:ineligible-role:001",
            "--signed-at",
            "2026-07-24T20:02:00Z",
            "--output",
            str(output),
        ]
    )


def case_ineligible_role() -> None:
    referenced = json.loads((POSITIVE / "referenced-policy.json").read_text())
    referenced["eligible_roles"] = ["observer"]
    referenced = E.validate_policy(referenced)
    referenced_digest = E.policy_digest(referenced)

    root = json.loads((POSITIVE / "root-policy.json").read_text())
    root["requirements"][1]["policy_digest"] = referenced_digest
    root = E.validate_policy(root)
    root_digest = E.policy_digest(root)

    context = json.loads((POSITIVE / "decision-context.json").read_text())
    context["policy"]["digest"] = root_digest

    root_path = HERE / "ineligible-role-root-policy.json"
    set_path = HERE / "ineligible-role-policy-set.json"
    signed_path = HERE / "ineligible-role-signed-context.json"
    write_json(root_path, root)
    write_json(set_path, [referenced])
    sign_context_for_policy(context=context, output=signed_path)

    result = run(
        [
            sys.executable,
            str(EVALUATOR_PATH),
            str(signed_path),
            "--policy",
            str(root_path),
            "--policy-set",
            str(set_path),
            "--keyring",
            str(POSITIVE / "keyring.json"),
        ],
        expected=2,
    )
    payload = json.loads(result.stdout)
    assert payload["status"] == "unsatisfied", payload
    assert "POLICY_REFERENCE_NOT_SATISFIED" in payload["failure_codes"], payload
    reference = next(
        item
        for item in payload["requirement_results"]
        if item["type"] == "policy_reference"
    )
    assert reference["failure_code"] == "POLICY_REFERENCE_NOT_SATISFIED"
    print(
        "PASS  "
        f"{'ineligible_role':<20} "
        "POLICY_REFERENCE_NOT_SATISFIED"
    )


def case_cycle_detected() -> None:
    child_identity = PolicyReferenceIdentity(
        policy_id="policy:example:cycle-child",
        policy_version=1,
        policy_digest="1" * 64,
    )
    child_policy = {
        "object_type": "agp.trust-policy/2",
        "policy_id": child_identity.policy_id,
        "version": child_identity.policy_version,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:self-cycle",
                "type": "policy_reference",
                "policy_id": child_identity.policy_id,
                "policy_version": child_identity.policy_version,
                "policy_digest": child_identity.policy_digest,
            }
        ],
    }
    child_policy = E.validate_policy(child_policy)

    root = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:cycle-root",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:child",
                "type": "policy_reference",
                "policy_id": child_identity.policy_id,
                "policy_version": child_identity.policy_version,
                "policy_digest": child_identity.policy_digest,
            }
        ],
    }
    root = E.validate_policy(root)

    child_entry = PolicySetEntry(
        identity=child_identity,
        policy=child_policy,
    )
    index = PolicySetIndex(
        entries=(child_entry,),
        _by_policy_key={
            (
                child_identity.policy_id,
                child_identity.policy_version,
            ): child_entry,
        },
    )

    try:
        E.validate_policy_reference_graph(root, index)
    except E.EvaluationFailure as exc:
        assert exc.code == "POLICY_REFERENCE_CYCLE", (exc.code, exc.detail)
    else:
        raise AssertionError("cycle was not detected")

    print(
        "PASS  "
        f"{'cycle_detected':<20} "
        "POLICY_REFERENCE_CYCLE"
    )


def main() -> int:
    prepare_positive_material()
    case_digest_mismatch()
    case_missing_policy()
    case_ineligible_role()
    case_cycle_detected()
    print("POLICY_REFERENCE_FAILURE_EXAMPLES_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
