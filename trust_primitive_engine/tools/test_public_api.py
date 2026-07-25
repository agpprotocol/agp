#!/usr/bin/env python3
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TPE_PYTHON = ROOT / "trust_primitive_engine/python"
POSITIVE = ROOT / "trust_primitive_engine/examples/policy-references"
SIGNER = ROOT / "signed_decision_context/python/sign_decision_context.py"

if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from trust_primitive_engine import (  # noqa: E402
    TrustPolicyEvaluationError,
    evaluate_trust_policy,
)


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def run(command: list[str]) -> None:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"command failed: {completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def prepare_signed_context() -> None:
    run([sys.executable, str(POSITIVE / "generate_example.py")])

    output = POSITIVE / "signed-context.json"
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
            "sig:operations:public-api:001",
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
            "sig:security:public-api:001",
            "--signed-at",
            "2026-07-24T20:02:00Z",
            "--output",
            str(output),
        ]
    )


def sign_temporary_context(
    context: dict,
    *,
    name: str,
) -> Path:
    temporary_context = POSITIVE / f"{name}-context.json"
    temporary_signed = POSITIVE / f"{name}-signed.json"

    temporary_context.write_text(
        json.dumps(context, indent=2) + "\n",
        encoding="utf-8",
    )

    run(
        [
            sys.executable,
            str(SIGNER),
            str(temporary_context),
            "--private-key",
            str(POSITIVE / "operations-private-key.json"),
            "--signer-id",
            "authority:operations",
            "--key-id",
            "key:operations:example",
            "--signature-id",
            f"sig:operations:{name}",
            "--signed-at",
            "2026-07-24T20:01:00Z",
            "--output",
            str(temporary_signed),
        ]
    )
    run(
        [
            sys.executable,
            str(SIGNER),
            str(temporary_signed),
            "--append",
            "--private-key",
            str(POSITIVE / "security-private-key.json"),
            "--signer-id",
            "authority:security",
            "--key-id",
            "key:security:example",
            "--signature-id",
            f"sig:security:{name}",
            "--signed-at",
            "2026-07-24T20:02:00Z",
            "--output",
            str(temporary_signed),
        ]
    )

    temporary_context.unlink(missing_ok=True)
    return temporary_signed


def tpe24_fixture(
    *,
    expected_service: str,
):
    import evaluate_trust_policy_v2 as evaluator

    evidence_digest = "a" * 64

    referenced = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:tpe24-security-review",
        "version": 1,
        "eligible_roles": ["reviewer"],
        "requirements": [
            {
                "requirement_id": "requirement:context-service",
                "type": "context_value_equals",
                "path": "/proposal/payload/service",
                "value": expected_service,
            },
            {
                "requirement_id": "requirement:context-version",
                "type": "context_value_present",
                "path": "/proposal/payload/version",
            },
            {
                "requirement_id": "requirement:evidence-security",
                "type": "evidence_present",
                "evidence_id": "evidence.security-report",
                "digest": evidence_digest,
                "media_type": "application/json",
            },
        ],
    }
    referenced = evaluator.validate_policy(referenced)

    root = {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:example:tpe24-production-change",
        "version": 1,
        "eligible_roles": ["approver"],
        "requirements": [
            {
                "requirement_id": "requirement:operations-approval",
                "type": "required_signer",
                "signer_id": "authority:operations",
            },
            {
                "requirement_id": "requirement:tpe24-security-policy",
                "type": "policy_reference",
                "policy_id": referenced["policy_id"],
                "policy_version": referenced["version"],
                "policy_digest": evaluator.policy_digest(referenced),
            },
        ],
    }
    root = evaluator.validate_policy(root)

    context = load_json(POSITIVE / "decision-context.json")
    context["context_id"] = (
        "ctx:example:tpe24-public-api:"
        + ("satisfied" if expected_service == "payments-api" else "unsatisfied")
    )
    context["policy"] = {
        "id": root["policy_id"],
        "version": root["version"],
        "digest": evaluator.policy_digest(root),
    }
    context["evidence"] = [
        {
            "id": "evidence.security-report",
            "digest": evidence_digest,
            "media_type": "application/json",
        }
    ]

    return root, referenced, context


def test_satisfied() -> None:
    result = evaluate_trust_policy(
        signed_context=load_json(POSITIVE / "signed-context.json"),
        policy=load_json(POSITIVE / "root-policy.json"),
        keyring=load_json(POSITIVE / "keyring.json"),
        policy_set=load_json(POSITIVE / "policy-set.json"),
    )

    assert result["status"] == "satisfied", result
    assert result["failure_codes"] == [], result
    print("PASS public API satisfied evaluation")


def test_unsatisfied() -> None:
    referenced = load_json(POSITIVE / "referenced-policy.json")
    referenced["eligible_roles"] = ["observer"]

    import evaluate_trust_policy_v2 as evaluator

    referenced = evaluator.validate_policy(referenced)
    referenced_digest = evaluator.policy_digest(referenced)

    root = load_json(POSITIVE / "root-policy.json")
    root["requirements"][1]["policy_digest"] = referenced_digest
    root = evaluator.validate_policy(root)

    context = load_json(POSITIVE / "decision-context.json")
    context["policy"]["digest"] = evaluator.policy_digest(root)

    temporary_context = POSITIVE / "public-api-unsatisfied-context.json"
    temporary_signed = POSITIVE / "public-api-unsatisfied-signed.json"
    temporary_context.write_text(
        json.dumps(context, indent=2) + "\n",
        encoding="utf-8",
    )

    try:
        run(
            [
                sys.executable,
                str(SIGNER),
                str(temporary_context),
                "--private-key",
                str(POSITIVE / "operations-private-key.json"),
                "--signer-id",
                "authority:operations",
                "--key-id",
                "key:operations:example",
                "--signature-id",
                "sig:operations:public-api:unsatisfied",
                "--signed-at",
                "2026-07-24T20:01:00Z",
                "--output",
                str(temporary_signed),
            ]
        )
        run(
            [
                sys.executable,
                str(SIGNER),
                str(temporary_signed),
                "--append",
                "--private-key",
                str(POSITIVE / "security-private-key.json"),
                "--signer-id",
                "authority:security",
                "--key-id",
                "key:security:example",
                "--signature-id",
                "sig:security:public-api:unsatisfied",
                "--signed-at",
                "2026-07-24T20:02:00Z",
                "--output",
                str(temporary_signed),
            ]
        )

        result = evaluate_trust_policy(
            signed_context=load_json(temporary_signed),
            policy=root,
            keyring=load_json(POSITIVE / "keyring.json"),
            policy_set=[referenced],
        )
    finally:
        temporary_context.unlink(missing_ok=True)
        temporary_signed.unlink(missing_ok=True)

    assert result["status"] == "unsatisfied", result
    assert "POLICY_REFERENCE_NOT_SATISFIED" in result["failure_codes"]
    print("PASS public API unsatisfied evaluation")


def test_tpe24_satisfied() -> None:
    root, referenced, context = tpe24_fixture(
        expected_service="payments-api",
    )
    signed_path = sign_temporary_context(
        context,
        name="public-api-tpe24-satisfied",
    )

    try:
        result = evaluate_trust_policy(
            signed_context=load_json(signed_path),
            policy=root,
            keyring=load_json(POSITIVE / "keyring.json"),
            policy_set=[referenced],
        )
    finally:
        signed_path.unlink(missing_ok=True)

    assert result["status"] == "satisfied", result
    assert result["failure_codes"] == [], result

    referenced_result = result["requirement_results"][1]
    inner = referenced_result["referenced_policy"]
    assert inner["status"] == "satisfied", inner
    assert [
        item["type"]
        for item in inner["requirement_results"]
    ] == [
        "context_value_equals",
        "context_value_present",
        "evidence_present",
    ], inner

    print("PASS public API TPE 2.4 satisfied evaluation")


def test_tpe24_unsatisfied() -> None:
    root, referenced, context = tpe24_fixture(
        expected_service="staging",
    )
    signed_path = sign_temporary_context(
        context,
        name="public-api-tpe24-unsatisfied",
    )

    try:
        result = evaluate_trust_policy(
            signed_context=load_json(signed_path),
            policy=root,
            keyring=load_json(POSITIVE / "keyring.json"),
            policy_set=[referenced],
        )
    finally:
        signed_path.unlink(missing_ok=True)

    assert result["status"] == "unsatisfied", result
    assert result["failure_codes"] == [
        "POLICY_REFERENCE_NOT_SATISFIED",
        "CONTEXT_VALUE_NOT_EQUAL",
    ], result

    inner = (
        result["requirement_results"][1]
        ["referenced_policy"]
    )
    assert inner["failure_codes"] == [
        "CONTEXT_VALUE_NOT_EQUAL",
    ], inner

    print("PASS public API TPE 2.4 unsatisfied evaluation")


def test_fatal_error() -> None:
    try:
        evaluate_trust_policy(
            signed_context=load_json(POSITIVE / "signed-context.json"),
            policy=load_json(POSITIVE / "root-policy.json"),
            keyring=load_json(POSITIVE / "keyring.json"),
            policy_set=[],
        )
    except TrustPolicyEvaluationError as exc:
        assert exc.code == "POLICY_REFERENCE_NOT_FOUND", exc
    else:
        raise AssertionError("fatal API error was not raised")

    print("PASS public API fatal error")


def main() -> int:
    prepare_signed_context()
    test_satisfied()
    test_unsatisfied()
    test_tpe24_satisfied()
    test_tpe24_unsatisfied()
    test_fatal_error()
    print("AGP TPE public Python API: 5/5 passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
