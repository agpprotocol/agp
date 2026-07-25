#!/usr/bin/env python3
"""Run and verify the TPE 2.4 context/evidence examples."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE_DIR = Path(__file__).resolve().parent
SIGNER = ROOT / "signed_decision_context/python/sign_decision_context.py"
EVALUATOR = ROOT / "trust_primitive_engine/python/evaluate_trust_policy_v2.py"

SCENARIOS = {
    "satisfied": {
        "returncode": 0,
        "status": "satisfied",
        "root_failures": [],
        "inner_failures": [],
        "failing_requirement": None,
        "match_status": None,
    },
    "wrong-environment": {
        "returncode": 2,
        "status": "unsatisfied",
        "root_failures": [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "CONTEXT_VALUE_NOT_EQUAL",
        ],
        "inner_failures": ["CONTEXT_VALUE_NOT_EQUAL"],
        "failing_requirement": "requirement:context-environment",
        "match_status": None,
    },
    "missing-evidence": {
        "returncode": 2,
        "status": "unsatisfied",
        "root_failures": [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED",
        ],
        "inner_failures": [
            "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED",
        ],
        "failing_requirement": "requirement:evidence-security-report",
        "match_status": "absent",
    },
    "digest-mismatch": {
        "returncode": 2,
        "status": "unsatisfied",
        "root_failures": [
            "POLICY_REFERENCE_NOT_SATISFIED",
            "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED",
        ],
        "inner_failures": [
            "EVIDENCE_MANIFEST_REQUIREMENT_NOT_SATISFIED",
        ],
        "failing_requirement": "requirement:evidence-security-report",
        "match_status": "digest_mismatch",
    },
}


def run(
    command: list[str],
    *,
    expected: int = 0,
) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    if completed.returncode != expected:
        raise RuntimeError(
            f"command failed: {command!r}\n"
            f"expected={expected} actual={completed.returncode}\n"
            f"stdout={completed.stdout}\n"
            f"stderr={completed.stderr}"
        )
    return completed


def sign(name: str) -> Path:
    context = EXAMPLE_DIR / f"decision-context-{name}.json"
    signed = EXAMPLE_DIR / f"signed-context-{name}.json"

    run(
        [
            sys.executable,
            str(SIGNER),
            str(context),
            "--private-key",
            str(EXAMPLE_DIR / "operations-private-key.json"),
            "--signer-id",
            "authority:operations",
            "--key-id",
            "key:operations:tpe24-example",
            "--signature-id",
            f"sig:operations:tpe24:{name}",
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
            str(EXAMPLE_DIR / "security-private-key.json"),
            "--signer-id",
            "authority:security",
            "--key-id",
            "key:security:tpe24-example",
            "--signature-id",
            f"sig:security:tpe24:{name}",
            "--signed-at",
            "2026-07-24T20:02:00Z",
            "--output",
            str(signed),
        ]
    )
    return signed


def evaluate(name: str, expected_returncode: int) -> dict[str, Any]:
    completed = run(
        [
            sys.executable,
            str(EVALUATOR),
            str(EXAMPLE_DIR / f"signed-context-{name}.json"),
            "--policy",
            str(EXAMPLE_DIR / "root-policy.json"),
            "--policy-set",
            str(EXAMPLE_DIR / "policy-set.json"),
            "--keyring",
            str(EXAMPLE_DIR / "keyring.json"),
        ],
        expected=expected_returncode,
    )

    result = json.loads(completed.stdout)
    output = EXAMPLE_DIR / f"evaluation-result-{name}.json"
    output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return result


def verify(name: str, result: dict[str, Any]) -> None:
    expected = SCENARIOS[name]

    assert result["status"] == expected["status"], result
    assert result["failure_codes"] == expected["root_failures"], result

    root_results = {
        item["requirement_id"]: item
        for item in result["requirement_results"]
    }
    operations = root_results["requirement:operations-approval"]
    reference = root_results["requirement:tpe24-context-evidence-policy"]

    assert operations["status"] == "satisfied", operations
    assert operations["matched_signers"] == ["authority:operations"], operations

    inner = reference["referenced_policy"]
    assert inner["failure_codes"] == expected["inner_failures"], inner

    if name == "satisfied":
        assert reference["status"] == "satisfied", reference
        assert inner["status"] == "satisfied", inner
        assert reference["matched_signers"] == ["authority:security"], reference

        types = [item["type"] for item in inner["requirement_results"]]
        assert types == [
            "context_integer_at_least",
            "context_value_equals",
            "context_integer_at_most",
            "context_value_present",
            "evidence_present",
            "required_signer",
        ], types
        return

    assert reference["status"] == "unsatisfied", reference
    assert inner["status"] == "unsatisfied", inner

    inner_results = {
        item["requirement_id"]: item
        for item in inner["requirement_results"]
    }
    failing = inner_results[expected["failing_requirement"]]
    assert failing["status"] == "unsatisfied", failing

    if expected["match_status"] is not None:
        assert failing["observed"]["match_status"] == expected["match_status"], failing


def main() -> int:
    run([sys.executable, str(EXAMPLE_DIR / "generate_example.py")])

    passed = 0
    for name, expected in SCENARIOS.items():
        sign(name)
        result = evaluate(name, expected["returncode"])
        verify(name, result)
        print(
            f"PASS  {name:<20} "
            f"status={result['status']} "
            f"failures={len(result['failure_codes'])}"
        )
        passed += 1

    assert passed == 4
    print("TPE_2_4_CONTEXT_EVIDENCE_EXAMPLES_PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
