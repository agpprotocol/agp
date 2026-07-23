#!/usr/bin/env python3
"""End-to-end conformance tests for AGP Trust Policy 2.0 / TPE Phase 1."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)


ROOT = Path(__file__).resolve().parents[2]

SIGNER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "sign_decision_context.py"
)

EVALUATOR = (
    ROOT
    / "trust_primitive_engine"
    / "python"
    / "evaluate_trust_policy_v2.py"
)

TPE_PYTHON = ROOT / "trust_primitive_engine" / "python"
if str(TPE_PYTHON) not in sys.path:
    sys.path.insert(0, str(TPE_PYTHON))

from evaluate_trust_policy_v2 import policy_digest


LEGAL_SEED_1 = bytes(range(1, 33))
LEGAL_SEED_2 = bytes(range(33, 65))
FINANCE_SEED = bytes(range(65, 97))
SECURITY_SEED = bytes(range(97, 129))
OBSERVER_SEED = bytes(range(129, 161))
OUTSIDER_SEED = bytes(range(161, 193))


class TestFailure(Exception):
    pass


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def public_key(seed: bytes) -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    return private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TestFailure(f"{path}: expected JSON object")
    return value


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_output(
    completed: subprocess.CompletedProcess[str],
    name: str,
) -> dict[str, Any]:
    output = completed.stdout.strip()

    if not output:
        raise TestFailure(
            f"{name}: no JSON output; "
            f"stderr={completed.stderr.strip()!r}"
        )

    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise TestFailure(
            f"{name}: invalid JSON output={output!r}; "
            f"stderr={completed.stderr.strip()!r}"
        ) from exc

    if not isinstance(value, dict):
        raise TestFailure(f"{name}: output must be an object")

    return value


def base_policy() -> dict[str, Any]:
    return {
        "object_type": "agp.trust-policy/2",
        "policy_id": "policy:production-change",
        "version": 2,
        "eligible_roles": [
            "approver",
            "reviewer",
        ],
        "requirements": [
            {
                "requirement_id": "requirement:global-count",
                "type": "global_signature_threshold",
                "minimum_signatures": 2,
            },
            {
                "requirement_id": "requirement:global-weight",
                "type": "global_weight_threshold",
                "minimum_weight": 3,
            },
            {
                "requirement_id": "requirement:legal",
                "type": "required_signer",
                "signer_id": "authority:legal",
            },
            {
                "requirement_id": "requirement:risk-function",
                "type": "signer_threshold",
                "signer_ids": [
                    "authority:finance",
                    "authority:security",
                ],
                "minimum_signatures": 1,
            },
        ],
    }


def base_participants() -> list[dict[str, Any]]:
    return [
        {
            "id": "authority:finance",
            "role": "approver",
            "weight": 1,
        },
        {
            "id": "authority:legal",
            "role": "approver",
            "weight": 2,
        },
        {
            "id": "authority:observer",
            "role": "observer",
            "weight": 5,
        },
        {
            "id": "authority:security",
            "role": "reviewer",
            "weight": 2,
        },
    ]


def context_value(
    *,
    policy: dict[str, Any],
    participants: list[dict[str, Any]],
    policy_id: str | None = None,
    policy_version: int | None = None,
    digest: str | None = None,
    context_id: str = "ctx:tpe:test:001",
) -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/1",
        "context_id": context_id,
        "created_at": "2026-07-23T18:00:00Z",
        "expires_at": None,
        "policy": {
            "id": (
                policy["policy_id"]
                if policy_id is None
                else policy_id
            ),
            "version": (
                policy["version"]
                if policy_version is None
                else policy_version
            ),
            "digest": (
                policy_digest(policy)
                if digest is None
                else digest
            ),
        },
        "proposal": {
            "type": "proposal:production-change",
            "payload": {
                "service": "payments-api",
                "version": "3.0.0",
            },
        },
        "participants": sorted(
            deepcopy(participants),
            key=lambda item: item["id"],
        ),
        "evidence": [],
        "constraints": [],
    }


def signer_spec(
    signer_id: str,
    key_id: str,
    signature_id: str,
    seed: bytes,
    signed_at: str,
) -> dict[str, Any]:
    return {
        "signer_id": signer_id,
        "key_id": key_id,
        "signature_id": signature_id,
        "seed": seed,
        "signed_at": signed_at,
    }


LEGAL = signer_spec(
    "authority:legal",
    "key:legal:2026-q3",
    "sig:legal:0001",
    LEGAL_SEED_1,
    "2026-07-23T18:00:00Z",
)

LEGAL_SECOND_KEY = signer_spec(
    "authority:legal",
    "key:legal:2026-q4",
    "sig:legal:0002",
    LEGAL_SEED_2,
    "2026-07-23T18:01:00Z",
)

FINANCE = signer_spec(
    "authority:finance",
    "key:finance:2026-q3",
    "sig:finance:0001",
    FINANCE_SEED,
    "2026-07-23T18:02:00Z",
)

SECURITY = signer_spec(
    "authority:security",
    "key:security:2026-q3",
    "sig:security:0001",
    SECURITY_SEED,
    "2026-07-23T18:03:00Z",
)

OBSERVER = signer_spec(
    "authority:observer",
    "key:observer:2026-q3",
    "sig:observer:0001",
    OBSERVER_SEED,
    "2026-07-23T18:04:00Z",
)

OUTSIDER = signer_spec(
    "authority:outsider",
    "key:outsider:2026-q3",
    "sig:outsider:0001",
    OUTSIDER_SEED,
    "2026-07-23T18:05:00Z",
)


def signer_command(
    *,
    input_path: Path,
    private_key_path: Path,
    signer: dict[str, Any],
    output_path: Path,
    append: bool,
) -> list[str]:
    command = [
        sys.executable,
        str(SIGNER),
        str(input_path),
        "--private-key",
        str(private_key_path),
        "--signer-id",
        signer["signer_id"],
        "--key-id",
        signer["key_id"],
        "--signature-id",
        signer["signature_id"],
        "--signed-at",
        signer["signed_at"],
        "--output",
        str(output_path),
    ]

    if append:
        command.append("--append")

    return command


def create_signed_context(
    *,
    directory: Path,
    name: str,
    context: dict[str, Any],
    signers: list[dict[str, Any]],
) -> tuple[Path, Path]:
    if not signers:
        raise TestFailure(f"{name}: at least one signer is required")

    case_dir = directory / name
    case_dir.mkdir(parents=True, exist_ok=True)

    context_path = case_dir / "context.json"
    keyring_path = case_dir / "keyring.json"
    write_json(context_path, context)

    keyring_entries = []
    current_input = context_path
    final_output: Path | None = None

    for index, signer in enumerate(signers):
        private_key_path = case_dir / f"private-key-{index:02d}.json"
        output_path = case_dir / f"signed-{index + 1:02d}.json"

        write_json(
            private_key_path,
            {
                "algorithm": "ed25519",
                "private_key": b64url(signer["seed"]),
            },
        )

        keyring_entries.append(
            {
                "signer_id": signer["signer_id"],
                "key_id": signer["key_id"],
                "algorithm": "ed25519",
                "public_key": b64url(public_key(signer["seed"])),
            }
        )

        completed = run(
            signer_command(
                input_path=current_input,
                private_key_path=private_key_path,
                signer=signer,
                output_path=output_path,
                append=index > 0,
            )
        )
        result = parse_output(completed, f"{name}:signer:{index}")

        if completed.returncode != 0:
            raise TestFailure(
                f"{name}: signer failed: {result!r}; "
                f"stderr={completed.stderr.strip()!r}"
            )

        expected_status = (
            "signed" if index == 0 else "signature_appended"
        )
        if result.get("status") != expected_status:
            raise TestFailure(
                f"{name}: expected signer status "
                f"{expected_status}, got {result!r}"
            )

        current_input = output_path
        final_output = output_path

    write_json(
        keyring_path,
        {
            "keys": sorted(
                keyring_entries,
                key=lambda entry: (
                    entry["signer_id"],
                    entry["key_id"],
                    entry["algorithm"],
                ),
            )
        },
    )

    assert final_output is not None
    return final_output, keyring_path


def evaluate_command(
    *,
    signed_path: Path,
    policy_path: Path,
    keyring_path: Path,
) -> subprocess.CompletedProcess[str]:
    return run(
        [
            sys.executable,
            str(EVALUATOR),
            str(signed_path),
            "--policy",
            str(policy_path),
            "--keyring",
            str(keyring_path),
        ]
    )


def execute_case(
    *,
    directory: Path,
    name: str,
    context: dict[str, Any],
    policy: dict[str, Any],
    signers: list[dict[str, Any]],
) -> tuple[
    subprocess.CompletedProcess[str],
    dict[str, Any],
    Path,
    Path,
]:
    case_dir = directory / name
    policy_path = case_dir / "policy.json"

    signed_path, keyring_path = create_signed_context(
        directory=directory,
        name=name,
        context=context,
        signers=signers,
    )
    write_json(policy_path, policy)

    completed = evaluate_command(
        signed_path=signed_path,
        policy_path=policy_path,
        keyring_path=keyring_path,
    )
    result = parse_output(completed, name)

    return completed, result, signed_path, keyring_path


def expect_satisfied(
    completed: subprocess.CompletedProcess[str],
    result: dict[str, Any],
    name: str,
) -> None:
    if completed.returncode != 0:
        raise TestFailure(
            f"{name}: expected return code 0, "
            f"got {completed.returncode}; result={result!r}"
        )

    if result.get("status") != "satisfied":
        raise TestFailure(
            f"{name}: expected satisfied, got {result!r}"
        )


def expect_unsatisfied(
    completed: subprocess.CompletedProcess[str],
    result: dict[str, Any],
    name: str,
    expected_codes: list[str],
) -> None:
    if completed.returncode != 2:
        raise TestFailure(
            f"{name}: expected return code 2, "
            f"got {completed.returncode}; result={result!r}"
        )

    if result.get("status") != "unsatisfied":
        raise TestFailure(
            f"{name}: expected unsatisfied, got {result!r}"
        )

    actual = result.get("failure_codes")
    if actual != expected_codes:
        raise TestFailure(
            f"{name}: expected failures={expected_codes}, got {actual}"
        )


def expect_error(
    completed: subprocess.CompletedProcess[str],
    result: dict[str, Any],
    name: str,
    expected_code: str,
) -> None:
    if completed.returncode != 1:
        raise TestFailure(
            f"{name}: expected return code 1, "
            f"got {completed.returncode}; result={result!r}"
        )

    if result.get("status") != "error":
        raise TestFailure(
            f"{name}: expected status=error, got {result!r}"
        )

    if result.get("error_code") != expected_code:
        raise TestFailure(
            f"{name}: expected error={expected_code}, "
            f"got {result.get('error_code')}"
        )


def print_pass(name: str, detail: str) -> None:
    print(f"PASS  {name:<44} {detail}")


def result_by_id(
    evaluation: dict[str, Any],
    requirement_id: str,
) -> dict[str, Any]:
    for item in evaluation.get("requirement_results", []):
        if item.get("requirement_id") == requirement_id:
            return item
    raise TestFailure(
        f"requirement result not found: {requirement_id}"
    )


def main() -> int:
    passed = 0
    total = 18

    with tempfile.TemporaryDirectory(
        prefix="agp-tpe-2-conformance-"
    ) as directory:
        temp = Path(directory)
        policy = base_policy()
        participants = base_participants()

        # 1
        completed, result, _, _ = execute_case(
            directory=temp,
            name="satisfied_all_primitives",
            context=context_value(
                policy=policy,
                participants=participants,
            ),
            policy=policy,
            signers=[LEGAL, FINANCE],
        )
        expect_satisfied(completed, result, "satisfied_all_primitives")

        if result["matched_signers"] != [
            "authority:finance",
            "authority:legal",
        ]:
            raise TestFailure(
                "satisfied_all_primitives: unexpected matched_signers"
            )
        if result["signature_count"] != 2 or result["weight"] != 3:
            raise TestFailure(
                "satisfied_all_primitives: unexpected totals"
            )
        if len(result["requirement_results"]) != 4:
            raise TestFailure(
                "satisfied_all_primitives: expected four results"
            )

        print_pass(
            "satisfied_all_primitives",
            "requirements=4 count=2 weight=3",
        )
        passed += 1

        # 2
        completed, result, _, _ = execute_case(
            directory=temp,
            name="required_signer_missing",
            context=context_value(
                policy=policy,
                participants=participants,
            ),
            policy=policy,
            signers=[FINANCE, SECURITY],
        )
        expect_unsatisfied(
            completed,
            result,
            "required_signer_missing",
            ["REQUIRED_SIGNER_MISSING"],
        )
        item = result_by_id(result, "requirement:legal")
        if item["status"] != "unsatisfied":
            raise TestFailure(
                "required_signer_missing: primitive result not failed"
            )
        print_pass(
            "required_signer_missing",
            "failure=REQUIRED_SIGNER_MISSING",
        )
        passed += 1

        # 3
        threshold_policy = deepcopy(policy)
        threshold_policy["requirements"][3]["minimum_signatures"] = 2

        completed, result, _, _ = execute_case(
            directory=temp,
            name="signer_threshold_not_reached",
            context=context_value(
                policy=threshold_policy,
                participants=participants,
            ),
            policy=threshold_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_unsatisfied(
            completed,
            result,
            "signer_threshold_not_reached",
            ["SIGNER_THRESHOLD_NOT_REACHED"],
        )
        print_pass(
            "signer_threshold_not_reached",
            "risk-function=1/2",
        )
        passed += 1

        # 4
        count_policy = deepcopy(policy)
        count_policy["requirements"][0]["minimum_signatures"] = 3

        completed, result, _, _ = execute_case(
            directory=temp,
            name="global_signature_threshold_not_reached",
            context=context_value(
                policy=count_policy,
                participants=participants,
            ),
            policy=count_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_unsatisfied(
            completed,
            result,
            "global_signature_threshold_not_reached",
            ["GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"],
        )
        print_pass(
            "global_signature_threshold_not_reached",
            "count=2 required=3",
        )
        passed += 1

        # 5
        weight_policy = deepcopy(policy)
        weight_policy["requirements"][1]["minimum_weight"] = 5

        completed, result, _, _ = execute_case(
            directory=temp,
            name="global_weight_threshold_not_reached",
            context=context_value(
                policy=weight_policy,
                participants=participants,
            ),
            policy=weight_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_unsatisfied(
            completed,
            result,
            "global_weight_threshold_not_reached",
            ["GLOBAL_WEIGHT_THRESHOLD_NOT_REACHED"],
        )
        print_pass(
            "global_weight_threshold_not_reached",
            "weight=3 required=5",
        )
        passed += 1

        # 6: failure order follows deterministic requirement order.
        multi_policy = deepcopy(policy)
        multi_policy["requirements"][0]["minimum_signatures"] = 3
        multi_policy["requirements"][1]["minimum_weight"] = 5
        multi_policy["requirements"][3]["minimum_signatures"] = 2

        completed, result, _, _ = execute_case(
            directory=temp,
            name="multiple_failures_deterministic_order",
            context=context_value(
                policy=multi_policy,
                participants=participants,
            ),
            policy=multi_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_unsatisfied(
            completed,
            result,
            "multiple_failures_deterministic_order",
            [
                "GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED",
                "GLOBAL_WEIGHT_THRESHOLD_NOT_REACHED",
                "SIGNER_THRESHOLD_NOT_REACHED",
            ],
        )
        print_pass(
            "multiple_failures_deterministic_order",
            "order=requirement_id",
        )
        passed += 1

        # 7
        role_policy = deepcopy(policy)
        role_policy["requirements"] = [
            {
                "requirement_id": "requirement:count",
                "type": "global_signature_threshold",
                "minimum_signatures": 2,
            }
        ]

        completed, result, _, _ = execute_case(
            directory=temp,
            name="ineligible_role_excluded",
            context=context_value(
                policy=role_policy,
                participants=participants,
            ),
            policy=role_policy,
            signers=[LEGAL, OBSERVER],
        )
        expect_unsatisfied(
            completed,
            result,
            "ineligible_role_excluded",
            ["GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"],
        )
        if result["ineligible_role_signers"] != [
            "authority:observer"
        ]:
            raise TestFailure(
                "ineligible_role_excluded: observer not reported"
            )
        print_pass(
            "ineligible_role_excluded",
            "observer=not_counted",
        )
        passed += 1

        # 8
        completed, result, _, _ = execute_case(
            directory=temp,
            name="unknown_participant_excluded",
            context=context_value(
                policy=role_policy,
                participants=participants,
            ),
            policy=role_policy,
            signers=[LEGAL, OUTSIDER],
        )
        expect_unsatisfied(
            completed,
            result,
            "unknown_participant_excluded",
            ["GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"],
        )
        if result["unauthorized_signers"] != [
            "authority:outsider"
        ]:
            raise TestFailure(
                "unknown_participant_excluded: outsider not reported"
            )
        print_pass(
            "unknown_participant_excluded",
            "outsider=not_counted",
        )
        passed += 1

        # 9
        dedup_policy = deepcopy(role_policy)
        dedup_policy["requirements"][0]["minimum_signatures"] = 3

        completed, result, _, _ = execute_case(
            directory=temp,
            name="same_signer_multiple_keys_counted_once",
            context=context_value(
                policy=dedup_policy,
                participants=participants,
            ),
            policy=dedup_policy,
            signers=[LEGAL, LEGAL_SECOND_KEY, FINANCE],
        )
        expect_unsatisfied(
            completed,
            result,
            "same_signer_multiple_keys_counted_once",
            ["GLOBAL_SIGNATURE_THRESHOLD_NOT_REACHED"],
        )
        if len(result["verified_signature_ids"]) != 3:
            raise TestFailure(
                "same_signer_multiple_keys_counted_once: "
                "expected three verified signatures"
            )
        if result["signature_count"] != 2:
            raise TestFailure(
                "same_signer_multiple_keys_counted_once: "
                "expected two identities"
            )
        print_pass(
            "same_signer_multiple_keys_counted_once",
            "signatures=3 identities=2",
        )
        passed += 1

        # 10
        invalid_policy = deepcopy(policy)
        invalid_policy["requirements"][1]["requirement_id"] = (
            invalid_policy["requirements"][0]["requirement_id"]
        )

        completed, result, _, _ = execute_case(
            directory=temp,
            name="duplicate_requirement_id_rejected",
            context=context_value(
                policy=invalid_policy,
                participants=participants,
            ),
            policy=invalid_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "duplicate_requirement_id_rejected",
            "INVALID_TRUST_POLICY",
        )
        print_pass(
            "duplicate_requirement_id_rejected",
            "error=INVALID_TRUST_POLICY",
        )
        passed += 1

        # 11
        invalid_policy = deepcopy(policy)
        invalid_policy["requirements"] = list(
            reversed(invalid_policy["requirements"])
        )

        completed, result, _, _ = execute_case(
            directory=temp,
            name="unsorted_requirements_rejected",
            context=context_value(
                policy=invalid_policy,
                participants=participants,
            ),
            policy=invalid_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "unsorted_requirements_rejected",
            "INVALID_TRUST_POLICY",
        )
        print_pass(
            "unsorted_requirements_rejected",
            "error=INVALID_TRUST_POLICY",
        )
        passed += 1

        # 12
        invalid_policy = deepcopy(policy)
        invalid_policy["requirements"] = [
            {
                "requirement_id": "requirement:future",
                "type": "future_primitive",
            }
        ]

        completed, result, _, _ = execute_case(
            directory=temp,
            name="unsupported_primitive_rejected",
            context=context_value(
                policy=invalid_policy,
                participants=participants,
            ),
            policy=invalid_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "unsupported_primitive_rejected",
            "UNSUPPORTED_TRUST_PRIMITIVE",
        )
        print_pass(
            "unsupported_primitive_rejected",
            "error=UNSUPPORTED_TRUST_PRIMITIVE",
        )
        passed += 1

        # 13
        invalid_policy = deepcopy(policy)
        invalid_policy["requirements"][3]["minimum_signatures"] = 3

        completed, result, _, _ = execute_case(
            directory=temp,
            name="threshold_exceeds_group_rejected",
            context=context_value(
                policy=invalid_policy,
                participants=participants,
            ),
            policy=invalid_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "threshold_exceeds_group_rejected",
            "INVALID_TRUST_POLICY",
        )
        print_pass(
            "threshold_exceeds_group_rejected",
            "error=INVALID_TRUST_POLICY",
        )
        passed += 1

        # 14
        actual_policy = base_policy()
        provided_policy = deepcopy(actual_policy)
        provided_policy["policy_id"] = "policy:other-change"

        completed, result, _, _ = execute_case(
            directory=temp,
            name="policy_id_mismatch",
            context=context_value(
                policy=actual_policy,
                participants=participants,
            ),
            policy=provided_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "policy_id_mismatch",
            "POLICY_ID_MISMATCH",
        )
        print_pass(
            "policy_id_mismatch",
            "error=POLICY_ID_MISMATCH",
        )
        passed += 1

        # 15
        provided_policy = deepcopy(actual_policy)
        provided_policy["version"] = 3

        completed, result, _, _ = execute_case(
            directory=temp,
            name="policy_version_mismatch",
            context=context_value(
                policy=actual_policy,
                participants=participants,
            ),
            policy=provided_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "policy_version_mismatch",
            "POLICY_VERSION_MISMATCH",
        )
        print_pass(
            "policy_version_mismatch",
            "error=POLICY_VERSION_MISMATCH",
        )
        passed += 1

        # 16
        completed, result, _, _ = execute_case(
            directory=temp,
            name="policy_digest_mismatch",
            context=context_value(
                policy=actual_policy,
                participants=participants,
                digest="0" * 64,
            ),
            policy=actual_policy,
            signers=[LEGAL, FINANCE],
        )
        expect_error(
            completed,
            result,
            "policy_digest_mismatch",
            "POLICY_DIGEST_MISMATCH",
        )
        print_pass(
            "policy_digest_mismatch",
            "error=POLICY_DIGEST_MISMATCH",
        )
        passed += 1

        # 17
        _, _, signed_path, keyring_path = execute_case(
            directory=temp,
            name="invalid_signature_rejected_setup",
            context=context_value(
                policy=policy,
                participants=participants,
            ),
            policy=policy,
            signers=[LEGAL, FINANCE],
        )

        tampered = read_json(signed_path)
        signature = tampered["signatures"][0]["signature"]
        padding = "=" * ((4 - len(signature) % 4) % 4)
        signature_bytes = bytearray(
            base64.urlsafe_b64decode(signature + padding)
        )
        signature_bytes[0] ^= 0x01
        tampered["signatures"][0]["signature"] = b64url(
            bytes(signature_bytes)
        )

        case_dir = temp / "invalid_signature_rejected_setup"
        tampered_path = case_dir / "tampered.json"
        policy_path = case_dir / "policy.json"
        write_json(tampered_path, tampered)

        completed = evaluate_command(
            signed_path=tampered_path,
            policy_path=policy_path,
            keyring_path=keyring_path,
        )
        result = parse_output(
            completed,
            "invalid_signature_rejected",
        )
        expect_error(
            completed,
            result,
            "invalid_signature_rejected",
            "SIGNATURE_VERIFICATION_FAILED",
        )
        print_pass(
            "invalid_signature_rejected",
            "error=SIGNATURE_VERIFICATION_FAILED",
        )
        passed += 1

        # 18
        deterministic_dir = temp / "deterministic_evaluation"
        deterministic_policy_path = deterministic_dir / "policy.json"

        signed_path, keyring_path = create_signed_context(
            directory=temp,
            name="deterministic_evaluation",
            context=context_value(
                policy=policy,
                participants=participants,
            ),
            signers=[LEGAL, FINANCE],
        )
        write_json(deterministic_policy_path, policy)

        completed_one = evaluate_command(
            signed_path=signed_path,
            policy_path=deterministic_policy_path,
            keyring_path=keyring_path,
        )
        completed_two = evaluate_command(
            signed_path=signed_path,
            policy_path=deterministic_policy_path,
            keyring_path=keyring_path,
        )

        result_one = parse_output(
            completed_one,
            "deterministic_evaluation:first",
        )
        result_two = parse_output(
            completed_two,
            "deterministic_evaluation:second",
        )

        expect_satisfied(
            completed_one,
            result_one,
            "deterministic_evaluation:first",
        )
        expect_satisfied(
            completed_two,
            result_two,
            "deterministic_evaluation:second",
        )

        if completed_one.stdout != completed_two.stdout:
            raise TestFailure(
                "deterministic_evaluation: output bytes differ"
            )

        print_pass(
            "deterministic_evaluation",
            "bytes=identical",
        )
        passed += 1

    print(
        "AGP Trust Primitive Engine 2.0 conformance: "
        f"{passed}/{total} passed"
    )
    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
