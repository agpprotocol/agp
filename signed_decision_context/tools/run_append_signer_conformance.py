#!/usr/bin/env python3
"""Conformance tests for appending Signed Decision Context signatures."""

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

PYTHON_VERIFIER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "verify_signed_decision_context.py"
)

GO_MODULE = ROOT / "signed_decision_context" / "go"
GO_PACKAGE = "./cmd/agp-signed-decision-context-verify"

LEGAL_SEED = bytes(range(1, 33))
FINANCE_SEED = bytes(range(33, 65))


class TestFailure(Exception):
    pass


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )


def run(
    command: list[str],
    *,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_result(
    completed: subprocess.CompletedProcess[str],
    name: str,
) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise TestFailure(
            f"{name}: invalid JSON output "
            f"stdout={completed.stdout!r} "
            f"stderr={completed.stderr!r}"
        ) from exc

    if not isinstance(value, dict):
        raise TestFailure(
            f"{name}: output is not an object"
        )

    return value


def public_key(seed: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(seed)

    return key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )


def base_context() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/1",
        "context_id": "ctx:append:test:001",
        "created_at": "2026-07-22T20:00:00Z",
        "expires_at": None,
        "policy": {
            "id": "policy:example:approval",
            "version": 1,
            "digest": "1" * 64,
        },
        "proposal": {
            "type": "proposal:example:change",
            "payload": {
                "enabled": True,
            },
        },
        "participants": [
            {
                "id": "authority:finance",
                "role": "approver",
                "weight": 1,
            },
            {
                "id": "authority:legal",
                "role": "approver",
                "weight": 1,
            },
        ],
        "evidence": [],
        "constraints": [],
    }


def signer_command(
    *,
    input_path: Path,
    private_key_path: Path,
    signer_id: str,
    key_id: str,
    signature_id: str,
    signed_at: str,
    output_path: Path,
    append: bool = False,
) -> list[str]:
    command = [
        sys.executable,
        str(SIGNER),
        str(input_path),
        "--private-key",
        str(private_key_path),
        "--signer-id",
        signer_id,
        "--key-id",
        key_id,
        "--signature-id",
        signature_id,
        "--signed-at",
        signed_at,
        "--output",
        str(output_path),
    ]

    if append:
        command.append("--append")

    return command


def expect_success(
    completed: subprocess.CompletedProcess[str],
    name: str,
    expected_status: str,
) -> dict[str, Any]:
    result = parse_result(completed, name)

    if completed.returncode != 0:
        raise TestFailure(
            f"{name}: failed with {result!r}; "
            f"stderr={completed.stderr.strip()}"
        )

    if result.get("status") != expected_status:
        raise TestFailure(
            f"{name}: expected status={expected_status}, "
            f"got {result!r}"
        )

    return result


def expect_error(
    completed: subprocess.CompletedProcess[str],
    name: str,
    expected_code: str,
) -> None:
    result = parse_result(completed, name)

    if completed.returncode == 0:
        raise TestFailure(
            f"{name}: expected failure"
        )

    if result.get("status") != "error":
        raise TestFailure(
            f"{name}: expected status=error, got {result!r}"
        )

    if result.get("error_code") != expected_code:
        raise TestFailure(
            f"{name}: expected {expected_code}, "
            f"got {result.get('error_code')}"
        )


def main() -> int:
    passed = 0
    total = 8

    with tempfile.TemporaryDirectory(
        prefix="agp-append-conformance-"
    ) as directory:
        temp = Path(directory)

        context_path = temp / "context.json"
        legal_key_path = temp / "legal-private.json"
        finance_key_path = temp / "finance-private.json"
        keyring_path = temp / "keyring.json"

        signed_one = temp / "signed-one.json"
        signed_two = temp / "signed-two.json"
        signed_two_repeat = temp / "signed-two-repeat.json"

        write_json(context_path, base_context())

        write_json(
            legal_key_path,
            {
                "algorithm": "ed25519",
                "private_key": b64url(LEGAL_SEED),
            },
        )

        write_json(
            finance_key_path,
            {
                "algorithm": "ed25519",
                "private_key": b64url(FINANCE_SEED),
            },
        )

        write_json(
            keyring_path,
            {
                "keys": [
                    {
                        "signer_id": "authority:finance",
                        "key_id": "key:finance:2026-q3",
                        "algorithm": "ed25519",
                        "public_key": b64url(
                            public_key(FINANCE_SEED)
                        ),
                    },
                    {
                        "signer_id": "authority:legal",
                        "key_id": "key:legal:2026-q3",
                        "algorithm": "ed25519",
                        "public_key": b64url(
                            public_key(LEGAL_SEED)
                        ),
                    },
                ]
            },
        )

        completed = run(
            signer_command(
                input_path=context_path,
                private_key_path=legal_key_path,
                signer_id="authority:legal",
                key_id="key:legal:2026-q3",
                signature_id="sig:legal:0002",
                signed_at="2026-07-22T20:00:00Z",
                output_path=signed_one,
            )
        )

        result = expect_success(
            completed,
            "create_first_signature",
            "signed",
        )

        if result.get("signature_count") != 1:
            raise TestFailure(
                "create_first_signature: expected one signature"
            )

        print(
            "PASS  create_first_signature             "
            "signature_count=1"
        )
        passed += 1

        first_value = json.loads(
            signed_one.read_text(encoding="utf-8")
        )
        first_signature = deepcopy(
            first_value["signatures"][0]
        )
        first_context_bytes = json.dumps(
            first_value["context"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        completed = run(
            signer_command(
                input_path=signed_one,
                private_key_path=finance_key_path,
                signer_id="authority:finance",
                key_id="key:finance:2026-q3",
                signature_id="sig:finance:0001",
                signed_at="2026-07-22T20:01:00Z",
                output_path=signed_two,
                append=True,
            )
        )

        result = expect_success(
            completed,
            "append_second_signature",
            "signature_appended",
        )

        if result.get("signature_count") != 2:
            raise TestFailure(
                "append_second_signature: expected two signatures"
            )

        print(
            "PASS  append_second_signature            "
            "signature_count=2"
        )
        passed += 1

        second_value = json.loads(
            signed_two.read_text(encoding="utf-8")
        )

        actual_ids = [
            entry["signature_id"]
            for entry in second_value["signatures"]
        ]

        expected_ids = [
            "sig:finance:0001",
            "sig:legal:0002",
        ]

        if actual_ids != expected_ids:
            raise TestFailure(
                "sorted_signatures: "
                f"expected {expected_ids}, got {actual_ids}"
            )

        print(
            "PASS  sorted_signatures                  "
            f"ids={actual_ids}"
        )
        passed += 1

        preserved = next(
            entry
            for entry in second_value["signatures"]
            if entry["signature_id"] == "sig:legal:0002"
        )

        if preserved != first_signature:
            raise TestFailure(
                "preserves_existing_signature: "
                "existing signature was modified"
            )

        second_context_bytes = json.dumps(
            second_value["context"],
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        if second_context_bytes != first_context_bytes:
            raise TestFailure(
                "preserves_existing_signature: context changed"
            )

        if (
            second_value["context_digest"]
            != first_value["context_digest"]
        ):
            raise TestFailure(
                "preserves_existing_signature: digest changed"
            )

        print(
            "PASS  preserves_existing_material        "
            "context,digest,signature=unchanged"
        )
        passed += 1

        completed = run(
            [
                sys.executable,
                str(PYTHON_VERIFIER),
                str(signed_two),
                "--keyring",
                str(keyring_path),
            ]
        )

        result = expect_success(
            completed,
            "python_verifies_two_signatures",
            "verified",
        )

        if result.get("verified_signature_count") != 2:
            raise TestFailure(
                "python_verifies_two_signatures: "
                "expected two verified signatures"
            )

        print(
            "PASS  python_verifies_two_signatures     "
            "verified=2"
        )
        passed += 1

        completed = run(
            [
                "go",
                "run",
                GO_PACKAGE,
                str(signed_two),
                "--keyring",
                str(keyring_path),
            ],
            cwd=GO_MODULE,
        )

        result = expect_success(
            completed,
            "go_verifies_two_signatures",
            "verified",
        )

        if result.get("verified_signature_count") != 2:
            raise TestFailure(
                "go_verifies_two_signatures: "
                "expected two verified signatures"
            )

        print(
            "PASS  go_verifies_two_signatures         "
            "verified=2"
        )
        passed += 1

        duplicate_output = temp / "duplicate.json"

        completed = run(
            signer_command(
                input_path=signed_two,
                private_key_path=finance_key_path,
                signer_id="authority:finance",
                key_id="key:finance:2026-q3",
                signature_id="sig:finance:0001",
                signed_at="2026-07-22T20:02:00Z",
                output_path=duplicate_output,
                append=True,
            )
        )

        expect_error(
            completed,
            "duplicate_signature_id",
            "DUPLICATE_SIGNATURE_ID",
        )

        if duplicate_output.exists():
            raise TestFailure(
                "duplicate_signature_id: output was created"
            )

        print(
            "PASS  duplicate_signature_id             "
            "error=DUPLICATE_SIGNATURE_ID"
        )
        passed += 1

        completed = run(
            signer_command(
                input_path=signed_one,
                private_key_path=finance_key_path,
                signer_id="authority:finance",
                key_id="key:finance:2026-q3",
                signature_id="sig:finance:0001",
                signed_at="2026-07-22T20:01:00Z",
                output_path=signed_two_repeat,
                append=True,
            )
        )

        expect_success(
            completed,
            "deterministic_append",
            "signature_appended",
        )

        if signed_two.read_bytes() != signed_two_repeat.read_bytes():
            raise TestFailure(
                "deterministic_append: output bytes differ"
            )

        print(
            "PASS  deterministic_append               "
            "bytes=identical"
        )
        passed += 1

    print(
        "AGP Signed Decision Context 1.0 append "
        f"conformance: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
