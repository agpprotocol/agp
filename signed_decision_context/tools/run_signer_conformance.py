#!/usr/bin/env python3
"""End-to-end conformance tests for the Python SDC signer."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
except ImportError as exc:
    raise SystemExit(
        "cryptography is required: pip install 'cryptography>=42.0'"
    ) from exc


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

SIGNER_ID = "authority:legal"
KEY_ID = "key:authority-legal:2026-q3"
SIGNATURE_ID = "sig:authority-legal:0001"
SIGNED_AT = "2026-07-22T20:00:00Z"

PRIVATE_SEED = bytes(range(1, 33))


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


def parse_json_output(
    completed: subprocess.CompletedProcess[str],
    name: str,
) -> dict[str, Any]:
    output = completed.stdout.strip()

    if not output:
        raise TestFailure(
            f"{name}: command produced no JSON output\n"
            f"stderr={completed.stderr.strip()}"
        )

    try:
        value = json.loads(output)
    except json.JSONDecodeError as exc:
        raise TestFailure(
            f"{name}: invalid JSON output: {output!r}\n"
            f"stderr={completed.stderr.strip()}"
        ) from exc

    if not isinstance(value, dict):
        raise TestFailure(
            f"{name}: output must be a JSON object"
        )

    return value


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


def context_value() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/1",
        "context_id": "ctx:signer:test:001",
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
                "id": SIGNER_ID,
                "role": "approver",
                "weight": 1,
            }
        ],
        "evidence": [],
        "constraints": [],
    }


def signer_command(
    context_path: Path,
    private_key_path: Path,
    output_path: Path,
) -> list[str]:
    return [
        sys.executable,
        str(SIGNER),
        str(context_path),
        "--private-key",
        str(private_key_path),
        "--signer-id",
        SIGNER_ID,
        "--key-id",
        KEY_ID,
        "--signature-id",
        SIGNATURE_ID,
        "--signed-at",
        SIGNED_AT,
        "--output",
        str(output_path),
    ]


def expect_signer_error(
    *,
    name: str,
    context_path: Path,
    private_key_path: Path,
    output_path: Path,
    expected_code: str,
) -> None:
    completed = run(
        signer_command(
            context_path,
            private_key_path,
            output_path,
        )
    )

    result = parse_json_output(completed, name)

    actual = result.get("error_code")

    if completed.returncode == 0:
        raise TestFailure(
            f"{name}: expected failure but command succeeded"
        )

    if result.get("status") != "error":
        raise TestFailure(
            f"{name}: expected status=error, got {result!r}"
        )

    if actual != expected_code:
        raise TestFailure(
            f"{name}: expected {expected_code}, got {actual}"
        )

    if output_path.exists():
        raise TestFailure(
            f"{name}: signer created output after failure"
        )

    print(
        f"PASS  {name:<34} "
        f"error={actual}"
    )


def main() -> int:
    passed = 0
    total = 7

    private_key = Ed25519PrivateKey.from_private_bytes(
        PRIVATE_SEED
    )

    public_key = private_key.public_key().public_bytes(
        Encoding.Raw,
        PublicFormat.Raw,
    )

    with tempfile.TemporaryDirectory(
        prefix="agp-signer-conformance-"
    ) as directory:
        temp = Path(directory)

        context_path = temp / "context.json"
        private_key_path = temp / "private-key.json"
        keyring_path = temp / "keyring.json"
        output_one = temp / "signed-one.json"
        output_two = temp / "signed-two.json"

        write_json(
            context_path,
            context_value(),
        )

        write_json(
            private_key_path,
            {
                "algorithm": "ed25519",
                "private_key": b64url(PRIVATE_SEED),
            },
        )

        write_json(
            keyring_path,
            {
                "keys": [
                    {
                        "signer_id": SIGNER_ID,
                        "key_id": KEY_ID,
                        "algorithm": "ed25519",
                        "public_key": b64url(public_key),
                    }
                ]
            },
        )

        completed = run(
            signer_command(
                context_path,
                private_key_path,
                output_one,
            )
        )

        result = parse_json_output(
            completed,
            "valid_signing",
        )

        if completed.returncode != 0:
            raise TestFailure(
                "valid_signing failed: "
                f"{result!r} stderr={completed.stderr.strip()}"
            )

        if result.get("status") != "signed":
            raise TestFailure(
                f"valid_signing: unexpected result {result!r}"
            )

        private_text = b64url(PRIVATE_SEED)

        if (
            private_text in completed.stdout
            or private_text in completed.stderr
        ):
            raise TestFailure(
                "valid_signing: private key leaked to output"
            )

        if not output_one.is_file():
            raise TestFailure(
                "valid_signing: output file was not created"
            )

        print(
            "PASS  valid_signing                      "
            "status=signed"
        )
        passed += 1

        completed = run(
            [
                sys.executable,
                str(PYTHON_VERIFIER),
                str(output_one),
                "--keyring",
                str(keyring_path),
            ]
        )

        result = parse_json_output(
            completed,
            "python_verification",
        )

        if (
            completed.returncode != 0
            or result.get("status") != "verified"
            or result.get("verified_signature_ids")
            != [SIGNATURE_ID]
        ):
            raise TestFailure(
                "python_verification failed: "
                f"{result!r} stderr={completed.stderr.strip()}"
            )

        print(
            "PASS  python_verification                "
            "status=verified"
        )
        passed += 1

        completed = run(
            [
                "go",
                "run",
                GO_PACKAGE,
                str(output_one),
                "--keyring",
                str(keyring_path),
            ],
            cwd=GO_MODULE,
        )

        result = parse_json_output(
            completed,
            "go_verification",
        )

        if (
            completed.returncode != 0
            or result.get("status") != "verified"
            or result.get("verified_signature_ids")
            != [SIGNATURE_ID]
        ):
            raise TestFailure(
                "go_verification failed: "
                f"{result!r} stderr={completed.stderr.strip()}"
            )

        print(
            "PASS  go_verification                    "
            "status=verified"
        )
        passed += 1

        completed = run(
            signer_command(
                context_path,
                private_key_path,
                output_two,
            )
        )

        result = parse_json_output(
            completed,
            "deterministic_output",
        )

        if completed.returncode != 0:
            raise TestFailure(
                f"deterministic_output failed: {result!r}"
            )

        if output_one.read_bytes() != output_two.read_bytes():
            raise TestFailure(
                "deterministic_output: output bytes differ"
            )

        print(
            "PASS  deterministic_output               "
            "bytes=identical"
        )
        passed += 1

        padded_key = temp / "private-key-padded.json"
        padded_output = temp / "padded-output.json"

        write_json(
            padded_key,
            {
                "algorithm": "ed25519",
                "private_key": b64url(PRIVATE_SEED) + "=",
            },
        )

        expect_signer_error(
            name="padded_private_key",
            context_path=context_path,
            private_key_path=padded_key,
            output_path=padded_output,
            expected_code="INVALID_PRIVATE_KEY_ENCODING",
        )
        passed += 1

        short_key = temp / "private-key-short.json"
        short_output = temp / "short-output.json"

        write_json(
            short_key,
            {
                "algorithm": "ed25519",
                "private_key": b64url(b"\x01" * 31),
            },
        )

        expect_signer_error(
            name="invalid_private_key_length",
            context_path=context_path,
            private_key_path=short_key,
            output_path=short_output,
            expected_code="INVALID_PRIVATE_KEY_LENGTH",
        )
        passed += 1

        unsupported_key = temp / "private-key-rsa.json"
        unsupported_output = temp / "rsa-output.json"

        write_json(
            unsupported_key,
            {
                "algorithm": "rsa-pss",
                "private_key": b64url(PRIVATE_SEED),
            },
        )

        expect_signer_error(
            name="unsupported_algorithm",
            context_path=context_path,
            private_key_path=unsupported_key,
            output_path=unsupported_output,
            expected_code="UNSUPPORTED_SIGNATURE_ALGORITHM",
        )
        passed += 1

    print(
        "AGP Signed Decision Context 1.0 signer "
        f"conformance: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
