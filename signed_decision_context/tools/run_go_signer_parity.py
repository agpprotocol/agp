#!/usr/bin/env python3
"""Verify byte-identical Python/Go Signed Decision Context signing."""

from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)


ROOT = Path(__file__).resolve().parents[2]

PYTHON_SIGNER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "sign_decision_context.py"
)

SIGNER_V3_CONFORMANCE = (
    ROOT
    / "signed_decision_context"
    / "tools"
    / "run_signer_v3_conformance.py"
)

GO_DIR = ROOT / "signed_decision_context" / "go"

GO_SIGNER_BINARY = (
    GO_DIR
    / "agp-signed-decision-context-sign"
)

GO_VERIFIER_BINARY = (
    GO_DIR
    / "agp-signed-decision-context-verify"
)


class ParityFailure(RuntimeError):
    pass


def load_signer_fixture_module() -> Any:
    spec = importlib.util.spec_from_file_location(
        "sdc_signer_v3_fixture",
        SIGNER_V3_CONFORMANCE,
    )

    if spec is None or spec.loader is None:
        raise ParityFailure(
            "unable to load v3 signer conformance fixtures"
        )

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )


def run_json(
    command: list[str],
    *,
    cwd: Path,
    label: str,
) -> dict[str, Any]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.returncode != 0:
        raise ParityFailure(
            f"{label} failed with exit code "
            f"{completed.returncode}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )

    try:
        result = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ParityFailure(
            f"{label} returned invalid JSON:\n"
            f"{completed.stdout}"
        ) from exc

    if not isinstance(result, dict):
        raise ParityFailure(
            f"{label} did not return a JSON object"
        )

    return result


def build_go_binary(
    output: Path,
    package: str,
    label: str,
) -> None:
    completed = subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(output),
            package,
        ],
        cwd=GO_DIR,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.returncode != 0:
        raise ParityFailure(
            f"unable to build {label}\n"
            f"stdout:\n{completed.stdout}\n"
            f"stderr:\n{completed.stderr}"
        )


def signer_command(
    executable: list[str],
    *,
    input_path: Path,
    private_key_path: Path,
    output_path: Path,
    signer_id: str,
    key_id: str,
    signature_id: str,
    signed_at: str,
    append: bool = False,
) -> list[str]:
    command = [
        *executable,
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


def public_key(seed: bytes) -> bytes:
    private_key = Ed25519PrivateKey.from_private_bytes(seed)

    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def main() -> int:
    fixtures = load_signer_fixture_module()

    legal_seed: bytes = fixtures.LEGAL_SEED
    finance_seed: bytes = fixtures.FINANCE_SEED
    context: dict[str, Any] = fixtures.context_v3()

    passed = 0
    total = 4

    try:
        build_go_binary(
            GO_SIGNER_BINARY,
            "./cmd/agp-signed-decision-context-sign",
            "Go signer",
        )
        build_go_binary(
            GO_VERIFIER_BINARY,
            "./cmd/agp-signed-decision-context-verify",
            "Go verifier",
        )

        with tempfile.TemporaryDirectory(
            prefix="agp-go-signer-parity-",
        ) as raw_temp:
            temp = Path(raw_temp)

            context_path = temp / "context.json"
            legal_private = temp / "legal-private.json"
            finance_private = temp / "finance-private.json"
            keyring_path = temp / "keyring.json"

            python_one = temp / "python-one.json"
            go_one = temp / "go-one.json"
            python_two = temp / "python-two.json"
            go_two = temp / "go-two.json"
            go_two_repeat = temp / "go-two-repeat.json"

            write_json(context_path, context)

            write_json(
                legal_private,
                {
                    "algorithm": "ed25519",
                    "private_key": b64url(legal_seed),
                },
            )
            write_json(
                finance_private,
                {
                    "algorithm": "ed25519",
                    "private_key": b64url(finance_seed),
                },
            )

            create_metadata = {
                "signer_id": "authority:legal",
                "key_id": "key:legal:2026-q3",
                "signature_id": "sig:legal:0002",
                "signed_at": "2026-07-25T20:00:00Z",
            }

            python_create = run_json(
                signer_command(
                    [sys.executable, str(PYTHON_SIGNER)],
                    input_path=context_path,
                    private_key_path=legal_private,
                    output_path=python_one,
                    **create_metadata,
                ),
                cwd=ROOT,
                label="Python create",
            )

            go_create = run_json(
                signer_command(
                    [str(GO_SIGNER_BINARY)],
                    input_path=context_path,
                    private_key_path=legal_private,
                    output_path=go_one,
                    **create_metadata,
                ),
                cwd=ROOT,
                label="Go create",
            )

            create_passed = (
                python_create.get("status") == "signed"
                and go_create.get("status") == "signed"
                and python_one.read_bytes() == go_one.read_bytes()
            )

            print(
                f"{'PASS' if create_passed else 'FAIL'}  "
                "create_python_go_byte_parity"
            )

            if not create_passed:
                raise ParityFailure(
                    "Python and Go create outputs differ"
                )

            passed += 1

            append_metadata = {
                "signer_id": "authority:finance",
                "key_id": "key:finance:2026-q3",
                "signature_id": "sig:finance:0001",
                "signed_at": "2026-07-25T20:01:00Z",
            }

            python_append = run_json(
                signer_command(
                    [sys.executable, str(PYTHON_SIGNER)],
                    input_path=python_one,
                    private_key_path=finance_private,
                    output_path=python_two,
                    append=True,
                    **append_metadata,
                ),
                cwd=ROOT,
                label="Python append",
            )

            go_append = run_json(
                signer_command(
                    [str(GO_SIGNER_BINARY)],
                    input_path=go_one,
                    private_key_path=finance_private,
                    output_path=go_two,
                    append=True,
                    **append_metadata,
                ),
                cwd=ROOT,
                label="Go append",
            )

            append_passed = (
                python_append.get("status")
                == "signature_appended"
                and go_append.get("status")
                == "signature_appended"
                and python_two.read_bytes() == go_two.read_bytes()
            )

            print(
                f"{'PASS' if append_passed else 'FAIL'}  "
                "append_python_go_byte_parity"
            )

            if not append_passed:
                raise ParityFailure(
                    "Python and Go append outputs differ"
                )

            passed += 1

            run_json(
                signer_command(
                    [str(GO_SIGNER_BINARY)],
                    input_path=go_one,
                    private_key_path=finance_private,
                    output_path=go_two_repeat,
                    append=True,
                    **append_metadata,
                ),
                cwd=ROOT,
                label="Go deterministic append",
            )

            deterministic_passed = (
                go_two.read_bytes()
                == go_two_repeat.read_bytes()
            )

            print(
                f"{'PASS' if deterministic_passed else 'FAIL'}  "
                "go_signer_deterministic_output"
            )

            if not deterministic_passed:
                raise ParityFailure(
                    "repeated Go signing produced different bytes"
                )

            passed += 1

            write_json(
                keyring_path,
                {
                    "keys": [
                        {
                            "signer_id": "authority:finance",
                            "key_id": "key:finance:2026-q3",
                            "algorithm": "ed25519",
                            "public_key": b64url(
                                public_key(finance_seed)
                            ),
                        },
                        {
                            "signer_id": "authority:legal",
                            "key_id": "key:legal:2026-q3",
                            "algorithm": "ed25519",
                            "public_key": b64url(
                                public_key(legal_seed)
                            ),
                        },
                    ],
                },
            )

            verified = run_json(
                [
                    str(GO_VERIFIER_BINARY),
                    str(go_two),
                    "--keyring",
                    str(keyring_path),
                ],
                cwd=ROOT,
                label="Go verification of Go signer output",
            )

            verification_passed = (
                verified.get("status") == "verified"
                and verified.get(
                    "verified_signature_count"
                ) == 2
            )

            print(
                f"{'PASS' if verification_passed else 'FAIL'}  "
                "go_signer_output_verified_by_go"
            )

            if not verification_passed:
                raise ParityFailure(
                    "Go verifier did not verify both signatures"
                )

            passed += 1

    except ParityFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)

    finally:
        GO_SIGNER_BINARY.unlink(missing_ok=True)
        GO_VERIFIER_BINARY.unlink(missing_ok=True)

    print(
        "AGP Signed Decision Context Go signer parity: "
        f"{passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
