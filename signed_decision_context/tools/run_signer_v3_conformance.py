#!/usr/bin/env python3
"""End-to-end conformance tests for Signed Decision Context v3 signing."""

from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

ROOT = Path(__file__).resolve().parents[2]
SIGNER = ROOT / "signed_decision_context/python/sign_decision_context.py"
VERIFIER = ROOT / "signed_decision_context/python/verify_signed_decision_context.py"
SCHEMA_DIR = ROOT / "registry/schemas"
GO_MODULE = ROOT / "signed_decision_context" / "go"
GO_PACKAGE = "./cmd/agp-signed-decision-context-verify"
LEGAL_SEED = bytes(range(1, 33))
FINANCE_SEED = bytes(range(33, 65))

class TestFailure(Exception):
    pass

def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

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

def parse_result(completed: subprocess.CompletedProcess[str], name: str) -> dict[str, Any]:
    try:
        value = json.loads(completed.stdout.strip())
    except json.JSONDecodeError as exc:
        raise TestFailure(f"{name}: invalid JSON output stdout={completed.stdout!r} stderr={completed.stderr!r}") from exc
    if not isinstance(value, dict):
        raise TestFailure(f"{name}: output is not an object")
    return value

def public_key(seed: bytes) -> bytes:
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

def context_v3() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/3",
        "context_id": "ctx:signer-v3:test:001",
        "created_at": "2026-07-25T20:00:00Z",
        "expires_at": None,
        "evaluation_time": 1785009600,
        "policy": {"id": "policy:example:approval", "version": 1, "digest": "1" * 64},
        "proposal": {"type": "proposal:example:change", "payload": {"enabled": True}},
        "participants": [
            {"id": "authority:finance", "role": "approver", "weight": 1},
            {"id": "authority:legal", "role": "approver", "weight": 1},
        ],
        "evidence": [{
            "id": "evidence.security-review",
            "digest": "2" * 64,
            "media_type": "application/json",
            "evidence_type": "agp.evidence.security-review/1",
            "issuer_id": "authority:security-lab",
        }],
        "constraints": [],
    }

def signer_command(*, input_path: Path, private_key_path: Path, signer_id: str, key_id: str, signature_id: str, signed_at: str, output_path: Path, append: bool = False) -> list[str]:
    command = [
        sys.executable, str(SIGNER), str(input_path),
        "--private-key", str(private_key_path),
        "--signer-id", signer_id,
        "--key-id", key_id,
        "--signature-id", signature_id,
        "--signed-at", signed_at,
        "--output", str(output_path),
        "--schema-dir", str(SCHEMA_DIR),
    ]
    if append:
        command.append("--append")
    return command

def expect_success(completed: subprocess.CompletedProcess[str], name: str, expected_status: str) -> dict[str, Any]:
    result = parse_result(completed, name)
    if completed.returncode != 0:
        raise TestFailure(f"{name}: failed with {result!r}; stderr={completed.stderr.strip()}")
    if result.get("status") != expected_status:
        raise TestFailure(f"{name}: expected status={expected_status}, got {result!r}")
    return result

def main() -> int:
    passed = 0
    total = 9
    with tempfile.TemporaryDirectory(prefix="agp-signer-v3-conformance-") as directory:
        temp = Path(directory)
        context_path = temp / "context-v3.json"
        legal_key_path = temp / "legal-private.json"
        finance_key_path = temp / "finance-private.json"
        keyring_path = temp / "keyring.json"
        signed_one = temp / "signed-one-v3.json"
        signed_two = temp / "signed-two-v3.json"
        signed_two_repeat = temp / "signed-two-v3-repeat.json"

        write_json(context_path, context_v3())
        write_json(legal_key_path, {"algorithm": "ed25519", "private_key": b64url(LEGAL_SEED)})
        write_json(finance_key_path, {"algorithm": "ed25519", "private_key": b64url(FINANCE_SEED)})
        write_json(keyring_path, {"keys": [
            {"signer_id": "authority:finance", "key_id": "key:finance:2026-q3", "algorithm": "ed25519", "public_key": b64url(public_key(FINANCE_SEED))},
            {"signer_id": "authority:legal", "key_id": "key:legal:2026-q3", "algorithm": "ed25519", "public_key": b64url(public_key(LEGAL_SEED))},
        ]})

        completed = run(signer_command(input_path=context_path, private_key_path=legal_key_path, signer_id="authority:legal", key_id="key:legal:2026-q3", signature_id="sig:legal:0002", signed_at="2026-07-25T20:00:00Z", output_path=signed_one))
        result = expect_success(completed, "create_v3_signature", "signed")
        if result.get("signature_count") != 1:
            raise TestFailure("create_v3_signature: expected one signature")
        value_one = json.loads(signed_one.read_text(encoding="utf-8"))
        statement = value_one["signatures"][0]["statement"]
        if value_one.get("object_type") != "agp.signed-decision-context/3":
            raise TestFailure("create_v3_signature: wrong wrapper version")
        if statement.get("object_type") != "agp.signature-statement/3":
            raise TestFailure("create_v3_signature: wrong statement version")
        if statement.get("context_object_type") != "agp.decision-context/3":
            raise TestFailure("create_v3_signature: wrong context reference")
        print("PASS  create_v3_signature                 wrapper=3 statement=3")
        passed += 1

        completed = run([sys.executable, str(VERIFIER), str(signed_one), "--keyring", str(keyring_path), "--schema-dir", str(SCHEMA_DIR)])
        result = expect_success(completed, "verify_v3_signature", "verified")
        if result.get("verified_signature_count") != 1:
            raise TestFailure("verify_v3_signature: expected one signature")
        print("PASS  verify_v3_signature                 verified=1")
        passed += 1

        completed = run(
            [
                "go",
                "run",
                GO_PACKAGE,
                str(signed_one),
                "--keyring",
                str(keyring_path),
                "--schema-dir",
                str(SCHEMA_DIR),
            ],
            cwd=GO_MODULE,
        )
        result = expect_success(
            completed,
            "go_verify_v3_signature",
            "verified",
        )
        if result.get("verified_signature_count") != 1:
            raise TestFailure(
                "go_verify_v3_signature: expected one signature"
            )
        print("PASS  go_verify_v3_signature              verified=1")
        passed += 1

        completed = run(signer_command(input_path=signed_one, private_key_path=finance_key_path, signer_id="authority:finance", key_id="key:finance:2026-q3", signature_id="sig:finance:0001", signed_at="2026-07-25T20:01:00Z", output_path=signed_two, append=True))
        result = expect_success(completed, "append_v3_signature", "signature_appended")
        if result.get("signature_count") != 2:
            raise TestFailure("append_v3_signature: expected two signatures")
        print("PASS  append_v3_signature                 signature_count=2")
        passed += 1

        value_two = json.loads(signed_two.read_text(encoding="utf-8"))
        statement_types = {entry["statement"]["object_type"] for entry in value_two["signatures"]}
        context_types = {entry["statement"]["context_object_type"] for entry in value_two["signatures"]}
        if statement_types != {"agp.signature-statement/3"}:
            raise TestFailure("append_v3_signature: mixed statement versions")
        if context_types != {"agp.decision-context/3"}:
            raise TestFailure("append_v3_signature: mixed context references")
        print("PASS  v3_versions_preserved               all-statements=3")
        passed += 1

        completed = run([sys.executable, str(VERIFIER), str(signed_two), "--keyring", str(keyring_path), "--schema-dir", str(SCHEMA_DIR)])
        result = expect_success(completed, "verify_two_v3_signatures", "verified")
        if result.get("verified_signature_count") != 2:
            raise TestFailure("verify_two_v3_signatures: expected two signatures")
        print("PASS  verify_two_v3_signatures            verified=2")
        passed += 1

        completed = run(
            [
                "go",
                "run",
                GO_PACKAGE,
                str(signed_two),
                "--keyring",
                str(keyring_path),
                "--schema-dir",
                str(SCHEMA_DIR),
            ],
            cwd=GO_MODULE,
        )
        result = expect_success(
            completed,
            "go_verify_two_v3_signatures",
            "verified",
        )
        if result.get("verified_signature_count") != 2:
            raise TestFailure(
                "go_verify_two_v3_signatures: expected two signatures"
            )
        print("PASS  go_verify_two_v3_signatures         verified=2")
        passed += 1

        completed = run(signer_command(input_path=signed_one, private_key_path=finance_key_path, signer_id="authority:finance", key_id="key:finance:2026-q3", signature_id="sig:finance:0001", signed_at="2026-07-25T20:01:00Z", output_path=signed_two_repeat, append=True))
        expect_success(completed, "deterministic_v3_append", "signature_appended")
        if signed_two.read_bytes() != signed_two_repeat.read_bytes():
            raise TestFailure("deterministic_v3_append: output bytes differ")
        print("PASS  deterministic_v3_append             bytes=identical")
        passed += 1

        tampered = json.loads(signed_one.read_text(encoding="utf-8"))
        tampered["context"]["evidence"][0]["issuer_id"] = "authority:other-lab"
        tampered_path = temp / "tampered-v3.json"
        write_json(tampered_path, tampered)
        completed = run([sys.executable, str(VERIFIER), str(tampered_path), "--keyring", str(keyring_path), "--schema-dir", str(SCHEMA_DIR)])
        result = parse_result(completed, "tampered_v3_provenance")
        if completed.returncode == 0 or result.get("error_code") != "CONTEXT_DIGEST_MISMATCH":
            raise TestFailure("tampered_v3_provenance: expected CONTEXT_DIGEST_MISMATCH")
        print("PASS  tampered_v3_provenance              error=CONTEXT_DIGEST_MISMATCH")
        passed += 1

    print(f"AGP Signed Decision Context v3 signer conformance: {passed}/{total} passed")
    return 0 if passed == total else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
