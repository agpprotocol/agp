#!/usr/bin/env python3
"""End-to-end conformance tests for Signed Decision Context v2 signing."""

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
LEGAL_SEED = bytes(range(1, 33))
FINANCE_SEED = bytes(range(33, 65))

class TestFailure(Exception):
    pass

def b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")

def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)

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

def context_v2() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/2",
        "context_id": "ctx:signer-v2:test:001",
        "created_at": "2026-07-22T20:00:00Z",
        "expires_at": None,
        "evaluation_time": 1784894400,
        "policy": {"id": "policy:example:approval", "version": 1, "digest": "1" * 64},
        "proposal": {"type": "proposal:example:change", "payload": {"enabled": True}},
        "participants": [
            {"id": "authority:finance", "role": "approver", "weight": 1},
            {"id": "authority:legal", "role": "approver", "weight": 1},
        ],
        "evidence": [],
        "constraints": [],
    }

def signer_command(*, input_path: Path, private_key_path: Path, signer_id: str, key_id: str, signature_id: str, signed_at: str, output_path: Path, append: bool = False) -> list[str]:
    command = [sys.executable, str(SIGNER), str(input_path), "--private-key", str(private_key_path), "--signer-id", signer_id, "--key-id", key_id, "--signature-id", signature_id, "--signed-at", signed_at, "--output", str(output_path)]
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
    total = 6
    with tempfile.TemporaryDirectory(prefix="agp-signer-v2-conformance-") as directory:
        temp = Path(directory)
        context_path = temp / "context-v2.json"
        legal_key_path = temp / "legal-private.json"
        finance_key_path = temp / "finance-private.json"
        keyring_path = temp / "keyring.json"
        signed_one = temp / "signed-one-v2.json"
        signed_two = temp / "signed-two-v2.json"
        signed_two_repeat = temp / "signed-two-v2-repeat.json"

        write_json(context_path, context_v2())
        write_json(legal_key_path, {"algorithm": "ed25519", "private_key": b64url(LEGAL_SEED)})
        write_json(finance_key_path, {"algorithm": "ed25519", "private_key": b64url(FINANCE_SEED)})
        write_json(keyring_path, {"keys": [
            {"signer_id": "authority:finance", "key_id": "key:finance:2026-q3", "algorithm": "ed25519", "public_key": b64url(public_key(FINANCE_SEED))},
            {"signer_id": "authority:legal", "key_id": "key:legal:2026-q3", "algorithm": "ed25519", "public_key": b64url(public_key(LEGAL_SEED))},
        ]})

        completed = run(signer_command(input_path=context_path, private_key_path=legal_key_path, signer_id="authority:legal", key_id="key:legal:2026-q3", signature_id="sig:legal:0002", signed_at="2026-07-22T20:00:00Z", output_path=signed_one))
        result = expect_success(completed, "create_v2_signature", "signed")
        if result.get("signature_count") != 1:
            raise TestFailure("create_v2_signature: expected one signature")
        value_one = json.loads(signed_one.read_text(encoding="utf-8"))
        statement = value_one["signatures"][0]["statement"]
        if value_one.get("object_type") != "agp.signed-decision-context/2":
            raise TestFailure("create_v2_signature: wrong wrapper version")
        if statement.get("object_type") != "agp.signature-statement/2":
            raise TestFailure("create_v2_signature: wrong statement version")
        if statement.get("context_object_type") != "agp.decision-context/2":
            raise TestFailure("create_v2_signature: wrong context reference")
        print("PASS  create_v2_signature                 wrapper=2 statement=2")
        passed += 1

        completed = run([sys.executable, str(VERIFIER), str(signed_one), "--keyring", str(keyring_path)])
        result = expect_success(completed, "verify_v2_signature", "verified")
        if result.get("verified_signature_count") != 1:
            raise TestFailure("verify_v2_signature: expected one signature")
        print("PASS  verify_v2_signature                 verified=1")
        passed += 1

        completed = run(signer_command(input_path=signed_one, private_key_path=finance_key_path, signer_id="authority:finance", key_id="key:finance:2026-q3", signature_id="sig:finance:0001", signed_at="2026-07-22T20:01:00Z", output_path=signed_two, append=True))
        result = expect_success(completed, "append_v2_signature", "signature_appended")
        if result.get("signature_count") != 2:
            raise TestFailure("append_v2_signature: expected two signatures")
        print("PASS  append_v2_signature                 signature_count=2")
        passed += 1

        value_two = json.loads(signed_two.read_text(encoding="utf-8"))
        statement_types = {entry["statement"]["object_type"] for entry in value_two["signatures"]}
        context_types = {entry["statement"]["context_object_type"] for entry in value_two["signatures"]}
        if statement_types != {"agp.signature-statement/2"}:
            raise TestFailure("append_v2_signature: mixed statement versions")
        if context_types != {"agp.decision-context/2"}:
            raise TestFailure("append_v2_signature: mixed context references")
        print("PASS  v2_versions_preserved               all-statements=2")
        passed += 1

        completed = run([sys.executable, str(VERIFIER), str(signed_two), "--keyring", str(keyring_path)])
        result = expect_success(completed, "verify_two_v2_signatures", "verified")
        if result.get("verified_signature_count") != 2:
            raise TestFailure("verify_two_v2_signatures: expected two signatures")
        print("PASS  verify_two_v2_signatures            verified=2")
        passed += 1

        completed = run(signer_command(input_path=signed_one, private_key_path=finance_key_path, signer_id="authority:finance", key_id="key:finance:2026-q3", signature_id="sig:finance:0001", signed_at="2026-07-22T20:01:00Z", output_path=signed_two_repeat, append=True))
        expect_success(completed, "deterministic_v2_append", "signature_appended")
        if signed_two.read_bytes() != signed_two_repeat.read_bytes():
            raise TestFailure("deterministic_v2_append: output bytes differ")
        print("PASS  deterministic_v2_append             bytes=identical")
        passed += 1

    print(f"AGP Signed Decision Context v2 signer conformance: {passed}/{total} passed")
    return 0 if passed == total else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except TestFailure as exc:
        print(f"FAIL  {exc}", file=sys.stderr)
        raise SystemExit(1)
