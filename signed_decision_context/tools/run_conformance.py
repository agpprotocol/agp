#!/usr/bin/env python3
"""Ephemeral Stage 1 conformance runner using AGP-C14N-0.7."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "signed_decision_context/python/validate_signed_decision_context.py"
SCHEMA_DIR = ROOT / "registry/schemas"
CANONICALIZATION_PYTHON = ROOT / "canonicalization" / "python"

if str(CANONICALIZATION_PYTHON) not in sys.path:
    sys.path.insert(0, str(CANONICALIZATION_PYTHON))

from canonicalize import canonical_bytes


def base_context() -> dict[str, Any]:
    return {
        "object_type": "agp.decision-context/1",
        "context_id": "ctx:example:001",
        "created_at": "2026-07-22T20:00:00Z",
        "expires_at": None,
        "policy": {
            "id": "policy:example:approval",
            "version": 1,
            "digest": "1" * 64,
        },
        "proposal": {
            "type": "proposal:example:change",
            "payload": {"enabled": True},
        },
        "participants": [
            {"id": "authority:legal", "role": "approver", "weight": 1}
        ],
        "evidence": [],
        "constraints": [],
    }


def valid_object() -> dict[str, Any]:
    context = base_context()
    digest = hashlib.sha256(canonical_bytes(context)).hexdigest()
    statement = {
        "object_type": "agp.signature-statement/1",
        "purpose": "decision-context-attestation",
        "context_object_type": "agp.decision-context/1",
        "context_digest": {"algorithm": "sha-256", "value": digest},
        "signer_id": "authority:legal",
        "key_id": "key:authority-legal:2026-q3",
        "algorithm": "ed25519",
        "signed_at": "2026-07-22T20:00:00Z",
    }
    return {
        "object_type": "agp.signed-decision-context/1",
        "context": context,
        "context_digest": {"algorithm": "sha-256", "value": digest},
        "signatures": [{
            "signature_id": "sig:authority-legal:0001",
            "statement": statement,
            "signature": "AA",
        }],
    }


def run_case(name: str, obj: Any, expected_code: str | None) -> bool:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "case.json"
        path.write_text(
            json.dumps(obj, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        proc = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(path),
                "--schema-dir",
                str(SCHEMA_DIR),
            ],
            text=True,
            capture_output=True,
        )

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"FAIL {name}: invalid validator output: {proc.stdout!r}")
        return False

    actual = None if result.get("status") == "valid" else result.get("error_code")
    ok = actual == expected_code
    print(f"{'PASS' if ok else 'FAIL'} {name}: expected={expected_code} actual={actual}")
    if not ok and result.get("detail"):
        print(f"  detail={result['detail']}")
    return ok


def run_raw_case(name: str, raw: bytes, expected_code: str) -> bool:
    with tempfile.TemporaryDirectory() as td:
        path = Path(td) / "case.json"
        path.write_bytes(raw)
        proc = subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                str(path),
                "--schema-dir",
                str(SCHEMA_DIR),
            ],
            text=True,
            capture_output=True,
        )

    try:
        result = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(f"FAIL {name}: invalid validator output: {proc.stdout!r}")
        return False

    actual = result.get("error_code")
    ok = actual == expected_code
    print(f"{'PASS' if ok else 'FAIL'} {name}: expected={expected_code} actual={actual}")
    return ok


def main() -> int:
    valid = valid_object()
    cases: list[tuple[str, Any, str | None]] = [
        ("valid_single_signature", valid, None),
    ]

    x = deepcopy(valid)
    x["object_type"] = "agp.invalid/1"
    cases.append(("invalid_object_type", x, "INVALID_OBJECT_TYPE"))

    x = deepcopy(valid)
    x["extra"] = True
    cases.append(("unknown_top_level", x, "UNKNOWN_TOP_LEVEL_MEMBER"))

    x = deepcopy(valid)
    x["context"]["context_id"] = "X"
    cases.append(("invalid_context", x, "INVALID_CONTEXT"))

    x = deepcopy(valid)
    x["context_digest"]["value"] = "0" * 64
    cases.append(("context_digest_mismatch", x, "CONTEXT_DIGEST_MISMATCH"))

    x = deepcopy(valid)
    x["signatures"] = []
    cases.append(("empty_signatures", x, "EMPTY_SIGNATURE_COLLECTION"))

    x = deepcopy(valid)
    x["signatures"][0]["statement"]["context_digest"]["value"] = "0" * 64
    cases.append((
        "statement_context_digest_mismatch",
        x,
        "STATEMENT_CONTEXT_DIGEST_MISMATCH",
    ))

    x = deepcopy(valid)
    x["signatures"][0]["signature"] = "AA=="
    cases.append(("padded_signature", x, "INVALID_SIGNATURE_ENCODING"))

    x = deepcopy(valid)
    second = deepcopy(x["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    second["statement"]["key_id"] = "key:authority-legal:2026-q2"
    x["signatures"] = [x["signatures"][0], second]
    cases.append(("unsorted_signatures", x, "UNSORTED_SIGNATURES"))

    x = deepcopy(valid)
    x["signatures"].append(deepcopy(x["signatures"][0]))
    cases.append(("duplicate_signature_id", x, "DUPLICATE_SIGNATURE_ID"))

    x = deepcopy(valid)
    x["signatures"][0]["signature_id"] = "X"
    cases.append(("invalid_signature_id", x, "INVALID_SIGNATURE_ENTRY"))

    x = deepcopy(valid)
    x["signatures"][0]["statement"]["context_object_type"] = "agp.invalid/1"
    cases.append((
        "statement_context_type_mismatch",
        x,
        "STATEMENT_CONTEXT_TYPE_MISMATCH",
    ))

    x = deepcopy(valid)
    second = deepcopy(x["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    x["signatures"].append(second)
    cases.append((
        "duplicate_signature_entry",
        x,
        "DUPLICATE_SIGNATURE_ENTRY",
    ))

    x = deepcopy(valid)
    second = deepcopy(x["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    second["signature"] = "AB"
    x["signatures"].append(second)
    cases.append(("duplicate_attestation", x, "DUPLICATE_ATTESTATION"))

    structured_ok = all(run_case(*case) for case in cases)

    valid_raw = json.dumps(valid, separators=(",", ":")).encode("utf-8")
    raw_cases = [
        ("utf8_bom", b"\xef\xbb\xbf" + valid_raw, "INVALID_JSON"),
        (
            "duplicate_json_member",
            b'{"object_type":"agp.signed-decision-context/1",'
            b'"object_type":"agp.signed-decision-context/1"}',
            "INVALID_JSON",
        ),
        (
            "decimal_number",
            valid_raw[:-1] + b',"forbidden":1.5}',
            "INVALID_JSON",
        ),
        (
            "trailing_data",
            valid_raw + b"\n{}",
            "INVALID_JSON",
        ),
    ]
    raw_ok = all(run_raw_case(*case) for case in raw_cases)

    return 0 if structured_ok and raw_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
