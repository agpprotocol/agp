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


def base_context(version: int = 1) -> dict[str, Any]:
    context = {
        "object_type": f"agp.decision-context/{version}",
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

    if version in {2, 3}:
        context["evaluation_time"] = 1784894400

    if version == 3:
        context["evidence"] = [
            {
                "id": "evidence.security-review",
                "digest": "2" * 64,
                "media_type": "application/json",
                "evidence_type": "agp.evidence.security-review/1",
                "issuer_id": "authority:security-lab",
            }
        ]

    return context


def valid_object(version: int = 1) -> dict[str, Any]:
    context = base_context(version)
    digest = hashlib.sha256(canonical_bytes(context)).hexdigest()
    statement = {
        "object_type": f"agp.signature-statement/{version}",
        "purpose": "decision-context-attestation",
        "context_object_type": f"agp.decision-context/{version}",
        "context_digest": {"algorithm": "sha-256", "value": digest},
        "signer_id": "authority:legal",
        "key_id": "key:authority-legal:2026-q3",
        "algorithm": "ed25519",
        "signed_at": "2026-07-22T20:00:00Z",
    }
    return {
        "object_type": f"agp.signed-decision-context/{version}",
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
    valid = valid_object(1)
    valid_v2 = valid_object(2)
    valid_v3 = valid_object(3)

    cases: list[tuple[str, Any, str | None]] = [
        ("valid_single_signature_v1", valid, None),
        ("valid_single_signature_v2", valid_v2, None),
        ("valid_single_signature_v3", valid_v3, None),
    ]

    x = deepcopy(valid_v3)
    del x["context"]["evidence"][0]["issuer_id"]
    cases.append(("v3_missing_issuer_id", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v3)
    del x["context"]["evidence"][0]["evidence_type"]
    cases.append(("v3_missing_evidence_type", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v3)
    x["context"]["evidence"][0]["evidence_type"] = "agp.evidence.review/0"
    cases.append(("v3_invalid_evidence_type", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v3)
    x["object_type"] = "agp.signed-decision-context/2"
    cases.append(("wrapper_v2_context_v3_mismatch", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v3)
    x["signatures"][0]["statement"]["object_type"] = (
        "agp.signature-statement/2"
    )
    cases.append((
        "wrapper_v3_statement_v2_mismatch",
        x,
        "INVALID_SIGNATURE_STATEMENT",
    ))

    x = deepcopy(valid_v2)
    del x["context"]["evaluation_time"]
    cases.append(("v2_missing_evaluation_time", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v2)
    x["context"]["evaluation_time"] = True
    cases.append(("v2_boolean_evaluation_time", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v2)
    x["context"]["evaluation_time"] = -1
    cases.append(("v2_negative_evaluation_time", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v2)
    x["context"]["evaluation_time"] = 9007199254740992
    cases.append(("v2_unsafe_evaluation_time", x, "INVALID_JSON"))

    x = deepcopy(valid_v2)
    x["context"]["object_type"] = "agp.decision-context/1"
    cases.append(("wrapper_v2_context_v1_mismatch", x, "INVALID_CONTEXT"))

    x = deepcopy(valid)
    x["context"]["object_type"] = "agp.decision-context/2"
    x["context"]["evaluation_time"] = 1784894400
    cases.append(("wrapper_v1_context_v2_mismatch", x, "INVALID_CONTEXT"))

    x = deepcopy(valid_v2)
    x["signatures"][0]["statement"]["object_type"] = (
        "agp.signature-statement/1"
    )
    cases.append((
        "wrapper_v2_statement_v1_mismatch",
        x,
        "INVALID_SIGNATURE_STATEMENT",
    ))

    x = deepcopy(valid_v2)
    x["signatures"][0]["statement"]["context_object_type"] = (
        "agp.decision-context/1"
    )
    cases.append((
        "v2_statement_context_v1_mismatch",
        x,
        "STATEMENT_CONTEXT_TYPE_MISMATCH",
    ))

    x = deepcopy(valid)
    x["signatures"][0]["statement"]["object_type"] = (
        "agp.signature-statement/2"
    )
    cases.append((
        "wrapper_v1_statement_v2_mismatch",
        x,
        "INVALID_SIGNATURE_STATEMENT",
    ))

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

    x = deepcopy(valid)

    first = deepcopy(x["signatures"][0])
    first["signature_id"] = "sig:z-authority:0001"
    first["statement"]["signer_id"] = "authority:z"
    first["statement"]["key_id"] = "key:authority-z:2026"

    second = deepcopy(x["signatures"][0])
    second["signature_id"] = "sig:z-authority:0001"
    second["statement"]["signer_id"] = "authority:a"
    second["statement"]["key_id"] = "key:authority-a:2026"

    x["signatures"] = [first, second]

    cases.append((
        "unsorted_precedes_duplicate_signature_id",
        x,
        "UNSORTED_SIGNATURES",
    ))

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
