#!/usr/bin/env python3
"""Compare Python and Go Stage 1 Signed Decision Context validation."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

PYTHON_VALIDATOR = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "validate_signed_decision_context.py"
)

GO_DIR = ROOT / "signed_decision_context" / "go"
SCHEMA_DIR = ROOT / "registry" / "schemas"

RUNNER_PATH = (
    ROOT
    / "signed_decision_context"
    / "tools"
    / "run_conformance.py"
)


def load_stage1_runner():
    spec = importlib.util.spec_from_file_location(
        "signed_decision_context_stage1_runner",
        RUNNER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Stage 1 runner")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_json(command: list[str]) -> tuple[int, dict[str, Any] | None, str]:
    process = subprocess.run(
        command,
        text=True,
        capture_output=True,
    )

    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        return process.returncode, None, process.stderr

    return process.returncode, result, process.stderr


def observable(result: dict[str, Any] | None) -> tuple[str | None, str | None]:
    if result is None:
        return None, None

    status = result.get("status")
    error = None if status == "valid" else result.get("error_code")
    return status, error


def run_case(
    binary: Path,
    name: str,
    value: Any,
    expected_error: str | None,
) -> bool:
    raw = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")

    return run_raw_case(
        binary,
        name,
        raw,
        expected_error,
    )


def run_raw_case(
    binary: Path,
    name: str,
    raw: bytes,
    expected_error: str | None,
) -> bool:
    with tempfile.TemporaryDirectory() as temp_dir:
        input_path = Path(temp_dir) / "case.json"
        input_path.write_bytes(raw)

        python_code, python_result, python_stderr = run_json([
            sys.executable,
            str(PYTHON_VALIDATOR),
            str(input_path),
            "--schema-dir",
            str(SCHEMA_DIR),
        ])

        go_code, go_result, go_stderr = run_json([
            str(binary),
            str(input_path),
            "--structural-only",
            "--schema-dir",
            str(SCHEMA_DIR),
        ])

    expected = (
        ("valid", None)
        if expected_error is None
        else ("invalid", expected_error)
    )

    python_observable = observable(python_result)
    go_observable = observable(go_result)

    passed = (
        python_result is not None
        and go_result is not None
        and python_observable == expected
        and go_observable == expected
        and python_code == go_code
    )

    print(
        f"{'PASS' if passed else 'FAIL'}  "
        f"{name:<42} "
        f"python={python_observable} "
        f"go={go_observable}"
    )

    if not passed:
        print(f"      expected={expected}")
        print(
            f"      exits: python={python_code} "
            f"go={go_code}"
        )

        if python_result is not None:
            print(f"      python_result={python_result}")
        elif python_stderr:
            print(f"      python_stderr={python_stderr!r}")

        if go_result is not None:
            print(f"      go_result={go_result}")
        elif go_stderr:
            print(f"      go_stderr={go_stderr!r}")

    return passed


def structured_cases(module):
    valid = module.valid_object()

    cases: list[tuple[str, Any, str | None]] = [
        ("valid_single_signature", valid, None),
    ]

    value = deepcopy(valid)
    value["object_type"] = "agp.invalid/1"
    cases.append((
        "invalid_object_type",
        value,
        "INVALID_OBJECT_TYPE",
    ))

    value = deepcopy(valid)
    value["extra"] = True
    cases.append((
        "unknown_top_level",
        value,
        "UNKNOWN_TOP_LEVEL_MEMBER",
    ))

    value = deepcopy(valid)
    value["context"]["context_id"] = "X"
    cases.append((
        "invalid_context",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid)
    value["context_digest"]["value"] = "0" * 64
    cases.append((
        "context_digest_mismatch",
        value,
        "CONTEXT_DIGEST_MISMATCH",
    ))

    value = deepcopy(valid)
    value["signatures"] = []
    cases.append((
        "empty_signatures",
        value,
        "EMPTY_SIGNATURE_COLLECTION",
    ))

    value = deepcopy(valid)
    value["signatures"][0]["statement"][
        "context_digest"
    ]["value"] = "0" * 64
    cases.append((
        "statement_context_digest_mismatch",
        value,
        "STATEMENT_CONTEXT_DIGEST_MISMATCH",
    ))

    value = deepcopy(valid)
    value["signatures"][0]["signature"] = "AA=="
    cases.append((
        "padded_signature",
        value,
        "INVALID_SIGNATURE_ENCODING",
    ))

    value = deepcopy(valid)
    second = deepcopy(value["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    second["statement"]["key_id"] = "key:authority-legal:2026-q2"
    value["signatures"] = [
        value["signatures"][0],
        second,
    ]
    cases.append((
        "unsorted_signatures",
        value,
        "UNSORTED_SIGNATURES",
    ))

    value = deepcopy(valid)
    value["signatures"].append(
        deepcopy(value["signatures"][0])
    )
    cases.append((
        "duplicate_signature_id",
        value,
        "DUPLICATE_SIGNATURE_ID",
    ))

    value = deepcopy(valid)
    value["signatures"][0]["signature_id"] = "X"
    cases.append((
        "invalid_signature_id",
        value,
        "INVALID_SIGNATURE_ENTRY",
    ))

    value = deepcopy(valid)
    value["signatures"][0]["statement"][
        "context_object_type"
    ] = "agp.invalid/1"
    cases.append((
        "statement_context_type_mismatch",
        value,
        "STATEMENT_CONTEXT_TYPE_MISMATCH",
    ))

    value = deepcopy(valid)
    second = deepcopy(value["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    value["signatures"].append(second)
    cases.append((
        "duplicate_signature_entry",
        value,
        "DUPLICATE_SIGNATURE_ENTRY",
    ))

    value = deepcopy(valid)
    second = deepcopy(value["signatures"][0])
    second["signature_id"] = "sig:authority-legal:0002"
    second["signature"] = "AB"
    value["signatures"].append(second)
    cases.append((
        "duplicate_attestation",
        value,
        "DUPLICATE_ATTESTATION",
    ))

    value = deepcopy(valid)

    first = deepcopy(value["signatures"][0])
    first["signature_id"] = "sig:z-authority:0001"
    first["statement"]["signer_id"] = "authority:z"
    first["statement"]["key_id"] = "key:authority-z:2026"

    second = deepcopy(value["signatures"][0])
    second["signature_id"] = "sig:z-authority:0001"
    second["statement"]["signer_id"] = "authority:a"
    second["statement"]["key_id"] = "key:authority-a:2026"

    value["signatures"] = [first, second]

    cases.append((
        "unsorted_precedes_duplicate_signature_id",
        value,
        "UNSORTED_SIGNATURES",
    ))

    return valid, cases


def main() -> int:
    module = load_stage1_runner()
    valid, cases = structured_cases(module)

    with tempfile.TemporaryDirectory() as temp_dir:
        binary = (
            Path(temp_dir)
            / "agp-signed-decision-context-verify"
        )

        build = subprocess.run(
            [
                "go",
                "build",
                "-o",
                str(binary),
                "./cmd/agp-signed-decision-context-verify",
            ],
            cwd=GO_DIR,
            text=True,
            capture_output=True,
        )

        if build.returncode != 0:
            print("ERROR: unable to build Go verifier")
            if build.stdout:
                print(build.stdout)
            if build.stderr:
                print(build.stderr)
            return 1

        results = [
            run_case(binary, *case)
            for case in cases
        ]

        valid_raw = json.dumps(
            valid,
            separators=(",", ":"),
        ).encode("utf-8")

        raw_cases = [
            (
                "utf8_bom",
                b"\xef\xbb\xbf" + valid_raw,
                "INVALID_JSON",
            ),
            (
                "duplicate_json_member",
                (
                    b'{"object_type":'
                    b'"agp.signed-decision-context/1",'
                    b'"object_type":'
                    b'"agp.signed-decision-context/1"}'
                ),
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

        results.extend(
            run_raw_case(binary, *case)
            for case in raw_cases
        )

    passed = sum(results)
    total = len(results)

    print(
        "AGP Signed Decision Context 1.0 "
        f"Python/Go structural parity: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
