#!/usr/bin/env python3
"""Compare Python and Go Signed Decision Context 1/2/3 validation."""

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


def load_runner():
    spec = importlib.util.spec_from_file_location(
        "signed_decision_context_stage1_runner",
        RUNNER_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load Stage 1 runner")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_json(
    command: list[str],
) -> tuple[int, dict[str, Any] | None, str]:
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


def observable(
    result: dict[str, Any] | None,
) -> tuple[str | None, str | None]:
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


def main() -> int:
    module = load_runner()

    valid_v1 = module.valid_object(1)
    valid_v2 = module.valid_object(2)
    valid_v3 = module.valid_object(3)

    cases: list[tuple[str, Any, str | None]] = [
        ("valid_single_signature_v1", valid_v1, None),
        ("valid_single_signature_v2", valid_v2, None),
        ("valid_single_signature_v3", valid_v3, None),
    ]

    value = deepcopy(valid_v2)
    del value["context"]["evaluation_time"]
    cases.append((
        "v2_missing_evaluation_time",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid_v3)
    del value["context"]["evidence"][0]["issuer_id"]
    cases.append((
        "v3_missing_issuer_id",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid_v3)
    del value["context"]["evidence"][0]["evidence_type"]
    cases.append((
        "v3_missing_evidence_type",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid_v3)
    value["context"]["evidence"][0]["evidence_type"] = (
        "agp.evidence.review/0"
    )
    cases.append((
        "v3_invalid_evidence_type",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid_v3)
    value["object_type"] = "agp.signed-decision-context/2"
    cases.append((
        "wrapper_v2_context_v3_mismatch",
        value,
        "INVALID_CONTEXT",
    ))

    value = deepcopy(valid_v3)
    value["signatures"][0]["statement"]["object_type"] = (
        "agp.signature-statement/2"
    )
    cases.append((
        "wrapper_v3_statement_v2_mismatch",
        value,
        "INVALID_SIGNATURE_STATEMENT",
    ))

    value = deepcopy(valid_v3)
    value["signatures"][0]["statement"]["context_object_type"] = (
        "agp.decision-context/2"
    )
    cases.append((
        "v3_statement_context_v2_mismatch",
        value,
        "STATEMENT_CONTEXT_TYPE_MISMATCH",
    ))

    value = deepcopy(valid_v1)
    value["object_type"] = "agp.invalid/1"
    cases.append((
        "invalid_object_type",
        value,
        "INVALID_OBJECT_TYPE",
    ))

    value = deepcopy(valid_v1)
    value["context_digest"]["value"] = "0" * 64
    cases.append((
        "context_digest_mismatch",
        value,
        "CONTEXT_DIGEST_MISMATCH",
    ))

    value = deepcopy(valid_v1)
    value["signatures"] = []
    cases.append((
        "empty_signatures",
        value,
        "EMPTY_SIGNATURE_COLLECTION",
    ))

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

    passed = sum(results)
    total = len(results)

    print(
        "AGP Signed Decision Context 1/2/3 "
        f"Python/Go structural parity: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
