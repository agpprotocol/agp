#!/usr/bin/env python3
"""Compare Python and Go Signed Decision Context crypto verification."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

PYTHON_VERIFIER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "verify_signed_decision_context.py"
)

GO_DIR = ROOT / "signed_decision_context" / "go"

GO_BINARY = (
    GO_DIR
    / "agp-signed-decision-context-verify"
)

VECTORS = ROOT / "signed_decision_context" / "vectors"
SCHEMA_DIR = ROOT / "registry" / "schemas"


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def build_go() -> bool:
    process = subprocess.run(
        [
            "go",
            "build",
            "-o",
            str(GO_BINARY),
            "./cmd/agp-signed-decision-context-verify",
        ],
        cwd=GO_DIR,
        text=True,
        capture_output=True,
    )

    if process.returncode != 0:
        print("ERROR: unable to build Go verifier")

        if process.stdout:
            print(process.stdout)

        if process.stderr:
            print(process.stderr)

        return False

    return True


def run_command(command: list[str]) -> tuple[int, dict[str, Any] | None, str]:
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


def observable(result: dict[str, Any] | None) -> tuple[Any, Any]:
    if result is None:
        return None, None

    return result.get("status"), result.get("error_code")


def run_vector(item: dict[str, Any]) -> bool:
    input_path = VECTORS / item["input"]
    keyring_path = VECTORS / item["keyring"]
    meta = read_json(VECTORS / item["meta"])

    python_code, python_result, python_stderr = run_command([
        sys.executable,
        str(PYTHON_VERIFIER),
        str(input_path),
        "--keyring",
        str(keyring_path),
        "--schema-dir",
        str(SCHEMA_DIR),
    ])

    go_code, go_result, go_stderr = run_command([
        str(GO_BINARY),
        str(input_path),
        "--keyring",
        str(keyring_path),
        "--schema-dir",
        str(SCHEMA_DIR),
    ])

    python_observable = observable(python_result)
    go_observable = observable(go_result)

    expected_status = (
        "verified"
        if meta["verified"]
        else "unverified"
    )
    expected = (
        expected_status,
        meta["error_code"],
    )

    passed = (
        python_result is not None
        and go_result is not None
        and python_observable == go_observable
        and python_observable == expected
        and python_code == go_code
    )

    print(
        f"{'PASS' if passed else 'FAIL'}  "
        f"{meta['vector']:<28} "
        f"python={python_observable} "
        f"go={go_observable}"
    )

    if not passed:
        print(f"      expected={expected}")
        print(f"      python_exit={python_code}")
        print(f"      go_exit={go_code}")

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
    if not build_go():
        return 1

    manifest = read_json(VECTORS / "manifest.json")

    results = [
        run_vector(item)
        for item in manifest["vectors"]
    ]

    passed = sum(results)
    total = len(results)

    print(
        "AGP Signed Decision Context 1.0 "
        f"Python/Go crypto parity: {passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
