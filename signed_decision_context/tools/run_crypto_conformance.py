#!/usr/bin/env python3
"""Run persistent Stage 2 Ed25519 conformance vectors."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]

VERIFIER = (
    ROOT
    / "signed_decision_context"
    / "python"
    / "verify_signed_decision_context.py"
)

VECTORS = ROOT / "signed_decision_context" / "vectors"
SCHEMA_DIR = ROOT / "registry" / "schemas"


def read_json(path: Path) -> Any:
    return json.loads(
        path.read_text(encoding="utf-8")
    )


def run_vector(item: dict[str, Any]) -> bool:
    input_path = VECTORS / item["input"]
    keyring_path = VECTORS / item["keyring"]
    meta_path = VECTORS / item["meta"]

    meta = read_json(meta_path)

    process = subprocess.run(
        [
            sys.executable,
            str(VERIFIER),
            str(input_path),
            "--keyring",
            str(keyring_path),
            "--schema-dir",
            str(SCHEMA_DIR),
        ],
        text=True,
        capture_output=True,
    )

    try:
        result = json.loads(process.stdout)
    except json.JSONDecodeError:
        print(
            f"FAIL  {meta['vector']:<28} "
            f"invalid verifier output={process.stdout!r}"
        )

        if process.stderr:
            print(f"      stderr={process.stderr!r}")

        return False

    actual_verified = result.get("status") == "verified"
    actual_error = (
        None
        if actual_verified
        else result.get("error_code")
    )

    passed = (
        actual_verified == meta["verified"]
        and actual_error == meta["error_code"]
    )

    print(
        f"{'PASS' if passed else 'FAIL'}  "
        f"{meta['vector']:<28} "
        f"verified={actual_verified} "
        f"error={actual_error}"
    )

    if not passed and result.get("detail"):
        print(f"      detail={result['detail']}")

    return passed


def main() -> int:
    manifest_path = VECTORS / "manifest.json"

    if not manifest_path.exists():
        print(
            "ERROR: crypto vectors not found; run "
            "signed_decision_context/tools/"
            "generate_crypto_vectors.py first"
        )
        return 1

    manifest = read_json(manifest_path)

    results = [
        run_vector(item)
        for item in manifest["vectors"]
    ]

    passed = sum(results)
    total = len(results)

    print(
        f"AGP Signed Decision Context 1.0 crypto: "
        f"{passed}/{total} passed"
    )

    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
