#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CANON = ROOT / "canonicalization"
VECTORS = CANON / "vectors"
RESULTS = CANON / "results"
PY_RESULTS = RESULTS / "python"
GO_RESULTS = RESULTS / "go"
GO_BINARY = RESULTS / "agp-canonicalize-go"


def run(command: list[str], cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def main() -> int:
    shutil.rmtree(PY_RESULTS, ignore_errors=True)
    shutil.rmtree(GO_RESULTS, ignore_errors=True)
    PY_RESULTS.mkdir(parents=True)
    GO_RESULTS.mkdir(parents=True)

    run(
        [
            "go",
            "build",
            "-o",
            str(GO_BINARY),
            "./cmd/agp-canonicalize",
        ],
        cwd=CANON / "go",
    )

    manifest = json.loads(
        (VECTORS / "manifest.json").read_text(encoding="utf-8")
    )

    rows = []

    for vector in manifest["vectors"]:
        source = VECTORS / vector["input"]
        python_output = PY_RESULTS / (source.stem + ".receipt.json")
        go_output = GO_RESULTS / (source.stem + ".receipt.json")

        run(
            [
                sys.executable,
                str(CANON / "python" / "canonicalize.py"),
                str(source),
                str(python_output),
            ]
        )
        run([str(GO_BINARY), str(source), str(go_output)])

        python_bytes = python_output.read_bytes()
        go_bytes = go_output.read_bytes()
        python_receipt = json.loads(python_bytes)

        expected_error = vector["expected_error"]
        errors = python_receipt["error_codes"]

        expected_matches = (
            python_receipt["accepted"] == vector["expected"]
            and (
                expected_error is None
                or errors == [expected_error]
            )
        )

        byte_identical = python_bytes == go_bytes
        passed = expected_matches and byte_identical

        rows.append(
            {
                "vector": vector["name"],
                "accepted": python_receipt["accepted"],
                "expected": vector["expected"],
                "expected_error": expected_error,
                "error_codes": errors,
                "byte_identical": byte_identical,
                "passed": passed,
            }
        )

    summary = {
        "profile": "AGP-Canonicalization-0.7",
        "vectors": len(rows),
        "passed": sum(row["passed"] for row in rows),
        "failed": sum(not row["passed"] for row in rows),
        "byte_identical": all(row["byte_identical"] for row in rows),
        "rows": rows,
    }

    (RESULTS / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(
        "AGP v0.7 Canonicalization: "
        f"{summary['passed']}/{summary['vectors']} passed"
    )
    print(
        "Byte-identical canonicalization receipts: "
        f"{summary['byte_identical']}"
    )

    for row in rows:
        status = "PASS" if row["passed"] else "FAIL"
        print(
            f"{status:4}  {row['vector']:<30} "
            f"accepted={row['accepted']} "
            f"errors={row['error_codes']}"
        )

    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
