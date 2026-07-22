from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BASE = ROOT / "decision" / "signed"
VECTORS = BASE / "vectors"
PYTHON_RESULTS = BASE / "results" / "python"
GO_RESULTS = BASE / "results" / "go"
GO_BINARY = BASE / "results" / "agp-signed-decision-go"


subprocess.run(
    [
        sys.executable,
        str(BASE / "tools" / "generate_vectors.py"),
    ],
    check=True,
)

for directory in (PYTHON_RESULTS, GO_RESULTS):
    shutil.rmtree(directory, ignore_errors=True)
    directory.mkdir(parents=True, exist_ok=True)

subprocess.run(
    [
        "go",
        "build",
        "-o",
        str(GO_BINARY),
        "./cmd/agp-signed-decision",
    ],
    cwd=BASE / "go",
    check=True,
)

subprocess.run(
    [
        sys.executable,
        str(BASE / "python" / "verify_signed_decision.py"),
        str(VECTORS),
        str(PYTHON_RESULTS),
    ],
    check=True,
)

subprocess.run(
    [
        str(GO_BINARY),
        str(VECTORS),
        str(GO_RESULTS),
    ],
    check=True,
)

rows = []

for vector_path in sorted(VECTORS.glob("*.json")):
    python_path = PYTHON_RESULTS / vector_path.name
    go_path = GO_RESULTS / vector_path.name

    python_bytes = python_path.read_bytes()
    go_bytes = go_path.read_bytes()

    vector = json.loads(vector_path.read_text(encoding="utf-8"))
    receipt = json.loads(python_bytes)

    expected_accepted = vector["expected"]
    expected_errors = vector["expected_errors"]

    byte_identical = python_bytes == go_bytes
    accepted_matches = (
        receipt["accepted"] == expected_accepted
    )
    errors_match = (
        receipt["error_codes"] == expected_errors
    )

    passed = (
        byte_identical
        and accepted_matches
        and errors_match
    )

    rows.append(
        {
            "vector": vector_path.name,
            "accepted": receipt["accepted"],
            "expected": expected_accepted,
            "errors": receipt["error_codes"],
            "expected_errors": expected_errors,
            "byte_identical": byte_identical,
            "passed": passed,
        }
    )

summary = {
    "profile": "AGP-Signed-Decision-Context-0.6",
    "vectors": len(rows),
    "passed": sum(row["passed"] for row in rows),
    "failed": sum(not row["passed"] for row in rows),
    "byte_identical": all(
        row["byte_identical"]
        for row in rows
    ),
    "rows": rows,
}

summary_path = BASE / "results" / "summary.json"
summary_path.write_text(
    json.dumps(summary, indent=2) + "\n",
    encoding="utf-8",
)

print(
    "AGP v0.6 Signed Decision Context: "
    f"{summary['passed']}/{summary['vectors']} passed"
)
print(
    "Byte-identical verification receipts: "
    f"{summary['byte_identical']}"
)

raise SystemExit(1 if summary["failed"] else 0)
