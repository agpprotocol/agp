#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PY_VALIDATOR = ROOT / "decision_context/python/validate_decision_context.py"
GO_DIR = ROOT / "decision_context/go"
GO_BINARY = ROOT / "decision_context/results/agp-decision-context-validate-go"
VECTORS = ROOT / "decision_context/vectors"
SUMMARY = ROOT / "decision_context/results/summary.json"

spec = importlib.util.spec_from_file_location(
    "validate_decision_context",
    PY_VALIDATOR,
)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

GO_BINARY.parent.mkdir(parents=True, exist_ok=True)
subprocess.run(
    [
        "go",
        "build",
        "-o",
        str(GO_BINARY),
        "./cmd/agp-decision-context-validate",
    ],
    cwd=GO_DIR,
    check=True,
)

manifest = json.loads(
    (VECTORS / "manifest.json").read_text(encoding="utf-8")
)
results = []

for item in manifest["vectors"]:
    input_path = VECTORS / item["input"]
    meta = json.loads(
        (VECTORS / item["meta"]).read_text(encoding="utf-8")
    )
    raw = input_path.read_bytes()

    python_result = module.validate_bytes(raw)
    go_process = subprocess.run(
        [str(GO_BINARY), str(input_path)],
        text=True,
        capture_output=True,
    )
    go_result = json.loads(go_process.stdout)

    identical = (
        python_result["accepted"] == go_result["accepted"]
        and python_result["error_code"] == go_result["error_code"]
    )
    expected = (
        python_result["accepted"] == meta["accepted"]
        and python_result["error_code"] == meta["error_code"]
    )
    passed = identical and expected

    results.append(
        {
            "vector": meta["vector"],
            "passed": passed,
            "python": {
                "accepted": python_result["accepted"],
                "error_code": python_result["error_code"],
            },
            "go": {
                "accepted": go_result["accepted"],
                "error_code": go_result["error_code"],
            },
            "cross_language_identical": identical,
        }
    )

    print(
        f"{'PASS' if passed else 'FAIL'}  {meta['vector']:<28} "
        f"accepted={python_result['accepted']} "
        f"error={python_result['error_code']} "
        f"python_go={identical}"
    )

passed_count = sum(result["passed"] for result in results)
summary = {
    "profile": manifest["profile"],
    "vectors": len(results),
    "passed": passed_count,
    "failed": len(results) - passed_count,
    "cross_language_identical": all(
        result["cross_language_identical"] for result in results
    ),
    "results": results,
}
SUMMARY.write_text(
    json.dumps(summary, indent=2) + "\n",
    encoding="utf-8",
)

print(
    f"AGP Decision Context 0.9 cross-language: "
    f"{passed_count}/{len(results)} passed"
)
print(
    "Python/Go acceptance and error codes identical: "
    f"{summary['cross_language_identical']}"
)
raise SystemExit(0 if passed_count == len(results) else 1)
