from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VECTORS = ROOT / "generated"
PY_RESULTS = ROOT / "results" / "python"
GO_RESULTS = ROOT / "results" / "go"
GO_BIN = ROOT / "results" / "agp-resolver-go"


def run(cmd: list[str], cwd: Path | None = None) -> None:
    subprocess.run(cmd, cwd=cwd, check=True)


def main() -> None:
    run([sys.executable, str(ROOT / "tools" / "generate_vectors.py")])

    for directory in [PY_RESULTS, GO_RESULTS]:
        if directory.exists():
            shutil.rmtree(directory)
        directory.mkdir(parents=True)

    run(["go", "build", "-o", str(GO_BIN), "./cmd/agp-resolver"], cwd=ROOT / "go")
    run([sys.executable, str(ROOT / "python" / "resolver.py"), str(VECTORS), str(PY_RESULTS)])
    run([str(GO_BIN), str(VECTORS), str(GO_RESULTS)])

    rows = []
    mismatches = []
    for vector in sorted(VECTORS.glob("*.json")):
        py_out = PY_RESULTS / vector.name
        go_out = GO_RESULTS / vector.name
        py_bytes = py_out.read_bytes()
        go_bytes = go_out.read_bytes()
        identical = py_bytes == go_bytes
        source = json.loads(vector.read_text(encoding="utf-8"))
        result = json.loads(py_bytes)
        expected = source.get("expected_outcome")
        expected_ok = expected is None or result["outcome"] == expected
        row = {
            "vector": vector.name,
            "outcome": result["outcome"],
            "expected": expected,
            "byte_identical": identical,
            "expected_ok": expected_ok,
            "passed": identical and expected_ok,
        }
        rows.append(row)
        if not row["passed"]:
            mismatches.append(row)

    summary = {
        "profile": "AGP-Conformance-0.3",
        "implementations": ["Python", "Go"],
        "vectors": len(rows),
        "passed": sum(1 for r in rows if r["passed"]),
        "failed": len(mismatches),
        "byte_identical": all(r["byte_identical"] for r in rows),
        "rows": rows,
    }
    (ROOT / "results" / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"AGP v0.3 Conformance: {summary['passed']}/{summary['vectors']} passed")
    print(f"Byte-identical across Python and Go: {summary['byte_identical']}")
    if mismatches:
        print(json.dumps(mismatches[:10], indent=2))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
