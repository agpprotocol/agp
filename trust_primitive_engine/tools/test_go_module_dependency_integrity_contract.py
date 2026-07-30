#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/go-release-integrity.yml"
VERIFIER = ROOT / "trust_primitive_engine/tools/verify_go_module_dependency_integrity.py"
EXPECTED_TOTAL = 12

EXPECTED_MODULES = (
    "canonicalization/go",
    "decision/signed/go",
    "decision_context/go",
    "go",
    "registry/go",
    "signed/go",
    "signed_decision_context/go",
    "transparency/go",
    "trust_primitive_engine/go",
)


def main() -> int:
    workflow_text = WORKFLOW.read_text(encoding="utf-8") if WORKFLOW.is_file() else ""
    verifier_text = VERIFIER.read_text(encoding="utf-8") if VERIFIER.is_file() else ""

    module_files = tuple(
        str(path.parent.relative_to(ROOT))
        for path in sorted(ROOT.rglob("go.mod"))
        if ".git" not in path.parts
    )
    go_sum_modules = tuple(
        str(path.parent.relative_to(ROOT))
        for path in sorted(ROOT.rglob("go.sum"))
        if ".git" not in path.parts
    )

    checks = [
        ("Go verifier exists", VERIFIER.is_file()),
        ("expected module inventory is exact", module_files == EXPECTED_MODULES),
        ("only TPE has an external checksum file",
         go_sum_modules == ("trust_primitive_engine/go",)),
        ("verifier inventories every module",
         all(f'Path("{module}")' in verifier_text for module in EXPECTED_MODULES)),
        ("verifier runs go mod verify",
         '["go", "mod", "verify"]' in verifier_text),
        ("verifier resolves the full module graph",
         '["go", "list", "-m", "all"]' in verifier_text),
        ("verifier checks tidy stability",
         '["go", "mod", "tidy"]' in verifier_text),
        ("verifier uses isolated temporary copies",
         "TemporaryDirectory" in verifier_text and "copytree" in verifier_text),
        ("default public proxy is explicit",
         "https://proxy.golang.org,direct" in verifier_text),
        ("default checksum database is explicit",
         "sum.golang.org" in verifier_text),
        ("release integrity workflow runs the verifier",
         "verify_go_module_dependency_integrity.py" in workflow_text),
        ("workflow does not disable checksum verification",
         not re.search(r"(?m)^\s*GOSUMDB:\s*off\s*$", workflow_text)),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(
        "AGP Go module dependency integrity contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
