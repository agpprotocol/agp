#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 9

EXPECTED_WORKFLOWS = {
    "canonicalization-conformance.yml",
    "conformance.yml",
    "decision-context-conformance.yml",
    "go-release-integrity.yml",
    "pages.yml",
    "publish-pypi.yml",
    "schema-registry-conformance.yml",
    "tpe-conformance.yml",
}

GO_123_WORKFLOWS = {
    "conformance.yml",
    "go-release-integrity.yml",
}


def load_workflows() -> dict[str, str]:
    return {
        path.name: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOW_DIR.glob("*.y*ml"))
    }


def main() -> int:
    workflows = load_workflows()
    combined = "\n".join(workflows.values())

    checks = [
        (
            "expected workflow inventory is exact",
            set(workflows) == EXPECTED_WORKFLOWS,
        ),
        (
            "all workflows use ubuntu 24.04",
            all(
                "runs-on: ubuntu-24.04" in text
                for text in workflows.values()
            ),
        ),
        (
            "ubuntu-latest is absent",
            "ubuntu-latest" not in combined,
        ),
        (
            "historical conformance uses Go 1.23.x",
            'go-version: "1.23.x"'
            in workflows["conformance.yml"],
        ),
        (
            "release integrity uses Go 1.23.x",
            'go-version: "1.23.x"'
            in workflows["go-release-integrity.yml"],
        ),
        (
            "moving stable Go input is absent",
            'go-version: "stable"' not in combined,
        ),
        (
            "check-latest is absent",
            "check-latest:" not in combined,
        ),
        (
            "reviewed Go workflows are exact",
            {
                name
                for name, text in workflows.items()
                if 'go-version: "1.23.x"' in text
            }
            == GO_123_WORKFLOWS,
        ),
        (
            "module-file workflows remain module driven",
            all(
                "go-version-file:" in workflows[name]
                for name in (
                    "canonicalization-conformance.yml",
                    "schema-registry-conformance.yml",
                )
            ),
        ),
    ]

    passed = 0

    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(
        "AGP CI runtime reproducibility contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )

    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
