#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 8

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

EXPECTED_OTHER_ACTIONS = {
    "actions/configure-pages@v5",
    "actions/upload-pages-artifact@v3",
    "actions/deploy-pages@v4",
    "pypa/gh-action-pypi-publish@release/v1",
}

LEGACY_OFFICIAL_ACTIONS = {
    "actions/checkout@v4",
    "actions/checkout@v5",
    "actions/checkout@v6",
    "actions/setup-go@v5",
    "actions/setup-go@v6",
    "actions/setup-python@v5",
    "actions/setup-python@v6",
}


def load_workflows() -> dict[str, str]:
    workflows = {}

    for workflow_file in sorted(WORKFLOW_DIR.glob("*.y*ml")):
        workflows[workflow_file.name] = workflow_file.read_text(
            encoding="utf-8"
        )

    return workflows


def files_using(
    workflows: dict[str, str],
    marker: str,
) -> set[str]:
    return {
        file_name
        for file_name, text in workflows.items()
        if marker in text
    }


def main() -> int:
    workflows = load_workflows()
    all_text = "\n".join(workflows.values())

    checkout_workflows = files_using(
        workflows,
        "actions/checkout@v7",
    )
    setup_go_workflows = files_using(
        workflows,
        "actions/setup-go@v7",
    )
    setup_python_workflows = files_using(
        workflows,
        "actions/setup-python@v7",
    )

    checks = [
        (
            "expected workflow inventory is present",
            EXPECTED_WORKFLOWS.issubset(workflows),
        ),
        (
            "checkout is migrated to v7",
            checkout_workflows
            == {
                "canonicalization-conformance.yml",
                "conformance.yml",
                "decision-context-conformance.yml",
                "go-release-integrity.yml",
                "pages.yml",
                "publish-pypi.yml",
                "schema-registry-conformance.yml",
                "tpe-conformance.yml",
            },
        ),
        (
            "setup-go is migrated to v7",
            setup_go_workflows
            == {
                "canonicalization-conformance.yml",
                "conformance.yml",
                "decision-context-conformance.yml",
                "go-release-integrity.yml",
                "schema-registry-conformance.yml",
            },
        ),
        (
            "setup-python is migrated to v7",
            setup_python_workflows
            == {
                "canonicalization-conformance.yml",
                "conformance.yml",
                "decision-context-conformance.yml",
                "publish-pypi.yml",
                "schema-registry-conformance.yml",
                "tpe-conformance.yml",
            },
        ),
        (
            "legacy official action versions are absent",
            not any(
                marker in all_text
                for marker in LEGACY_OFFICIAL_ACTIONS
            ),
        ),
        (
            "Go release integrity keeps full tag checkout",
            all(
                marker
                in workflows.get("go-release-integrity.yml", "")
                for marker in (
                    "actions/checkout@v7",
                    "fetch-depth: 0",
                    "actions/setup-go@v7",
                    'go-version: "stable"',
                    "check-latest: true",
                )
            ),
        ),
        (
            "TPE conformance keeps full history and Python 3.12",
            all(
                marker in workflows.get("tpe-conformance.yml", "")
                for marker in (
                    "actions/checkout@v7",
                    "fetch-depth: 0",
                    "actions/setup-python@v7",
                    'python-version: "3.12"',
                )
            ),
        ),
        (
            "unrelated action families remain unchanged",
            all(marker in all_text for marker in EXPECTED_OTHER_ACTIONS),
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
        "AGP GitHub Actions runtime contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
