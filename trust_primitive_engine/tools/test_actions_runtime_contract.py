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

EXPECTED_PRIVILEGED_ACTIONS = {
    (
        "actions/configure-pages@"
        "45bfe0192ca1faeb007ade9deae92b16b8254a0d"
        " # v6.0.0"
    ),
    (
        "actions/upload-pages-artifact@"
        "7b1f4a764d45c48632c6b24a0339c27f5614fb0b"
        " # v4.0.0"
    ),
    (
        "actions/deploy-pages@"
        "cd2ce8fcbc39b97be8ca5fce6e763baed58fa128"
        " # v5.0.0"
    ),
    (
        "pypa/gh-action-pypi-publish@"
        "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
        " # v1.14.2"
    ),
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
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
    )
    setup_go_workflows = files_using(
        workflows,
        "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
    )
    setup_python_workflows = files_using(
        workflows,
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
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
            "Go release integrity keeps reviewed checkout and Go 1.23.x",
            all(
                marker
                in workflows.get("go-release-integrity.yml", "")
                for marker in (
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                    "fetch-depth: 0",
                    "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
                    'go-version: "1.23.x"',
                )
            ),
        ),
        (
            "TPE conformance keeps full history and Python 3.12",
            all(
                marker in workflows.get("tpe-conformance.yml", "")
                for marker in (
                    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
                    "fetch-depth: 0",
                    "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97 # v7.0.0",
                    'python-version: "3.12"',
                )
            ),
        ),
        (
            "historical conformance uses reviewed Go 1.23.x",
            all(
                marker in workflows.get("conformance.yml", "")
                for marker in (
                    "actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e # v7.0.0",
                    'go-version: "1.23.x"',
                )
            ),
        ),
        (
            "privileged action families remain explicitly reviewed",
            all(
                marker in all_text
                for marker in EXPECTED_PRIVILEGED_ACTIONS
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
        "AGP GitHub Actions runtime contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
