#!/usr/bin/env python3

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/go-release-integrity.yml"
SDC_MODULE = "signed_decision_context/go"
TPE_MODULE = "trust_primitive_engine/go"
SDC_TAG = "signed_decision_context/go/v0.2.0"
TPE_TAG = "trust_primitive_engine/go/v0.2.2"
EXPECTED_TOTAL = 8


def workflow_has_module_integrity_block(
    workflow_text: str,
    module: str,
) -> bool:
    pattern = re.compile(
        rf"working-directory:\s*{re.escape(module)}"
        rf".*?go mod verify"
        rf".*?go test \./\.\.\."
        rf".*?go vet \./\.\.\."
        rf".*?govulncheck \./\.\.\.",
        re.DOTALL,
    )
    return pattern.search(workflow_text) is not None


def is_annotated_tag(tag_name: str) -> bool:
    completed = subprocess.run(
        ["git", "cat-file", "-t", tag_name],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    return completed.returncode == 0 and completed.stdout.strip() == "tag"


def main() -> int:
    workflow_exists = WORKFLOW.is_file()
    workflow_text = (
        WORKFLOW.read_text(encoding="utf-8")
        if workflow_exists
        else ""
    )

    checks = [
        ("dedicated workflow exists", workflow_exists),
        (
            "workflow permissions are read-only",
            re.search(
                r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$",
                workflow_text,
            )
            is not None,
        ),
        (
            "checkout and setup-go are pinned",
            all(
                marker in workflow_text
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
            "govulncheck is pinned to v1.6.0",
            "go install golang.org/x/vuln/cmd/govulncheck@v1.6.0"
            in workflow_text,
        ),
        (
            "Signed Decision Context runs verify/test/vet/vuln",
            workflow_has_module_integrity_block(workflow_text, SDC_MODULE),
        ),
        (
            "Trust Primitive Engine runs verify/test/vet/vuln",
            workflow_has_module_integrity_block(workflow_text, TPE_MODULE),
        ),
        (
            "current public release tags are annotated",
            all(
                tag_name in workflow_text
                and 'git cat-file -t "$release_tag"' in workflow_text
                and is_annotated_tag(tag_name)
                for tag_name in (SDC_TAG, TPE_TAG)
            ),
        ),
        (
            "timeout and concurrency are bounded",
            all(
                marker in workflow_text
                for marker in (
                    "timeout-minutes: 20",
                    "concurrency:",
                    "cancel-in-progress: true",
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
        "AGP Go release integrity contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
