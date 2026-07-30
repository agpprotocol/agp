#!/usr/bin/env python3
"""Permanent contract for trusted release-recovery execution."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/verify-release-attestations.yml"
EXPECTED_TOTAL = 20


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    checks = [
        ("manual recovery workflow exists", WORKFLOW.is_file()),
        (
            "workflow accepts explicit release tag",
            "workflow_dispatch:" in text
            and "required: true" in text,
        ),
        (
            "tag input restricted to tpe releases",
            'case "$RELEASE_TAG" in' in text
            and "tpe-v*) ;;" in text,
        ),
        (
            "trusted tooling checkout explicit",
            "Check out trusted recovery tooling" in text,
        ),
        (
            "checkout avoids historical tag",
            "ref: ${{ inputs.tag }}" not in text,
        ),
        (
            "checkout credentials not persisted",
            "persist-credentials: false" in text,
        ),
        (
            "historical tag fetched as data",
            "git fetch --force --no-tags origin \\" in text,
        ),
        (
            "tag refspec is explicit",
            '"refs/tags/${RELEASE_TAG}:refs/tags/${RELEASE_TAG}"'
            in text,
        ),
        (
            "tag resolves to commit",
            'git rev-list -n 1 "$RELEASE_TAG"' in text,
        ),
        (
            "resolved commit must be nonempty",
            'test -n "$release_commit"' in text,
        ),
        (
            "resolved identity recorded",
            "RELEASE_COMMIT=%s" in text
            and '>> "$GITHUB_ENV"' in text,
        ),
        (
            "historical source uses detached worktree",
            'git worktree add --detach released-source "$release_commit"'
            in text,
        ),
        (
            "verification runs in historical context",
            "working-directory: released-source" in text,
        ),
        (
            "trusted verifier path used",
            'python "$GITHUB_WORKSPACE/trust_primitive_engine/tools/'
            'verify_release_attestations.py" \\' in text,
        ),
        (
            "report written outside worktree",
            '--output-dir "$GITHUB_WORKSPACE/'
            'release-verification-report"' in text,
        ),
        (
            "requested tag passed to verifier",
            '--tag "$RELEASE_TAG"' in text,
        ),
        (
            "repository identity fixed",
            "--repository agpprotocol/agp" in text,
        ),
        (
            "signer workflow fixed",
            "--signer-workflow agpprotocol/agp/.github/workflows/"
            "publish-pypi.yml" in text,
        ),
        (
            "workflow remains verification only",
            not any(
                marker in text
                for marker in (
                    "python -m build",
                    "gh release upload",
                    "twine upload",
                    "gh release delete",
                )
            ),
        ),
        (
            "evidence retained",
            "if: always()" in text
            and "retention-days: 90" in text
            and "if-no-files-found: error" in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP release recovery trust boundary contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
