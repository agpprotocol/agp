#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_DIR = ROOT / ".github/workflows"
EXPECTED_TOTAL = 8

EXPECTED_REFERENCES = {
    "pages.yml": {
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
    },
    "publish-pypi.yml": {
        (
            "pypa/gh-action-pypi-publish@"
            "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
            " # v1.14.2"
        ),
    },
}

PRIVILEGED_ACTION_PATTERN = re.compile(
    r"uses:\s*("
    r"actions/(?:configure-pages|upload-pages-artifact|deploy-pages)"
    r"|pypa/gh-action-pypi-publish"
    r")@([^\s#]+)"
)

FULL_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def read_workflow(name: str) -> str:
    return (WORKFLOW_DIR / name).read_text(encoding="utf-8")


def main() -> int:
    pages = read_workflow("pages.yml")
    pypi = read_workflow("publish-pypi.yml")
    combined = pages + "\n" + pypi
    references = PRIVILEGED_ACTION_PATTERN.findall(combined)

    checks = [
        (
            "expected privileged action references are pinned",
            all(
                marker in read_workflow(file_name)
                for file_name, markers in EXPECTED_REFERENCES.items()
                for marker in markers
            ),
        ),
        (
            "all privileged actions use full commit SHAs",
            len(references) == 4
            and all(
                FULL_SHA_PATTERN.fullmatch(reference)
                for _, reference in references
            ),
        ),
        (
            "no privileged action uses a moving tag",
            not any(
                marker in combined
                for marker in (
                    "actions/configure-pages@v",
                    "actions/upload-pages-artifact@v",
                    "actions/deploy-pages@v",
                    "pypa/gh-action-pypi-publish@release/",
                    "pypa/gh-action-pypi-publish@v",
                )
            ),
        ),
        (
            "Pages permissions remain least privilege",
            all(
                marker in pages
                for marker in (
                    "permissions:",
                    "contents: read",
                    "pages: write",
                    "id-token: write",
                )
            ),
        ),
        (
            "Pages deployment remains environment-bound",
            all(
                marker in pages
                for marker in (
                    "name: github-pages",
                    "steps.deployment.outputs.page_url",
                    'group: "pages"',
                    "cancel-in-progress: true",
                )
            ),
        ),
        (
            "PyPI publishing retains trusted publishing",
            all(
                marker in pypi
                for marker in (
                    "environment:",
                    "name: pypi",
                    "id-token: write",
                    "pypa/gh-action-pypi-publish@",
                )
            )
            and not any(
                marker in pypi
                for marker in (
                    "password:",
                    "user:",
                    "username:",
                    "api-token:",
                    "repository-url:",
                )
            ),
        ),
        (
            "PyPI checkout remains release-tag bound",
            all(
                marker in pypi
                for marker in (
                    "ref: ${{ github.event.release.tag_name }}",
                    "persist-credentials: false",
                    "RELEASE_TAG_CHECKOUT_PASS",
                    "TAG_VERSION_MATCH_PASS",
                )
            ),
        ),
        (
            "PyPI release remains guarded and non-republishing",
            all(
                marker in pypi
                for marker in (
                    "startsWith("
                    "github.event.release.tag_name, 'tpe-v'"
                    ")",
                    "Refuse an existing PyPI version",
                    "python -m twine check dist/*",
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
        "AGP GitHub Actions supply-chain contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
