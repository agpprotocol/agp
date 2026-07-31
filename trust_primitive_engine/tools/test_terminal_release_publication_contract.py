#!/usr/bin/env python3
"""Contract for terminal release publication verification."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "verify_terminal_release_publication.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("terminal verifier exists", TOOL.is_file()),
        ("terminal verifier is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "repository tag version and commit are explicit",
            all(
                marker in text
                for marker in (
                    '"--repository"',
                    '"--tag"',
                    '"--version"',
                    '"--source-commit"',
                )
            ),
        ),
        (
            "workflow run identity is explicit",
            '"--workflow-run-id"' in text,
        ),
        (
            "verification evidence is explicit",
            '"--verification-evidence"' in text,
        ),
        (
            "release exact fields are read",
            "tagName,name,isDraft,isPrerelease,createdAt,"
            in text
            and "publishedAt,targetCommitish,assets,url"
            in text,
        ),
        (
            "release must be published",
            '"isDraft": False' in text
            and '"isPrerelease": False' in text,
        ),
        (
            "release target must match exact commit",
            "published release target does not match source commit"
            in text,
        ),
        (
            "release requires exactly four assets",
            "published release must contain exactly four assets"
            in text,
        ),
        (
            "four release asset classes are fixed",
            all(
                marker in text
                for marker in (
                    '"wheel":',
                    '"sdist":',
                    '"checksums":',
                    '"sbom":',
                )
            ),
        ),
        (
            "assets must be uploaded and nonempty",
            "release asset is not uploaded" in text
            and "release asset size is invalid" in text,
        ),
        (
            "workflow identity is fixed",
            'EXPECTED_WORKFLOW_NAME = "Publish AGP TPE to PyPI"'
            in text,
        ),
        (
            "workflow must be completed successfully",
            '"status": "completed"' in text
            and '"conclusion": "success"' in text,
        ),
        (
            "workflow binds release tag and commit",
            '"headBranch": tag' in text
            and '"headSha": source_commit' in text,
        ),
        (
            "PyPI lookup is configurable",
            '"--pypi-endpoint"' in text
            and "urllib.request.urlopen" in text,
        ),
        (
            "PyPI requires exactly two distributions",
            "PyPI release must contain exactly two distributions"
            in text,
        ),
        (
            "PyPI wheel and sdist are required",
            '{"bdist_wheel", "sdist"}' in text,
        ),
        (
            "PyPI distributions require SHA256 and not-yanked state",
            "missing PyPI SHA-256 digest" in text
            and "PyPI distribution is yanked" in text,
        ),
        (
            "attestation evidence must pass for four assets",
            '"overall_status") != "passed"' in text
            and "verification evidence must cover four assets"
            in text,
        ),
        (
            "verifier is read-only",
            "gh release edit" not in text
            and "gh release create" not in text
            and "gh release upload" not in text
            and "gh release delete" not in text
            and "gh run rerun" not in text
            and "gh workflow run" not in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP terminal release publication contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
