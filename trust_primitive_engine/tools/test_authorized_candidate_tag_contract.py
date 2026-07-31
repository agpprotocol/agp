#!/usr/bin/env python3
"""Contract for explicit local candidate-tag authorization."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "materialize_authorized_candidate_tag.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("tag materialization tool exists", TOOL.is_file()),
        ("tag materialization tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate evidence is explicit",
            '"--candidate-report"' in text and "required=True" in text,
        ),
        (
            "authorization evidence is explicit",
            '"--authorization-file"' in text,
        ),
        (
            "candidate evidence digest is computed",
            all(
                marker in text
                for marker in (
                    "candidate_digest = hashlib.sha256(",
                    "candidate_raw",
                    ").hexdigest()",
                )
            ),
        ),
        (
            "authorization binds candidate digest",
            '"candidate_sha256": candidate_digest' in text,
        ),
        (
            "authorization binds release tag",
            '"release_tag": candidate["release_tag"]' in text,
        ),
        (
            "authorization binds source commit",
            '"source_commit": candidate["source_commit"]' in text,
        ),
        (
            "authorization decision is exact",
            "authorize-local-annotated-tag" in text,
        ),
        (
            "authorization statement is exact",
            "I authorize creation of the local annotated candidate tag."
            in text,
        ),
        (
            "authorizer identity is required",
            "authorization identity is missing" in text,
        ),
        (
            "authorization time is bounded to UTC syntax",
            "authorization time must be RFC3339 UTC" in text,
        ),
        (
            "candidate passed state is required",
            '"validation_status": "passed"' in text,
        ),
        (
            "candidate remains non-destructive",
            '"creates_tag": False' in text
            and '"creates_github_release": False' in text
            and '"publishes_to_pypi": False' in text,
        ),
        (
            "tracked repository state must be clean",
            "tracked worktree or index is not clean" in text,
        ),
        (
            "HEAD must equal candidate commit",
            "current HEAD does not match candidate source commit"
            in text,
        ),
        (
            "tag availability is rechecked",
            "local release tag already exists" in text
            and "remote release tag already exists" in text,
        ),
        (
            "only annotated local tag is created",
            '"tag",\n                "--annotate"' in text,
        ),
        (
            "materialized tag identity is verified",
            "materialized reference is not an annotated tag" in text
            and "materialized tag does not peel to candidate commit"
            in text,
        ),
        (
            "push release and publication are absent",
            "git push" not in text
            and "gh release create" not in text
            and "pypa/gh-action-pypi-publish" not in text
            and 'print("TAG_PUSHED=no")' in text
            and 'print("GITHUB_RELEASE_CREATED=no")' in text
            and 'print("PYPI_PUBLISHED=no")' in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP authorized candidate tag contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
