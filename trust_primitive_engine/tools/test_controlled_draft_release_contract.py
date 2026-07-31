#!/usr/bin/env python3
"""Contract for controlled draft GitHub Release creation."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "create_authorized_draft_release.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("draft release tool exists", TOOL.is_file()),
        ("draft release tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate evidence is explicit",
            '"--candidate-report"' in text,
        ),
        (
            "authorization evidence is explicit",
            '"--authorization-file"' in text,
        ),
        (
            "release notes are explicit",
            '"--notes-file"' in text,
        ),
        (
            "repository is explicit",
            '"--repository"' in text,
        ),
        (
            "candidate digest is recomputed",
            "candidate_digest = hashlib.sha256(" in text,
        ),
        (
            "authorization remains bound",
            '"candidate_sha256": candidate_digest' in text
            and '"release_tag": candidate["release_tag"]' in text
            and '"source_commit": candidate["source_commit"]' in text,
        ),
        (
            "tracked repository state must be clean",
            "tracked worktree or index is not clean" in text,
        ),
        (
            "HEAD and package metadata must align",
            "current HEAD does not match candidate source commit" in text
            and "current package version does not match candidate"
            in text,
        ),
        (
            "remote annotated tag is required",
            "remote annotated release tag is missing" in text,
        ),
        (
            "remote tag commit is verified",
            "remote tag does not peel to candidate source commit"
            in text,
        ),
        (
            "existing release is rejected",
            "GitHub Release already exists" in text,
        ),
        (
            "tag verification is mandatory",
            '"--verify-tag"' in text,
        ),
        (
            "release is created as draft",
            '"--draft"' in text,
        ),
        (
            "title is deterministic",
            "AGP Trust Primitive Engine" in text
            and '"--title"' in text,
        ),
        (
            "notes file is passed directly",
            '"--notes-file"' in text
            and "generate-notes" not in text,
        ),
        (
            "draft state is verified",
            '"isDraft": True' in text
            and '"publishedAt": None' in text,
        ),
        (
            "draft starts with no assets",
            '"assets": []' in text,
        ),
        (
            "publication and package upload are absent",
            '"--draft=false"' not in text
            and "gh release edit" not in text
            and "gh release upload" not in text
            and "pypa/gh-action-pypi-publish" not in text
            and 'print("RELEASE_PUBLISHED=no")' in text
            and 'print("PYPI_PUBLISHED=no")' in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP controlled draft release contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
