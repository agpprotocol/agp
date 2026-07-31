#!/usr/bin/env python3
"""Contract for controlled publication of an authorized draft."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "publish_authorized_draft_release.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("publication tool exists", TOOL.is_file()),
        ("publication tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate evidence is explicit",
            '"--candidate-report"' in text,
        ),
        (
            "tag authorization is explicit",
            '"--tag-authorization-file"' in text,
        ),
        (
            "publication authorization is explicit",
            '"--publication-authorization-file"' in text,
        ),
        (
            "candidate digest is recomputed",
            "candidate_digest = hashlib.sha256(" in text,
        ),
        (
            "clean tracked state is required",
            "tracked worktree or index is not clean" in text,
        ),
        (
            "source identity is verified",
            "current HEAD does not match candidate source commit"
            in text
            and "current package version does not match candidate"
            in text,
        ),
        (
            "remote annotated tag is verified",
            "remote annotated release tag is missing" in text
            and "remote tag does not peel to candidate source commit"
            in text,
        ),
        (
            "exact draft fields are read",
            "tagName,name,isDraft,isPrerelease,createdAt,"
            in text
            and "publishedAt,targetCommitish,assets,url"
            in text,
        ),
        (
            "draft must remain exact before mutation",
            '"isDraft": True' in text
            and '"publishedAt": None' in text
            and '"assets": []' in text,
        ),
        (
            "draft evidence is canonically hashed",
            "canonical_sha256" in text
            and "sort_keys=True" in text
            and 'separators=(",", ":")' in text,
        ),
        (
            "publication authorization binds exact draft",
            '"draft_release_sha256": draft_digest' in text
            and "authorize-draft-release-publication" in text,
        ),
        (
            "single exact publication mutation is used",
            "def publish_release(" in text
            and '"gh",' in text
            and '"release",' in text
            and '"edit",' in text
            and '"--draft=false",' in text
            and text.count('"--draft=false",') == 1,
        ),
        (
            "no release creation upload or deletion exists",
            "gh release create" not in text
            and "gh release upload" not in text
            and "gh release delete" not in text,
        ),
        (
            "published state is verified",
            '"isDraft": False' in text
            and "published release timestamp must be RFC3339 UTC"
            in text,
        ),
        (
            "release workflow event is required",
            '"--event",' in text
            and '"release",' in text
            and "matching release workflow run was not observed"
            in text,
        ),
        (
            "workflow identity is fixed",
            'EXPECTED_WORKFLOW_NAME = "Publish AGP TPE to PyPI"'
            in text,
        ),
        (
            "workflow run binds tag and commit",
            'item.get("headBranch") == tag' in text
            and 'item.get("headSha")' in text
            and 'candidate["source_commit"]' in text,
        ),
        (
            "tool reports publication trigger not success",
            'print("RELEASE_PUBLISHED=yes")' in text
            and 'print("PYPI_PUBLICATION_TRIGGERED=yes")'
            in text
            and "PYPI_PUBLISHED=yes" not in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP controlled draft publication contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
