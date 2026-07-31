#!/usr/bin/env python3
"""Contract for explicit draft publication authorization."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "validate_draft_publication_authorization.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("authorization validator exists", TOOL.is_file()),
        ("authorization validator is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate evidence is explicit",
            '"--candidate-report"' in text,
        ),
        (
            "tag authorization is explicit",
            '"--tag-authorization-file"' in text,
        ),
        (
            "publication authorization is separate",
            '"--publication-authorization-file"' in text,
        ),
        (
            "repository identity is explicit",
            '"--repository"' in text,
        ),
        (
            "candidate digest is recomputed",
            "candidate_digest = hashlib.sha256(" in text,
        ),
        (
            "tag authorization remains bound",
            '"decision": "authorize-local-annotated-tag"' in text
            and '"candidate_sha256": candidate_digest' in text,
        ),
        (
            "tracked repository state must be clean",
            "tracked worktree or index is not clean" in text,
        ),
        (
            "source state must align",
            "current HEAD does not match candidate source commit"
            in text
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
            "draft exact fields are read",
            all(
                marker in text
                for marker in (
                    "tagName,name,isDraft,isPrerelease,createdAt,",
                    "publishedAt,targetCommitish,assets,url",
                )
            ),
        ),
        (
            "draft state must remain unpublished",
            '"isDraft": True' in text
            and '"publishedAt": None' in text,
        ),
        (
            "draft must contain zero assets",
            '"assets": []' in text,
        ),
        (
            "draft target must match candidate",
            "draft release target does not match candidate source"
            in text,
        ),
        (
            "draft evidence is canonically hashed",
            "canonical_sha256" in text
            and "sort_keys=True" in text
            and 'separators=(",", ":")' in text,
        ),
        (
            "publication authorization binds all identities",
            '"draft_release_sha256": draft_digest' in text
            and '"repository": repository' in text
            and '"release_tag": candidate["release_tag"]' in text
            and '"source_commit": candidate["source_commit"]'
            in text,
        ),
        (
            "exact publication decision and statement are required",
            "authorize-draft-release-publication" in text
            and "which will trigger the configured release workflow"
            in text,
        ),
        (
            "validator performs no publication",
            "gh release edit" not in text
            and "--draft=false" not in text
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
        "AGP draft publication authorization contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
