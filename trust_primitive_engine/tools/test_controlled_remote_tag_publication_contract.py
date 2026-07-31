#!/usr/bin/env python3
"""Contract for controlled publication of one authorized tag."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "publish_authorized_candidate_tag.py"
)
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("remote publication tool exists", TOOL.is_file()),
        ("remote publication tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate evidence is explicit",
            '"--candidate-report"' in text and "required=True" in text,
        ),
        (
            "authorization evidence is explicit",
            '"--authorization-file"' in text,
        ),
        (
            "candidate evidence digest is recomputed",
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
            "authorization remains bound to candidate",
            '"candidate_sha256": candidate_digest' in text
            and '"release_tag": candidate["release_tag"]' in text
            and '"source_commit": candidate["source_commit"]' in text,
        ),
        (
            "candidate passed state is required",
            '"validation_status": "passed"' in text,
        ),
        (
            "candidate availability evidence is required",
            '"local_tag_available": True' in text
            and '"remote_tag_available": True' in text
            and '"pypi_version_available": True' in text,
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
            "package metadata must equal candidate",
            "current package name does not match candidate" in text
            and "current package version does not match candidate"
            in text,
        ),
        (
            "local tag must be annotated",
            "local release reference is not an annotated tag" in text,
        ),
        (
            "local tag must peel to candidate commit",
            "local tag does not peel to candidate source commit"
            in text,
        ),
        (
            "remote absence is rechecked",
            "remote release tag already exists" in text,
        ),
        (
            "only exact tag refspec is pushed",
            'f"{ref}:{ref}"' in text
            and '"--atomic"' in text,
        ),
        (
            "all tags are never pushed",
            '"push",\n        "--tags"' not in text
            and '"push",\n        "--mirror"' not in text
            and '"push",\n        "--all"' not in text,
        ),
        (
            "force and deletion are absent",
            '"--force"' not in text
            and '"--force-with-lease"' not in text
            and '"--delete"' not in text,
        ),
        (
            "remote tag object is verified",
            "remote tag object does not match local tag object" in text,
        ),
        (
            "remote peeled commit is verified",
            "remote tag does not peel to candidate source commit" in text,
        ),
        (
            "release creation and PyPI publication are absent",
            "gh release create" not in text
            and "pypa/gh-action-pypi-publish" not in text
            and 'print("GITHUB_RELEASE_CREATED=no")' in text
            and 'print("PYPI_PUBLISHED=no")' in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP controlled remote tag publication contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
