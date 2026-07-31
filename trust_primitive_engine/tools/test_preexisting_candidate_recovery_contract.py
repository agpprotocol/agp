#!/usr/bin/env python3
"""Contract for controlled recovery of preexisting candidate evidence."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = (
    ROOT
    / "trust_primitive_engine/tools/"
    "recover_preexisting_release_candidate.py"
)
EXPECTED_TOTAL = 21


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("recovery tool exists", TOOL.is_file()),
        ("recovery tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "version repository commit and source are explicit",
            all(
                marker in text
                for marker in (
                    '"--version"',
                    '"--repository"',
                    '"--source-commit"',
                    '"--source-dir"',
                    '"--output-dir"',
                )
            ),
        ),
        (
            "tracked tree must be clean",
            "tracked source tree is not clean" in text,
        ),
        (
            "full Git object identifier is required",
            'GIT_OBJECT_ID = re.compile(r"^[0-9a-f]{40,64}$")'
            in text
            and "source commit must be a full lowercase Git "
            in text,
        ),
        (
            "worktree head binds source commit",
            "source worktree HEAD does not match source commit"
            in text,
        ),
        (
            "package version binds requested version",
            "package version does not match requested version"
            in text,
        ),
        (
            "local tag must be annotated",
            "local release tag is not annotated" in text,
        ),
        (
            "local tag peels to source commit",
            "local release tag does not peel to source commit"
            in text,
        ),
        (
            "remote tag object matches local tag",
            "remote annotated tag object does not match local tag"
            in text,
        ),
        (
            "remote tag peels to source commit",
            "remote release tag does not peel to source commit"
            in text,
        ),
        (
            "GitHub Release must be absent",
            "GitHub Release already exists" in text
            and "unable to prove GitHub Release absence" in text,
        ),
        (
            "PyPI version must be absent",
            "candidate version already exists on PyPI" in text,
        ),
        (
            "global validation is rerun",
            "run_all_tests.py" in text
            and "global validation did not fully pass" in text,
        ),
        (
            "validation baseline is explicit and bound",
            '"--expected-validation-total"' in text
            and '"--expected-validation-runner-sha256"' in text
            and "unexpected historical validation total" in text
            and "historical validation runner SHA-256 mismatch"
            in text,
        ),
        (
            "canonical candidate format is preserved",
            '"format": "agp-tpe-release-candidate-v1"' in text,
        ),
        (
            "recovery evidence has separate format",
            "agp-tpe-release-candidate-recovery-v1" in text,
        ),
        (
            "recovery binds candidate digest",
            '"candidate_sha256": candidate_digest' in text,
        ),
        (
            "recovery records exact tag object and commit",
            '"local_tag_object": tag_object' in text
            and '"local_tag_peeled_commit": peeled' in text,
        ),
        (
            "recovery creates no authorization",
            '"creates_authorization": False' in text
            and "AUTHORIZATION_CREATED=no" in text,
        ),
        (
            "recovery is read-only",
            "gh release create" not in text
            and "gh release edit" not in text
            and "gh release upload" not in text
            and "gh release delete" not in text
            and "git tag " not in text
            and "git push" not in text
            and "gh workflow run" not in text
            and "gh run rerun" not in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP preexisting candidate recovery contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
