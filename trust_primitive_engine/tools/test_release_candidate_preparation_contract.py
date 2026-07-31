#!/usr/bin/env python3
"""Permanent contract for non-destructive candidate release preparation."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "trust_primitive_engine/tools/prepare_release_candidate.py"
EXPECTED_TOTAL = 20


def main() -> int:
    text = TOOL.read_text(encoding="utf-8")

    checks = [
        ("candidate tool exists", TOOL.is_file()),
        ("candidate tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "candidate version is explicit",
            'parser.add_argument("--version", required=True)' in text,
        ),
        (
            "candidate evidence directory is explicit",
            '"--output-dir"' in text and "required=True" in text,
        ),
        (
            "candidate version requires stable SemVer",
            "candidate version must be stable SemVer X.Y.Z" in text,
        ),
        (
            "package identity is validated",
            "unexpected package name" in text,
        ),
        (
            "candidate must match project metadata",
            "candidate version does not match pyproject.toml" in text,
        ),
        (
            "tracked tree must be clean",
            "tracked worktree or index is not clean" in text,
        ),
        (
            "local tag availability is checked",
            "local release tag already exists" in text,
        ),
        (
            "remote tag availability is checked",
            '"git", "ls-remote", "--tags"' in text
            and "remote release tag already exists" in text,
        ),
        (
            "PyPI version availability is checked",
            "urllib.request.urlopen" in text
            and "candidate version already exists on PyPI" in text,
        ),
        (
            "only PyPI 404 means available",
            "if exc.code == 404:" in text,
        ),
        (
            "source commit is recorded",
            '"git", "rev-parse", "HEAD"' in text,
        ),
        (
            "source branch is recorded",
            '"git", "branch", "--show-current"' in text,
        ),
        (
            "complete validation is executed",
            "trust_primitive_engine/tools/run_all_tests.py" in text,
        ),
        (
            "complete validation marker is parsed",
            "AGP TPE 2\\.6 development validation:" in text,
        ),
        (
            "deterministic JSON evidence is written",
            "release-candidate.json" in text
            and "sort_keys=True" in text,
        ),
        (
            "human-readable summary is written",
            "release-candidate.md" in text,
        ),
        (
            "validation log is retained",
            "validation.log" in text,
        ),
        (
            "tool explicitly remains non-destructive",
            '"creates_tag": False' in text
            and '"creates_github_release": False' in text
            and '"publishes_to_pypi": False' in text
            and "git tag " not in text
            and "gh release create" not in text,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP release candidate preparation contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
