#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
EXPECTED_TOTAL = 10


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    checks = [
        (
            "publishing workflow grants release asset permission",
            "contents: write" in text,
        ),
        (
            "checksum generation occurs after distribution build",
            text.index("Build distributions")
            < text.index("Generate release checksums"),
        ),
        (
            "checksum manifest is generated from wheel and sdist only",
            "printf '%s\\n' *.whl *.tar.gz | sort"
            in text
            and "xargs sha256sum -- < /tmp/release-files.txt > SHA256SUMS"
            in text,
        ),
        (
            "checksum generation is deterministic",
            "LC_ALL=C" in text
            and "printf '%s\\n' *.whl *.tar.gz | sort" in text,
        ),
        (
            "manifest requires exactly two distribution entries",
            "checksum_entries" in text
            and '[ "$checksum_entries" -eq 2 ]' in text,
        ),
        (
            "manifest is verified before publishing",
            "sha256sum --check SHA256SUMS" in text
            and text.index("Verify release checksums")
            < text.index("Publish distributions to PyPI"),
        ),
        (
            "wheel and source distribution validation remain present",
            "python -m zipfile --list dist/*.whl" in text
            and "tar -tzf dist/*.tar.gz" in text,
        ),
        (
            "PyPI publishing remains trusted-publisher based",
            "pypa/gh-action-pypi-publish@"
            "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"
            in text
            and "id-token: write" in text,
        ),
        (
            "checksum manifest is attached after PyPI publication",
            text.index("Publish distributions to PyPI")
            < text.index("Attach checksums to GitHub release"),
        ),
        (
            "release attachment is tag-bound and idempotent",
            'gh release upload "${{ github.event.release.tag_name }}"'
            in text
            and "--clobber" in text
            and "GH_TOKEN: ${{ github.token }}" in text,
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
        "AGP release artifact checksum contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
