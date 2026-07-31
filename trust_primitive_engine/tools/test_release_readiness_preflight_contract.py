#!/usr/bin/env python3
"""Permanent contract for the reusable release-readiness preflight."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
TOOL = ROOT / "trust_primitive_engine/tools/release_readiness_preflight.py"
EXPECTED_TOTAL = 20


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    tool = TOOL.read_text(encoding="utf-8")

    preflight_index = workflow.index(
        "- name: Run release readiness preflight"
    )
    build_index = workflow.index("- name: Build distributions")

    checks = [
        ("preflight tool exists", TOOL.is_file()),
        ("tool is executable", TOOL.stat().st_mode & 0o111 != 0),
        (
            "tool accepts explicit tag",
            'parser.add_argument("--tag", required=True)' in tool,
        ),
        (
            "tool accepts reusable source directory",
            'parser.add_argument("--source-dir"' in tool,
        ),
        (
            "tool accepts expected package identity",
            'parser.add_argument("--expected-package"' in tool,
        ),
        (
            "tool uses configurable PyPI endpoint",
            '"--pypi-base-url"' in tool,
        ),
        (
            "tool reads project metadata",
            "pyproject.toml" in tool
            and 'payload["project"]' in tool,
        ),
        (
            "tool derives tag from package version",
            'expected_tag = f"tpe-v{package_version}"' in tool,
        ),
        (
            "tool rejects package identity drift",
            "unexpected package name" in tool,
        ),
        (
            "tool rejects tag-version mismatch",
            "release tag does not match pyproject.toml version"
            in tool,
        ),
        (
            "tool requires annotated tags",
            '"cat-file", "-t", args.tag' in tool
            and "release tag must be annotated" in tool,
        ),
        (
            "tool resolves tag commit",
            '"rev-list"' in tool and "args.tag" in tool,
        ),
        (
            "tool resolves checkout commit",
            '"rev-parse", "HEAD"' in tool,
        ),
        (
            "tool rejects checkout-tag mismatch",
            "checkout does not match release tag" in tool,
        ),
        (
            "tool checks exact PyPI package version",
            "urllib.request.urlopen" in tool and "/json" in tool,
        ),
        (
            "tool treats only 404 as available",
            "if exc.code == 404:" in tool and "return" in tool,
        ),
        (
            "tool refuses an existing version",
            "refusing to republish existing version" in tool,
        ),
        (
            "workflow invokes canonical preflight",
            "release_readiness_preflight.py" in workflow
            and '--tag "$RELEASE_TAG"' in workflow,
        ),
        (
            "preflight blocks before build",
            preflight_index < build_index
            and "if: always()" not in workflow[
                preflight_index:build_index
            ],
        ),
        (
            "inline preflight duplication removed",
            "TAG_VERSION_MATCH_PASS" not in workflow
            and "RELEASE_TAG_CHECKOUT_PASS" not in workflow
            and "Refuse an existing PyPI version" not in workflow,
        ),
    ]

    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)

    print(
        "AGP release readiness preflight contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
