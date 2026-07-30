#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_LOCK = ROOT / "requirements-ci-lock.txt"
RELEASE_LOCK = ROOT / "requirements-release-lock.txt"
WORKFLOWS = ROOT / ".github/workflows"
EXPECTED_TOTAL = 14


def lock_inventory(path: Path) -> tuple[set[str], int]:
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    packages = {
        match.group(1).lower()
        for match in re.finditer(r"(?m)^([A-Za-z0-9_.-]+)==", text)
    }
    hashes = text.count("--hash=sha256:")
    return packages, hashes


def main() -> int:
    runtime_packages, runtime_hashes = lock_inventory(RUNTIME_LOCK)
    release_packages, release_hashes = lock_inventory(RELEASE_LOCK)
    conformance = (WORKFLOWS / "conformance.yml").read_text(encoding="utf-8")
    tpe = (WORKFLOWS / "tpe-conformance.yml").read_text(encoding="utf-8")
    publish = (WORKFLOWS / "publish-pypi.yml").read_text(encoding="utf-8")
    all_workflows = "\n".join(
        path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOWS.glob("*.y*ml"))
    )

    runtime_required = {
        "attrs", "cffi", "cryptography", "hypothesis",
        "jsonschema", "jsonschema-specifications", "pycparser",
        "referencing", "rpds-py", "sortedcontainers",
    }
    release_required = {
        "build", "twine", "hatchling", "packaging", "pyproject-hooks",
    }

    checks = [
        ("runtime lock exists", RUNTIME_LOCK.is_file()),
        ("release lock exists", RELEASE_LOCK.is_file()),
        ("runtime graph inventory is complete", runtime_required <= runtime_packages),
        ("release graph inventory is complete", release_required <= release_packages),
        ("runtime lock includes hashes", runtime_hashes >= len(runtime_packages)),
        ("release lock includes hashes", release_hashes >= len(release_packages)),
        ("historical conformance enforces runtime hashes",
         "python -m pip install --require-hashes -r requirements-ci-lock.txt" in conformance),
        ("TPE conformance enforces runtime hashes",
         "python -m pip install --require-hashes -r requirements-ci-lock.txt" in tpe),
        ("publishing enforces release hashes",
         "python -m pip install --require-hashes -r requirements-release-lock.txt" in publish),
        ("publishing disables isolated dependency resolution",
         "python -m build --no-isolation" in publish),
        ("runtime lock is watched by TPE workflow",
         tpe.count('- "requirements-ci-lock.txt"') == 2),
        ("release lock is watched by TPE workflow",
         tpe.count('- "requirements-release-lock.txt"') == 2),
        ("lock files participate in pip cache key",
         "requirements-ci-lock.txt" in tpe and "requirements-release-lock.txt" in tpe),
        ("workflow installs do not bypass hash enforcement",
         "pip install -c constraints-ci.txt -r requirements-v0.4.txt" not in all_workflows),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(f"AGP Python transitive lock contract: {passed}/{EXPECTED_TOTAL} passed")
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
