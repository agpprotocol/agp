#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
GENERATOR = ROOT / "trust_primitive_engine/tools/generate_release_sbom.py"
EXPECTED_TOTAL = 12


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    generator = GENERATOR.read_text(encoding="utf-8")

    checks = [
        ("SBOM generator exists", GENERATOR.is_file()),
        ("CycloneDX JSON 1.7 is explicit",
         '"1.7"' in generator and "bom-1.7.schema.json" in generator),
        ("generator avoids external SBOM tooling",
         "import cyclonedx" not in generator
         and "spdx_tools" not in generator
         and "syft" not in generator),
        ("wheel metadata is authoritative",
         ".dist-info/METADATA" in generator
         and "Requires-Dist: " in generator),
        ("runtime markers are evaluated",
         "default_environment" in generator
         and 'environment["extra"] = ""' in generator),
        ("runtime dependency closure is recursive",
         "deque" in generator
         and "distribution.requires" in generator),
        ("artifact SHA-256 hashes are embedded",
         '"alg": "SHA-256"' in generator
         and "sha256(wheel)" in generator
         and "sha256(sdist)" in generator),
        ("output is deterministic",
         "sort_keys=True" in generator
         and "sorted(set(direct_refs))" in generator),
        ("workflow generates SBOM after build",
         workflow.index("Build distributions")
         < workflow.index("Generate release SBOM")),
        ("SBOM stays outside PyPI distribution directory",
         "--output release-assets/agp-tpe.cdx.json" in workflow),
        ("SBOM is validated before publication",
         workflow.index("Generate release SBOM")
         < workflow.index("Publish distributions to PyPI")),
        ("SBOM is attached to exact GitHub release",
         "release-assets/agp-tpe.cdx.json" in workflow
         and 'gh release upload "${{ github.event.release.tag_name }}"'
         in workflow),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(f"AGP release SBOM contract: {passed}/{EXPECTED_TOTAL} passed")
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
