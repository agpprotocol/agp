#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
EXPECTED_ACTION = (
    "actions/attest@"
    "508db95dd578ae2727ebd6217d5ba78e4fbda05d"
)
EXPECTED_TOTAL = 14


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    checks = [
        ("attestation action is pinned to reviewed SHA",
         text.count(EXPECTED_ACTION) == 2),
        ("moving attest action tags are absent",
         not re.search(r"actions/attest@v[0-9]", text)),
        ("OIDC permission remains enabled",
         "id-token: write" in text),
        ("attestation write permission is explicit",
         "attestations: write" in text),
        ("artifact metadata write permission is explicit",
         "artifact-metadata: write" in text),
        ("build provenance step exists",
         "Attest release build provenance" in text),
        ("wheel is a provenance subject",
         "dist/*.whl" in text),
        ("source distribution is a provenance subject",
         "dist/*.tar.gz" in text),
        ("checksum manifest is a provenance subject",
         "dist/SHA256SUMS" in text),
        ("SBOM is a provenance subject",
         "release-assets/agp-tpe.cdx.json" in text),
        ("dedicated SBOM attestation exists",
         "Attest release SBOM" in text
         and "sbom-path: release-assets/agp-tpe.cdx.json" in text),
        ("SBOM attestation covers both Python distributions",
         text.count("subject-path: |") == 2
         and text.count("dist/*.whl") >= 2
         and text.count("dist/*.tar.gz") >= 2),
        ("attestations are created before PyPI publication",
         text.index("Attest release build provenance")
         < text.index("Publish distributions to PyPI")
         and text.index("Attest release SBOM")
         < text.index("Publish distributions to PyPI")),
        ("release upload remains after successful publication",
         text.index("Publish distributions to PyPI")
         < text.index("Attach checksums to GitHub release")),
    ]

    passed = 0
    for label, condition in checks:
        if condition:
            passed += 1
            print(f"PASS  {label}")
        else:
            print(f"FAIL  {label}", file=sys.stderr)

    print(
        "AGP release provenance attestation contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
