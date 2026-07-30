#!/usr/bin/env python3
"""Contract for the successful attested release gate."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
EXPECTED_TOTAL = 18


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")
    upload = text.index("gh release upload")
    verify = text.index("- name: Verify published release attestations")
    summary = text.index("- name: Publish release verification summary")
    retain = text.index("- name: Upload release verification evidence")
    checks = [
        ("workflow is release-published only", "release:" in text and "types:" in text and "published" in text),
        ("workflow remains restricted to tpe tags", "startsWith(github.event.release.tag_name, 'tpe-v')" in text),
        ("release job retains trusted publishing environment", "environment:" in text and "pypi" in text.lower()),
        ("OIDC permission remains enabled", "id-token: write" in text),
        ("attestation permission remains enabled", "attestations: write" in text),
        ("wheel and sdist are built before publication", "python -m build --no-isolation" in text and text.index("python -m build --no-isolation") < upload),
        ("CycloneDX SBOM is generated before publication", "--output release-assets/agp-tpe.cdx.json" in text and text.index("--output release-assets/agp-tpe.cdx.json") < upload),
        ("checksums are generated before publication", "xargs sha256sum -- < /tmp/release-files.txt > SHA256SUMS" in text),
        ("checksums are validated before publication", "sha256sum --check SHA256SUMS" in text),
        ("release subjects receive provenance attestations", "actions/attest@" in text and "subject-path:" in text),
        ("packages receive CycloneDX SBOM attestations", "sbom-path: release-assets/agp-tpe.cdx.json" in text),
        ("distributions are published through trusted publisher", "pypa/gh-action-pypi-publish@" in text),
        ("all four required release assets are uploaded", all(marker in text[upload:verify] for marker in ("dist/*.whl", "dist/*.tar.gz", "dist/SHA256SUMS", "release-assets/agp-tpe.cdx.json"))),
        ("canonical gate runs only after release upload", upload < verify),
        ("canonical gate is the only post-upload verifier", "Verify downloaded release assets" not in text and "Download published release assets" not in text),
        ("canonical failure blocks successful completion", "if: always()" not in text[verify:summary]),
        ("failure summary remains observable", verify < summary < retain and "if: always()" in text[summary:retain]),
        ("verification evidence is retained after any outcome", "if: always()" in text[retain:] and "retention-days: 90" in text[retain:]),
    ]
    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)
    print(f"AGP successful attested release gate contract: {passed}/{EXPECTED_TOTAL} passed")
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
