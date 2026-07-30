#!/usr/bin/env python3

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
EXPECTED_TOTAL = 20
CYCLONEDX_PREDICATE = "https://cyclonedx.org/bom"


def main() -> int:
    text = WORKFLOW.read_text(encoding="utf-8")

    upload_block = text[
        text.index("gh release upload"):
        text.index("--clobber", text.index("gh release upload")) + len("--clobber")
    ]

    verify_block = text[
        text.index("Verify downloaded release assets"):
    ]

    checks = [
        (
            "release job can write GitHub Release assets",
            re.search(
                r"jobs:\s*\n\s+publish:.*?"
                r"permissions:\s*\n"
                r"\s+contents:\s+write",
                text,
                re.DOTALL,
            )
            is not None,
        ),
        (
            "wheel is attached to GitHub Release",
            "dist/*.whl" in upload_block,
        ),
        (
            "source distribution is attached to GitHub Release",
            "dist/*.tar.gz" in upload_block,
        ),
        (
            "checksum manifest remains attached",
            "dist/SHA256SUMS" in upload_block,
        ),
        (
            "CycloneDX SBOM remains attached",
            "release-assets/agp-tpe.cdx.json" in upload_block,
        ),
        (
            "fresh release download step exists",
            "Download published release assets" in text
            and "gh release download" in text,
        ),
        (
            "all four release asset classes are downloaded",
            all(
                pattern in text
                for pattern in (
                    "--pattern '*.whl'",
                    "--pattern '*.tar.gz'",
                    "--pattern 'SHA256SUMS'",
                    "--pattern 'agp-tpe.cdx.json'",
                )
            ),
        ),
        (
            "asset cardinality is enforced",
            all(
                marker in text
                for marker in (
                    "wheel_count",
                    "sdist_count",
                    "checksum_count",
                    "sbom_count",
                )
            ),
        ),
        (
            "downloaded checksums are verified",
            "sha256sum --check SHA256SUMS" in text,
        ),
        (
            "release tag source ref is enforced",
            "--source-ref \"refs/tags/${RELEASE_TAG}\"" in verify_block,
        ),
        (
            "released tag commit digest is enforced",
            "--source-digest \"${SOURCE_DIGEST}\"" in verify_block,
        ),
        (
            "source digest comes from checked-out tag",
            'SOURCE_DIGEST="$(git rev-parse HEAD)"' in text,
        ),
        (
            "repository identity is enforced",
            "--repo agpprotocol/agp" in verify_block,
        ),
        (
            "signer workflow identity is enforced",
            "--signer-workflow "
            "agpprotocol/agp/.github/workflows/publish-pypi.yml"
            in verify_block,
        ),
        (
            "self-hosted attestations are rejected",
            "--deny-self-hosted-runners" in verify_block,
        ),
        (
            "SLSA provenance is verified for every release asset",
            'for artifact in "$release_dir"/*; do' in verify_block
            and "gh attestation verify" in verify_block,
        ),
        (
            "CycloneDX predicate type is explicit",
            f"--predicate-type {CYCLONEDX_PREDICATE}" in verify_block,
        ),
        (
            "SBOM attestation is verified for wheel and sdist",
            'for package in "$release_dir"/*.whl '
            '"$release_dir"/*.tar.gz; do' in verify_block,
        ),
        (
            "verification occurs after release upload",
            text.index("gh release upload")
            < text.index("Download published release assets")
            < text.index("Verify downloaded release assets"),
        ),
        (
            "release verification remains after PyPI publication",
            text.index("Publish distributions to PyPI")
            < text.index("Verify downloaded release assets"),
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
        "AGP release attestation verification contract: "
        f"{passed}/{EXPECTED_TOTAL} passed"
    )
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    raise SystemExit(main())
