#!/usr/bin/env python3
"""Contract for canonical verification of published release attestations."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/publish-pypi.yml"
TOOL = ROOT / "trust_primitive_engine/tools/verify_release_attestations.py"
EXPECTED_TOTAL = 20


def main() -> int:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    tool = TOOL.read_text(encoding="utf-8")
    upload_index = workflow.index("gh release upload")
    verify_index = workflow.index("- name: Verify published release attestations")
    summary_index = workflow.index("- name: Publish release verification summary")
    evidence_index = workflow.index("- name: Upload release verification evidence")
    checks = [
        ("publish workflow exists", WORKFLOW.is_file()),
        ("canonical verifier exists", TOOL.is_file()),
        ("release assets uploaded before verification", upload_index < verify_index),
        ("canonical verifier is the blocking gate", "Generate release verification evidence" not in workflow and "Verify downloaded release assets" not in workflow and "Download published release assets" not in workflow),
        ("verification step is not always-run", "      - name: Verify published release attestations\n        if: always()" not in workflow),
        ("verification shell is fail-fast", "set -euo pipefail" in workflow[verify_index:summary_index]),
        ("workflow invokes repository verifier", "python trust_primitive_engine/tools/verify_release_attestations.py \\" in workflow),
        ("release tag is passed explicitly", '--tag "$RELEASE_TAG"' in workflow),
        ("repository identity is fixed", "--repository agpprotocol/agp" in workflow),
        ("signer workflow identity is fixed", "--signer-workflow agpprotocol/agp/.github/workflows/publish-pypi.yml" in workflow),
        ("deterministic evidence directory is used", "--output-dir release-verification-report" in workflow),
        ("summary follows blocking verification", verify_index < summary_index),
        ("artifact upload follows summary", summary_index < evidence_index),
        ("summary is always published", "- name: Publish release verification summary\n        if: always()" in workflow),
        ("evidence is always uploaded", "- name: Upload release verification evidence\n        if: always()" in workflow),
        ("missing evidence fails artifact upload", "if-no-files-found: error" in workflow),
        ("evidence retention is ninety days", "retention-days: 90" in workflow),
        ("tool verifies one required asset of each class", all(marker in tool for marker in ('"wheel": "*.whl"', '"sdist": "*.tar.gz"', '"checksums": "SHA256SUMS"', '"sbom": "agp-tpe.cdx.json"'))),
        ("tool verifies provenance and CycloneDX predicates", "--deny-self-hosted-runners" in tool and "CYCLONEDX_PREDICATE" in tool),
        ("tool returns nonzero on verification errors", "if errors:" in tool and "return 1" in tool and "return 0" in tool),
    ]
    passed = 0
    for name, ok in checks:
        print(("PASS" if ok else "FAIL") + f": {name}")
        passed += int(ok)
    print(f"AGP release attestation verification contract: {passed}/{EXPECTED_TOTAL} passed")
    return 0 if passed == EXPECTED_TOTAL else 1


if __name__ == "__main__":
    sys.exit(main())
